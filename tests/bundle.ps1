param(
    [Parameter(Mandatory)][string]$BundlePath,
    [Parameter(Mandatory)][ValidateSet('C', 'Rust')][string]$Variant,
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$scratch = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())

# Burn shows a package's DisplayName as the current step on the progress page;
# it is recorded in the bootstrapper application data, not the Burn manifest.
function Assert-DisplayNames($baFolder, $expected, $scope) {
    $data = [xml](Get-Content -LiteralPath (Join-Path $baFolder 'BootstrapperApplicationData.xml') -Raw)
    $names = @{}
    foreach ($node in @($data.SelectNodes('//*[local-name() = "WixPackageProperties"]'))) {
        $names[$node.Package] = $node.DisplayName
    }
    foreach ($package in $expected.Keys) {
        if ($names[$package] -ne $expected[$package]) {
            throw "$scope must report '$package' as '$($expected[$package])'; found '$($names[$package])'"
        }
    }
}
function Assert-BundleCondition($manifest, $scope) {
    $conditions = @($manifest.DocumentElement.SelectNodes('./*[local-name() = "Condition"]'))
    if ($conditions.Count -ne 1 -or
        $conditions[0].InnerText -ne 'VersionNT >= v10.0 AND VersionNT64 >= v10.0 AND WindowsBuildNumber >= 17763') {
        throw "$scope has an invalid or escaped minimum-Windows condition"
    }
}
try {
    $contents = Join-Path $scratch 'contents'
    $ba = Join-Path $scratch 'ba'
    & dotnet tool run wix burn extract $BundlePath -o $contents -oba $ba
    if ($LASTEXITCODE -ne 0) { throw 'Failed to extract built bundle' }
    $outer = [xml](Get-Content -LiteralPath (Join-Path $ba 'manifest.xml') -Raw)
    Assert-BundleCondition $outer 'Setup'
    $outerNs = [Xml.XmlNamespaceManager]::new($outer.NameTable)
    $outerNs.AddNamespace('b', $outer.DocumentElement.NamespaceURI)
    $outerPackages = @($outer.SelectNodes('//b:Chain/b:BundlePackage', $outerNs))
    if ($outerPackages.Count -ne 2 -or $outerPackages[0].Id -ne "Core$Variant" -or
        $outerPackages[1].Id -ne 'Java' -or $outerPackages[1].Permanent -ne 'yes') {
        throw 'Setup must execute legacy migration before fresh permanent Java detection'
    }
    if ($outerPackages[1].RollbackBoundaryForward -ne 'PayloadCommitted') {
        throw 'Java failure must retain the committed Ghidra installation for retry'
    }
    Assert-DisplayNames $ba @{
        "Core$Variant" = 'Ghidra Launch and Ghidra files'
        'Java'         = 'Java runtime (Eclipse Temurin)'
    } 'Setup'
    $outerEmbedded = @(Get-ChildItem -LiteralPath $contents -Recurse -File)
    if ($outerEmbedded.Count -ne 2) { throw 'Setup must embed only its native core and Java bundles' }
    $coreName = "GhidraLaunchCore$Variant.exe"
    $core = @($outerEmbedded | Where-Object Name -eq $coreName)
    $java = @($outerEmbedded | Where-Object Name -eq 'GhidraLaunchJava.exe')
    foreach ($entry in @(@($core, $coreName), @($java, 'GhidraLaunchJava.exe'))) {
        $files, $name = $entry
        if ($files.Count -ne 1 -or
            (Get-FileHash $files[0].FullName).Hash -ne (Get-FileHash "$root/GhidraLaunchSetup/bin/$Configuration/$name").Hash) {
            throw "Setup contains an unexpected nested bundle: $name"
        }
    }
    $javaContents = Join-Path $scratch 'java'
    $javaBa = Join-Path $scratch 'java-ba'
    & dotnet tool run wix burn extract $java[0].FullName -o $javaContents -oba $javaBa
    if ($LASTEXITCODE -ne 0) { throw 'Failed to extract Java stage' }
    $javaManifest = [xml](Get-Content (Join-Path $javaBa 'manifest.xml') -Raw)
    Assert-BundleCondition $javaManifest 'Java stage'
    $javaPackage = @($javaManifest.SelectNodes('//b:Chain/b:MsiPackage', $outerNs))
    if ($javaPackage.Count -ne 1 -or $javaPackage[0].Id -ne 'Temurin' -or
        $javaPackage[0].Permanent -ne 'yes') { throw 'Java stage must retain the shared JDK' }
    Assert-DisplayNames $javaBa @{ 'Temurin' = 'Java runtime (Eclipse Temurin)' } 'Java stage'
    $coreContents = Join-Path $scratch 'core'
    $coreBa = Join-Path $scratch 'core-ba'
    & dotnet tool run wix burn extract $core[0].FullName -o $coreContents -oba $coreBa
    if ($LASTEXITCODE -ne 0) { throw 'Failed to extract native core' }
    $contents = $coreContents
    $ba = $coreBa
    $helperName = if ($Variant -eq 'C') { 'GhidraLaunchGhidraHelperC.exe' } else { 'GhidraLaunchGhidraHelperRS.exe' }
    $helper = if ($Variant -eq 'C') {
        "$root/GhidraLaunchGhidraHelperC/x64/$Configuration/bin/$helperName"
    } else {
        "$root/GhidraLaunchGhidraHelperRS/bin/$Configuration/$helperName"
    }
    $expected = @{
        $helperName = $helper
        "GhidraLaunchInstaller$Variant.msi" = "$root/GhidraLaunchInstaller/bin/$Configuration/GhidraLaunchInstaller$Variant.msi"
    }
    foreach ($name in $expected.Keys) {
        $files = @(Get-ChildItem -LiteralPath $contents -Recurse -File | Where-Object Name -eq $name)
        if ($files.Count -ne 1 -or (Get-FileHash -LiteralPath $files[0].FullName).Hash -ne (Get-FileHash -LiteralPath $expected[$name]).Hash) {
            throw "Bundle does not contain the exact packaged $name"
        }
    }
    $embedded = @(Get-ChildItem -LiteralPath $contents -Recurse -File)
    if ($embedded.Count -ne 2) { throw 'Bundle contains unexpected payloads (upstream software must remain external)' }
    $manifest = [xml](Get-Content -LiteralPath (Join-Path $ba 'manifest.xml') -Raw)
    Assert-BundleCondition $manifest 'Core'
    $ns = [Xml.XmlNamespaceManager]::new($manifest.NameTable)
    $ns.AddNamespace('b', $manifest.DocumentElement.NamespaceURI)
    $exe = @($manifest.SelectNodes('//b:Chain/b:ExePackage', $ns))
    if ($exe.Count -ne 1 -or $exe[0].InstallArguments -notmatch 'WixBundleProviderKey' -or
        $exe[0].UninstallArguments -notmatch 'WixBundleProviderKey' -or
        $exe[0].DetectCondition -notmatch 'GhidraPayloadOwner') {
        throw 'Built bundle does not use matching ownership-aware helper commands and detection'
    }
    $chain = @($manifest.SelectSingleNode('//b:Chain', $ns).ChildNodes | Where-Object NodeType -eq Element)
    $packages = @($chain | Where-Object { $_.LocalName -in @('MsiPackage', 'ExePackage') })
    if ($packages.Count -ne 2 -or $packages[1].LocalName -ne 'ExePackage' -or
        $packages[0].Id -ne "Launcher$Variant") {
        throw 'Core must install the launcher before final transactional extraction'
    }
    Assert-DisplayNames $coreBa @{
        "Launcher$Variant" = 'Ghidra Launch launcher'
        "Ghidra$Variant"   = 'Ghidra files'
    } 'Core'
    foreach ($name in @('Ghidra.zip', 'OpenJDK*U-jdk_x64.msi')) {
        $payloads = @($outer.SelectNodes('//b:Payload', $outerNs) | Where-Object { (Split-Path $_.FilePath -Leaf) -like $name })
        if ($payloads.Count -ne 1 -or $payloads[0].Packaging -ne 'external' -or -not $payloads[0].DownloadUrl) {
            throw "Bundle lost external download metadata for $name"
        }
    }
    Write-Host "$Variant bundle payload checks passed."
} finally {
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}
