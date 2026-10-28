param(
    [Parameter(Mandatory)][string]$BundlePath,
    [Parameter(Mandatory)][ValidateSet('C', 'Rust')][string]$Variant,
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$ExpectedNativeVersion
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. "$root/scripts/build-version.ps1"
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
    $coreRelations = @($outerPackages[0].SelectNodes('./b:RelatedBundle', $outerNs))
    if ($coreRelations.Count -ne 1 -or $coreRelations[0].Id -ne '{D2557D9A-CD4F-4AD2-B84A-0289EF4208DE}' -or
        $coreRelations[0].Action -ne 'Upgrade') {
        throw 'Setup must detect only the Ghidra-specific Core upgrade family'
    }
    $migration = @($outer.SelectNodes('//b:Chain/b:ExePackage', $outerNs) | Where-Object Id -eq "LegacyGhidra$Variant")
    $outerChain = @($outer.SelectSingleNode('//b:Chain', $outerNs).ChildNodes |
        Where-Object { $_.LocalName -in @('BundlePackage', 'ExePackage') })
    if ($outerChain.Count -ne 3 -or $outerChain[0].Id -ne "Core$Variant" -or
        $outerChain[1].Id -ne "LegacyGhidra$Variant" -or $outerChain[2].Id -ne 'Java' -or
        $migration.Count -ne 1 -or $migration[0].RollbackBoundaryForward -ne 'PayloadCommitted' -or
        $outerPackages[0].RollbackBoundaryBackward -ne 'WixDefaultBoundary') {
        throw 'Migration/Java failure must not roll back the completed Core'
    }
    Assert-DisplayNames $ba @{
        "Core$Variant" = 'Ghidra Launch and Ghidra files'
        "LegacyGhidra$Variant" = 'Finishing legacy Ghidra migration'
        'Java'         = 'Java runtime (Eclipse Temurin)'
    } 'Setup'
    $outerEmbedded = @(Get-ChildItem -LiteralPath $contents -Recurse -File)
    if ($outerEmbedded.Count -ne 3) { throw 'Setup must embed Core, migration helper and Java' }
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
    $nativeVersion = Get-BuildVersion $(if ($ExpectedNativeVersion) { $ExpectedNativeVersion } else { (Get-Item -LiteralPath $helper).VersionInfo.FileVersion })
    $migrationFile = @($outerEmbedded | Where-Object Name -eq "GhidraLaunchLegacyMigration$Variant.exe")
    if ($migrationFile.Count -ne 1) { throw 'Setup is missing its migration helper' }
    Assert-SameArtifact $migrationFile[0].FullName $helper
    Assert-ExecutableVersion $migrationFile[0].FullName $nativeVersion -Native
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
    if ($embedded.Count -ne 2) { throw 'Core must embed only its MSI and extraction helper' }
    $packagedMsi = @($embedded | Where-Object Name -eq "GhidraLaunchInstaller$Variant.msi")
    $packagedHelper = @($embedded | Where-Object Name -eq $helperName)
    Assert-MsiVersion $packagedMsi[0].FullName $nativeVersion $Variant
    Assert-ExecutableVersion $packagedHelper[0].FullName $nativeVersion -Native
    $manifest = [xml](Get-Content -LiteralPath (Join-Path $ba 'manifest.xml') -Raw)
    Assert-BundleCondition $manifest 'Core'
    $ns = [Xml.XmlNamespaceManager]::new($manifest.NameTable)
    $ns.AddNamespace('b', $manifest.DocumentElement.NamespaceURI)
    $relations = @($manifest.SelectNodes('/b:BurnManifest/b:RelatedBundle', $ns))
    if ($relations.Count -ne 1 -or $relations[0].Id -ne '{D2557D9A-CD4F-4AD2-B84A-0289EF4208DE}' -or
        $relations[0].Action -ne 'Upgrade') {
        throw 'Core must never automatically upgrade the ambiguous legacy bundle family'
    }
    $exe = @($manifest.SelectNodes('//b:Chain/b:ExePackage', $ns) | Where-Object Id -eq "Ghidra$Variant")
    if ($exe.Count -ne 1 -or $exe[0].InstallArguments -notmatch 'WixBundleProviderKey' -or
        $exe[0].UninstallArguments -notmatch 'WixBundleProviderKey' -or
        $exe[0].DetectCondition -notmatch 'GhidraPayloadOwner') {
        throw 'Built bundle does not use matching ownership-aware helper commands and detection'
    }
    $version = $manifest.SelectSingleNode('/b:BurnManifest/b:Registration', $ns).Version
    $coreOwner = $manifest.SelectSingleNode('/b:BurnManifest/b:Registration', $ns).ProviderKey
    $migrationArguments = 'migrate-legacy "[LocalAppDataFolder]Ghidra Launch\Ghidra" "' + $coreOwner + '" "' + $version + '"'
    if ($migration.Count -ne 1 -or $migration[0].Permanent -ne 'yes' -or
        $migration[0].Vital -ne 'yes' -or $migration[0].PerMachine -ne 'no' -or $migration[0].DetectCondition -ne '0' -or
        $migration[0].InstallArguments -ne $migrationArguments) {
        throw 'Setup must migrate legacy installations using its exact committed Core owner'
    }
    if ($migration[0].CacheId -ne "GhidraLaunchLegacy$Variant-$((Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash)") {
        throw 'Migration must use a separate cache identity derived from the exact signed helper bytes'
    }
    $chain = @($manifest.SelectSingleNode('//b:Chain', $ns).ChildNodes | Where-Object NodeType -eq Element)
    $packages = @($chain | Where-Object { $_.LocalName -in @('MsiPackage', 'ExePackage') })
    if ($packages.Count -ne 2 -or $packages[0].Id -ne "Launcher$Variant" -or
        $packages[1].Id -ne "Ghidra$Variant") {
        throw 'Core must commit launcher and payload without legacy cleanup inside its rollback boundary'
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
        $nested = if ($name -eq 'Ghidra.zip') { $manifest } else { $javaManifest }
        $nestedPayloads = @($nested.SelectNodes('/*/*[local-name()="Payload"]') |
            Where-Object { (Split-Path $_.FilePath -Leaf) -like $name })
        if ($nestedPayloads.Count -ne 1 -or $nestedPayloads[0].Hash -ne $payloads[0].Hash -or
            $nestedPayloads[0].FileSize -ne $payloads[0].FileSize -or
            $nestedPayloads[0].DownloadUrl -cne $payloads[0].DownloadUrl -or
            $nestedPayloads[0].FilePath -ne $payloads[0].FilePath) {
            throw "Setup and its nested bundle disagree on external payload $name"
        }
    }
    Write-Host "$Variant bundle payload checks passed."
} finally {
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}
