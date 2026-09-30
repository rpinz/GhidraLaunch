function Get-BuildVersion([string]$Version) {
    if ($Version -notmatch '^\d+\.\d+\.\d+(?:\.\d+)?$') {
        throw 'Build version must be MAJOR.MINOR.PATCH[.REVISION].'
    }
    $parts = @($Version.Split('.') | ForEach-Object { [int]$_ })
    if (@($parts | Where-Object { $_ -gt 255 }).Count) {
        throw 'Build version components must be <= 255 for Windows compatibility.'
    }
    $product = $parts[0..2] -join '.'
    $file = if ($parts.Count -eq 3) { "$product.0" } else { $parts -join '.' }
    [pscustomobject]@{ Product = $product; File = $file }
}

function Set-NativeVersion([string]$Root, $Version) {
    $path = Join-Path $Root 'Resources/Version.h'
    $content = @"
#ifndef GHIDRA_LAUNCH_VERSION
#define GHIDRA_LAUNCH_VERSION "$($Version.File)"
#define GHIDRA_LAUNCH_FILEVERSION $($Version.File.Replace('.', ','))
#define GHIDRA_LAUNCH_PRODUCT_VERSION "$($Version.Product)"
#endif
"@
    if ((Get-Content -LiteralPath $path -Raw).TrimEnd() -ne $content.TrimEnd()) {
        Set-Content -LiteralPath $path -Value $content -Encoding ascii
    }
}

function Assert-ExecutableVersion([string]$Path, $Version, [switch]$Native) {
    $info = (Get-Item -LiteralPath $Path).VersionInfo
    if ($info.ProductName -ne 'Ghidra Launch' -or
        ([version]$info.ProductVersion).ToString(3) -ne $Version.Product -or
        ($Native -and [version]$info.FileVersion -ne [version]$Version.File)) {
        throw "Version mismatch for ${Path}: product='$($info.ProductVersion)', file='$($info.FileVersion)'; expected $($Version.Product)/$($Version.File). Rebuild the prerequisite before packaging."
    }
}

function Invoke-WithBundleContents([string]$Path, [scriptblock]$Action) {
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
    try {
        $output = & dotnet tool run wix burn extract $Path -o "$scratch/contents" -oba "$scratch/ba" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Cannot inspect bundle ${Path}: $output" }
        $manifest = [xml](Get-Content -LiteralPath "$scratch/ba/manifest.xml" -Raw)
        & $Action $manifest "$scratch/contents"
    } finally {
        if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
    }
}

function Get-BundleProviderKey([string]$Path) {
    Invoke-WithBundleContents $Path {
        param($manifest, $contents)
        $registration = $manifest.SelectSingleNode('/*/*[local-name()="Registration"]')
        $key = [guid]::Empty
        if (-not $registration -or -not [guid]::TryParse($registration.ProviderKey, [ref]$key)) {
            throw "Bundle has no unique GUID provider key: $Path"
        }
        $registration.ProviderKey
    }
}

function Invoke-WithMsiContents([string]$Path, [scriptblock]$Action) {
    # WiX decompilation extracts cabinets; it does not run msiexec or any MSI
    # actions. Inspect the packaged PE, not just its declared File table version.
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
    try {
        $output = & dotnet tool run wix msi decompile $Path -x "$scratch/files" -o "$scratch/Product.wxs" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Cannot inspect MSI ${Path}: $output" }
        & $Action "$scratch/files"
    } finally {
        if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
    }
}

function Get-MsiProperties([string]$Path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    $view = $null
    try {
        $database = $installer.OpenDatabase((Resolve-Path -LiteralPath $Path).Path, 0)
        $view = $database.OpenView('SELECT `Property`, `Value` FROM `Property`')
        $null = $view.Execute()
        $properties = @{}
        while ($record = $view.Fetch()) {
            try {
                $properties[$record.StringData(1)] = $record.StringData(2)
            } finally {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
            }
        }
        $properties
    } finally {
        if ($view) {
            $null = $view.Close()
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
        }
        if ($database) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    }
}

function Assert-MsiVersion([string]$Path, $Version, [string]$Variant) {
    $properties = Get-MsiProperties $Path
    if ($properties.ProductVersion -ne $Version.Product -or $properties.ProductName -ne 'Ghidra Launch' -or
        ($Variant -and $properties.GHIDRALAUNCHVARIANT -ne $Variant)) {
        throw "Version/product/variant mismatch for ${Path}; expected $($Version.Product) $Variant. Rebuild the MSI before packaging."
    }
    Invoke-WithMsiContents $Path {
        param($contents)
        Assert-ExecutableVersion (Join-Path $contents 'File/LauncherFile') $Version -Native
    }
}

function Assert-SameArtifact([string]$Packaged, [string]$Expected) {
    if ((Get-FileHash -LiteralPath $Packaged -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $Expected -Algorithm SHA256).Hash) {
        throw "Packaged artifact differs from its current prerequisite: $Expected"
    }
}

function Get-UpstreamBuildMetadata([string]$VersionsFile) {
    $text = Get-Content -LiteralPath $VersionsFile -Raw
    $values = @{}
    foreach ($name in @('JavaVersion', 'JavaDownloadUrl', 'GhidraDownloadUrl')) {
        $matches = [regex]::Matches($text, ('<\?define\s+' + $name + '\s*=\s*"([^"]+)"\s*\?>'))
        if ($matches.Count -ne 1) { throw "Missing or ambiguous $name in $VersionsFile" }
        $values[$name] = [Net.WebUtility]::HtmlDecode($matches[0].Groups[1].Value)
    }
    $values
}

function Assert-ExternalPayload($Manifest, [string]$Name, [string]$Path, [string]$Url) {
    $payloads = @($Manifest.SelectNodes('/*/*[local-name()="Payload"]') |
        Where-Object { $_.FilePath -eq $Name })
    if ($payloads.Count -ne 1 -or $payloads[0].Packaging -ne 'external' -or
        $payloads[0].DownloadUrl -cne $Url -or
        [long]$payloads[0].FileSize -ne (Get-Item -LiteralPath $Path).Length -or
        $payloads[0].Hash -ne (Get-FileHash -LiteralPath $Path -Algorithm SHA512).Hash) {
        throw "Bundle has stale or inconsistent external payload metadata for $Name. Rebuild the internal bundle before packaging."
    }
}

function Assert-InternalBundle([string]$Path, $Version, [ValidateSet('Core', 'Java')][string]$Stage,
                               [string]$Variant, [string]$MsiPath, [string]$HelperPath,
                               [string]$PayloadRoot, [string]$VersionsFile) {
    Assert-ExecutableVersion $Path $Version
    $upstream = Get-UpstreamBuildMetadata $VersionsFile
    Invoke-WithBundleContents $Path {
        param($manifest, $contents)
        $registration = $manifest.SelectSingleNode('/*/*[local-name()="Registration"]')
        if (-not $registration -or ([version]$registration.Version).ToString(3) -ne $Version.Product) {
            throw "Bundle registration version mismatch: $Path"
        }
        if ($Stage -eq 'Core') {
            if ($registration.Tag -ne $Variant) { throw "Core variant mismatch: $Path" }
            $msiName = "GhidraLaunchInstaller$Variant.msi"
            $helperName = if ($Variant -eq 'C') { 'GhidraLaunchGhidraHelperC.exe' } else { 'GhidraLaunchGhidraHelperRS.exe' }
            $files = @(Get-ChildItem -LiteralPath $contents -Recurse -File)
            $msi = @($files | Where-Object Name -eq $msiName)
            $helper = @($files | Where-Object Name -eq $helperName)
            if ($files.Count -ne 2 -or $msi.Count -ne 1 -or $helper.Count -ne 1) {
                throw "Core must contain exactly its launcher MSI and matching helper: $Path"
            }
            Assert-MsiVersion $msi[0].FullName $Version $Variant
            Assert-ExecutableVersion $helper[0].FullName $Version -Native
            Assert-SameArtifact $msi[0].FullName $MsiPath
            Assert-SameArtifact $helper[0].FullName $HelperPath
            Assert-ExternalPayload $manifest 'Ghidra.zip' "$PayloadRoot/Ghidra.zip" $upstream.GhidraDownloadUrl
        } else {
            $name = "OpenJDK$($upstream.JavaVersion)U-jdk_x64.msi"
            Assert-ExternalPayload $manifest $name (Join-Path $PayloadRoot $name) $upstream.JavaDownloadUrl
        }
    }
}
