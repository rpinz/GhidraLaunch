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

function Assert-MsiVersion([string]$Path, $Version) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    $view = $null
    try {
        $database = $installer.OpenDatabase((Resolve-Path -LiteralPath $Path).Path, 0)
        $view = $database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = 'ProductVersion'")
        $null = $view.Execute()
        $record = $view.Fetch()
        try {
            if (-not $record -or $record.StringData(1) -ne $Version.Product) {
                throw "Version mismatch for ${Path}; expected $($Version.Product). Rebuild the MSI before packaging."
            }
        } finally {
            if ($record) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
        }
    } finally {
        if ($view) {
            $null = $view.Close()
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
        }
        if ($database) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    }
}
