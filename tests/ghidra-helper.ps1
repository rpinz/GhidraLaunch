param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string[]]$HelperPath,
    [string]$GhidraZipPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if ($GhidraZipPath) { $GhidraZipPath = (Resolve-Path -LiteralPath $GhidraZipPath).Path }
if (-not $HelperPath) {
    $HelperPath = @(
        "$root/GhidraLaunchGhidraHelperC/x64/$Configuration/bin/GhidraLaunchGhidraHelperC.exe",
        "$root/GhidraLaunchGhidraHelperRS/bin/$Configuration/GhidraLaunchGhidraHelperRS.exe"
    )
}
foreach ($helper in $HelperPath) {
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw "Missing helper: $helper" }
    $image = [IO.File]::ReadAllBytes($helper)
    $pe = [BitConverter]::ToInt32($image, 0x3c)
    if ([BitConverter]::ToUInt32($image, $pe) -ne 0x4550 -or
        [BitConverter]::ToUInt16($image, $pe + 4) -ne 0x8664 -or
        [BitConverter]::ToUInt16($image, $pe + 24) -ne 0x20b) {
        throw "Helper is not an x64 PE executable: $helper"
    }
    if ([BitConverter]::ToUInt64($image, $pe + 24 + 112 + 14 * 8) -ne 0) {
        throw "Helper unexpectedly contains a managed CLR header: $helper"
    }
}

function Invoke-Helper {
    param([string]$Helper, [string[]]$HelperArgs, [int]$Expected = 0)
    $arguments = ($HelperArgs | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $process = Start-Process -FilePath $Helper -ArgumentList $arguments -PassThru -Wait -NoNewWindow
    try {
        if ($process.ExitCode -ne $Expected) {
            throw "$Helper $arguments exited $($process.ExitCode), expected $Expected"
        }
    } finally {
        $process.Dispose()
    }
}

function New-FixtureZip {
    param([string]$Path, [hashtable]$Entries)
    $archive = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $Entries.Keys) {
            $entry = $archive.CreateEntry($name)
            $writer = [IO.StreamWriter]::new($entry.Open())
            try { $writer.Write($Entries[$name]) } finally { $writer.Dispose() }
        }
    } finally {
        $archive.Dispose()
    }
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $zip = Join-Path $scratch 'first.zip'
    $changed = Join-Path $scratch 'changed.zip'
    New-FixtureZip $zip @{ 'ghidra_PUBLIC/ghidraRun.bat' = '@echo off'; 'ghidra_PUBLIC/support/x.txt' = 'first' }
    New-FixtureZip $changed @{ 'ghidra_PUBLIC/ghidraRun.bat' = '@echo off'; 'ghidra_PUBLIC/support/x.txt' = 'second' }

    foreach ($helper in $HelperPath) {
        $dest = Join-Path $scratch ("Ghidra space " + [char]0xe9)
        $file = Join-Path $dest 'support/x.txt'
        $marker = Join-Path $dest '.ghidralaunch-source.sha256'
        Invoke-Helper $helper @('extract', $zip, $dest)
        if (-not (Test-Path -LiteralPath "$dest/ghidraRun.bat")) { throw 'Top-level folder was not stripped' }
        if ((Get-Content -LiteralPath $file -Raw) -ne 'first') { throw 'Wrong extracted content' }
        if ((Get-Content -LiteralPath $marker -Raw).Trim() -ine (Get-FileHash -LiteralPath $zip).Hash) {
            throw 'Standalone marker is not legacy-compatible SHA-256'
        }
        Set-Content -LiteralPath $file -Value 'untouched' -NoNewline
        Invoke-Helper $helper @('extract', $zip, $dest)
        if ((Get-Content -LiteralPath $file -Raw) -ne 'untouched') { throw 'Unchanged extraction replaced user content' }

        Invoke-Helper $helper @('extract', $changed, $dest)
        if ((Get-Content -LiteralPath $file -Raw) -ne 'second') { throw 'Changed source did not re-extract' }
        Invoke-Helper $helper @('remove', $dest, $zip)
        Invoke-Helper $helper @('remove', $dest, "$scratch/missing.zip")
        if (-not (Test-Path -LiteralPath $file)) { throw 'Non-matching removal deleted the tree' }

        $corrupt = Join-Path $scratch 'corrupt.zip'
        Set-Content -LiteralPath $corrupt -Value 'not a zip'
        Invoke-Helper $helper @('extract', $corrupt, $dest) 1
        Invoke-Helper $helper @('extract', "$scratch/missing.zip", $dest) 1
        if ((Get-Content -LiteralPath $file -Raw) -ne 'second') { throw 'Failed extraction destroyed the old tree' }
        Invoke-Helper $helper @('unknown') 2

        foreach ($name in @('../escape.txt', '..\escape.txt', '/absolute.txt', 'C:/drive.txt',
                            '//server/share.txt', 'dir/file:stream', 'dir/CON.txt', 'dir/trailing.')) {
            $malicious = Join-Path $scratch 'malicious.zip'
            New-FixtureZip $malicious @{ $name = 'bad' }
            Invoke-Helper $helper @('extract', $malicious, $dest) 1
            if ((Get-Content -LiteralPath $file -Raw) -ne 'second') { throw "Unsafe entry damaged the destination: $name" }
            Remove-Item -LiteralPath $malicious
        }

        $duplicate = Join-Path $scratch 'duplicate.zip'
        $entries = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
        $entries.Add('dir/Name.txt', 'first')
        $entries.Add('dir/name.txt', 'second')
        $archive = [IO.Compression.ZipFile]::Open($duplicate, [IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($name in $entries.Keys) {
                $writer = [IO.StreamWriter]::new($archive.CreateEntry($name).Open())
                try { $writer.Write($entries[$name]) } finally { $writer.Dispose() }
            }
        } finally { $archive.Dispose() }
        Invoke-Helper $helper @('extract', $duplicate, $dest) 1
        Remove-Item -LiteralPath $duplicate

        Invoke-Helper $helper @('extract', $changed, $dest, '1.0.0-C')
        if ((Get-Content -LiteralPath $marker -Raw) -notmatch '\nowner=1.0.0-C\n$') { throw 'Bundle owner marker missing' }
        Invoke-Helper $helper @('remove', $dest, $changed)
        Invoke-Helper $helper @('remove', $dest, $changed, '1.0.0-Rust')
        if (-not (Test-Path -LiteralPath $file)) { throw 'Outgoing bundle removed incoming owned payload' }
        Invoke-Helper $helper @('remove', $dest, $changed, '1.0.0-C')
        if (Test-Path -LiteralPath $dest) { throw 'Matching bundle did not remove its payload' }

        $flat = Join-Path $scratch 'flat.zip'
        New-FixtureZip $flat @{ 'ghidraRun.bat' = '@echo off'; 'readme.txt' = 'flat' }
        Invoke-Helper $helper @('extract', $flat, $dest)
        if (-not (Test-Path -LiteralPath "$dest/readme.txt")) { throw 'Flat ZIP was not preserved' }
        Invoke-Helper $helper @('remove', $dest, $flat)
        Invoke-Helper $helper @('remove', $dest)
        Remove-Item -LiteralPath $flat

        if ($GhidraZipPath) {
            Invoke-Helper $helper @('extract', $GhidraZipPath, $dest)
            foreach ($relative in @('ghidraRun.bat', 'Ghidra/application.properties')) {
                if (-not (Test-Path -LiteralPath (Join-Path $dest $relative) -PathType Leaf)) {
                    throw "Real Ghidra archive extraction is missing $relative"
                }
            }
            if ((Get-Content -LiteralPath $marker -Raw).Trim() -ine (Get-FileHash -LiteralPath $GhidraZipPath).Hash) {
                throw 'Real Ghidra archive marker hash is incorrect'
            }
            Invoke-Helper $helper @('remove', $dest, $GhidraZipPath)
            if (Test-Path -LiteralPath $dest) { throw 'Real archive extraction was not removed' }
        }
    }

    if ($HelperPath.Count -eq 2) {
        $dest = Join-Path $scratch 'interop'
        foreach ($pair in @(@(0, 1), @(1, 0))) {
            Invoke-Helper $HelperPath[$pair[0]] @('extract', $zip, $dest, '1.0.0-C')
            Set-Content -LiteralPath "$dest/support/x.txt" -Value 'keep' -NoNewline
            Invoke-Helper $HelperPath[$pair[1]] @('extract', $zip, $dest, '1.0.0-Rust')
            if ((Get-Content -LiteralPath "$dest/support/x.txt" -Raw) -ne 'keep') { throw 'Ownership adoption re-extracted unchanged content' }
            Invoke-Helper $HelperPath[$pair[0]] @('remove', $dest, $zip, '1.0.0-C')
            if (-not (Test-Path -LiteralPath $dest)) { throw 'Outgoing owner deleted adopted payload' }
            Invoke-Helper $HelperPath[$pair[1]] @('remove', $dest, $zip, '1.0.0-Rust')
            if (Test-Path -LiteralPath $dest) { throw 'Cross-language matching removal failed' }
        }
    }
    Write-Host 'Native helper conformance checks passed.'
} finally {
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}
