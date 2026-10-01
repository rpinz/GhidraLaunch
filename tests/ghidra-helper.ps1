param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')

# Exercises GhidraLaunchGhidraHelper's extract/remove commands against a small synthetic
# fixture zip (not a real Ghidra download) to verify: top-level folder stripping, idempotent
# no-op on an unchanged zip, re-extraction on a changed zip, and removal.

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$helper = Join-Path $root "GhidraLaunchGhidraHelper/bin/$Configuration/net48/GhidraLaunchGhidraHelper.exe"
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw "Missing helper: $helper" }

$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
$fixtureRoot = Join-Path $scratch 'ghidra_11.4_PUBLIC'
$zip = Join-Path $scratch 'fixture.zip'
$matchingZip = Join-Path $scratch 'second.zip'
$dest = Join-Path $scratch 'dest'

function Invoke-Helper {
    param([string[]]$HelperArgs)
    $process = Start-Process -FilePath $helper -ArgumentList $HelperArgs -PassThru -Wait -NoNewWindow
    if ($process.ExitCode -ne 0) { throw "GhidraLaunchGhidraHelper $($HelperArgs -join ' ') exited $($process.ExitCode)" }
}

function New-FixtureZip {
    param([string]$Content)
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
    New-Item -ItemType Directory -Path "$fixtureRoot/support" | Out-Null
    Set-Content -LiteralPath (Join-Path $fixtureRoot 'ghidraRun.bat') -Value '@echo off' -Encoding Ascii
    Set-Content -LiteralPath (Join-Path $fixtureRoot 'support/x.txt') -Value $Content -Encoding Ascii
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path $fixtureRoot -DestinationPath $zip
}

try {
    New-Item -ItemType Directory -Path $scratch | Out-Null

    # extract: top-level folder is stripped, ghidraRun.bat lands directly in dest
    New-FixtureZip 'first'
    Invoke-Helper @('extract', $zip, $dest)
    if (-not (Test-Path -LiteralPath (Join-Path $dest 'ghidraRun.bat'))) {
        throw 'extract did not strip the top-level folder'
    }
    if ((Get-Content -LiteralPath (Join-Path $dest 'support/x.txt') -Raw).Trim() -ne 'first') {
        throw 'extract did not copy fixture contents'
    }

    # extract again with an unchanged zip: no-op (existing marker preserved, content untouched)
    Set-Content -LiteralPath (Join-Path $dest 'support/x.txt') -Value 'untouched' -Encoding Ascii
    Invoke-Helper @('extract', $zip, $dest)
    if ((Get-Content -LiteralPath (Join-Path $dest 'support/x.txt') -Raw).Trim() -ne 'untouched') {
        throw 'extract re-extracted an unchanged zip instead of skipping'
    }

    # extract with a changed zip: re-extracts
    New-FixtureZip 'second'
    Invoke-Helper @('extract', $zip, $dest)
    if ((Get-Content -LiteralPath (Join-Path $dest 'support/x.txt') -Raw).Trim() -ne 'second') {
        throw 'extract did not re-extract a changed zip'
    }
    Copy-Item -LiteralPath $zip -Destination $matchingZip

    # remove from an older bundle: leaves a newer extracted tree in place
    New-FixtureZip 'newer'
    Invoke-Helper @('remove', $dest, $zip)
    if (-not (Test-Path -LiteralPath (Join-Path $dest 'ghidraRun.bat'))) {
        throw 'remove deleted a Ghidra tree belonging to a newer bundle'
    }
    # remove: deletes the extracted tree when the source matches
    Invoke-Helper @('remove', $dest, $matchingZip)
    if (Test-Path -LiteralPath $dest) { throw 'remove did not delete the destination directory' }

    Write-Host 'GhidraLaunchGhidraHelper checks passed.'
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
