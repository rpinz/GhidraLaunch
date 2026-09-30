param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())

function Invoke-Launcher($path, $workingDirectory, $expectedCode, $ghidraHome) {
    Write-Host "Launching $path (expected exit: $expectedCode; GHIDRA_HOME: $ghidraHome)"
    $previousHome = $env:GHIDRA_HOME
    $env:GHIDRA_HOME = $ghidraHome
    try {
        $process = Start-Process -FilePath $path -WorkingDirectory $workingDirectory -PassThru
    } finally {
        $env:GHIDRA_HOME = $previousHome
    }
    try {
        if (-not $process.WaitForExit(20000)) { throw "Launcher timed out: $path" }
        if ($process.ExitCode -ne $expectedCode) {
            throw "$path exited $($process.ExitCode), expected $expectedCode"
        }
    } finally {
        if (-not $process.HasExited) { $process.Kill() }
        $process.Dispose()
    }
}

try {
    New-Item -ItemType Directory -Path $scratch | Out-Null

    $binaries = @(
        (Join-Path $root "GhidraLaunchC/x64/$Configuration/bin/GhidraLaunchC.exe"),
        (Join-Path $root 'GhidraLaunchRS/GhidraLaunchRS.exe')
    )
    foreach ($binary in $binaries) {
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "Missing launcher: $binary" }
        $directory = Join-Path $scratch ("Ghidra Launch " + [IO.Path]::GetFileNameWithoutExtension($binary))
        New-Item -ItemType Directory -Path $directory | Out-Null
        $launcher = Join-Path $directory ([IO.Path]::GetFileName($binary))
        Copy-Item -LiteralPath $binary -Destination $launcher
        $batch = Join-Path $directory 'ghidraRun.bat'
        $marker = Join-Path $directory 'called.txt'

        Set-Content -LiteralPath $batch -Value '@echo off', 'echo %cd%>"%~dp0called.txt"', 'exit /b 0' -Encoding Ascii
        Remove-Item -LiteralPath $marker -ErrorAction SilentlyContinue
        Invoke-Launcher $launcher $scratch 0 $null
        if (-not (Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne $directory) {
            throw "$launcher did not run the adjacent batch from its own directory"
        }

        $configured = Join-Path $scratch ("Configured " + [IO.Path]::GetFileNameWithoutExtension($binary))
        New-Item -ItemType Directory -Path $configured | Out-Null
        $configuredBatch = Join-Path $configured 'ghidraRun.bat'
        $configuredMarker = Join-Path $configured 'called.txt'
        Set-Content -LiteralPath $configuredBatch -Value '@echo off', 'echo %cd%>"%~dp0called.txt"', 'exit /b 0' -Encoding Ascii
        Invoke-Launcher $launcher $scratch 0 $configured
        if (-not (Test-Path -LiteralPath $configuredMarker) -or (Get-Content -LiteralPath $configuredMarker -Raw).Trim() -ne $configured) {
            throw "$launcher did not run the configured batch from GHIDRA_HOME"
        }
        Write-Host "Launcher checks passed: $binary"
    }
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
