param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())

Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class LauncherDialog {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindow(string className, string windowName);
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
}
'@

function Invoke-Launcher($path, $workingDirectory, $expectedCode) {
    $process = Start-Process -FilePath $path -WorkingDirectory $workingDirectory -PassThru
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        while (-not $process.HasExited -and [DateTime]::UtcNow -lt $deadline) {
            $window = [LauncherDialog]::FindWindow($null, 'GhidraLaunch')
            if ($window -ne [IntPtr]::Zero) {
                [uint32]$owner = 0
                [void][LauncherDialog]::GetWindowThreadProcessId($window, [ref]$owner)
                if ($owner -eq $process.Id) {
                    [void][LauncherDialog]::PostMessage($window, 0x111, [IntPtr]::new(1), [IntPtr]::Zero)
                }
            }
            Start-Sleep -Milliseconds 100
            $process.Refresh()
        }
        if (-not $process.HasExited) { throw "Launcher timed out: $path" }
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
    $decoy = Join-Path $scratch 'ghidraRun.bat'
    Set-Content -LiteralPath $decoy -Value '@echo off', 'echo wrong>"%~dp0decoy.txt"', 'exit /b 99' -Encoding Ascii

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

        foreach ($code in @(0, 37)) {
            Set-Content -LiteralPath $batch -Value '@echo off', 'echo %cd%>"%~dp0called.txt"', "exit /b $code" -Encoding Ascii
            Remove-Item -LiteralPath $marker -ErrorAction SilentlyContinue
            Invoke-Launcher $launcher $scratch $code
            if (-not (Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne $directory) {
                throw "$launcher did not run the adjacent batch from its own directory"
            }
        }

        Remove-Item -LiteralPath $batch
        Remove-Item -LiteralPath $marker
        Invoke-Launcher $launcher $scratch 1
        if (Test-Path -LiteralPath $marker) { throw "$launcher ran a batch without an adjacent ghidraRun.bat" }
        if (Test-Path -LiteralPath (Join-Path $scratch 'decoy.txt')) { throw "$launcher ran the working-directory batch" }
        Write-Host "Launcher checks passed: $binary"
    }
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
