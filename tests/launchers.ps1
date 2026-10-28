param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string[]]$LauncherPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())

function Invoke-Launcher($path, $workingDirectory, $expectedCode, $ghidraHome, $arguments = '') {
    Write-Host "Launching $path (expected exit: $expectedCode; GHIDRA_HOME: $ghidraHome)"
    $previousHome = $env:GHIDRA_HOME
    $env:GHIDRA_HOME = $ghidraHome
    try {
        $options = @{ FilePath = $path; WorkingDirectory = $workingDirectory; PassThru = $true }
        if ($arguments) { $options.ArgumentList = $arguments }
        $process = Start-Process @options
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

function Assert-LauncherFailure($path, $workingDirectory, $ghidraHome, $expectedText) {
    $previousHome = $env:GHIDRA_HOME
    $env:GHIDRA_HOME = $ghidraHome
    $failure = $null
    try {
        $failure = Start-Process -FilePath $path -WorkingDirectory $workingDirectory -PassThru
        $null = $failure.Handle
        $deadline = (Get-Date).AddSeconds(20)
        $diagnostic = $null
        while (-not $failure.HasExited -and (Get-Date) -lt $deadline) {
            $diagnostic = [LauncherDialog]::Dismiss($failure.Id, $expectedText)
            if ($diagnostic) { break }
            Start-Sleep -Milliseconds 100
        }
        $exited = $failure.WaitForExit(5000)
        $failure.Refresh()
        if (-not $exited -or $failure.ExitCode -ne 1 -or -not $diagnostic) {
            throw "$path did not report '$expectedText' for GHIDRA_HOME '$ghidraHome' (exit=$($failure.ExitCode), diagnostic=$diagnostic)"
        }
    } finally {
        if ($failure) {
            if (-not $failure.HasExited) { $failure.Kill() }
            $failure.Dispose()
        }
        $env:GHIDRA_HOME = $previousHome
    }
}

try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $recorder = Join-Path $scratch 'record-arguments.ps1'
    Set-Content -LiteralPath $recorder -Encoding Ascii -Value '[IO.File]::AppendAllText($env:GL_CAPTURE_PATH, (ConvertTo-Json -Compress -InputObject ([string]$env:GL_CAPTURE)) + "`n")'

    $binaries = if ($LauncherPath) { @($LauncherPath | ForEach-Object { (Resolve-Path -LiteralPath $_).Path }) } else {
        @(
            (Join-Path $root "GhidraLaunchC/x64/$Configuration/bin/GhidraLaunchC.exe"),
            (Join-Path $root 'GhidraLaunchRS/GhidraLaunchRS.exe')
        )
    }
    foreach ($binary in $binaries) {
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "Missing launcher: $binary" }
        $directory = Join-Path $scratch ("Ghidra Launch " + [IO.Path]::GetFileNameWithoutExtension($binary))
        New-Item -ItemType Directory -Path $directory | Out-Null
        $launcher = Join-Path $directory ([IO.Path]::GetFileName($binary))
        Copy-Item -LiteralPath $binary -Destination $launcher
        $batch = Join-Path $directory 'ghidraRun.bat'
        $marker = Join-Path $directory 'called.txt'

        Set-Content -LiteralPath $batch -Value '@echo off', 'setlocal DisableDelayedExpansion', 'cd>"%~dp0called.txt"', 'exit /b 0' -Encoding Ascii
        Remove-Item -LiteralPath $marker -ErrorAction SilentlyContinue
        Invoke-Launcher $launcher $scratch 0 $null
        if (-not (Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne $directory) {
            throw "$launcher did not run the adjacent batch from its own directory"
        }

        $configured = Join-Path $scratch ("Configured %PATH% !bang! ^caret &and " + [IO.Path]::GetFileNameWithoutExtension($binary))
        New-Item -ItemType Directory -Path $configured | Out-Null
        $configuredBatch = Join-Path $configured 'ghidraRun.bat'
        $configuredMarker = Join-Path $configured 'called.txt'
        Set-Content -LiteralPath $configuredBatch -Value '@echo off', 'setlocal DisableDelayedExpansion', 'cd>"%~dp0called.txt"', 'exit /b 0' -Encoding Ascii
        $configuredHomes = @($configured, ('.\' + [IO.Path]::GetFileName($configured)))
        foreach ($selectedHome in $configuredHomes) {
            Remove-Item -LiteralPath $configuredMarker -ErrorAction SilentlyContinue
            Invoke-Launcher $launcher $scratch 0 $selectedHome
            if (-not (Test-Path -LiteralPath $configuredMarker) -or (Get-Content -LiteralPath $configuredMarker -Raw).Trim() -ne $configured) {
                throw "$launcher did not run the configured batch from GHIDRA_HOME '$selectedHome'"
            }
        }
        $env:GL_PS = (Get-Process -Id $PID).Path
        $env:GL_RECORDER = $recorder
        $env:GL_CAPTURE_PATH = Join-Path $configured 'arguments.txt'
        Set-Content -LiteralPath $configuredBatch -Encoding Ascii -Value '@echo off', 'setlocal DisableDelayedExpansion',
            'set /a GL_INDEX=0', ':next', 'if %GL_INDEX%==11 exit /b 0', 'set "GL_CAPTURE=%~1"',
            '"%GL_PS%" -NoProfile -NonInteractive -File "%GL_RECORDER%"', 'if errorlevel 1 exit /b 1',
            'shift', 'set /a GL_INDEX+=1', 'goto next'
        $arguments = 'one "two words" "" "%PATH%" "!literal!" "^caret" "&and" "pipe|value" "日本語" "C:\tail\\" "a\"b"'
        try {
            foreach ($selectedHome in $configuredHomes) {
                Remove-Item -LiteralPath $env:GL_CAPTURE_PATH -ErrorAction SilentlyContinue
                Invoke-Launcher $launcher $scratch 0 $selectedHome $arguments
                $actualArguments = @(Get-Content -LiteralPath $env:GL_CAPTURE_PATH | ForEach-Object { ConvertFrom-Json -InputObject $_ -NoEnumerate })
                $expectedArguments = @('one', 'two words', '', '%PATH%', '!literal!', '^caret', '&and', 'pipe|value', '日本語', 'C:\tail\\', 'a\"b')
                if (($actualArguments | ConvertTo-Json -Compress) -cne ($expectedArguments | ConvertTo-Json -Compress)) {
                    throw "$launcher changed fallback arguments with GHIDRA_HOME '$selectedHome': $($actualArguments | ConvertTo-Json -Compress)"
                }
            }
        } finally {
            Remove-Item Env:GL_PS, Env:GL_RECORDER, Env:GL_CAPTURE_PATH -ErrorAction SilentlyContinue
        }
        Write-Host "Launcher checks passed: $binary"
    }

    # a packaged-Ghidra layout with stub LaunchSupport/Ghidra classes must start Java directly, never ghidraRun.bat
    $javac = Get-Command javac -ErrorAction SilentlyContinue
    if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME 'bin/javac.exe'))) { $javac = Get-Item (Join-Path $env:JAVA_HOME 'bin/javac.exe') }
    if (-not $javac) { throw 'javac not found; a JDK is required for the native launch test' }
    $javacPath = if ($javac.Source) { $javac.Source } else { $javac.FullName }
    $jdkBin = Split-Path $javacPath -Parent
    $jdkHome = Split-Path $jdkBin -Parent
    $sources = Join-Path $scratch 'stub'
    New-Item -ItemType Directory -Path "$sources/ghidra", "$sources/out" | Out-Null
    Set-Content -LiteralPath "$sources/LaunchSupport.java" -Encoding Ascii -Value @'
public class LaunchSupport {
    public static void main(String[] args) {
        String option = args[args.length - 1];
        if (System.getenv("GL_NO_JDK") != null) {
            if (option.equals("-ask")) throw new AssertionError("Interactive JDK selection is forbidden");
            System.exit(1);
        }
        if (option.equals("-save")) System.out.println(System.getProperty("java.home"));
        else if (option.equals("-envvars")) { System.out.println("GL_TEST_PROPS=from-props"); System.out.println("GL_TEST_KEEP=overridden"); }
        else if (option.equals("-vmargs")) System.out.println("-Dgl.test=props");
    }
}
'@
    Set-Content -LiteralPath "$sources/ghidra/Ghidra.java" -Encoding Ascii -Value @'
package ghidra;
public class Ghidra {
    public static void main(String[] args) throws Exception {
        java.util.List<String> lines = new java.util.ArrayList<>();
        lines.add("dir=" + System.getProperty("user.dir"));
        lines.add("class=" + args[0]);
        lines.add("args=" + String.join("|", java.util.Arrays.copyOfRange(args, 1, args.length)));
        lines.add("prop=" + System.getProperty("gl.test") + "/" + System.getProperty("gl.options"));
        lines.add("env=" + System.getenv("GL_TEST_PROPS") + "/" + System.getenv("GL_TEST_KEEP"));
        java.nio.file.Files.write(java.nio.file.Paths.get(System.getenv("GL_MARKER")), lines);
    }
}
'@
    & $javacPath -d "$sources/out" "$sources/LaunchSupport.java" "$sources/ghidra/Ghidra.java"
    if ($LASTEXITCODE -ne 0) { throw 'javac failed' }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class LauncherDialog {
    private delegate bool Callback(IntPtr window, IntPtr context);
    [DllImport("user32.dll")] private static extern bool EnumWindows(Callback callback, IntPtr context);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr parent, Callback callback, IntPtr context);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr window, StringBuilder text, int length);
    [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr window, uint message, IntPtr value, IntPtr extra);
    public static string Dismiss(int pid, string expectedText) {
        string result = null;
        EnumWindows((window, context) => {
            uint owner;
            GetWindowThreadProcessId(window, out owner);
            if (owner != pid) return true;
            StringBuilder title = new StringBuilder(1024);
            GetWindowText(window, title, title.Capacity);
            if (title.ToString() != "GhidraLaunch") return true;
            StringBuilder labels = new StringBuilder();
            EnumChildWindows(window, (child, ignored) => {
                StringBuilder text = new StringBuilder(4096);
                GetWindowText(child, text, text.Capacity);
                labels.Append(text).Append('\n');
                return true;
            }, IntPtr.Zero);
            if (labels.ToString().IndexOf(expectedText, StringComparison.Ordinal) < 0) return true;
            result = labels.ToString();
            PostMessage(window, 0x10, IntPtr.Zero, IntPtr.Zero);
            return false;
        }, IntPtr.Zero);
        return result;
    }
}
'@

    foreach ($binary in $binaries) {
        $name = [IO.Path]::GetFileNameWithoutExtension($binary)
        $ghidra = Join-Path $scratch "Native café $name"
        $relativeHome = '.\' + [IO.Path]::GetFileName($ghidra)
        New-Item -ItemType Directory -Path "$ghidra/support", "$ghidra/Ghidra/Framework/Utility/lib" | Out-Null
        Copy-Item -LiteralPath $binary -Destination $ghidra
        Set-Content -LiteralPath "$ghidra/ghidraRun.bat" -Value '@echo off', 'echo batch>"%~dp0batch.txt"', 'exit /b 7' -Encoding Ascii
        Set-Content -LiteralPath "$ghidra/Ghidra/application.properties" -Value 'application.name=Ghidra' -Encoding Ascii
        & (Join-Path $jdkBin 'jar.exe') cf "$ghidra/Ghidra/Framework/Utility/lib/Utility.jar" -C "$sources/out" ghidra
        if ($LASTEXITCODE -ne 0) { throw 'Utility.jar fixture creation failed' }
        & (Join-Path $jdkBin 'jar.exe') cf "$ghidra/support/LaunchSupport.jar" -C "$sources/out" LaunchSupport.class
        if ($LASTEXITCODE -ne 0) { throw 'LaunchSupport.jar fixture creation failed' }
        $marker = Join-Path $ghidra 'native.txt'
        $env:GL_MARKER = $marker
        $env:GL_TEST_KEEP = 'kept'
        $env:GHIDRA_JAVA_OPTIONS = '-Dgl.options=caller'
        $previousJavaHome = $env:JAVA_HOME
        $previousGhidraHome = $env:GHIDRA_HOME
        $env:JAVA_HOME = $jdkHome
        try {
            foreach ($selectedHome in @($ghidra, $relativeHome)) {
                Remove-Item -LiteralPath $marker -ErrorAction SilentlyContinue
                Invoke-Launcher (Join-Path $ghidra ([IO.Path]::GetFileName($binary))) $scratch 0 $selectedHome 'one "two words"'
                $deadline = (Get-Date).AddSeconds(20)
                while (-not (Test-Path -LiteralPath $marker) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
                if (-not (Test-Path -LiteralPath $marker)) { throw "$binary did not start Java with GHIDRA_HOME '$selectedHome'" }
                if (Test-Path -LiteralPath "$ghidra/batch.txt") { throw "$binary ran ghidraRun.bat instead of starting Java" }
                $expected = @("dir=$ghidra", 'class=ghidra.GhidraRun', 'args=one|two words', 'prop=props/caller', 'env=from-props/kept')
                $actual = Get-Content -LiteralPath $marker
                if (($actual -join "`n") -ne ($expected -join "`n")) { throw "$binary launched Java unexpectedly with GHIDRA_HOME '$selectedHome':`n$($actual -join "`n")" }
            }
        } finally {
            Remove-Item Env:GL_MARKER, Env:GL_TEST_KEEP, Env:GHIDRA_JAVA_OPTIONS -ErrorAction SilentlyContinue
            $env:JAVA_HOME = $previousJavaHome
            $env:GHIDRA_HOME = $previousGhidraHome
        }
        $env:GL_NO_JDK = '1'
        $previousGhidraHome = $env:GHIDRA_HOME
        $previousJavaHome = $env:JAVA_HOME
        $env:JAVA_HOME = $jdkHome
        try {
            $launcher = Join-Path $ghidra ([IO.Path]::GetFileName($binary))
            Assert-LauncherFailure $launcher $scratch $relativeHome 'JAVA_HOME'
            if (Test-Path -LiteralPath "$ghidra/batch.txt") { throw "$binary retried unsupported JDK selection through batch fallback" }
            Remove-Item Env:GL_NO_JDK -ErrorAction SilentlyContinue
            Assert-LauncherFailure $launcher $scratch ('.\Missing ' + $name) 'ghidraRun.bat'
            if (Test-Path -LiteralPath "$ghidra/batch.txt") { throw "$binary ignored the missing relative GHIDRA_HOME" }
        } finally {
            Remove-Item Env:GL_NO_JDK -ErrorAction SilentlyContinue
            $env:GHIDRA_HOME = $previousGhidraHome
            $env:JAVA_HOME = $previousJavaHome
        }
        Write-Host "Native launch checks passed: $binary"
    }
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
