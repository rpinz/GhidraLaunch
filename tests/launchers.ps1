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

    # a packaged-Ghidra layout with stub LaunchSupport/Ghidra classes must start Java directly, never ghidraRun.bat
    $javac = Get-Command javac -ErrorAction SilentlyContinue
    if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME 'bin/javac.exe'))) { $javac = Get-Item (Join-Path $env:JAVA_HOME 'bin/javac.exe') }
    if (-not $javac) { throw 'javac not found; a JDK is required for the native launch test' }
    $javacPath = if ($javac.Source) { $javac.Source } else { $javac.FullName }
    $jdkBin = Split-Path $javacPath -Parent
    $jdkHome = Split-Path $jdkBin -Parent
    $sources = Join-Path $scratch 'stub'
    New-Item -ItemType Directory -Path "$sources/ghidra" | Out-Null
    Set-Content -LiteralPath "$sources/LaunchSupport.java" -Encoding Ascii -Value @'
public class LaunchSupport {
    public static void main(String[] args) {
        String option = args[args.length - 1];
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

    foreach ($binary in $binaries) {
        $name = [IO.Path]::GetFileNameWithoutExtension($binary)
        $ghidra = Join-Path $scratch "Native $name"
        New-Item -ItemType Directory -Path "$ghidra/support", "$ghidra/Ghidra/Framework/Utility/lib" | Out-Null
        Copy-Item -LiteralPath $binary -Destination $ghidra
        Set-Content -LiteralPath "$ghidra/ghidraRun.bat" -Value '@echo off', 'echo batch>"%~dp0batch.txt"', 'exit /b 7' -Encoding Ascii
        Set-Content -LiteralPath "$ghidra/Ghidra/application.properties" -Value 'application.name=Ghidra' -Encoding Ascii
        & (Join-Path $jdkBin 'jar.exe') cf "$ghidra/Ghidra/Framework/Utility/lib/Utility.jar" -C "$sources/out" ghidra
        & (Join-Path $jdkBin 'jar.exe') cf "$ghidra/support/LaunchSupport.jar" -C "$sources/out" LaunchSupport.class
        $marker = Join-Path $ghidra 'native.txt'
        $env:GL_MARKER = $marker
        $env:GL_TEST_KEEP = 'kept'
        $env:GHIDRA_JAVA_OPTIONS = '-Dgl.options=caller'
        $previousJavaHome = $env:JAVA_HOME
        $env:JAVA_HOME = $jdkHome
        try {
            $process = Start-Process -FilePath (Join-Path $ghidra ([IO.Path]::GetFileName($binary))) -ArgumentList 'one "two words"' -WorkingDirectory $scratch -PassThru
            if (-not $process.WaitForExit(30000)) { throw "Native launcher timed out: $binary" }
            if ($process.ExitCode -ne 0) { throw "$binary exited $($process.ExitCode) on native launch" }
            $deadline = (Get-Date).AddSeconds(20)
            while (-not (Test-Path -LiteralPath $marker) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
        } finally {
            Remove-Item Env:GL_MARKER, Env:GL_TEST_KEEP, Env:GHIDRA_JAVA_OPTIONS -ErrorAction SilentlyContinue
            $env:JAVA_HOME = $previousJavaHome
        }
        if (-not (Test-Path -LiteralPath $marker)) { throw "$binary did not start Java directly" }
        if (Test-Path -LiteralPath "$ghidra/batch.txt") { throw "$binary ran ghidraRun.bat instead of starting Java" }
        $expected = @("dir=$ghidra", 'class=ghidra.GhidraRun', 'args=one|two words', 'prop=props/caller', 'env=from-props/kept')
        $actual = Get-Content -LiteralPath $marker
        if (($actual -join "`n") -ne ($expected -join "`n")) { throw "$binary launched Java unexpectedly:`n$($actual -join "`n")" }
        Write-Host "Native launch checks passed: $binary"
    }
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
