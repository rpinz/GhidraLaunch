param(
    [ValidateSet('Native', 'Faults', 'Installer', 'Setup', 'Internal')][string]$Target = 'Native',
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$ReleaseVersion = '0.0.0',
    [string]$PayloadRoot,
    [string]$VersionsFile,
    [switch]$Rebuild
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot/build-version.ps1"
$version = Get-BuildVersion $ReleaseVersion
$msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\Current\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) { throw 'MSBuild not found; install Visual Studio 2022 with Desktop development with C++.' }
$buildTarget = if ($Rebuild) { 'Rebuild' } else { 'Build' }
Push-Location $root
try {
    $launchers = @(
        "$root/GhidraLaunchC/x64/$Configuration/bin/GhidraLaunchC.exe",
        "$root/GhidraLaunchRS/bin/$Configuration/GhidraLaunchRS.exe"
    )
    $helpers = @(
        "$root/GhidraLaunchGhidraHelperC/x64/$Configuration/bin/GhidraLaunchGhidraHelperC.exe",
        "$root/GhidraLaunchGhidraHelperRS/bin/$Configuration/GhidraLaunchGhidraHelperRS.exe"
    )
    if ($Target -eq 'Faults') {
        & $msbuild "$root/GhidraLaunchGhidraHelperC/GhidraLaunchGhidraHelperC.vcxproj" "/t:$buildTarget" "/p:Configuration=$Configuration" /p:Platform=x64 /p:HelperFaultTests=true
        if ($LASTEXITCODE -ne 0) { throw "Fault-test driver build failed ($LASTEXITCODE)" }
    } elseif ($Target -eq 'Native') {
        Set-NativeVersion $root $version
        foreach ($project in @(
            'GhidraLaunchC/GhidraLaunchC.vcxproj',
            'GhidraLaunchRS/GhidraLaunchRS.vcxproj',
            'GhidraLaunchGhidraHelperC/GhidraLaunchGhidraHelperC.vcxproj',
            'GhidraLaunchGhidraHelperRS/GhidraLaunchGhidraHelperRS.vcxproj'
        )) {
            & $msbuild $project "/t:$buildTarget" "/p:Configuration=$Configuration" /p:Platform=x64 "/p:SolutionDir=$root\"
            if ($LASTEXITCODE -ne 0) { throw "Build failed: $project ($LASTEXITCODE)" }
        }
        foreach ($path in $launchers + $helpers) {
            Assert-ExecutableVersion $path $version -Native
        }
    } else {
        $payloads = if ($PayloadRoot) { (Resolve-Path -LiteralPath $PayloadRoot).Path } else { $root }
        $versions = if ($VersionsFile) { (Resolve-Path -LiteralPath $VersionsFile).Path } else { "$root/GhidraLaunchSetup/Versions.wxi" }
        if ($Target -eq 'Installer') {
            foreach ($path in $launchers) { Assert-ExecutableVersion $path $version -Native }
        } elseif ($Target -eq 'Internal') {
            foreach ($path in $helpers) { Assert-ExecutableVersion $path $version -Native }
            foreach ($variant in @('C', 'Rust')) {
                Assert-MsiVersion "$root/GhidraLaunchInstaller/bin/$Configuration/GhidraLaunchInstaller$variant.msi" $version $variant
            }
        } else {
            for ($i = 0; $i -lt 2; $i++) {
                $variant = @('C', 'Rust')[$i]
                Assert-ExecutableVersion $helpers[$i] $version -Native
                Assert-InternalBundle "$root/GhidraLaunchSetup/bin/$Configuration/GhidraLaunchCore$variant.exe" $version Core $variant `
                    "$root/GhidraLaunchInstaller/bin/$Configuration/GhidraLaunchInstaller$variant.msi" $helpers[$i] $payloads $versions
            }
            Assert-InternalBundle "$root/GhidraLaunchSetup/bin/$Configuration/GhidraLaunchJava.exe" $version Java '' '' '' $payloads $versions
        }
        $projects = if ($Target -eq 'Internal') {
            @('GhidraLaunchSetup/GhidraLaunchCoreC.wixproj', 'GhidraLaunchSetup/GhidraLaunchCoreRust.wixproj', 'GhidraLaunchSetup/GhidraLaunchJava.wixproj')
        } else {
            @("GhidraLaunch$Target/GhidraLaunch${Target}C.wixproj", "GhidraLaunch$Target/GhidraLaunch${Target}Rust.wixproj")
        }
        foreach ($project in $projects) {
            $arguments = @(
                $project, "/t:$buildTarget", '/restore', "/p:Configuration=$Configuration",
                '/p:Platform=x86', "/p:SolutionDir=$root\", "/p:ReleaseVersion=$($version.Product)",
                # Packaging must never overwrite previously signed native inputs/MSIs.
                '/p:BuildProjectReferences=false'
            )
            if ($PayloadRoot) { $arguments += "/p:PayloadRoot=$PayloadRoot" }
            if ($VersionsFile) { $arguments += "/p:VersionsFile=$VersionsFile" }
            & $msbuild @arguments
            if ($LASTEXITCODE -ne 0) { throw "Build failed: $project ($LASTEXITCODE)" }
        }
    }
} finally {
    Pop-Location
}
