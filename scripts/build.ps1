param(
    [ValidateSet('Native', 'Installer', 'Setup', 'Internal')][string]$Target = 'Native',
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$ReleaseVersion = '0.0.0',
    [string]$PayloadRoot,
    [string]$VersionsFile,
    [switch]$Rebuild
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\Current\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) { throw 'MSBuild not found; install Visual Studio 2022 with Desktop development with C++.' }
$buildTarget = if ($Rebuild) { 'Rebuild' } else { 'Build' }
Push-Location $root
try {
    if ($Target -eq 'Native') {
        foreach ($project in @(
            'GhidraLaunchC/GhidraLaunchC.vcxproj',
            'GhidraLaunchRS/GhidraLaunchRS.vcxproj',
            'GhidraLaunchGhidraHelperC/GhidraLaunchGhidraHelperC.vcxproj',
            'GhidraLaunchGhidraHelperRS/GhidraLaunchGhidraHelperRS.vcxproj'
        )) {
            & $msbuild $project "/t:$buildTarget" "/p:Configuration=$Configuration" /p:Platform=x64 "/p:SolutionDir=$root\"
            if ($LASTEXITCODE -ne 0) { throw "Build failed: $project ($LASTEXITCODE)" }
        }
    } else {
        $projects = if ($Target -eq 'Internal') {
            @('GhidraLaunchSetup/GhidraLaunchCoreC.wixproj', 'GhidraLaunchSetup/GhidraLaunchCoreRust.wixproj', 'GhidraLaunchSetup/GhidraLaunchJava.wixproj')
        } else {
            @("GhidraLaunch$Target/GhidraLaunch${Target}C.wixproj", "GhidraLaunch$Target/GhidraLaunch${Target}Rust.wixproj")
        }
        foreach ($project in $projects) {
            $arguments = @(
                $project, "/t:$buildTarget", '/restore', "/p:Configuration=$Configuration",
                '/p:Platform=x86', "/p:SolutionDir=$root\", "/p:ReleaseVersion=$ReleaseVersion",
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
