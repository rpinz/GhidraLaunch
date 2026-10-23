param([Parameter(Mandatory)][string]$Destination)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
$Destination = (Resolve-Path -LiteralPath $Destination).Path
& dotnet tool run wix build (Join-Path $PSScriptRoot 'fixtures/Upstream.wxs') -arch x86 -o "$Destination/OpenJDK21U-jdk_x64.msi"
if ($LASTEXITCODE -ne 0) { throw 'Failed to build synthetic upstream MSI' }
$fixture = Join-Path $Destination 'fixture'
New-Item -ItemType Directory -Path "$fixture/ghidra_PUBLIC/support" -Force | Out-Null
Set-Content -LiteralPath "$fixture/ghidra_PUBLIC/ghidraRun.bat" -Value '@echo off', 'exit /b 0' -Encoding Ascii
Set-Content -LiteralPath "$fixture/ghidra_PUBLIC/support/fixture.txt" -Value 'synthetic Ghidra' -Encoding Ascii
Compress-Archive -LiteralPath "$fixture/ghidra_PUBLIC" -DestinationPath "$Destination/Ghidra.zip" -Force
@'
<Include xmlns="http://wixtoolset.org/schemas/v4/wxs">
<?define JavaVersion = "21" ?>
<?define JavaDownloadUrl = "https://example.invalid/OpenJDK21U-jdk_x64.msi" ?>
<?define GhidraDownloadUrl = "https://example.invalid/Ghidra.zip" ?>
</Include>
'@ | Set-Content -LiteralPath "$Destination/Versions.wxi" -Encoding utf8
