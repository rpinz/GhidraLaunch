param(
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][string]$PayloadRoot
)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or -not $IsWindows) { throw 'Legacy fixture builds are restricted to Windows CI.' }
$root = Split-Path $PSScriptRoot -Parent
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
$Destination = (Resolve-Path -LiteralPath $Destination).Path
$tools = Join-Path $Destination 'wix3'
$zip = Join-Path $Destination 'wix314-binaries.zip'
Invoke-WebRequest 'https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip' -OutFile $zip
if ((Get-FileHash -LiteralPath $zip).Hash -ne '6ac824e1642d6f7277d0ed7ea09411a508f6116ba6fae0aa5f2c7daa2ff43d31') {
    throw 'Legacy WiX fixture toolchain checksum mismatch'
}
Expand-Archive -LiteralPath $zip -DestinationPath $tools
$csc = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\Current\Bin\Roslyn\csc.exe' | Select-Object -First 1
if (-not $csc) { throw 'Roslyn compiler not found for the frozen managed test fixture' }
$refs = "${env:ProgramFiles(x86)}\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8"
if (-not (Test-Path -LiteralPath "$refs/mscorlib.dll")) { throw '.NET 4.8 reference assemblies missing for the legacy fixture' }
& $csc /nologo /noconfig /nostdlib+ /target:exe "/out:$Destination/LegacyHelper.exe" "/r:$refs/mscorlib.dll" "/r:$refs/System.dll" "/r:$refs/System.Core.dll" "/r:$refs/System.IO.Compression.dll" "/r:$refs/System.IO.Compression.FileSystem.dll" "$PSScriptRoot/fixtures/LegacyHelper.cs"
if ($LASTEXITCODE -ne 0) { throw 'Legacy helper fixture compilation failed' }
foreach ($name in @('LegacyInstaller', 'LegacyBundle')) {
    & "$tools/candle.exe" -nologo -arch x86 -ext "$tools/WixBalExtension.dll" -ext "$tools/WixUtilExtension.dll" "-dRoot=$root" "-dPayloadRoot=$PayloadRoot" "-dDestination=$Destination" "$PSScriptRoot/fixtures/$name.wxs" -out "$Destination/$name.wixobj"
    if ($LASTEXITCODE -ne 0) { throw "Legacy authoring compilation failed: $name" }
    $extension = if ($name -eq 'LegacyInstaller') { 'msi' } else { 'exe' }
    & "$tools/light.exe" -nologo -sice:ICE61 -sice:ICE91 -ext "$tools/WixBalExtension.dll" -ext "$tools/WixUtilExtension.dll" "$Destination/$name.wixobj" -out "$Destination/$name.$extension"
    if ($LASTEXITCODE -ne 0) { throw "Legacy package linking failed: $name" }
}
