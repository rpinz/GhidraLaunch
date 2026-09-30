param(
    [string]$Destination = (Join-Path $env:RUNNER_TEMP 'release-syft')
)

$ErrorActionPreference = 'Stop'
$archive = "$Destination.zip"
Invoke-WebRequest -Uri 'https://github.com/anchore/syft/releases/download/v1.52.0/syft_1.52.0_windows_amd64.zip' -OutFile $archive
$expected = 'de787a374cf961c56fd7b206b2e183295abba32d0af3cb44d9aef2357ca9eda2'
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) { throw 'Syft archive checksum mismatch' }
Expand-Archive -LiteralPath $archive -DestinationPath $Destination -Force
$binary = Join-Path $Destination 'syft.exe'
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'Syft executable not found in verified archive' }
"SYFT_CMD=$binary" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
