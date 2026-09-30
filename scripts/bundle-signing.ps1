param(
    [Parameter(Mandatory)][ValidateSet('Detach', 'Reattach')][string]$Operation,
    [Parameter(Mandatory)][ValidateSet('Internal', 'Setup')][string]$Stage,
    [Parameter(Mandatory)][string]$Directory
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$names = if ($Stage -eq 'Internal') {
    @('GhidraLaunchCoreC.exe', 'GhidraLaunchCoreRust.exe', 'GhidraLaunchJava.exe')
} else {
    @('GhidraLaunchSetupC.exe', 'GhidraLaunchSetupRust.exe')
}
$Directory = [IO.Path]::GetFullPath($Directory)
New-Item -ItemType Directory -Path $Directory -Force | Out-Null

Push-Location $root
try {
    foreach ($name in $names) {
        $bundle = Join-Path $root "GhidraLaunchSetup\bin\Release\$name"
        if (-not (Test-Path -LiteralPath $bundle -PathType Leaf)) { throw "Missing bundle: $bundle" }
        if ($Operation -eq 'Detach') {
            & dotnet tool run wix -- burn detach $bundle -engine (Join-Path $Directory $name)
            if ($LASTEXITCODE -ne 0) { throw "Burn engine extraction failed for $name" }
        } else {
            $engines = @(Get-ChildItem -LiteralPath $Directory -Filter $name -File -Recurse)
            if ($engines.Count -ne 1) { throw "Expected one signed engine for $name; found $($engines.Count)" }
            $engine = $engines[0].FullName
            $signature = Get-AuthenticodeSignature -LiteralPath $engine
            if ($signature.Status -ne 'Valid') { throw "Invalid engine signature for ${name}: $($signature.StatusMessage)" }
            $reattached = Join-Path $Directory "$name.reattached"
            try {
                & dotnet tool run wix -- burn reattach $bundle -engine $engine -o $reattached
                if ($LASTEXITCODE -ne 0) { throw "Burn engine reattachment failed for $name" }
                Copy-Item -LiteralPath $reattached -Destination $bundle -Force
            } finally {
                if (Test-Path -LiteralPath $reattached) { Remove-Item -LiteralPath $reattached -Force }
            }
        }
    }
} finally {
    Pop-Location
}
