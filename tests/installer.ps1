param(
    [Parameter(Mandatory)][string]$MsiPath,
    [Parameter(Mandatory)][ValidateSet('C', 'Rust')][string]$Variant,
    [string]$ExpectedVersion
)

$ErrorActionPreference = 'Stop'
$installer = New-Object -ComObject WindowsInstaller.Installer
$resolvedMsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
$database = $installer.OpenDatabase($resolvedMsiPath, 0)
$summary = $installer.SummaryInformation($resolvedMsiPath, 0)
if ($summary.Property(3) -ne 'Ghidra Launch' -or $summary.Property(4) -ne 'rpinz') {
    throw 'Unexpected MSI SummaryInformation Subject/Author'
}

function Read-Rows($sql, $columns) {
    $view = $database.OpenView($sql)
    $view.Execute()
    try {
        while ($record = $view.Fetch()) {
            $row = @{}
            for ($i = 1; $i -le $columns; $i++) { $row["Column$i"] = $record.StringData($i) }
            [pscustomobject]$row
        }
    } finally {
        $view.Close()
    }
}

$properties = @{}
foreach ($row in @(Read-Rows 'SELECT `Property`, `Value` FROM `Property`' 2)) {
    $properties[$row.Column1] = $row.Column2
}
if ($properties['ProductName'] -ne 'Ghidra Launch' -or $properties['GHIDRALAUNCHVARIANT'] -ne $Variant) {
    throw 'Unexpected MSI product/variant'
}
if ($ExpectedVersion -and $properties['ProductVersion'] -ne $ExpectedVersion) {
    throw "MSI ProductVersion '$($properties['ProductVersion'])' does not match '$ExpectedVersion'"
}
if ($properties['UpgradeCode'] -ne '{E0958D3F-13B8-4707-9E18-D7CBC2625E71}') {
    throw 'MSI lost the legacy upgrade family'
}

$launcher = if ($Variant -eq 'C') { 'GhidraLaunchC.exe' } else { 'GhidraLaunchRS.exe' }
$files = @(Read-Rows 'SELECT `File`.`FileName`, `Component`.`Directory_` FROM `File`, `Component` WHERE `File`.`Component_` = `Component`.`Component`' 2)
if ($files.Count -ne 1 -or ($files[0].Column1 -split '\|')[-1] -ne $launcher -or $files[0].Column2 -ne 'INSTALLFOLDER') {
    throw "MSI must install only $launcher in INSTALLFOLDER"
}
$shortcuts = @(Read-Rows 'SELECT `Target` FROM `Shortcut`' 1)
if ($shortcuts.Count -ne 2 -or @($shortcuts | Where-Object { $_.Column1 -ne '[#LauncherFile]' }).Count) {
    throw 'Both shortcuts must target the matching launcher'
}

$directories = @(Read-Rows 'SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`' 3 |
    Where-Object { $_.Column1 -eq 'INSTALLFOLDER' })
if ($directories.Count -ne 1 -or $directories[0].Column2 -ne 'LocalAppDataFolder' -or
    ($directories[0].Column3 -split '\|')[-1] -ne 'Ghidra Launch') {
    throw 'MSI installation directory differs from the advertised per-user layout'
}
$environment = @(Read-Rows 'SELECT `Environment`.`Name`, `Environment`.`Value` FROM `Environment`' 2 |
    Where-Object { $_.Column1 -match 'GHIDRA_HOME$' })
if ($environment.Count -ne 1 -or $environment[0].Column2 -ne '[INSTALLFOLDER]Ghidra') {
    throw 'MSI must set GHIDRA_HOME to its managed Ghidra directory'
}
$owner = @(Read-Rows 'SELECT `Name`, `Value` FROM `Registry`' 2 |
    Where-Object { $_.Column1 -eq 'PayloadOwner' })
if ($owner.Count -ne 1 -or $owner[0].Column2 -ne '[GHIDRALAUNCHOWNER]') {
    throw 'MSI must record the owning bundle provider key'
}
$sequence = @{}
foreach ($row in @(Read-Rows 'SELECT `Action`, `Sequence` FROM `InstallExecuteSequence`' 2)) {
    $sequence[$row.Column1] = [int]$row.Column2
}
if ($sequence['RemoveExistingProducts'] -le $sequence['InstallInitialize'] -or
    $sequence['RemoveExistingProducts'] -ge $sequence['ProcessComponents']) {
    throw 'Variant replacement must remove the old MSI inside the transaction before installing components'
}
Write-Host "$Variant MSI layout checks passed."
