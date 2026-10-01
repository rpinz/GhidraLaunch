param([Parameter(Mandatory)][string]$MsiPath)

$ErrorActionPreference = 'Stop'
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase((Resolve-Path -LiteralPath $MsiPath).Path, 0)

function Read-Rows($sql, $columns) {
    $view = $database.OpenView($sql)
    $view.Execute()
    $result = @()
    try {
        while ($record = $view.Fetch()) {
            $row = @{}
            for ($i = 1; $i -le $columns; $i++) { $row["Column$i"] = $record.StringData($i) }
            $result += [pscustomobject]$row
        }
    } finally {
        $view.Close()
    }
    return $result
}

$files = @(Read-Rows 'SELECT `File`.`FileName`, `Component`.`Directory_` FROM `File`, `Component` WHERE `File`.`Component_` = `Component`.`Component`' 2)
$expected = @('GhidraLaunchC.exe', 'GhidraLaunchRS.exe')
$locations = @{}
foreach ($file in $files) {
    $name = ($file.Column1 -split '\|')[-1]
    if ($name -ieq 'ghidraRun.bat') { throw 'MSI unexpectedly contains Ghidra' }
    if ($expected -contains $name) { $locations[$name] = $file.Column2 }
}
foreach ($name in $expected) {
    if (-not $locations.ContainsKey($name)) { throw "MSI does not install $name" }
    if ($locations[$name] -ne 'INSTALLFOLDER') {
        throw "MSI installs $name outside INSTALLFOLDER"
    }
}

$directoryRows = @(Read-Rows 'SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`' 3 |
    Where-Object { $_.Column1 -eq 'INSTALLFOLDER' })
if ($directoryRows.Count -ne 1) {
    throw "MSI does not contain exactly one INSTALLFOLDER directory row (found $($directoryRows.Count))"
}
$installDirectory = $directoryRows[0]
if ($installDirectory.Column2 -ne 'LocalAppDataFolder' -or
    ($installDirectory.Column3 -split '\|')[-1] -ne 'Ghidra Launch') {
    throw 'MSI installation directory differs from the advertised per-user layout'
}

$environmentRows = @(Read-Rows 'SELECT `Environment`.`Name`, `Environment`.`Value` FROM `Environment`' 2 |
    Where-Object { $_.Column1 -match 'GHIDRA_HOME$' })
if ($environmentRows.Count -ne 1) {
    throw "MSI does not set exactly one GHIDRA_HOME environment row (found $($environmentRows.Count))"
}
if ($environmentRows[0].Column2 -ne '[INSTALLFOLDER]Ghidra') {
    throw "MSI sets GHIDRA_HOME to an unexpected value: $($environmentRows[0].Column2)"
}

$bundle = [xml](Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'GhidraLaunchSetup/Bundle.wxs') -Raw)
$namespace = [System.Xml.XmlNamespaceManager]::new($bundle.NameTable)
$namespace.AddNamespace('w', 'http://schemas.microsoft.com/wix/2006/wi')
$msiPackages = @($bundle.SelectNodes('//w:Chain/w:MsiPackage', $namespace))
$msiNames = @($msiPackages | ForEach-Object { $_.GetAttribute('SourceFile') })
if ($msiNames.Count -ne 2 -or
    -not ($msiNames -match 'OpenJDK.*U-jdk_x64\.msi') -or
    -not ($msiNames -match 'GhidraLaunchInstaller\.msi')) {
    throw 'Bundle does not chain the Temurin and launcher MSIs'
}

$javaPackage = $msiPackages | Where-Object { $_.GetAttribute('SourceFile') -match 'OpenJDK.*U-jdk_x64\.msi' }
if ($javaPackage.GetAttribute('Compressed') -ne 'no' -or -not $javaPackage.GetAttribute('DownloadUrl')) {
    throw 'Bundle does not fetch Temurin at install time (expected Compressed="no" with a DownloadUrl)'
}

$exePackages = @($bundle.SelectNodes('//w:Chain/w:ExePackage', $namespace))
if ($exePackages.Count -ne 1) {
    throw "Bundle does not chain exactly one ExePackage for Ghidra (found $($exePackages.Count))"
}
$ghidraPackage = $exePackages[0]
if ($ghidraPackage.GetAttribute('PerMachine') -ne 'no') {
    throw 'Ghidra ExePackage is not scoped per-user'
}
if (-not $ghidraPackage.GetAttribute('InstallCommand') -or -not $ghidraPackage.GetAttribute('UninstallCommand')) {
    throw 'Ghidra ExePackage does not define install/uninstall commands'
}
$ghidraPayloads = @($ghidraPackage.SelectNodes('w:Payload', $namespace))
$ghidraZipPayload = $ghidraPayloads | Where-Object { $_.GetAttribute('Name') -eq 'Ghidra.zip' }
if (-not $ghidraZipPayload) {
    throw 'Ghidra ExePackage does not reference a Ghidra.zip payload'
}
if ($ghidraZipPayload.GetAttribute('Compressed') -ne 'no' -or -not $ghidraZipPayload.GetAttribute('DownloadUrl')) {
    throw 'Bundle does not fetch Ghidra.zip at install time (expected Compressed="no" with a DownloadUrl)'
}

Write-Host 'MSI installs both launchers and sets GHIDRA_HOME, not Ghidra itself; bundle downloads and extracts Ghidra and Temurin at install time.'
