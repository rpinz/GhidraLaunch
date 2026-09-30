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

$directory = @(Read-Rows 'SELECT `Directory_Parent`, `DefaultDir` FROM `Directory` WHERE `Directory` = ''INSTALLFOLDER''' 2)
if ($directory.Count -ne 1) {
    throw "MSI does not contain exactly one INSTALLFOLDER directory row (found $($directory.Count))"
}
$installDirectory = $directory[0]
if ($installDirectory.Column1 -ne 'LocalAppDataFolder' -or
    ($installDirectory.Column2 -split '\|')[-1] -ne 'Ghidra Launch') {
    throw 'MSI installation directory differs from the advertised per-user layout'
}

$bundle = [xml](Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'GhidraLaunchSetup/Bundle.wxs') -Raw)
$namespace = [System.Xml.XmlNamespaceManager]::new($bundle.NameTable)
$namespace.AddNamespace('w', 'http://schemas.microsoft.com/wix/2006/wi')
$packages = @($bundle.SelectNodes('//w:Chain/w:MsiPackage', $namespace))
$names = @($packages | ForEach-Object { $_.GetAttribute('SourceFile') })
if ($names.Count -ne 2 -or
    -not ($names -match 'OpenJDK.*U-jdk_x64\.msi') -or
    -not ($names -match 'GhidraLaunchInstaller\.msi')) {
    throw 'Bundle does not chain the Temurin and launcher MSIs'
}

Write-Host 'MSI installs both launchers, not Ghidra; bundle references the MSI.'
