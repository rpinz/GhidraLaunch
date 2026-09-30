param(
    [Parameter(Mandatory)][string]$MsiPath
)

# Runs in its own process so the Windows Installer COM database handle is
# guaranteed to be released (by process exit) before the caller touches the
# file again. Relying on FinalReleaseComObject + GC in-process was not
# sufficient: the STA COM apartment can defer the underlying release past
# when the caller resumes, leaving the file locked for several seconds.
$ErrorActionPreference = 'Stop'
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($MsiPath, 1)
try {
    $view = $database.OpenView("SELECT ``Name`` FROM ``_Tables`` WHERE ``Name`` = 'CustomAction'")
    try {
        $view.Execute()
        $hasCustomActions = $null -ne $view.Fetch()
    } finally { $view.Close() }
    if (-not $hasCustomActions) {
        $view = $database.OpenView('CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255) PRIMARY KEY `Action`)')
        try { $view.Execute() } finally { $view.Close() }
    }
    foreach ($sql in @(
        "INSERT INTO ``CustomAction`` (``Action``, ``Type``, ``Target``) VALUES ('TestFailInstall', 19, 'Intentional rollback test')",
        "INSERT INTO ``InstallExecuteSequence`` (``Action``, ``Condition``, ``Sequence``) VALUES ('TestFailInstall', 'NOT REMOVE', 4001)"
    )) {
        $view = $database.OpenView($sql)
        try { $view.Execute() } finally { $view.Close() }
    }
    $database.Commit()
} finally {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
}
