param(
    [Parameter(Mandatory)][string]$PayloadRoot,
    [string]$LogRoot = (Join-Path $env:RUNNER_TEMP 'upgrade-logs')
)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or -not $IsWindows) {
    throw 'Installation tests must run in an isolated Windows GitHub Actions job, not a developer profile.'
}
$root = Split-Path $PSScriptRoot -Parent
$install = Join-Path $env:LOCALAPPDATA 'Ghidra Launch'
if (Test-Path -LiteralPath $install) { throw "Refusing to replace pre-existing installation: $install" }
$scratch = Join-Path $env:RUNNER_TEMP ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $scratch | Out-Null
New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
$LogRoot = (Resolve-Path -LiteralPath $LogRoot).Path
$script:invocation = 0
$originals = @(
    'Resources/Version.h',
    'GhidraLaunchC/x64/Release/bin/GhidraLaunchC.exe',
    'GhidraLaunchRS/GhidraLaunchRS.exe',
    'GhidraLaunchGhidraHelperC/x64/Release/bin/GhidraLaunchGhidraHelperC.exe',
    'GhidraLaunchGhidraHelperRS/bin/Release/GhidraLaunchGhidraHelperRS.exe'
)
$backup = Join-Path $scratch 'native-inputs'
New-Item -ItemType Directory -Path $backup | Out-Null
foreach ($path in $originals) {
    Copy-Item -LiteralPath (Join-Path $root $path) -Destination $backup
}

function Invoke-Bundle([string]$Path, [string]$Action, [bool]$Success = $true) {
    $script:invocation++
    $log = Join-Path $LogRoot ('{0:D3}-{1}-{2}.log' -f $script:invocation, [IO.Path]::GetFileNameWithoutExtension($Path), $Action.TrimStart('/'))
    $process = Start-Process -FilePath $Path -ArgumentList "$Action /quiet /norestart /log `"$log`"" -Wait -PassThru
    try {
        $ok = $process.ExitCode -in @(0, 3010)
        if ($ok -ne $Success) {
            if (Test-Path -LiteralPath $log) {
                Get-Content -LiteralPath $log -ErrorAction Continue | Write-Host
            } else {
                Write-Warning "Bundle did not create its diagnostic log: $log"
            }
            throw "Bundle $Action exited $($process.ExitCode): $Path"
        }
    } finally { $process.Dispose() }
}

function Wait-ForFileReady([string]$Path, [int]$TimeoutSeconds = 10) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ($true) {
        try {
            $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $stream.Dispose()
            return
        } catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw "Timed out waiting for exclusive access to $Path`: $_" }
            Start-Sleep -Milliseconds 200
        }
    }
}

function Assert-Shortcuts([string]$Launcher) {
    $shell = New-Object -ComObject WScript.Shell
    foreach ($link in @(
        (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Ghidra Launch.lnk'),
        (Join-Path ([Environment]::GetFolderPath('Programs')) 'Ghidra Launch/Ghidra Launch.lnk')
    )) {
        if (-not (Test-Path -LiteralPath $link) -or $shell.CreateShortcut($link).TargetPath -ne "$install\$Launcher") {
            throw 'Missing or stale shortcut after upgrade'
        }
    }
}

function Assert-Installed([string]$Variant, [string]$Version) {
    $launcher = if ($Variant -eq 'C') { 'GhidraLaunchC.exe' } else { 'GhidraLaunchRS.exe' }
    $other = if ($Variant -eq 'C') { 'GhidraLaunchRS.exe' } else { 'GhidraLaunchC.exe' }
    if (-not (Test-Path -LiteralPath "$install/$launcher") -or (Test-Path -LiteralPath "$install/$other")) {
        throw "Wrong installed launcher after switching to $Variant"
    }
    if (-not (Test-Path -LiteralPath "$install/Ghidra/ghidraRun.bat")) { throw 'Upgrade removed Ghidra' }
    if ((Get-ItemProperty 'HKLM:\Software\WOW6432Node\Ghidra Launch Tests\Upstream' -Name Installed).Installed -ne 1) {
        throw 'Upgrade removed the machine-wide upstream prerequisite'
    }
    $marker = Get-Content -LiteralPath "$install/Ghidra/.ghidralaunch-source.sha256" -Raw
    $owner = (Get-ItemProperty 'HKCU:\Software\rpinz\Ghidra Launch').PayloadOwner
    if (-not $owner -or $marker -notmatch "owner=$([regex]::Escape($owner))`n") {
        $markerOwner = [regex]::Match($marker, '(?m)^owner=(.+)$').Groups[1].Value
        throw "Wrong payload owner after upgrade: registry='$owner', marker='$markerOwner'"
    }
    if ([Environment]::GetEnvironmentVariable('GHIDRA_HOME', 'User') -ne "$install\Ghidra") {
        throw 'Upgrade lost GHIDRA_HOME'
    }
    Assert-Shortcuts $launcher
    $registered = @(Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall |
        Get-ItemProperty | Where-Object { $_.DisplayName -eq 'Ghidra Launch' -and $_.BundleCachePath -and -not $_.SystemComponent })
    if ($registered.Count -ne 1) { throw "Expected one registered bundle; found $($registered.Count)" }
    if (([version]$registered[0].DisplayVersion).ToString(3) -ne $Version) {
        throw "Wrong registered version; expected $Version, found $($registered[0].DisplayVersion)"
    }
}

$last = $null
$completed = $false
try {
    foreach ($version in @('1.0.0', '1.0.1')) {
        & "$root/scripts/build.ps1" -Target Native -ReleaseVersion $version
        & "$root/scripts/build.ps1" -Target Installer -ReleaseVersion $version
        & "$root/scripts/build.ps1" -Target Internal -ReleaseVersion $version -PayloadRoot $PayloadRoot -VersionsFile "$PayloadRoot/Versions.wxi"
        & "$root/scripts/build.ps1" -Target Setup -ReleaseVersion $version -PayloadRoot $PayloadRoot -VersionsFile "$PayloadRoot/Versions.wxi"
        foreach ($variant in @('C', 'Rust')) {
            $dir = Join-Path $scratch "$version-$variant"
            New-Item -ItemType Directory -Path $dir | Out-Null
            Copy-Item "$root/GhidraLaunchSetup/bin/Release/GhidraLaunchSetup$variant.exe" $dir
            Copy-Item "$PayloadRoot/Ghidra.zip", "$PayloadRoot/OpenJDK21U-jdk_x64.msi" $dir
        }
    }
    foreach ($legacyVersion in @('0.9.0', '1.0.0')) {
        $legacy = Join-Path $scratch "legacy-$legacyVersion"
        & "$root/scripts/build.ps1" -Target Native -ReleaseVersion $legacyVersion
        & "$PSScriptRoot/create-legacy-fixture.ps1" -Destination $legacy -PayloadRoot $PayloadRoot -LegacyVersion $legacyVersion
        foreach ($variant in @('C', 'Rust')) {
            Write-Host "Migrating legacy $legacyVersion to 1.0.0 $variant"
            $last = "$legacy/LegacyBundle.exe"
            Invoke-Bundle $last '/install'
            foreach ($launcher in @('GhidraLaunchC.exe', 'GhidraLaunchRS.exe')) {
                if (-not (Test-Path -LiteralPath "$install/$launcher")) { throw "Legacy fixture is missing $launcher" }
            }
            Assert-Shortcuts 'GhidraLaunchC.exe'
            $marker = Get-Content -LiteralPath "$install/Ghidra/.ghidralaunch-source.sha256" -Raw
            if ($marker.Trim() -ine (Get-FileHash "$PayloadRoot/Ghidra.zip").Hash) { throw 'Legacy marker fixture differs from the original contract' }
            Set-Content -LiteralPath "$install/Ghidra/support/user.txt" -Value 'preserved'
            $last = "$scratch/1.0.0-$variant/GhidraLaunchSetup$variant.exe"
            Invoke-Bundle $last '/install'
            Assert-Installed $variant '1.0.0'
            if ((Get-Content -LiteralPath "$install/Ghidra/support/user.txt" -Raw).Trim() -ne 'preserved') {
                throw 'Legacy migration deleted user content'
            }
            Invoke-Bundle $last '/uninstall'
            $last = $null
            if (Test-Path -LiteralPath "$install/Ghidra") { throw 'Legacy migration uninstall left Ghidra behind' }
        }
    }
    foreach ($step in @(@('1.0.0', 'C'), @('1.0.0', 'C'), @('1.0.0', 'Rust'), @('1.0.0', 'C'), @('1.0.1', 'Rust'), @('1.0.1', 'C'))) {
        $version, $variant = $step
        $last = "$scratch/$version-$variant/GhidraLaunchSetup$variant.exe"
        Invoke-Bundle $last '/install'
        Assert-Installed $variant $version
        if (Test-Path -LiteralPath "$install/Ghidra/support/user.txt") {
            if ((Get-Content -LiteralPath "$install/Ghidra/support/user.txt" -Raw).Trim() -ne 'preserved') {
                throw 'Same-source ownership handoff lost user content'
            }
        } else {
            if ($version -ne '1.0.0' -or $variant -ne 'C') { throw 'Upgrade deleted user content' }
            Set-Content -LiteralPath "$install/Ghidra/support/user.txt" -Value 'preserved'
        }
    }
    $previousOwner = (Get-ItemProperty 'HKCU:\Software\rpinz\Ghidra Launch').PayloadOwner
    & "$root/scripts/build.ps1" -Target Native -ReleaseVersion '1.0.1'
    & "$root/scripts/build.ps1" -Target Installer -ReleaseVersion '1.0.1' -Rebuild
    & "$root/scripts/build.ps1" -Target Internal -ReleaseVersion '1.0.1' -PayloadRoot $PayloadRoot -VersionsFile "$PayloadRoot/Versions.wxi" -Rebuild
    & "$root/scripts/build.ps1" -Target Setup -ReleaseVersion '1.0.1' -PayloadRoot $PayloadRoot -VersionsFile "$PayloadRoot/Versions.wxi" -Rebuild
    $rebuilt = Join-Path $scratch '1.0.1-C-rebuilt'
    New-Item -ItemType Directory -Path $rebuilt | Out-Null
    Copy-Item "$root/GhidraLaunchSetup/bin/Release/GhidraLaunchSetupC.exe", "$PayloadRoot/Ghidra.zip", "$PayloadRoot/OpenJDK21U-jdk_x64.msi" $rebuilt
    $last = "$rebuilt/GhidraLaunchSetupC.exe"
    Invoke-Bundle $last '/install'
    Assert-Installed C '1.0.1'
    if ((Get-ItemProperty 'HKCU:\Software\rpinz\Ghidra Launch').PayloadOwner -eq $previousOwner -or
        (Get-Content -LiteralPath "$install/Ghidra/support/user.txt" -Raw).Trim() -ne 'preserved') {
        throw 'Rebuilt same-version bundle did not safely transfer payload ownership'
    }
    $failedMsi = Join-Path $scratch 'failed-msi'
    New-Item -ItemType Directory -Path $failedMsi | Out-Null
    & "$root/scripts/build.ps1" -Target Native -ReleaseVersion '1.0.2'
    & "$root/scripts/build.ps1" -Target Installer -ReleaseVersion '1.0.2'
    $msiPath = Join-Path $failedMsi 'GhidraLaunchInstallerRust.msi'
    Copy-Item "$root/GhidraLaunchInstaller/bin/Release/GhidraLaunchInstallerRust.msi" $msiPath
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($msiPath, 1)
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
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    $database = $null
    $installer = $null
    # Releasing the Windows Installer COM objects does not guarantee the
    # underlying file handle is closed immediately (background AV scanning or
    # the Installer's own SxS cache can briefly hold it), which races with
    # wix.exe opening the same file as a bind input below. Force the RCWs to
    # be collected and wait until the file is actually free before continuing.
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    [GC]::Collect()
    Wait-ForFileReady $msiPath
    $msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\Current\Bin\MSBuild.exe' | Select-Object -First 1
    if (-not $msbuild) { throw 'MSBuild not found for failed-MSI rollback fixture' }
    & "$root/scripts/build.ps1" -Target Internal -ReleaseVersion '1.0.2' -PayloadRoot $PayloadRoot -VersionsFile "$PayloadRoot/Versions.wxi"
    & $msbuild "$root/GhidraLaunchSetup/GhidraLaunchCoreRust.wixproj" /restore /t:Rebuild /p:Configuration=Release /p:Platform=x86 /p:ReleaseVersion=1.0.2 /p:BuildProjectReferences=false "/p:SolutionDir=$root\" "/p:PayloadRoot=$PayloadRoot" "/p:VersionsFile=$PayloadRoot/Versions.wxi" "/p:MsiPath=$msiPath"
    if ($LASTEXITCODE -ne 0) { throw 'Failed to build launcher-MSI failure bundle' }
    & "$root/scripts/build.ps1" -Target Setup -ReleaseVersion '1.0.2' -PayloadRoot $PayloadRoot -VersionsFile "$PayloadRoot/Versions.wxi" -Rebuild
    Copy-Item "$root/GhidraLaunchSetup/bin/Release/GhidraLaunchSetupRust.exe", "$PayloadRoot/Ghidra.zip", "$PayloadRoot/OpenJDK21U-jdk_x64.msi" $failedMsi
    $previousOwner = (Get-ItemProperty 'HKCU:\Software\rpinz\Ghidra Launch').PayloadOwner
    Invoke-Bundle "$failedMsi/GhidraLaunchSetupRust.exe" '/install' $false
    Assert-Installed C '1.0.1'
    if ((Get-ItemProperty 'HKCU:\Software\rpinz\Ghidra Launch').PayloadOwner -ne $previousOwner -or
        (Get-Content -LiteralPath "$install/Ghidra/support/user.txt" -Raw).Trim() -ne 'preserved') {
        throw 'Failed launcher MSI damaged the incumbent payload or ownership'
    }
    $bad = Join-Path $scratch 'failed-upgrade'
    New-Item -ItemType Directory -Path $bad | Out-Null
    Copy-Item "$PayloadRoot/OpenJDK21U-jdk_x64.msi", "$PayloadRoot/Versions.wxi" $bad
    $archive = [IO.Compression.ZipFile]::Open("$bad/Ghidra.zip", [IO.Compression.ZipArchiveMode]::Create)
    try {
        $writer = [IO.StreamWriter]::new($archive.CreateEntry('../escape.txt').Open())
        try { $writer.Write('invalid entry') } finally { $writer.Dispose() }
    } finally { $archive.Dispose() }
    & "$root/scripts/build.ps1" -Target Installer -ReleaseVersion '1.0.2'
    & "$root/scripts/build.ps1" -Target Internal -ReleaseVersion '1.0.2' -PayloadRoot $bad -VersionsFile "$bad/Versions.wxi"
    & "$root/scripts/build.ps1" -Target Setup -ReleaseVersion '1.0.2' -PayloadRoot $bad -VersionsFile "$bad/Versions.wxi"
    Copy-Item "$root/GhidraLaunchSetup/bin/Release/GhidraLaunchSetupRust.exe" $bad
    Invoke-Bundle "$bad/GhidraLaunchSetupRust.exe" '/install' $false
    Assert-Installed C '1.0.1'
    if ((Get-Content -LiteralPath "$install/Ghidra/support/user.txt" -Raw).Trim() -ne 'preserved') {
        throw 'Failed bundle upgrade damaged the existing Ghidra tree'
    }
    Invoke-Bundle "$scratch/1.0.0-Rust/GhidraLaunchSetupRust.exe" '/install' $false
    Assert-Installed C '1.0.1'
    $failedJava = Join-Path $scratch 'failed-java'
    New-Item -ItemType Directory -Path $failedJava | Out-Null
    Copy-Item "$PayloadRoot/Ghidra.zip", "$PayloadRoot/Versions.wxi" $failedJava
    & dotnet tool run wix build "$PSScriptRoot/fixtures/Upstream.wxs" -arch x86 -d FailInstall=yes -o "$failedJava/OpenJDK21U-jdk_x64.msi"
    if ($LASTEXITCODE -ne 0) { throw 'Failed to build Java-stage failure MSI' }
    & "$root/scripts/build.ps1" -Target Native -ReleaseVersion '1.0.3'
    & "$root/scripts/build.ps1" -Target Installer -ReleaseVersion '1.0.3'
    & "$root/scripts/build.ps1" -Target Internal -ReleaseVersion '1.0.3' -PayloadRoot $failedJava -VersionsFile "$failedJava/Versions.wxi"
    & "$root/scripts/build.ps1" -Target Setup -ReleaseVersion '1.0.3' -PayloadRoot $failedJava -VersionsFile "$failedJava/Versions.wxi"
    Copy-Item "$root/GhidraLaunchSetup/bin/Release/GhidraLaunchSetupRust.exe" $failedJava
    $last = "$failedJava/GhidraLaunchSetupRust.exe"
    Invoke-Bundle $last '/install' $false
    if (-not (Test-Path -LiteralPath "$install/GhidraLaunchRS.exe") -or
        -not (Test-Path -LiteralPath "$install/Ghidra/ghidraRun.bat") -or
        (Get-Content -LiteralPath "$install/Ghidra/support/user.txt" -Raw).Trim() -ne 'preserved') {
        throw 'Failed Java stage deleted the committed core or user content'
    }
    & "$root/scripts/build.ps1" -Target Internal -ReleaseVersion '1.0.3' -PayloadRoot $PayloadRoot -VersionsFile "$PayloadRoot/Versions.wxi" -Rebuild
    & "$root/scripts/build.ps1" -Target Setup -ReleaseVersion '1.0.3' -PayloadRoot $PayloadRoot -VersionsFile "$PayloadRoot/Versions.wxi" -Rebuild
    $retry = Join-Path $scratch 'java-retry'
    New-Item -ItemType Directory -Path $retry | Out-Null
    Copy-Item "$root/GhidraLaunchSetup/bin/Release/GhidraLaunchSetupRust.exe", "$PayloadRoot/Ghidra.zip", "$PayloadRoot/OpenJDK21U-jdk_x64.msi" $retry
    $last = "$retry/GhidraLaunchSetupRust.exe"
    Invoke-Bundle $last '/install'
    Assert-Installed Rust '1.0.3'
    Invoke-Bundle $last '/uninstall'
    $last = $null
    if (Test-Path -LiteralPath "$install/Ghidra") { throw 'Uninstall left its owned Ghidra tree' }
    Write-Host 'Legacy migration, reinstall, downgrade, and same/newer-version switching checks passed.'
    $completed = $true
} catch {
    Write-Host "Upgrade failure diagnostics: $LogRoot"
    throw
} finally {
    try {
        if ($last) { Invoke-Bundle $last '/uninstall' }
    } catch {
        if ($completed) { throw }
        Write-Warning "Cleanup failed after the original upgrade error: $_"
    } finally {
        try {
            foreach ($path in $originals) {
                Copy-Item -LiteralPath (Join-Path $backup (Split-Path $path -Leaf)) -Destination (Join-Path $root $path) -Force
            }
            [IO.File]::SetLastWriteTimeUtc((Join-Path $root 'Resources/Version.h'), [datetime]::UtcNow)
            if ($completed) { Remove-Item -LiteralPath $scratch -Recurse -Force }
            else { Write-Warning "Preserving failed upgrade fixtures at $scratch" }
        } catch {
            if ($completed) { throw }
            Write-Warning "Input restoration failed after the original upgrade error: $_"
        }
    }
}
