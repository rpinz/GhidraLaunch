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
    if ($script:foreignInstalled) { Assert-ForeignBundle }
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

function Assert-RetainedUninstall {
    if ($script:foreignInstalled) { Assert-ForeignBundle }
    if (-not (Test-Path -LiteralPath "$install\Ghidra\ghidraRun.bat") -or
        [IO.File]::ReadAllText("$install\Ghidra\support\user.txt").Trim() -ne 'preserved') {
        throw 'Customized uninstall did not retain the complete Ghidra tree'
    }
    if ((Test-Path -LiteralPath "$install\GhidraLaunchC.exe") -or
        (Test-Path -LiteralPath "$install\GhidraLaunchRS.exe")) {
        throw 'Customized uninstall left an installed launcher'
    }
    $owner = (Get-ItemProperty 'HKCU:\Software\rpinz\Ghidra Launch' -Name PayloadOwner -ErrorAction SilentlyContinue).PayloadOwner
    if ($owner) { throw 'Customized uninstall left an active payload ownership record' }
}

function Assert-ForeignBundle {
    $foreignKey = 'HKLM:\Software\Ghidra Launch Tests\Foreign'
    if (-not (Test-Path -LiteralPath $foreignKey) -or
        (Get-ItemProperty -LiteralPath $foreignKey -Name Installed).Installed -ne 1) {
        throw 'Ghidra setup removed the unrelated application sharing its legacy upgrade family'
    }
}

$last = $null
$foreignBundle = $null
$script:foreignInstalled = $false
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
            Copy-Item "$root\GhidraLaunchInstaller\bin\Release\GhidraLaunchInstaller$variant.msi" $dir
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
            Assert-RetainedUninstall
            Remove-Item -LiteralPath "$install\Ghidra" -Recurse -Force
        }
    }
    $packages = & dotnet nuget locals global-packages --list
    if ($LASTEXITCODE -ne 0) { throw 'Failed to locate restored WiX extension' }
    $packageRoot = ($packages -replace '^global-packages:\s*', '').Trim()
    $bal = Join-Path $packageRoot 'wixtoolset.bal.wixext\5.0.2\wixext5\WixToolset.BootstrapperApplications.wixext.dll'
    $util = Join-Path $packageRoot 'wixtoolset.util.wixext\5.0.2\wixext5\WixToolset.Util.wixext.dll'
    $legacyNative = Join-Path $scratch 'legacy-native-same-msi'
    New-Item -ItemType Directory -Path $legacyNative | Out-Null
    & dotnet tool run wix build "$PSScriptRoot\fixtures\LegacyNativeBundle.wxs" -arch x86 -ext $bal -ext $util `
        -d "LauncherMsi=$scratch\1.0.0-C\GhidraLaunchInstallerC.msi" `
        -d "Helper=$root\GhidraLaunchGhidraHelperC\x64\Release\bin\GhidraLaunchGhidraHelperC.exe" `
        -d "PayloadRoot=$PayloadRoot" -o "$legacyNative\LegacyNativeBundle.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Failed to build same-MSI native legacy fixture' }
    if (-not (Test-Path -LiteralPath "$legacyNative\Ghidra.zip")) {
        Copy-Item "$PayloadRoot\Ghidra.zip" $legacyNative
    }
    $last = "$legacyNative\LegacyNativeBundle.exe"
    Invoke-Bundle $last '/install'
    Set-Content -LiteralPath "$install\Ghidra\support\user.txt" -Value 'preserved'
    $last = "$scratch\1.0.0-C\GhidraLaunchSetupC.exe"
    Invoke-Bundle $last '/install'
    Assert-Installed C '1.0.0'
    if ([IO.File]::ReadAllText("$install\Ghidra\support\user.txt").Trim() -ne 'preserved') {
        throw 'Same-MSI native legacy migration lost user additions'
    }
    Invoke-Bundle $last '/uninstall'
    $last = $null
    Assert-RetainedUninstall
    Remove-Item -LiteralPath "$install\Ghidra" -Recurse -Force

    $foreign = Join-Path $scratch 'foreign-upgrade-family'
    New-Item -ItemType Directory -Path $foreign | Out-Null
    & dotnet tool run wix build "$PSScriptRoot\fixtures\ForeignInstaller.wxs" -arch x64 -o "$foreign\ForeignInstaller.msi"
    if ($LASTEXITCODE -ne 0) { throw 'Failed to build foreign MSI fixture' }
    & dotnet tool run wix build "$PSScriptRoot\fixtures\ForeignBundle.wxs" -arch x64 -ext $bal -d "ForeignMsi=$foreign\ForeignInstaller.msi" -o "$foreign\ForeignBundle.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Failed to build foreign bundle fixture' }
    $foreignBundle = "$foreign\ForeignBundle.exe"
    Invoke-Bundle $foreignBundle '/install'
    $script:foreignInstalled = $true
    Assert-ForeignBundle
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
    $changedPayload = Join-Path $scratch 'changed-source'
    New-Item -ItemType Directory -Path $changedPayload | Out-Null
    Copy-Item "$PayloadRoot\Ghidra.zip", "$PayloadRoot\OpenJDK21U-jdk_x64.msi", "$PayloadRoot\Versions.wxi" $changedPayload
    [IO.File]::WriteAllText("$install\Ghidra\support\fixture.txt", 'edited upstream fixture')
    $archive = [IO.Compression.ZipFile]::Open("$changedPayload\Ghidra.zip", [IO.Compression.ZipArchiveMode]::Update)
    try {
        $archive.GetEntry('ghidra_PUBLIC/support/fixture.txt').Delete()
        $writer = [IO.StreamWriter]::new($archive.CreateEntry('ghidra_PUBLIC/support/fixture.txt').Open())
        try { $writer.Write('new upstream fixture') } finally { $writer.Dispose() }
    } finally { $archive.Dispose() }
    & "$root\scripts\build.ps1" -Target Internal -ReleaseVersion '1.0.1' -PayloadRoot $changedPayload -VersionsFile "$changedPayload\Versions.wxi"
    & "$root\scripts\build.ps1" -Target Setup -ReleaseVersion '1.0.1' -PayloadRoot $changedPayload -VersionsFile "$changedPayload\Versions.wxi"
    Copy-Item "$root\GhidraLaunchSetup\bin\Release\GhidraLaunchSetupC.exe" $changedPayload
    $last = "$changedPayload\GhidraLaunchSetupC.exe"
    Invoke-Bundle $last '/install'
    Assert-Installed C '1.0.1'
    if ([IO.File]::ReadAllText("$install\Ghidra\support\user.txt").Trim() -ne 'preserved' -or
        [IO.File]::ReadAllText("$install\Ghidra\support\fixture.txt") -ne 'new upstream fixture') {
        throw 'Changed-source upgrade did not migrate additions while installing the new upstream files'
    }
    $recovered = @(Get-ChildItem -LiteralPath "$env:LOCALAPPDATA\Ghidra Launch Recovery" -Recurse -File |
        Where-Object { $_.Name -eq 'fixture.txt' -and [IO.File]::ReadAllText($_.FullName) -eq 'edited upstream fixture' })
    if (-not $recovered.Count) { throw 'Changed-source upgrade lost edited upstream files' }
    $failedMsi = Join-Path $scratch 'failed-msi'
    New-Item -ItemType Directory -Path $failedMsi | Out-Null
    & "$root/scripts/build.ps1" -Target Native -ReleaseVersion '1.0.2'
    & "$root/scripts/build.ps1" -Target Installer -ReleaseVersion '1.0.2'
    $msiPath = Join-Path $failedMsi 'GhidraLaunchInstallerRust.msi'
    Copy-Item "$root/GhidraLaunchInstaller/bin/Release/GhidraLaunchInstallerRust.msi" $msiPath
    # Perform the Windows Installer COM edit in its own process: the STA COM
    # apartment can defer releasing its file handle well past when
    # FinalReleaseComObject/GC returns control to the caller, racing with
    # wix.exe opening the same file as a bind input below. A child process
    # exiting guarantees the OS has closed all of its handles.
    $injectProcess = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-File', "$PSScriptRoot/fixtures/inject-failing-custom-action.ps1", '-MsiPath', $msiPath
    ) -Wait -PassThru
    try {
        if ($injectProcess.ExitCode -ne 0) { throw "Failed to inject rollback-test custom action (exit $($injectProcess.ExitCode))" }
    } finally { $injectProcess.Dispose() }
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
    # This retry bundle ships the launcher MSI the failed Java stage already
    # installed, so Burn skips that package; ownership must still transfer.
    $previousOwner = (Get-ItemProperty 'HKCU:\Software\rpinz\Ghidra Launch').PayloadOwner
    Invoke-Bundle $last '/install'
    Assert-Installed Rust '1.0.3'
    if ((Get-ItemProperty 'HKCU:\Software\rpinz\Ghidra Launch').PayloadOwner -eq $previousOwner) {
        throw 'Republished bundle with an unchanged launcher MSI did not take payload ownership'
    }
    Invoke-Bundle $last '/uninstall'
    Assert-RetainedUninstall
    Invoke-Bundle $last '/install'
    Assert-Installed Rust '1.0.3'
    if ([IO.File]::ReadAllText("$install\Ghidra\support\user.txt").Trim() -ne 'preserved') {
        throw 'Reinstall into a retained tree lost user additions'
    }
    Remove-Item -LiteralPath "$install\Ghidra\support\user.txt"
    Invoke-Bundle $last '/uninstall'
    $last = $null
    if (Test-Path -LiteralPath "$install\Ghidra") { throw 'Clean uninstall left its owned Ghidra tree' }
    Assert-ForeignBundle
    Write-Host 'Legacy migration, foreign-family coexistence, preservation, and variant switching checks passed.'
    $completed = $true
} catch {
    Write-Host "Upgrade failure diagnostics: $LogRoot"
    throw
} finally {
    $foreignCleanupError = $null
    try {
        if ($foreignBundle) { Invoke-Bundle $foreignBundle '/uninstall' }
    } catch {
        if ($completed) { $foreignCleanupError = $_ }
        else { Write-Warning "Foreign fixture cleanup failed after the original upgrade error: $_" }
    }
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
        if ($foreignCleanupError) { throw $foreignCleanupError }
    }
}
