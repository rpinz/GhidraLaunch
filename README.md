# GhidraLaunch

Windows launchers for `ghidraRun.bat`, with a WiX installer and setup bundle.

## Install and launch

Ghidra is a **separate prerequisite**: the setup bundle installs Temurin and
the launchers, **not Ghidra**. Download a Ghidra release from
[the official releases](https://github.com/NationalSecurityAgency/ghidra/releases)
and extract it to a permanent location. Set the user environment variable
`GHIDRA_HOME` to the extracted directory **containing `ghidraRun.bat`** (for
example, `C:\Tools\ghidra_11.4_PUBLIC`, not its parent directory). From
PowerShell, substitute your actual extracted directory:

```powershell
[Environment]::SetEnvironmentVariable('GHIDRA_HOME', 'C:\Tools\ghidra_11.4_PUBLIC', 'User')
$env:GHIDRA_HOME = 'C:\Tools\ghidra_11.4_PUBLIC'
```

Run the setup bundle, then start Ghidra Launch from the Start menu or desktop.
Sign out and back in after setting the user variable so shortcuts started by
Explorer inherit it (the second PowerShell command only affects that shell).
Both launchers use `GHIDRA_HOME` when set; if it is unset or empty they instead
look for `ghidraRun.bat` next to the launcher executable. The MSI installs only
the launchers in Local AppData, so this fallback does not apply to a fresh MSI
installation. If you move Ghidra, update `GHIDRA_HOME` accordingly.

## Build

Use Visual Studio 2022 with the Desktop development with C++ workload, the
Windows SDK, and Rust's `x86_64-pc-windows-msvc` target. Open
`GhidraLaunch.sln` and build the x64 Debug or Release configuration. The Rust
project uses `cargo build --locked`; commit `GhidraLaunchRS/Cargo.lock` when
updating dependencies. Visual Studio Rebuild cleans and rebuilds the Rust
launcher.

The installer projects additionally require WiX Toolset v3.11 or newer v3
build tools. Run `download.sh` from a shell with Bash, curl, jq, and unzip to
obtain the Ghidra release (to determine the required Java version) and Temurin
files needed to build the setup bundle; downloading Ghidra does not install it
for setup users. The CI workflow
builds and rebuilds the launchers on Windows in both configurations; it does
not assemble the installer or download third-party binaries.

## Signing releases

Builds from this repository are **not signed**. Before distributing a release,
use an authorized code-signing certificate and Windows SDK `signtool.exe` to
sign the C and Rust launcher executables, then the built MSI, then the final
setup bundle. For example, with the certificate installed in your certificate
store:

```powershell
signtool sign /sha1 <certificate-thumbprint> /fd SHA256 /tr <trusted-timestamp-url> /td SHA256 <path-to-artifact>
signtool verify /pa /v <path-to-artifact>
```

Repeat signing and verification for each artifact in that order. Keep private
keys out of the repository and CI; do not publish unsigned release artifacts.
