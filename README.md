# GhidraLaunch

Windows launchers for `ghidraRun.bat`, with a WiX installer and setup bundle.

## Install and launch

The setup bundle installs Temurin, Ghidra, and the launchers for you — no
manual download or extraction needed. Run the setup bundle; it downloads the
Temurin JDK installer and a Ghidra release at install time (an internet
connection is required during setup), extracts Ghidra into
`%LocalAppData%\Ghidra Launch\Ghidra`, and automatically sets the user
environment variable `GHIDRA_HOME` to that location. Sign out and back in
after installing so shortcuts started by Explorer inherit the new variable.
The Temurin MSI installs machine-wide and therefore requires administrator
approval. The setup helper targets .NET Framework 4.8, which must be present
on Windows before installation.

Both launchers use `GHIDRA_HOME` when set; if it is unset or empty they
instead look for `ghidraRun.bat` next to the launcher executable (this
fallback does not apply to a fresh MSI installation, since the MSI only
installs the launchers and sets `GHIDRA_HOME`). If you previously set
`GHIDRA_HOME` to a different Ghidra install, running this setup will
overwrite it to point at the bundled copy.

**Uninstalling** removes the extracted Ghidra folder along with the
launchers, including any extensions, scripts, or other files you placed
inside it — back up anything you want to keep from that folder first. Ghidra
project files stored elsewhere in your profile are not affected.

## Build

Use Visual Studio 2022 with the Desktop development with C++ workload, the
Windows SDK, and Rust's `x86_64-pc-windows-msvc` target. Open
`GhidraLaunch.sln` and build the x64 Debug or Release configuration. The Rust
project uses `cargo build --locked`; commit `GhidraLaunchRS/Cargo.lock` when
updating dependencies. Visual Studio Rebuild cleans and rebuilds the Rust
launcher.

The installer projects additionally require WiX Toolset v3.11 or newer v3
build tools. Run `download.sh` (Bash, curl, jq, unzip) or `download.ps1` to
download and checksum-verify the Ghidra release and Temurin installer, and to
record their resolved download URLs in `GhidraLaunchSetup/Versions.wxi`. The
setup bundle does not embed these files; instead it re-downloads them from
those recorded URLs at install time, using the size/hash of the locally
verified copies to validate what it fetches. CI checks both launch paths,
builds the small `GhidraLaunchGhidraHelper` extraction helper and exercises
it against a synthetic fixture, and builds the launcher MSI to verify its
layout and `GHIDRA_HOME` setup, all without downloading third-party
installers.

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

## Releasing

Pushing a tag matching `vMAJOR.MINOR.PATCH` or
`vMAJOR.MINOR.PATCH.REVISION` (optionally with a suffix), or running the *Build and draft setup bundle
release* workflow manually with a `tag` input) builds the launchers, the MSI,
and the setup bundle on a Windows runner, re-downloading and verifying Ghidra
and Temurin the same way `download.ps1` does locally, then runs the same
checks as CI (`tests/launchers.ps1`, `tests/ghidra-helper.ps1`,
`tests/installer.ps1`). It publishes the results as a **draft** GitHub
release containing `GhidraLaunchSetup.exe` and `GhidraLaunchInstaller.msi` —
drafts are not visible to regular users, because these build artifacts are
unsigned. Before publishing the draft, download both assets, sign them per
[Signing releases](#signing-releases), replace the draft's assets with the
signed versions, then publish the release.
