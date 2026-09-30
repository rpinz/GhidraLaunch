# GhidraLaunch

Windows launchers for `ghidraRun.bat`, with a WiX installer and setup bundle.

## Build

Use Visual Studio 2022 with the Desktop development with C++ workload, the
Windows SDK, and Rust's `x86_64-pc-windows-msvc` target. Open
`GhidraLaunch.sln` and build the x64 Debug or Release configuration. The Rust
project uses `cargo build --locked`; commit `GhidraLaunchRS/Cargo.lock` when
updating dependencies. Visual Studio Rebuild cleans and rebuilds the Rust
launcher.

The installer projects additionally require WiX Toolset v3.11 or newer v3
build tools. Run `download.sh` from a shell with Bash, curl, jq, and unzip to
obtain the Ghidra and Temurin files needed by the setup bundle. The CI workflow
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
