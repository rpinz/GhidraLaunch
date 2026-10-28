# GhidraLaunch

Windows 10 version 1809 or newer / Windows 11 x64 launchers for `ghidraRun.bat`, with matched C and Rust distributions
built using WiX v5.

The selected Ghidra and Temurin releases may impose newer platform requirements.

## Install and launch

Choose one variant; both provide the same functionality:

| Variant | Complete setup | Launcher-only MSI |
|---|---|---|
| C | `GhidraLaunchSetupC.exe` | `GhidraLaunchInstallerC.msi` |
| Rust | `GhidraLaunchSetupRust.exe` | `GhidraLaunchInstallerRust.msi` |

Each setup contains its matching native launcher and extraction helper. The
variants replace one another rather than installing side by side, including
switching variants at the same release version. Both use the existing
installation folder. The embedded native core has a Ghidra-specific upgrade
family. Its native helper migrates older combined installations only when their
registered product name, publisher, and legacy family all identify Ghidra Launch;
unrelated applications that reused the old family are left alone.

The setup bundle installs Temurin, Ghidra, and the selected launcher for you — no
manual download or extraction needed. Run the setup bundle; it downloads the
Temurin JDK installer and a Ghidra release at install time (an internet
connection is required during setup), extracts Ghidra into
`%LocalAppData%\Ghidra Launch\Ghidra`, and automatically sets the user
environment variable `GHIDRA_HOME` to that location. Sign out and back in
after installing so shortcuts started by Explorer inherit the new variable.
The Temurin MSI installs machine-wide and therefore requires administrator
approval. Neither native helper requires .NET or an external ZIP extraction
tool on the installing machine.
Temurin is a shared prerequisite and is retained when uninstalling or switching
native variants; remove it separately through Windows Installed apps if needed.
Setup first commits the launcher and Ghidra Core, then performs identity-filtered
legacy cleanup before a separate native Java stage with fresh detection. This
prevents old cached uninstallers from removing Java after setup has checked it.
If cleanup or Java installation fails, setup reports the error and retains
Ghidra and the launcher; rerun setup to retry. The setup
and its embedded stages are WiX native bootstrapper applications, not managed
helpers or an external extraction dependency.

While setup runs, its progress page names the step in progress — acquiring and
installing "Ghidra Launch and Ghidra files", "Finishing legacy Ghidra migration",
then "Java runtime (Eclipse
Temurin)". Running an MSI directly reports its own steps ("Copying new files",
"Creating shortcuts", "Removing the previous version", and so on) rather than
listing individual files.

Both launchers use `GHIDRA_HOME` when set; if it is unset or empty they
instead look for `ghidraRun.bat` next to the launcher executable (this
fallback does not apply to a fresh MSI installation, since the MSI only
installs the selected launcher and sets `GHIDRA_HOME`). If you previously set
`GHIDRA_HOME` to a different Ghidra install, running this setup will
overwrite it to point at the bundled copy.

The launchers start Ghidra directly, without `cmd.exe`, following the same
steps as `ghidraRun.bat` and `support\launch.bat`: they run Ghidra's
`LaunchSupport` to choose a supported JDK and read `launch.properties` (JVM
arguments and environment variables), honour `GHIDRA_MAXMEM`,
`GHIDRA_GUI_MAXMEM`, `GHIDRA_JAVA_OPTIONS`, `GHIDRA_GUI_JAVA_OPTIONS` and
`JAVA_HOME`, forward command-line arguments (including through batch fallback), and start `javaw.exe` with no
console window. Java is found on `PATH`, then `JAVA_HOME`. If the folder is not
a packaged Ghidra (for example a source checkout), Java cannot be started
this way, or the path contains `!`, the launcher falls back to running
`ghidraRun.bat`.

If a packaged Ghidra cannot select a supported JDK, the launcher reports an
actionable error rather than running an invisible interactive prompt. Set
`JAVA_HOME` to a supported 64-bit JDK and restart the launcher, or run
`ghidraRun.bat` from a command prompt to use Ghidra's manual JDK selection.

**Upgrading** carries forward added files that do not conflict with the new
upstream tree. Edited upstream files and conflicting additions are preserved
under `%LOCALAPPDATA%\Ghidra Launch Recovery`; the newly installed tree uses the
new upstream versions. If an older installation cannot be classified safely,
its complete previous tree is retained there instead. Recovery copies are not
automatically deleted. Carried-forward extensions may still need updating for
compatibility with the new Ghidra release.

**Uninstalling** removes a clean, unchanged Ghidra tree. If files were added,
edited, or deleted, or its inventory cannot be verified, the entire Ghidra
folder is retained and its path is reported. The launcher, shortcuts and active
installation registration are still removed. These preservation rules also
apply to standalone helper commands. Reinstalling into a retained tree uses the
same preservation policy. Ghidra project files elsewhere in your profile are
not affected.

## WinGet

Each stable release (`vX.Y.Z[.W]`) produces WinGet manifests for the two
setup bundles as the `winget-manifests` workflow artifact:
`rpinz.GhidraLaunchC` and `rpinz.GhidraLaunchRust`. They use the setup EXE as
a `burn` installer (silent switches `/quiet /norestart`; Temurin still asks for
administrator approval). Templates are in `winget/templates`; render them locally
with `python scripts/winget_manifests.py --tag vX.Y.Z` after building the
setup bundles. Test with
`winget install --manifest <folder>` (requires
`winget settings --enable LocalManifestFiles`), then submit the folder to
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) manually.
The bundles are not yet Authenticode-signed, so SmartScreen may warn and
WinGet moderators may object until signing is enabled. Publishing is not
automated; the hash is taken from the final (post-signing) bundles.

## Build

Use Visual Studio 2022 with the Desktop development with C++ workload, the
Windows SDK, and Rust's `x86_64-pc-windows-msvc` target. The shared
`rust-toolchain.toml` pins Rust 1.99.1 with rustfmt and Clippy; restore it with
`rustup toolchain install 1.99.1 --profile minimal --component rustfmt --component clippy`.
Use rustup's `cargo` (`%USERPROFILE%\.cargo\bin` first on `PATH`); a standalone Rust
install ignores `rust-toolchain.toml`.
Open
`GhidraLaunch.sln` and build the x64 Debug or Release configuration. Both Rust
crates are members of one Cargo workspace (root `Cargo.toml`) with a single
checked-in `Cargo.lock`, shared release profile, lints and rustflags
(`.cargo/config.toml`); Cargo builds into the root `target/` with `--locked`, so
commit `Cargo.lock` when updating dependencies. Visual Studio Clean/Rebuild cleans
only the selected Rust package before rebuilding it. Native outputs are per
configuration: `GhidraLaunchC/x64/<Configuration>/bin/GhidraLaunchC.exe`,
`GhidraLaunchRS/bin/<Configuration>/GhidraLaunchRS.exe` and the matching helper
paths; each Rust executable is copied there with its PDB. The helper's ZIP/SHA-256
dependencies are not linked into the launcher.

From the repository root, check the Rust workspace with:

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check   # cargo install cargo-deny --locked; policy in deny.toml
```

All four executables link the CRT statically, are built with Control Flow Guard,
CET shadow-stack compatibility and System32-only DLL loading, and embed an
application manifest (`Resources/application.manifest` for the launchers,
`Resources/helper.manifest` for the helpers: `asInvoker`, Windows 10/11
supportedOS, long-path aware). C projects build at `/W4 /WX` with static analysis
(`/analyze`; SDK headers are treated as external), `/utf-8`, `/ZH:SHA_256`, and
reproducible Release output (`/Brepro`); vendored miniz builds at `/W3` without
analysis. CI checks every executable with `dumpbin` for Control Flow Guard, CET
compatibility and the absence of dynamic-CRT imports, and runs `cargo deny`.
The Rust crates use edition 2024, Clippy's pedantic group, overflow checks in
Release, and require a `// SAFETY:` comment on every `unsafe` block
(`clippy::undocumented_unsafe_blocks`).

WiX builds treat warnings (including ICE validation) as errors
(`Directory.Build.props`); the intentional ICE61/69/80/91 exceptions are listed
with their reasons in `GhidraLaunchInstaller/Installer.props`.

Installer builds additionally require the .NET 8 SDK and restored WiX **5.0.2**
SDK/extensions (SDK version pinned once in `global.json`). Run `dotnet tool restore` for the pinned WiX CLI; no globally
installed WiX v3 tools are used. .NET is a build prerequisite only.
All bundle stages (Setup, Core, Java) share one source,
`GhidraLaunchSetup/Bundle.wxs`; the per-variant `.wixproj` files only pick the
`Variant` (`C` or `Rust`, C by default) and `Stage`.
Run `download.sh` (Bash, curl, jq, unzip) or `download.ps1` to
download and checksum-verify the Ghidra release and Temurin installer, and to
record their resolved download URLs in `GhidraLaunchSetup/Versions.wxi`. The
setup bundle does not embed these files; instead it re-downloads them from
those recorded URLs at install time, using the size/hash of the locally
verified copies to validate what it fetches.

From a PowerShell prompt with the prerequisites installed:

```powershell
dotnet tool restore
./scripts/build.ps1 -Target Native -Configuration Release -ReleaseVersion 1.2.3
./scripts/build.ps1 -Target Installer -ReleaseVersion 1.2.3
./scripts/build.ps1 -Target Internal -ReleaseVersion 1.2.3
./scripts/build.ps1 -Target Setup -ReleaseVersion 1.2.3
```

The Native command stamps the shared version resource before compilation and
checks all four executable versions. Use the same `ReleaseVersion` for every
stage (default `0.0.0`; an optional fourth component sets the native file revision,
while MSI/bundle product versions use the first three components).
The packaging commands consume already-built inputs without rebuilding them,
preserving signatures, and reject prerequisite artifacts with mismatched versions.
WiX tracks build-time version and payload parameters as inputs, so changing them
also invalidates incremental builds without rebuilding signed prerequisites.
MSIs are written to `GhidraLaunchInstaller/bin/Release/` and setup EXEs to
`GhidraLaunchSetup/bin/Release/`. The solution's Release build also includes
both installer pairs; Debug builds the four native executables.

CI checks both launchers and helpers in Debug/Release, shared extraction and
ownership fixtures, both MSI layouts, built bundle payloads, and same-version/
newer-version switching using synthetic upstream packages. A separate test-only C
executable exercises backup, install, rollback and cleanup failures; it is never
packaged. Build it locally with `./scripts/build.ps1 -Target Faults`.
Build/version, signing, SBOM and publication contract tests also run before
release in ordinary CI. `tests/test_guid_uniqueness.py` fails if a production
identity GUID (project, upgrade code, component) is defined twice or reuses one of
the sibling HostsEditor project's GUIDs. The legacy migration
test downloads checksum-pinned WiX v3 tools and compiles a frozen managed helper
fixture solely to exercise the old cached-uninstaller behavior; neither is part
of production builds or distributed installers. CI does not download Ghidra or
Temurin for these checks. Actual install/uninstall tests are restricted to
isolated Windows CI profiles. The legacy fixture includes both launchers and
both shortcuts and tests older and equal-version migration into each variant.
Upgrade tests temporarily build versioned native inputs and restore the original
executables and version header before release packaging/signing.
On failure, Burn/MSI logs are retained in the runner's `upgrade-logs` directory
and uploaded by both build and release workflows; failed fixtures are retained
on the runner. Cleanup failures do not replace the original test error.

The synthetic upstream MSI is machine-wide, like Temurin, and upgrade checks
verify it survives bundle replacement. WiX warns that per-user bundles cannot
register dependencies on machine-wide packages, so native bundles deliberately
mark Temurin permanent. Legacy cleanup completes in Setup after Core commits and
before the Java stage performs its own fresh detection/install.

The Core chain installs the launcher and extracts/adopts its payload. Setup
commits that Core across a rollback boundary before running identity-filtered
legacy cleanup with the built Core's provider key. A failed cleanup cannot
roll back the committed Core. During each cached legacy uninstaller,
the native helper temporarily relocates the incoming Ghidra tree and restores it
afterwards, so older helpers cannot delete it. Installer regression fixtures
include a higher-version unrelated bundle sharing the ambiguous legacy family.

### Native helper contract

Extraction and removal accept case-insensitive commands and return 0 for success (including
logged retention, source/ownership-mismatch skips, or postcommit cleanup warnings), 1 for an operation failure,
and 2 for invalid usage:

```text
extract <zipPath> <destDir> [owner]
remove <destDir> [zipPath] [owner]
```

Setup also uses the private `migrate-legacy <destDir> <owner> <releaseVersion>`
command. It only targets verified Ghidra Launch registrations and the managed
destination. A successful migration can additionally return 3010 when a legacy
uninstaller requests a restart.

Extraction strips a single top-level directory, stages beside the destination,
and records the ZIP's SHA-256 in `.ghidralaunch-source.sha256`. Both helpers
share a versioned `.ghidralaunch-inventory` of upstream file hashes and
directories; it distinguishes customizations without treating existing user
edits as the new baseline. An unchanged ZIP preserves existing contents.
Failed precommit extraction or ownership recording restores the previous tree;
a postcommit cleanup failure reports the remaining backup without reverting
the consistently owned new installation. That cleanup-only warning returns
success so Burn does not roll back an already committed launcher installation.
Unsafe Windows archive paths and
links are rejected. Both helpers decode UTF-8-flagged and legacy CP437 ZIP names.

Standalone extraction uses the legacy plain-hash marker. The native Core supplies
an owner token (its unique Burn provider key), recorded as a second
`owner=...` line. Adopting an unchanged ZIP updates ownership without replacing
existing contents; legacy installations without an inventory first derive one
from the validated source archive. Owner-aware removal requires matching ownership and source hash; calls
without an owner skip owned trees. The older managed helper also skips these
extended markers, preventing an outgoing legacy bundle from removing the
incoming installation. Native helpers accept each other's markers and legacy
plain-hash markers. The C helper statically links vendored miniz (see its
provenance/license files); the Rust helper uses locked ZIP and SHA-256 crates.

Setup detects ownership through `HKCU\Software\rpinz\Ghidra Launch`'s
`PayloadOwner`. The helper is the only package that runs whenever ownership
changes - Burn skips an already installed launcher MSI when a republished
bundle ships the identical package - so an owner-aware helper call maintains
that value alongside the marker: it records the owner after extraction or
adoption, and retracts it when a matching owner removes or intentionally retains
the tree during uninstall. The record
describes `%LOCALAPPDATA%\Ghidra Launch\Ghidra`, so helper runs against any
other destination leave it untouched.

## Code signing policy

**Status:** SignPath Foundation enrollment is not yet confirmed, and the
required project role roster has not yet been supplied. Do not enable SignPath
signing until SignPath confirms this project's eligibility, all team members
have MFA enabled for SignPath and GitHub, role members are published below,
and the complete policy is visible here.

When accepted and enabled: **Free code signing provided by
[SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org).** SignPath must first confirm
that this project's use of Ghidra, a reverse-engineering framework, meets its
eligibility conditions. The signing team must be the team responsible for
developing and maintaining this repository. All team members must use MFA for
SignPath and GitHub. Publish names or public group links for each role before
enabling signing, and require review for every change from a non-committer:

- **Authors / Committers:** trusted to modify the repository without
  additional review — TBD
- **Reviewers:** review changes proposed by non-committers — TBD
- **Approvers:** approve every release signing request — TBD

This program will not transfer any information to other networked systems
unless specifically requested by the user or the person installing or
operating it. The setup program downloads Ghidra and Temurin from their
respective project distribution URLs when the operator runs setup. It does
not send user data to those services; as with any download, the distribution
providers receive ordinary connection metadata such as the requester's IP
address. See [GitHub's Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement)
and the [Eclipse Foundation Privacy Policy](https://www.eclipse.org/legal/privacy/)
for the upstream distribution services. Setup changes the per-user
`GHIDRA_HOME` environment variable, and the Temurin MSI installs
machine-wide; see [Install and launch](#install-and-launch) for the effects
and uninstall behavior.

## Signing releases

The release workflow keyless-signs both setup EXEs, both MSIs, and both SBOMs with
Sigstore/Cosign using GitHub Actions OIDC. Each asset has a matching
`.sigstore.json` verification bundle. To verify a downloaded asset against its
bundle (replace the tag and the filename as appropriate):

```sh
cosign verify-blob GhidraLaunchSetupC.exe \
  --bundle GhidraLaunchSetupC.exe.sigstore.json \
  --certificate-identity "https://github.com/rpinz/GhidraLaunch/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

For manually dispatched releases, the signing workflow identity ends in
`@refs/heads/<default-branch>` instead of the release tag; the workflow only
accepts dispatches from that branch and still builds the selected tag. Check
the expected identity in the release's workflow run rather than accepting an
arbitrary certificate identity. A valid bundle proves the file was signed by
the specified workflow identity, not that Windows trusts its publisher. This
is separate from Authenticode.

When SignPath is enabled, the workflow submits six artifacts (the launcher
and helper executables, both MSIs, internal bundle engines, complete internal
bundles, public setup engines, and complete public setups) for SignPath review
and waits for approval of each request. It enforces Ghidra Launch product-name/version
metadata on the PE files, signs the launchers before packaging, verifies those
signatures in the MSI, then signs internal bundles before embedding them into
the final signed setup EXEs. Each bundle's Burn engine is detached, signed,
and reattached before the complete bundle is signed, so cached repair,
uninstall, and elevated engines retain their signatures. The engine requests
reuse the corresponding internal/setup artifact configurations and filenames.
Bundle signing requests each allow 30 minutes for approval; the executable and
MSI requests each allow 60 minutes. Ghidra and Temurin are
upstream software and are never signed with this project's subscription.
After enrollment, verify Windows signatures in PowerShell:

```powershell
Get-AuthenticodeSignature .\GhidraLaunchSetupC.exe |
  Format-List Status,SignerCertificate
Get-AuthenticodeSignature .\GhidraLaunchInstallerC.msi |
  Format-List Status,SignerCertificate
```

SignPath configuration is external to the repository. Upload the XML
templates in `.signpath/artifact-configurations/` to the project's SignPath
artifact configurations, configure a signing policy with manual approval per
release and the named approvers, and set these GitHub repository variables.
Update the externally stored templates to match both variants before enabling
signing; existing single-installer templates are not interchangeable:
`SIGNPATH_ENABLED`, `SIGNPATH_POLICY_READY`, `SIGNPATH_ORGANIZATION_ID`,
`SIGNPATH_PROJECT_SLUG`, `SIGNPATH_SIGNING_POLICY_SLUG`,
`SIGNPATH_LAUNCHERS_ARTIFACT_CONFIGURATION_SLUG`,
`SIGNPATH_MSI_ARTIFACT_CONFIGURATION_SLUG`,
`SIGNPATH_INTERNAL_ARTIFACT_CONFIGURATION_SLUG`, and
`SIGNPATH_SETUP_ARTIFACT_CONFIGURATION_SLUG`. Store the submitter token as the
`SIGNPATH_API_TOKEN` GitHub Actions secret. Set `SIGNPATH_POLICY_READY=true`
only after eligibility has been confirmed, MFA and role assignments are
complete, repository review protections are in place, and the policy above
contains the actual team members.

Authenticode signing is optional. Until SignPath is enabled, both tag-triggered
and manually dispatched releases can be published without Authenticode; the
published assets and SBOMs are still keyless-signed with Sigstore. Enabling
SignPath adds Authenticode signatures but is not required to publish releases.

## Releasing

Pushing a tag matching `vMAJOR.MINOR.PATCH` or
`vMAJOR.MINOR.PATCH.REVISION` (optionally with a suffix), or running the
*Build and publish setup bundle release* workflow manually from the
default branch with an existing `tag` input, builds that exact tag on a Windows
runner. It re-downloads and verifies Ghidra and Temurin with `download.ps1`,
signs the four first-party executables in SignPath when enabled, then builds
both MSIs, the native core/Java bundles, and public setup EXEs in signing order.
It runs the checks
(`tests/launchers.ps1`, `tests/ghidra-helper.ps1`, `tests/installer.ps1`) and
generates SPDX 2.3 and CycloneDX JSON
SBOMs: they include hashes for all four installer artifacts, the two launchers,
both extraction helpers, the three internal bundles, Syft's inventory of the Rust workspace lockfile
(each Rust executable linked to its own package), the
vendored C ZIP library's version/license/source provenance, and
versioned URL/SHA-256 references to Ghidra and Temurin. Ghidra and Temurin are
fetched at install time, not embedded; their full component inventories are
**not** represented in these SBOMs.

The dependency graphs distinguish the C and Rust distributions; neither MSI
claims to include the other variant's launcher.

After generating SBOMs, the workflow keyless-signs and verifies the six
published files, uploads them and their six verification bundles to a draft, checks
downloaded assets byte-for-byte, and only then publishes the release. A failed
run may leave a draft for manual inspection; re-running against an existing
release fails rather than overwriting its assets. Publication also verifies that
the release tag still resolves to the exact commit built, including annotated
tags, before creating the draft and before making it public.
