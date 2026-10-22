# GhidraLaunch

Windows x64 launchers for `ghidraRun.bat`, with matched C and Rust distributions
built using WiX v5.

## Install and launch

Choose one variant; both provide the same functionality:

| Variant | Complete setup | Launcher-only MSI |
|---|---|---|
| C | `GhidraLaunchSetupC.exe` | `GhidraLaunchInstallerC.msi` |
| Rust | `GhidraLaunchSetupRust.exe` | `GhidraLaunchInstallerRust.msi` |

Each setup contains its matching native launcher and extraction helper. The
variants replace one another rather than installing side by side, including
switching variants at the same release version. Both use the existing
installation folder. An embedded native core retains the legacy upgrade family
to migrate older combined installations.

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
Setup first installs the native core and completes any legacy bundle removal,
then runs a separate native Java stage with fresh detection. This prevents old
cached uninstallers from removing Java after setup has checked it. The core is
committed before the Java stage: if Java installation fails, setup reports the
error and retains Ghidra and the launcher; rerun setup to retry Java. The setup
and its embedded stages are WiX native bootstrapper applications, not managed
helpers or an external extraction dependency.

Both launchers use `GHIDRA_HOME` when set; if it is unset or empty they
instead look for `ghidraRun.bat` next to the launcher executable (this
fallback does not apply to a fresh MSI installation, since the MSI only
installs the selected launcher and sets `GHIDRA_HOME`). If you previously set
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
projects. The Rust helper has its own checked-in
`GhidraLaunchGhidraHelperRS/Cargo.lock`; its ZIP/SHA-256 dependencies are
independent of the launcher.

Installer builds additionally require the .NET 8 SDK and restored WiX **5.0.2**
SDK/extensions. Run `dotnet tool restore` for the pinned WiX CLI; no globally
installed WiX v3 tools are used. .NET is a build prerequisite only.
Run `download.sh` (Bash, curl, jq, unzip) or `download.ps1` to
download and checksum-verify the Ghidra release and Temurin installer, and to
record their resolved download URLs in `GhidraLaunchSetup/Versions.wxi`. The
setup bundle does not embed these files; instead it re-downloads them from
those recorded URLs at install time, using the size/hash of the locally
verified copies to validate what it fetches.

From a PowerShell prompt with the prerequisites installed:

```powershell
dotnet tool restore
./scripts/build.ps1 -Target Native -Configuration Release
./scripts/build.ps1 -Target Installer -ReleaseVersion 1.2.3
./scripts/build.ps1 -Target Internal -ReleaseVersion 1.2.3
./scripts/build.ps1 -Target Setup -ReleaseVersion 1.2.3
```

The packaging commands consume already-built inputs without rebuilding them,
preserving signatures. Use the same version for both packaging commands.
MSIs are written to `GhidraLaunchInstaller/bin/Release/` and setup EXEs to
`GhidraLaunchSetup/bin/Release/`. The solution's Release build also includes
both installer pairs; Debug builds the four native executables.

CI checks both launchers and helpers in Debug/Release, shared extraction and
ownership fixtures, both MSI layouts, built bundle payloads, and same-version/
newer-version switching using synthetic upstream packages. The legacy migration
test downloads checksum-pinned WiX v3 tools and compiles a frozen managed helper
fixture solely to exercise the old cached-uninstaller behavior; neither is part
of production builds or distributed installers. CI does not download Ghidra or
Temurin for these checks. Actual install/uninstall tests are restricted to
isolated Windows CI profiles.

The synthetic upstream MSI is machine-wide, like Temurin, and upgrade checks
verify it survives bundle replacement. WiX warns that per-user bundles cannot
register dependencies on machine-wide packages, so native bundles deliberately
mark Temurin permanent. Legacy cleanup completes in the core stage before the
Java stage performs its own fresh detection/install.

### Native helper contract

Both helpers accept case-insensitive commands and return 0 for success (including
a logged source/ownership-mismatch removal skip), 1 for an operation failure,
and 2 for invalid usage:

```text
extract <zipPath> <destDir> [owner]
remove <destDir> [zipPath] [owner]
```

Extraction strips a single top-level directory, stages beside the destination,
and records the ZIP's SHA-256 in `.ghidralaunch-source.sha256`. An unchanged ZIP
preserves existing contents. Failed extraction must leave the previous tree
intact. Unsafe Windows archive paths and links are rejected.

Standalone extraction uses the legacy plain-hash marker. Setup supplies an
owner token (its unique Burn provider key), recorded as a second
`owner=...` line. Adopting an unchanged ZIP updates ownership without extracting
again. Owner-aware removal requires matching ownership and source hash; calls
without an owner skip owned trees. The older managed helper also skips these
extended markers, preventing an outgoing legacy bundle from removing the
incoming installation. Native helpers accept each other's markers and legacy
plain-hash markers. The C helper statically links vendored miniz (see its
provenance/license files); the Rust helper uses locked ZIP and SHA-256 crates.

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

When SignPath is enabled, the workflow submits four artifacts (the launcher
and helper executables, both MSIs, the three internal native bundles, and both
public setup EXEs) for SignPath review and waits for
approval of each request. It enforces Ghidra Launch product-name/version
metadata on the PE files, signs the launchers before packaging, verifies those
signatures in the MSI, then signs internal bundles before embedding them into
the final signed setup EXEs. Ghidra and Temurin are
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
both extraction helpers, the three internal bundles, Syft's inventories of both Rust lockfiles, the
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
release fails rather than overwriting its assets.
