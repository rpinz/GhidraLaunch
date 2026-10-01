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

The release workflow keyless-signs the setup EXE, MSI, and both SBOMs with
Sigstore/Cosign using GitHub Actions OIDC. Each asset has a matching
`.sigstore.json` verification bundle. To verify a downloaded asset against its
bundle (replace the tag and the filename as appropriate):

```sh
cosign verify-blob GhidraLaunchSetup.exe \
  --bundle GhidraLaunchSetup.exe.sigstore.json \
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

When SignPath is enabled, the workflow submits three artifacts (the launcher
and helper executables, MSI, and setup EXE) for SignPath review and waits for
approval of each request. It enforces Ghidra Launch product-name/version
metadata on the PE files, signs the launchers before packaging, verifies those
signatures in the MSI, and signs the MSI and setup EXE. Ghidra and Temurin are
upstream software and are never signed with this project's subscription.
After enrollment, verify Windows signatures in PowerShell:

```powershell
Get-AuthenticodeSignature .\GhidraLaunchSetup.exe |
  Format-List Status,SignerCertificate
Get-AuthenticodeSignature .\GhidraLaunchInstaller.msi |
  Format-List Status,SignerCertificate
```

SignPath configuration is external to the repository. Upload the XML
templates in `.signpath/artifact-configurations/` to the project's SignPath
artifact configurations, configure a signing policy with manual approval per
release and the named approvers, and set these GitHub repository variables:
`SIGNPATH_ENABLED`, `SIGNPATH_POLICY_READY`, `SIGNPATH_ORGANIZATION_ID`,
`SIGNPATH_PROJECT_SLUG`, `SIGNPATH_SIGNING_POLICY_SLUG`,
`SIGNPATH_LAUNCHERS_ARTIFACT_CONFIGURATION_SLUG`,
`SIGNPATH_MSI_ARTIFACT_CONFIGURATION_SLUG`, and
`SIGNPATH_SETUP_ARTIFACT_CONFIGURATION_SLUG`. Store the submitter token as the
`SIGNPATH_API_TOKEN` GitHub Actions secret. Set `SIGNPATH_POLICY_READY=true`
only after eligibility has been confirmed, MFA and role assignments are
complete, repository review protections are in place, and the policy above
contains the actual team members.

Before the project has any public release, a manually dispatched workflow may
publish one initial release without Authenticode by explicitly setting
`allow_unsigned_initial_release`. The workflow refuses this exception once a
public release exists. Tag-triggered releases require SignPath to be enabled.

## Releasing

Pushing a tag matching `vMAJOR.MINOR.PATCH` or
`vMAJOR.MINOR.PATCH.REVISION` (optionally with a suffix), or running the
*Build and publish signed setup bundle release* workflow manually from the
default branch with an existing `tag` input, builds that exact tag on a Windows
runner. It re-downloads and verifies Ghidra and Temurin with `download.ps1`,
signs the first-party executables in SignPath when enabled, then builds and
signs the MSI and setup EXE in order. It runs the CI checks
(`tests/launchers.ps1`, `tests/ghidra-helper.ps1`, `tests/installer.ps1`) and
generates SPDX 2.3 and CycloneDX JSON
SBOMs: they include hashes for the two published artifacts, the two launchers,
and the extraction helper, Syft's Rust lockfile dependency inventory, and
versioned URL/SHA-256 references to Ghidra and Temurin. Ghidra and Temurin are
fetched at install time, not embedded; their full component inventories are
**not** represented in these SBOMs.

After generating SBOMs, the workflow keyless-signs and verifies the four
published files, uploads them and their four bundles to a draft, checks
downloaded assets byte-for-byte, and only then publishes the release. A failed
run may leave a draft for manual inspection; re-running against an existing
release fails rather than overwriting its assets.
