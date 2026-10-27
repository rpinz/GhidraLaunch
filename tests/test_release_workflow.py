import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/release.yml"
ROOT = Path(__file__).resolve().parents[1]
BUILT_COMMIT = "a" * 40


def step_script(name):
    step = WORKFLOW.read_text().split(f"      - name: {name}\n", 1)[1]
    lines = step.split("        run: |\n", 1)[1].splitlines()
    body = []
    for line in lines:
        if line and not line.startswith("          "):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body))


class ReleaseWorkflowTests(unittest.TestCase):
    def test_publish_commands_have_explicit_repository_without_checkout(self):
        workflow = WORKFLOW.read_text()
        publish = workflow.split("\n  publish:\n", 1)[1]
        step = publish.split("      - name: Publish GitHub release\n", 1)[1]
        step = step.split("\n      - ", 1)[0]
        environment = step.split("        env:\n", 1)[1].split("        run:", 1)[0]
        self.assertIn("          GH_REPO: ${{ github.repository }}\n", environment)
        self.assertNotIn("actions/checkout@", publish)
        self.assertIn("      RELEASE_COMMIT: ${{ needs.build.outputs.release_commit }}", publish)
        build = workflow.split("\n  publish:\n", 1)[0]
        self.assertIn("      release_commit: ${{ steps.release_tag.outputs.commit }}", build)
        self.assertIn("      - name: Resolve release tag\n        id: release_tag\n", build)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required")
    def test_build_exports_only_the_checked_out_peeled_tag_commit(self):
        mocks = r"""
$ErrorActionPreference = 'Stop'
function git {
    $global:LASTEXITCODE = 0
    if ($args[0] -ne 'rev-parse') { throw 'Unexpected git command' }
    if ($args[-1] -eq 'refs/tags/v1.2.3^{commit}') { return $env:EXPECTED_COMMIT }
    if ($args[-1] -eq 'HEAD') {
        if ($env:TEST_MODE -eq 'wrong-checkout') { return ('b' * 40) }
        return $env:EXPECTED_COMMIT
    }
    throw 'Tag must be peeled to a commit'
}
function Invoke-WebRequest { return @{ StatusCode = 404 } }
"""
        for mode in ("success", "wrong-checkout"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "scripts").mkdir()
                (root / "scripts/build-version.ps1").write_text(
                    "function Get-BuildVersion { param($Version) "
                    "@{ Product = $Version; File = \"$Version.0\" } }\n"
                )
                output = root / "github-output"
                environment = {
                    **os.environ, "EVENT_NAME": "push", "REF_NAME": "v1.2.3",
                    "SIGNPATH_ENABLED": "", "GITHUB_REPOSITORY": "example/project",
                    "GITHUB_OUTPUT": str(output), "GITHUB_ENV": str(root / "github-env"),
                    "EXPECTED_COMMIT": BUILT_COMMIT, "TEST_MODE": mode,
                }
                result = subprocess.run(
                    ["pwsh", "-NoProfile", "-NonInteractive", "-Command",
                     mocks + step_script("Resolve release tag")],
                    cwd=root, env=environment, capture_output=True, text=True, timeout=30,
                )
                if mode == "success":
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(output.read_text(encoding="utf-8-sig").strip(),
                                     f"commit={BUILT_COMMIT}")
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertFalse(output.exists())

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required")
    def test_publish_uses_created_draft_and_validates_before_publication(self):
        script = step_script("Publish GitHub release")
        mocks = r"""
$ErrorActionPreference = 'Stop'
$global:uploaded = @()
$global:downloads = 0
$global:tagChecks = 0
function gh {
    $global:LASTEXITCODE = 0
    $arguments = @($args)
    if ($arguments[0] -ne 'api') { throw 'Unexpected tag-based release command' }
    if ($arguments[1] -eq "repos/{owner}/{repo}/git/ref/tags/$env:RELEASE_TAG") {
        $global:tagChecks++
        if ($env:TEST_MODE -eq 'missing-tag' -or
            ($env:TEST_MODE -eq 'late-missing-tag' -and $global:tagChecks -eq 2)) {
            $global:LASTEXITCODE = 1
            return
        }
        if ($env:TEST_MODE -eq 'malformed-ref') { return '{}' }
        $sha = $env:RELEASE_COMMIT
        if ($env:TEST_MODE -eq 'moved-tag' -or
            ($env:TEST_MODE -eq 'late-moved-tag' -and $global:tagChecks -eq 2)) {
            $sha = 'b' * 40
        }
        $type = 'commit'
        if ($env:TEST_MODE -like '*annotated*') { $type = 'tag'; $sha = 'c' * 40 }
        if ($env:TEST_MODE -eq 'noncommit-tag') { $type = 'tree' }
        return ConvertTo-Json -Compress @{ object = @{ type = $type; sha = $sha } }
    }
    if ($arguments[1] -eq ('repos/{owner}/{repo}/git/tags/' + ('c' * 40))) {
        if ($env:TEST_MODE -eq 'annotated-lookup-failure') { $global:LASTEXITCODE = 1; return }
        $sha = $env:RELEASE_COMMIT
        $type = 'commit'
        if ($env:TEST_MODE -eq 'moved-annotated-tag' -or
            ($env:TEST_MODE -eq 'late-moved-annotated-tag' -and $global:tagChecks -eq 2)) {
            $sha = 'b' * 40
        }
        if ($env:TEST_MODE -eq 'nested-annotated-success') { $type = 'tag'; $sha = 'd' * 40 }
        if ($env:TEST_MODE -eq 'cyclic-annotated-tag') { $type = 'tag'; $sha = 'c' * 40 }
        return ConvertTo-Json -Compress @{ object = @{ type = $type; sha = $sha } }
    }
    if ($arguments[1] -eq ('repos/{owner}/{repo}/git/tags/' + ('d' * 40))) {
        return ConvertTo-Json -Compress @{ object = @{ type = 'commit'; sha = $env:RELEASE_COMMIT } }
    }
    if ($arguments[2] -eq 'POST' -and $arguments[3] -eq 'repos/{owner}/{repo}/releases') {
        if ($arguments -notcontains 'draft=true') { throw 'Must create a draft' }
        $expected = 'prerelease=' + ($env:RELEASE_TAG.Contains('-')).ToString().ToLowerInvariant()
        if ($arguments -notcontains $expected) { throw 'Incorrect prerelease flag' }
        if ($global:tagChecks -ne 1) { throw 'Draft created before checking built commit' }
        Write-Host 'CREATED_DRAFT'
        return '{"id":42,"draft":true,"upload_url":"https://uploads.github.com/repos/example/project/releases/42/assets{?name,label}"}'
    }
    if ($arguments[2] -eq 'POST' -and $arguments[3] -like 'https://uploads.github.com/*/releases/42/assets?name=*') {
        if ($env:TEST_MODE -eq 'upload-failure') { $global:LASTEXITCODE = 1; return }
        $name = [Uri]::UnescapeDataString(($arguments[3] -split '\?name=', 2)[1])
        $global:uploaded += @{ id = 100 + $global:uploaded.Count; name = $name }
        return '{}'
    }
    if ($arguments[1] -eq 'repos/{owner}/{repo}/releases/42/assets') {
        if ($env:TEST_MODE -eq 'missing-asset') { return '[]' }
        return ConvertTo-Json -InputObject $global:uploaded -Compress
    }
    if ($arguments[2] -eq 'PATCH' -and $arguments[3] -eq 'repos/{owner}/{repo}/releases/42') {
        if ($global:downloads -ne 12 -or $global:tagChecks -ne 2 -or $arguments -notcontains 'draft=false') {
            throw 'Published before validating all assets and rechecking the tag'
        }
        Write-Host 'PUBLISHED_CREATED_DRAFT'
        return '{}'
    }
    throw "Unexpected API call: $arguments"
}
function Invoke-WebRequest {
    param($Uri, $Headers, $OutFile)
    if ($Headers.Authorization -ne ('Bearer ' + $env:GH_TOKEN) -or $Headers.Accept -ne 'application/octet-stream') {
        throw 'Missing authenticated binary download'
    }
    $asset = @($global:uploaded | Where-Object { $Uri -eq "https://api.github.com/repos/$env:GH_REPO/releases/assets/$($_.id)" })
    if ($asset.Count -ne 1) { throw 'Downloaded an asset from another release' }
    Copy-Item -LiteralPath (Join-Path 'release-assets' $asset[0].name) -Destination $OutFile
    if ($env:TEST_MODE -eq 'corrupt-asset') { Add-Content -LiteralPath $OutFile -Value 'corrupt' }
    $global:downloads++
}
"""
        names = (
            "GhidraLaunchSetupC.exe", "GhidraLaunchSetupRust.exe",
            "GhidraLaunchInstallerC.msi", "GhidraLaunchInstallerRust.msi",
            "GhidraLaunch.spdx.json", "GhidraLaunch.cyclonedx.json",
        )
        for mode, tag in (
            ("success", "v1.2.3"), ("success", "v1.2.3-rc.1"),
            ("annotated-success", "v1.2.3"), ("nested-annotated-success", "v1.2.3"),
            ("moved-tag", "v1.2.3"), ("late-moved-tag", "v1.2.3"),
            ("moved-annotated-tag", "v1.2.3"), ("late-moved-annotated-tag", "v1.2.3"),
            ("missing-tag", "v1.2.3"), ("late-missing-tag", "v1.2.3"),
            ("annotated-lookup-failure", "v1.2.3"), ("cyclic-annotated-tag", "v1.2.3"),
            ("malformed-ref", "v1.2.3"), ("noncommit-tag", "v1.2.3"),
            ("missing-provenance", "v1.2.3"),
            ("upload-failure", "v1.2.3"), ("missing-asset", "v1.2.3"),
            ("corrupt-asset", "v1.2.3"),
        ):
            with self.subTest(mode=mode, tag=tag), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                assets = root / "release-assets"
                assets.mkdir()
                for name in names:
                    for suffix in ("", ".sigstore.json"):
                        (assets / (name + suffix)).write_bytes(bytes(range(256)))
                environment = {
                    **os.environ, "RUNNER_TEMP": directory, "RELEASE_TAG": tag,
                    "GH_REPO": "example/project", "GH_TOKEN": "test-placeholder",
                    "SIGNPATH_ENABLED": "", "TEST_MODE": mode,
                    "RELEASE_COMMIT": "" if mode == "missing-provenance" else BUILT_COMMIT,
                }
                result = subprocess.run(
                    ["pwsh", "-NoProfile", "-NonInteractive", "-Command", mocks + script],
                    cwd=directory, env=environment, capture_output=True, text=True,
                    timeout=30,
                )
                if mode in ("success", "annotated-success", "nested-annotated-success"):
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("PUBLISHED_CREATED_DRAFT", result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn("PUBLISHED_CREATED_DRAFT", result.stdout)
                    if mode.startswith("late-") or mode in ("upload-failure", "missing-asset", "corrupt-asset"):
                        self.assertIn("CREATED_DRAFT", result.stdout)
                    else:
                        self.assertNotIn("CREATED_DRAFT", result.stdout)


if __name__ == "__main__":
    unittest.main()
