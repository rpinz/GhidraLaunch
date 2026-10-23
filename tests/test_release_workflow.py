import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/release.yml"


class ReleaseWorkflowTests(unittest.TestCase):
    def test_publish_commands_have_explicit_repository_without_checkout(self):
        workflow = WORKFLOW.read_text()
        publish = workflow.split("\n  publish:\n", 1)[1]
        step = publish.split("      - name: Publish GitHub release\n", 1)[1]
        step = step.split("\n      - ", 1)[0]
        environment = step.split("        env:\n", 1)[1].split("        run:", 1)[0]
        self.assertIn("          GH_REPO: ${{ github.repository }}\n", environment)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required")
    def test_publish_uses_created_draft_and_validates_before_publication(self):
        step = WORKFLOW.read_text().split("      - name: Publish GitHub release\n", 1)[1]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        mocks = r"""
$ErrorActionPreference = 'Stop'
$global:uploaded = @()
$global:downloads = 0
function gh {
    $global:LASTEXITCODE = 0
    $arguments = @($args)
    if ($arguments[0] -ne 'api') { throw 'Unexpected tag-based release command' }
    if ($arguments[1] -like '*/git/ref/tags/*') { return '{}' }
    if ($arguments[2] -eq 'POST' -and $arguments[3] -eq 'repos/{owner}/{repo}/releases') {
        if ($arguments -notcontains 'draft=true') { throw 'Must create a draft' }
        $expected = 'prerelease=' + ($env:RELEASE_TAG.Contains('-')).ToString().ToLowerInvariant()
        if ($arguments -notcontains $expected) { throw 'Incorrect prerelease flag' }
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
        if ($global:downloads -ne 12 -or $arguments -notcontains 'draft=false') {
            throw 'Published before validating all assets'
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
            ("upload-failure", "v1.2.3"), ("missing-asset", "v1.2.3"),
            ("corrupt-asset", "v1.2.3"),
        ):
            with self.subTest(mode=mode, tag=tag), tempfile.TemporaryDirectory() as directory:
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
                }
                result = subprocess.run(
                    ["pwsh", "-NoProfile", "-NonInteractive", "-Command", mocks + script],
                    cwd=directory, env=environment, capture_output=True, text=True,
                    timeout=30,
                )
                if mode == "success":
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("PUBLISHED_CREATED_DRAFT", result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn("PUBLISHED_CREATED_DRAFT", result.stdout)


if __name__ == "__main__":
    unittest.main()
