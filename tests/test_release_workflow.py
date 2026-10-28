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
    run = step.split("        run: ", 1)[1]
    if not run.startswith("|\n"):
        return run.splitlines()[0]
    lines = step.split("        run: |\n", 1)[1].splitlines()
    body = []
    for line in lines:
        if line and not line.startswith("          "):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body))


class ReleaseWorkflowTests(unittest.TestCase):
    def test_bundle_engines_are_signed_and_reattached_before_whole_bundles(self):
        workflow = WORKFLOW.read_text()
        for stage, whole_stage, whole_handoff, whole_step, config in (
            ("internal", "Stage internal bundles for signing", "Hand off internal bundles",
             "Sign internal native bundles", "INTERNAL"),
            ("setup", "Stage setup bundle for SignPath", "Hand off setup bundle",
             "Submit setup bundle for SignPath approval and signing", "SETUP"),
        ):
            names = [
                f"Stage {stage} bundle engines for signing",
                f"Hand off {stage} bundle engines",
                f"Sign {stage} bundle engines",
                f"Reattach signed {stage} bundle engines",
                whole_stage,
                whole_handoff,
                whole_step,
            ]
            offsets = [workflow.index(f"      - name: {name}\n") for name in names]
            self.assertEqual(offsets, sorted(offsets))
            for name in names:
                step = workflow.split(f"      - name: {name}\n", 1)[1].split("\n      - ", 1)[0]
                self.assertIn("if: vars.SIGNPATH_ENABLED == 'true'", step)
            engine_step = workflow[offsets[2]:offsets[3]]
            self.assertIn(f"vars.SIGNPATH_{config}_ARTIFACT_CONFIGURATION_SLUG", engine_step)
            self.assertIn(f"steps.unsigned_{stage}_engines.outputs.artifact-id", engine_step)
            self.assertIn("-Operation Detach", step_script(names[0]))
            self.assertIn("-Operation Reattach", step_script(names[3]))

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


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required")
class BundleSigningTests(unittest.TestCase):
    MOCKS = r"""
$ErrorActionPreference = 'Stop'
function dotnet {
    $global:LASTEXITCODE = 0
    $arguments = @($args | Where-Object { $_ -ne '--' })
    if (($arguments[0..3] -join ' ') -ne 'tool run wix burn') { throw 'Unexpected tooling' }
    $operation = $arguments[4]
    $name = [IO.Path]::GetFileName($arguments[5])
    Add-Content -LiteralPath 'calls.txt' -Value "$operation`:$name"
    if ($env:TEST_MODE -eq 'tool-failure') { $global:LASTEXITCODE = 1; return }
    $engineIndex = [Array]::IndexOf($arguments, '-engine')
    if ($engineIndex -lt 0) { throw 'Missing engine path' }
    $engine = $arguments[$engineIndex + 1]
    if ($operation -eq 'detach') {
        [IO.File]::WriteAllText($engine, "engine:$name")
    } elseif ($operation -eq 'reattach') {
        if ([IO.File]::ReadAllText($engine) -ne "signed:$name") { throw 'Wrong signed engine' }
        $outputIndex = [Array]::IndexOf($arguments, '-o')
        if ($outputIndex -lt 0) { throw 'Missing reattached output' }
        [IO.File]::WriteAllText($arguments[$outputIndex + 1], "reattached:$name")
    } else { throw 'Unexpected Burn command' }
}
function Get-AuthenticodeSignature {
    param($LiteralPath)
    if ($env:TEST_MODE -eq 'invalid-signature') {
        return @{ Status = 'NotSigned'; StatusMessage = 'unsigned test engine' }
    }
    return @{ Status = 'Valid'; StatusMessage = '' }
}
& $env:TEST_SCRIPT -Operation $env:TEST_OPERATION -Stage $env:TEST_STAGE -Directory $env:TEST_DIRECTORY
"""

    def run_signing(self, root, stage, operation, mode="success"):
        environment = {
            **os.environ,
            "TEST_SCRIPT": str(root / "scripts/bundle-signing.ps1"),
            "TEST_DIRECTORY": str(root / "engines"),
            "TEST_STAGE": stage, "TEST_OPERATION": operation, "TEST_MODE": mode,
        }
        return subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", self.MOCKS],
            cwd=root, env=environment, capture_output=True, text=True, timeout=30,
        )

    def prepare(self, root, stage, signed=False):
        scripts = root / "scripts"
        scripts.mkdir()
        shutil.copyfile(ROOT / "scripts/bundle-signing.ps1", scripts / "bundle-signing.ps1")
        names = (
            ("GhidraLaunchCoreC.exe", "GhidraLaunchCoreRust.exe", "GhidraLaunchJava.exe")
            if stage == "Internal" else ("GhidraLaunchSetupC.exe", "GhidraLaunchSetupRust.exe")
        )
        bundles = root / "GhidraLaunchSetup/bin/Release"
        bundles.mkdir(parents=True)
        for name in names:
            (bundles / name).write_text(f"original:{name}")
            if signed:
                engine = root / "engines/payload" / name
                engine.parent.mkdir(parents=True, exist_ok=True)
                engine.write_text(f"signed:{name}")
        return names, bundles

    def test_detaches_and_reattaches_each_stages_signed_engines(self):
        for stage in ("Internal", "Setup"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                names, bundles = self.prepare(root, stage)
                result = self.run_signing(root, stage, "Detach")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for name in names:
                    engine = root / "engines" / name
                    self.assertEqual(engine.read_text(), f"engine:{name}")
                    engine.write_text(f"signed:{name}")
                    nested = root / "engines/payload" / name
                    nested.parent.mkdir(exist_ok=True)
                    engine.rename(nested)
                result = self.run_signing(root, stage, "Reattach")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for name in names:
                    self.assertEqual((bundles / name).read_text(), f"reattached:{name}")
                self.assertEqual(list((root / "engines").glob("*.reattached")), [])

    def test_invalid_missing_duplicate_or_failed_engines_do_not_replace_bundles(self):
        for mode in ("invalid-signature", "missing-engine", "duplicate-engine", "tool-failure"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                names, bundles = self.prepare(root, "Setup", signed=True)
                first = root / "engines/payload" / names[0]
                if mode == "missing-engine":
                    first.unlink()
                elif mode == "duplicate-engine":
                    shutil.copyfile(first, root / "engines" / names[0])
                result = self.run_signing(root, "Setup", "Reattach", mode)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                expected_error = (
                    "Invalid engine signature" if mode == "invalid-signature"
                    else "Burn engine reattachment failed" if mode == "tool-failure"
                    else "Expected one signed engine"
                )
                self.assertIn(expected_error, result.stderr)
                for name in names:
                    self.assertEqual((bundles / name).read_text(), f"original:{name}")
                self.assertEqual(list((root / "engines").glob("*.reattached")), [])

    def test_detach_tool_failure_aborts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.prepare(root, "Setup")
            result = self.run_signing(root, "Setup", "Detach", "tool-failure")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Burn engine extraction failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
