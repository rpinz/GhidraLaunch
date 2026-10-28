import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/build-version.ps1"


class WixBuildParameterTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is required")
    def test_property_changes_invalidate_packaging_without_rebuilding_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = ET.Element("Project", DefaultTargets="Build")
            properties = ET.SubElement(project, "PropertyGroup")
            ET.SubElement(properties, "IntermediateOutputPath").text = "obj/"
            ET.SubElement(properties, "DefineConstants").text = "Version=$(ReleaseVersion);Payload=$(PayloadRoot)"
            ET.SubElement(project, "Import", Project=str(SCRIPT.parents[1] / "Directory.Build.targets"))
            compile_target = ET.SubElement(project, "Target", Name="CoreCompile", Inputs="@(Content)", Outputs="result.txt")
            ET.SubElement(compile_target, "WriteLinesToFile", File="result.txt", Lines="$(DefineConstants)", Overwrite="true")
            ET.SubElement(project, "Target", Name="Build", DependsOnTargets="CoreCompile")
            path = root / "fixture.wixproj"
            ET.ElementTree(project).write(path, encoding="utf-8")
            previous = None
            for version, payload, unchanged in (
                ("1.0.0", "first", False), ("1.0.0", "first", True),
                ("1.0.1", "first", False), ("1.0.1", "second", False),
            ):
                result = subprocess.run(
                    ["dotnet", "msbuild", str(path), "/nologo", "/verbosity:quiet",
                     f"/p:ReleaseVersion={version}", f"/p:PayloadRoot={payload}"],
                    cwd=root, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                output = root / "result.txt"
                self.assertEqual(output.read_text().splitlines(), [f"Version={version}", f"Payload={payload}"])
                if unchanged:
                    self.assertEqual(output.stat().st_mtime_ns, previous)
                previous = output.stat().st_mtime_ns


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required")
class BuildVersionTests(unittest.TestCase):
    def powershell(self, script):
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command",
             "$ErrorActionPreference = 'Stop'; . '" +
             str(SCRIPT).replace("'", "''") + "'; " + script],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_stamps_all_version_fields_without_touching_unchanged_header(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "Resources/Version.h"
            header.parent.mkdir()
            header.write_text("old header\n")
            data = self.powershell(r"""
$root = '""" + str(root).replace("'", "''") + r"""'
$version = Get-BuildVersion '01.2.3.4'
Set-NativeVersion $root $version
$path = Join-Path $root 'Resources/Version.h'
[IO.File]::SetLastWriteTimeUtc($path, [datetime]'2020-01-01')
Set-NativeVersion $root $version
@{
    product = $version.Product
    file = $version.File
    timestamp = [IO.File]::GetLastWriteTimeUtc($path).Year
} | ConvertTo-Json
""")
            self.assertEqual(data, {"product": "1.2.3", "file": "1.2.3.4", "timestamp": 2020})
            content = header.read_text()
            self.assertIn('#define GHIDRA_LAUNCH_VERSION "1.2.3.4"', content)
            self.assertIn('#define GHIDRA_LAUNCH_FILEVERSION 1,2,3,4', content)
            self.assertIn('#define GHIDRA_LAUNCH_PRODUCT_VERSION "1.2.3"', content)

    def test_rejects_invalid_or_out_of_range_versions(self):
        rejected = self.powershell(r"""
$rejected = @()
foreach ($value in @('1.2', 'v1.2.3', '1.2.3-rc.1', '1.2.3.4.5', '256.0.0', '1.2.3.256')) {
    try { $null = Get-BuildVersion $value }
    catch { $rejected += $value }
}
ConvertTo-Json -InputObject $rejected
""")
        self.assertEqual(len(rejected), 6)

    def test_rejects_stale_native_inputs_but_accepts_bundle_version_format(self):
        data = self.powershell(r"""
function Get-Item {
    param($LiteralPath)
    $product, $file = $LiteralPath.Split('/')
    [pscustomobject]@{ VersionInfo = [pscustomobject]@{
        ProductName = 'Ghidra Launch'; ProductVersion = $product; FileVersion = $file
    } }
}
$version = Get-BuildVersion '1.2.3'
Assert-ExecutableVersion '1.2.3/1.2.3.0' $version -Native
Assert-ExecutableVersion '1.2.3.0/1.2.3.0' $version
$rejected = @()
foreach ($path in @('0.0.0/0.0.0.0', '1.2.3/1.2.3.1')) {
    try { Assert-ExecutableVersion $path $version -Native }
    catch { $rejected += $path }
}
ConvertTo-Json -InputObject $rejected
""")
        self.assertEqual(data, ["0.0.0/0.0.0.0", "1.2.3/1.2.3.1"])

    def test_msi_gate_checks_packaged_native_revision_and_variant(self):
        data = self.powershell(r"""
$script:fileVersion = '1.2.3.4'
$script:variant = 'C'
$script:inspections = 0
function Get-MsiProperties {
    param($Path)
    @{ ProductName = 'Ghidra Launch'; ProductVersion = '1.2.3'; GHIDRALAUNCHVARIANT = $script:variant }
}
function Invoke-WithMsiContents {
    param($Path, $Action)
    $script:inspections++
    & $Action 'packaged'
}
function Get-Item {
    param($LiteralPath)
    [pscustomobject]@{ VersionInfo = [pscustomobject]@{
        ProductName = 'Ghidra Launch'; ProductVersion = '1.2.3'; FileVersion = $script:fileVersion
    } }
}
$version = Get-BuildVersion '1.2.3.4'
Assert-MsiVersion 'fixture.msi' $version C
$rejected = @()
$script:fileVersion = '1.2.3.3'
try { Assert-MsiVersion 'fixture.msi' $version C } catch { $rejected += 'revision' }
$script:fileVersion = '1.2.3.4'
$script:variant = 'Rust'
try { Assert-MsiVersion 'fixture.msi' $version C } catch { $rejected += 'variant' }
@{ rejected = $rejected; inspections = $script:inspections } | ConvertTo-Json
""")
        self.assertEqual(data, {"rejected": ["revision", "variant"], "inspections": 2})

    def test_core_gate_checks_packaged_revisions_artifacts_and_upstream_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.powershell(r"""
$root = '""" + str(Path(directory)).replace("'", "''") + r"""'
$null = New-Item -ItemType Directory -Path "$root/embedded"
Set-Content "$root/embedded/GhidraLaunchInstallerC.msi" 'msi'
Set-Content "$root/embedded/GhidraLaunchGhidraHelperC.exe" 'helper'
Copy-Item "$root/embedded/GhidraLaunchInstallerC.msi" "$root/expected.msi"
Copy-Item "$root/embedded/GhidraLaunchGhidraHelperC.exe" "$root/expected.exe"
Set-Content "$root/Ghidra.zip" 'verified upstream'
$hash = (Get-FileHash "$root/Ghidra.zip" -Algorithm SHA512).Hash
$size = (Get-Item "$root/Ghidra.zip").Length
$script:manifest = [xml]('<BurnManifest><Registration Version="1.2.3" Tag="C"/><Payload FilePath="Ghidra.zip" Packaging="external" DownloadUrl="https://example.invalid/Ghidra.zip" FileSize="' + $size + '" Hash="' + $hash + '"/></BurnManifest>')
$script:oldMsi = $false
$script:oldHelper = $false
function Invoke-WithBundleContents {
    param($Path, $Action)
    & $Action $script:manifest "$root/embedded"
}
function Get-UpstreamBuildMetadata {
    param($VersionsFile)
    @{ GhidraDownloadUrl = 'https://example.invalid/Ghidra.zip' }
}
function Assert-MsiVersion {
    param($Path, $Version, $Variant)
    if ($script:oldMsi) { throw 'Packaged launcher has an old fourth revision' }
}
function Assert-ExecutableVersion {
    param($Path, $Version, [switch]$Native)
    if ($Native -and $script:oldHelper) { throw 'Packaged helper has an old fourth revision' }
}
function Check-Core {
    Assert-InternalBundle 'core.exe' (Get-BuildVersion '1.2.3.4') Core C "$root/expected.msi" "$root/expected.exe" $root 'Versions.wxi'
}
Check-Core
$rejected = @()
$script:oldMsi = $true
try { Check-Core } catch { $rejected += 'launcher' }
$script:oldMsi = $false
$script:oldHelper = $true
try { Check-Core } catch { $rejected += 'helper' }
$script:oldHelper = $false
Set-Content "$root/expected.msi" 'different signed MSI'
try { Check-Core } catch { $rejected += 'artifact' }
Copy-Item "$root/embedded/GhidraLaunchInstallerC.msi" "$root/expected.msi" -Force
$script:manifest.BurnManifest.Payload.DownloadUrl = 'https://example.invalid/stale.zip'
try { Check-Core } catch { $rejected += 'url' }
$script:manifest.BurnManifest.Payload.DownloadUrl = 'https://example.invalid/Ghidra.zip'
Set-Content "$root/Ghidra.zip" 'changed upstream'
try { Check-Core } catch { $rejected += 'payload' }
ConvertTo-Json -InputObject $rejected
""")
            self.assertEqual(data, ["launcher", "helper", "artifact", "url", "payload"])

    def test_migration_is_after_completed_core_in_parent_rollback_boundary(self):
        root = SCRIPT.parents[1]
        text = (root / "GhidraLaunchSetup/Bundle.wxs").read_text()
        setup = text.split("<?if $(var.Stage) = Setup ?>", 1)[1].split("<?elseif", 1)[0]
        core = text.split("<?elseif $(var.Stage) = Core ?>", 1)[1].split("<?else?>", 1)[0]
        self.assertLess(setup.index('Id="Core$(var.Variant)"'), setup.index('Id="PayloadCommitted"'))
        self.assertLess(setup.index('Id="PayloadCommitted"'), setup.index('Id="LegacyGhidra$(var.Variant)"'))
        self.assertLess(setup.index('Id="LegacyGhidra$(var.Variant)"'), setup.index('Id="Java"'))
        self.assertIn('"$(var.CoreProviderKey)" "$(var.ReleaseVersion)"', setup)
        self.assertIn('Permanent="yes" Vital="yes"', setup)
        self.assertNotIn('migrate-legacy', core)
        lifecycle = (root / "tests/upgrades.ps1").read_text()
        self.assertIn("-FailUninstall", lifecycle)
        self.assertIn("Migration failure rolled back the committed incoming installation", lifecycle)

    def test_upgrade_cleanup_preserves_original_error_logs_and_native_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.powershell(r"""
$WarningPreference = 'SilentlyContinue'
$root = '""" + str(Path(directory)).replace("'", "''") + r"""'
$scratch = Join-Path $root 'failed-fixture'
$backup = Join-Path $scratch 'native-inputs'
$logs = Join-Path $root 'upgrade-logs'
$null = New-Item -ItemType Directory -Path $backup, $logs, "$root/Resources"
$originals = @('Resources/Version.h', 'launcher.exe')
foreach ($path in $originals) {
    Set-Content -LiteralPath (Join-Path $root $path) -Value 'test version'
    Set-Content -LiteralPath (Join-Path $backup (Split-Path $path -Leaf)) -Value 'original version'
}
Set-Content "$logs/burn.log" 'failure evidence'
function Invoke-Bundle { throw 'Cleanup failure' }
$last = 'failed-bundle'
$completed = $false
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '""" + str(SCRIPT.parents[1] / "tests/upgrades.ps1").replace("'", "''") + r"""',
    [ref]$tokens, [ref]$errors)
$try = $ast.EndBlock.Statements |
    Where-Object { $_ -is [System.Management.Automation.Language.TryStatementAst] } |
    Select-Object -Last 1
$code = "try { throw 'Original upgrade failure' } finally " + $try.Finally.Extent.Text
$message = ''
try { & ([scriptblock]::Create($code)) }
catch { $message = $_.Exception.Message }
@{
    error = $message
    header = (Get-Content "$root/Resources/Version.h" -Raw).Trim()
    executable = (Get-Content "$root/launcher.exe" -Raw).Trim()
    logs = Test-Path "$logs/burn.log"
    fixture = Test-Path $scratch
} | ConvertTo-Json
""")
            self.assertEqual(data, {
                "error": "Original upgrade failure", "header": "original version",
                "executable": "original version", "logs": True, "fixture": True,
            })


if __name__ == "__main__":
    unittest.main()
