import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/release_sbom.py"
SPEC = importlib.util.spec_from_file_location("release_sbom", SCRIPT)
SBOM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SBOM)


class ReleaseSbomTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "release-assets"
        for key, (_, relative) in SBOM.FILES.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("fixture-" + key).encode())
        lock = self.root / "GhidraLaunchRS/Cargo.lock"
        lock.write_bytes((SCRIPT.parents[1] / "GhidraLaunchRS/Cargo.lock").read_bytes())
        (self.root / "Ghidra.zip").write_bytes(b"ghidra archive fixture")
        (self.root / "OpenJDK21U-jdk_x64.msi").write_bytes(b"temurin installer fixture")
        (self.root / "GhidraLaunchSetup/Versions.wxi").write_text(
            '<?define JavaVersion = "21" ?>\n'
            '<?define JavaDownloadUrl = "https://example.org/OpenJDK21U-jdk_x64_windows_hotspot_21.0.8_9.msi?a=1&amp;b=2" ?>\n'
            '<?define GhidraDownloadUrl = "https://example.org/ghidra_12.1_PUBLIC_20260930.zip" ?>\n'
        )

    def test_both_formats_cover_artifacts_dependencies_and_external_downloads(self):
        SBOM.generate(self.root, self.output, "v1.2.3", os.environ.get("SYFT_CMD", "syft"))
        spdx = json.loads((self.output / "GhidraLaunch.spdx.json").read_text())
        cdx = json.loads((self.output / "GhidraLaunch.cyclonedx.json").read_text())
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertEqual(cdx["bomFormat"], "CycloneDX")
        self.assertEqual(cdx["metadata"]["component"]["bom-ref"], "ghidralaunch:release")
        for key, component in SBOM.release_components(self.root, "v1.2.3").items():
            spdx_package = next(p for p in spdx["packages"] if p["SPDXID"] == f"SPDXRef-GhidraLaunch-{key}")
            cdx_component = next(c for c in cdx["components"] if c["bom-ref"] == f"ghidralaunch:{key}")
            self.assertEqual(spdx_package["checksums"][0]["checksumValue"], component["hash"])
            self.assertEqual(cdx_component["hashes"][0]["content"], component["hash"])
            if key in ("setup", "installer"):
                self.assertEqual((self.output / component["path"].name).read_bytes(), component["path"].read_bytes())
        self.assertEqual(
            next(p for p in spdx["packages"] if p["SPDXID"] == "SPDXRef-GhidraLaunch-temurin")["downloadLocation"],
            "https://example.org/OpenJDK21U-jdk_x64_windows_hotspot_21.0.8_9.msi?a=1&b=2",
        )
        self.assertEqual(next(c for c in cdx["components"] if c["bom-ref"] == "ghidralaunch:temurin")["version"], "21.0.8+9")
        self.assertTrue(any(p["name"] == "windows-sys" for p in spdx["packages"]))
        self.assertTrue(any(c["name"] == "windows-sys" for c in cdx["components"]))
        self.assertIn(
            {"ref": "ghidralaunch:setup", "dependsOn": [
                "ghidralaunch:installer", "ghidralaunch:helper", "ghidralaunch:ghidra", "ghidralaunch:temurin"
            ]},
            cdx["dependencies"],
        )

    def test_changed_file_invalidates_generated_sbom(self):
        SBOM.generate(self.root, self.output, "v1.2.3", os.environ.get("SYFT_CMD", "syft"))
        components = SBOM.release_components(self.root, "v1.2.3")
        (self.root / "Ghidra.zip").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "Artifact changed"):
            SBOM.validate(self.output, components)

    def test_modified_sbom_hash_fails(self):
        SBOM.generate(self.root, self.output, "v1.2.3", os.environ.get("SYFT_CMD", "syft"))
        path = self.output / "GhidraLaunch.cyclonedx.json"
        document = json.loads(path.read_text())
        next(c for c in document["components"] if c["bom-ref"] == "ghidralaunch:setup")["hashes"][0]["content"] = "0" * 64
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "Bad CycloneDX checksum"):
            SBOM.validate(self.output, SBOM.release_components(self.root, "v1.2.3"))

    def test_missing_release_input_fails(self):
        (self.root / "OpenJDK21U-jdk_x64.msi").unlink()
        with self.assertRaises(FileNotFoundError):
            SBOM.generate(self.root, self.output, "v1.2.3", os.environ.get("SYFT_CMD", "syft"))


if __name__ == "__main__":
    unittest.main()
