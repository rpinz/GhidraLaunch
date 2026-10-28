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
        (self.root / SBOM.RUST_LOCKFILE).write_bytes((SCRIPT.parents[1] / SBOM.RUST_LOCKFILE).read_bytes())
        vendor = self.root / "GhidraLaunchGhidraHelperC/vendor/miniz"
        vendor.mkdir(parents=True)
        (vendor / "miniz.c").write_bytes(b"fixture")
        (vendor / "provenance.json").write_text(json.dumps({
            "name": "miniz", "version": "3.1.0", "url": "https://example.org/miniz",
            "license": "MIT", "files": {"miniz.c": SBOM.sha256(vendor / "miniz.c")},
        }))
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
            if key in SBOM.PUBLISHED:
                self.assertEqual((self.output / component["path"].name).read_bytes(), component["path"].read_bytes())
        self.assertEqual(
            next(p for p in spdx["packages"] if p["SPDXID"] == "SPDXRef-GhidraLaunch-temurin")["downloadLocation"],
            "https://example.org/OpenJDK21U-jdk_x64_windows_hotspot_21.0.8_9.msi?a=1&b=2",
        )
        self.assertEqual(next(c for c in cdx["components"] if c["bom-ref"] == "ghidralaunch:temurin")["version"], "21.0.8+9")
        self.assertTrue(any(p["name"] == "windows-sys" for p in spdx["packages"]))
        self.assertTrue(any(c["name"] == "windows-sys" for c in cdx["components"]))
        self.assertIn(
            {"ref": "ghidralaunch:setup-c", "dependsOn": [
                "ghidralaunch:core-c", "ghidralaunch:helper-c", "ghidralaunch:java"
            ]},
            cdx["dependencies"],
        )
        for parent, children in SBOM.LINKS.items():
            self.assertIn({
                "ref": f"ghidralaunch:{parent}",
                "dependsOn": [f"ghidralaunch:{child}" for child in children],
            }, cdx["dependencies"])
        self.assertTrue(any(p["name"] == "ghidra_launch_helper" for p in spdx["packages"]))
        # One workspace lockfile still keeps each variant's dependencies separate.
        names = {p["SPDXID"]: p["name"] for p in spdx["packages"]}
        dependencies = {
            (names.get(r["relatedSpdxElement"]), names.get(r["spdxElementId"]))
            for r in spdx["relationships"] if r["relationshipType"] == "DEPENDENCY_OF"
        }
        self.assertIn(("ghidra_launch_helper", "zip"), dependencies)
        self.assertIn(("ghidra_launch", "windows-sys"), dependencies)
        self.assertNotIn(("ghidra_launch", "zip"), dependencies)
        self.assertEqual(
            next(c for c in cdx["components"] if c["bom-ref"] == "ghidralaunch:miniz")["licenses"],
            [{"license": {"id": "MIT"}}],
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
        next(c for c in document["components"] if c["bom-ref"] == "ghidralaunch:setup-c")["hashes"][0]["content"] = "0" * 64
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "Bad CycloneDX checksum"):
            SBOM.validate(self.output, SBOM.release_components(self.root, "v1.2.3"))

    def test_missing_release_input_fails(self):
        (self.root / "OpenJDK21U-jdk_x64.msi").unlink()
        with self.assertRaises(FileNotFoundError):
            SBOM.generate(self.root, self.output, "v1.2.3", os.environ.get("SYFT_CMD", "syft"))

    def test_changed_vendored_source_fails_provenance_validation(self):
        (self.root / "GhidraLaunchGhidraHelperC/vendor/miniz/miniz.c").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "differs from provenance"):
            SBOM.release_components(self.root, "v1.2.3")


class VendoredMinizTests(unittest.TestCase):
    """Guard the checked out bytes, which release_components hashes at release
    time. Upstream mixes line endings, so a clone that translates them silently
    breaks provenance long after the change that would have to fix it."""

    VENDOR = SCRIPT.parents[1] / "GhidraLaunchGhidraHelperC/vendor/miniz"

    def setUp(self):
        self.expected = json.loads((self.VENDOR / "provenance.json").read_text(encoding="utf-8"))["files"]

    def test_working_tree_matches_recorded_upstream_hashes(self):
        for relative, expected in self.expected.items():
            with self.subTest(file=relative):
                self.assertEqual(SBOM.sha256(self.VENDOR / relative), expected)

    def test_checksum_file_matches_provenance(self):
        listed = (self.VENDOR / "SHA256SUMS").read_text(encoding="utf-8").split()
        self.assertEqual(dict(zip(listed[1::2], listed[0::2])), self.expected)


if __name__ == "__main__":
    unittest.main()
