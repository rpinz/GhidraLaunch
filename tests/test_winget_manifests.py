import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import winget_manifests  # noqa: E402


class WingetManifestTests(unittest.TestCase):
    def generate(self, tag):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        assets = Path(temp.name) / "assets"
        assets.mkdir()
        for variant in winget_manifests.VARIANTS:
            (assets / f"GhidraLaunchSetup{variant}.exe").write_bytes(variant.encode())
        out = Path(temp.name) / "out"
        winget_manifests.main(["--tag", tag, "--assets", str(assets), "--output", str(out)])
        return out

    def test_stable_tag_renders_both_variants_with_hash_and_url(self):
        out = self.generate("v1.2.3")
        for variant in winget_manifests.VARIANTS:
            folder = out / f"rpinz.GhidraLaunch{variant}" / "1.2.3"
            self.assertEqual(3, len(list(folder.glob("*.yaml"))))
            installer = (folder / f"rpinz.GhidraLaunch{variant}.installer.yaml").read_text()
            digest = hashlib.sha256(variant.encode()).hexdigest().upper()
            self.assertIn(f"InstallerSha256: {digest}", installer)
            self.assertIn(
                f"/releases/download/v1.2.3/GhidraLaunchSetup{variant}.exe", installer)
            self.assertIn("InstallerType: burn", installer)
            for path in folder.glob("*.yaml"):
                self.assertNotIn("{{", path.read_text())

    def test_prerelease_tag_is_skipped(self):
        self.assertFalse((self.generate("v1.2.3-rc1") / "rpinz.GhidraLaunchC").exists())


if __name__ == "__main__":
    unittest.main()
