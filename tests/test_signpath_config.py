import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / ".signpath" / "artifact-configurations"
NAMESPACE = {"s": "http://signpath.io/artifact-configuration/v1"}


class SignPathConfigurationTests(unittest.TestCase):
    def load(self, name):
        return ET.parse(CONFIG_DIR / name).getroot()

    def test_first_party_executables_enforce_product_metadata(self):
        root = self.load("launchers.xml")
        files = root.findall(".//s:pe-file", NAMESPACE)
        self.assertEqual(
            [file.attrib["path"] for file in files],
            [
                "GhidraLaunchC.exe",
                "GhidraLaunchRS.exe",
                "GhidraLaunchGhidraHelperC.exe",
                "GhidraLaunchGhidraHelperRS.exe",
            ],
        )
        for file in files:
            self.assertEqual(file.attrib["product-name"], "Ghidra Launch")
            self.assertEqual(file.attrib["product-version"], "${version}")
            self.assertIsNotNone(file.find("s:authenticode-sign", NAMESPACE))

    def test_msi_verifies_embedded_executables_and_signs_package(self):
        root = self.load("installer.xml")
        packages = root.findall(".//s:msi-file", NAMESPACE)
        self.assertEqual([p.attrib["path"] for p in packages],
                         ["GhidraLaunchInstallerC.msi", "GhidraLaunchInstallerRust.msi"])
        for msi, launcher in zip(packages, ["GhidraLaunchC.exe", "GhidraLaunchRS.exe"]):
            self.assertEqual(msi.attrib["subject"], "Ghidra Launch")
            self.assertEqual(msi.attrib["author"], "rpinz")
            executable_set = msi.find("s:pe-file-set", NAMESPACE)
            self.assertEqual(executable_set.attrib["product-name"], "Ghidra Launch")
            self.assertEqual(executable_set.attrib["product-version"], "${version}")
            self.assertEqual(
                [item.attrib["path"] for item in executable_set.findall("s:include", NAMESPACE)],
                [launcher],
            )
            self.assertIsNotNone(executable_set.find(".//s:authenticode-verify", NAMESPACE))
            self.assertIsNotNone(msi.find("s:authenticode-sign", NAMESPACE))

    def test_setup_bundle_enforces_product_metadata(self):
        root = self.load("setup.xml")
        setups = root.findall(".//s:pe-file", NAMESPACE)
        self.assertEqual([s.attrib["path"] for s in setups],
                         ["GhidraLaunchSetupC.exe", "GhidraLaunchSetupRust.exe"])
        for setup in setups:
            self.assertEqual(setup.attrib["product-name"], "Ghidra Launch")
            self.assertEqual(setup.attrib["product-version"], "${version}")
            self.assertIsNotNone(setup.find("s:authenticode-sign", NAMESPACE))

    def test_internal_bundles_enforce_product_metadata(self):
        root = self.load("internal.xml")
        bundles = root.findall(".//s:pe-file", NAMESPACE)
        self.assertEqual([b.attrib["path"] for b in bundles],
                         ["GhidraLaunchCoreC.exe", "GhidraLaunchCoreRust.exe", "GhidraLaunchJava.exe"])
        for bundle in bundles:
            self.assertEqual(bundle.attrib["product-name"], "Ghidra Launch")
            self.assertEqual(bundle.attrib["product-version"], "${version}")
            self.assertIsNotNone(bundle.find("s:authenticode-sign", NAMESPACE))


if __name__ == "__main__":
    unittest.main()
