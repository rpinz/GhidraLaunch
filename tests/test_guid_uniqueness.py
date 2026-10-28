import re
import unittest
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUID = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
# Where a GUID gives something its identity, as opposed to referring to it.
DEFINITIONS = [
    re.compile(rf"<ProjectGuid>\{{?({GUID})\}}?</ProjectGuid>"),
    re.compile(rf"SolutionGuid\s*=\s*\{{({GUID})\}}"),
    re.compile(rf"UpgradeCode\s*=\s*\"\{{?({GUID})\}}?\""),
    re.compile(rf"<Component\b[^>]*\bGuid=\"\{{?({GUID})\}}?\""),
    re.compile(rf"define\s+\w*Guid\s*=\s*\"\{{?({GUID})\}}?\""),
]
# Identity GUIDs owned by the sibling HostsEditor project (projects, solution, MSI and bundle
# upgrade codes). Reusing any of them would make the two products' installations interfere.
HOSTS_EDITOR = {
    "8E71980B-7C18-4939-8073-20A75FE78B26",
    "2AEC9C0F-C26C-456D-AB3E-71BCD228009C",
    "EE7ABA7F-03E4-4469-9044-73B58A78081E",
    "809660D6-D2F9-4623-9901-31833887C113",
    "23A10499-750E-4F7E-8825-32AA6B459D83",
    "92A00B0C-F753-4B99-BBAD-D514CD0E34BC",
    "010DA19B-D22F-4E30-BFB4-0F8A7B121698",
}
SOURCES = ("*.sln", "*.vcxproj", "*.wixproj", "*.props", "*.targets", "*.wxs", "*.wxi",
           "*.c", "*.h", "*.rc", "*.rs", "*.ps1", "*.py", "*.yml", "*.xml")
SKIPPED = {"target", "obj", "bin", "vendor", ".git", ".vs", "__pycache__"}


def sources():
    for pattern in SOURCES:
        for path in ROOT.rglob(pattern):
            relative = path.relative_to(ROOT)
            if not SKIPPED.intersection(relative.parts) and relative.parts[:2] != ("tests", "fixtures"):
                yield relative, path.read_text(encoding="utf-8", errors="replace")


class GuidUniquenessTests(unittest.TestCase):
    def test_production_identity_guids_are_defined_once(self):
        # Test fixtures intentionally reuse production identities to model upgrades.
        sites = defaultdict(list)
        for relative, text in sources():
            for pattern in DEFINITIONS:
                for match in pattern.finditer(text):
                    sites[match.group(1).upper()].append(str(relative))
        # 4 projects, the solution, 4 upgrade codes and 7 components; guards against a parser regression
        self.assertGreaterEqual(len(sites), 16)
        duplicates = {guid: places for guid, places in sites.items() if len(places) > 1}
        self.assertEqual(duplicates, {})

    def test_no_hosts_editor_identity_guid_is_reused(self):
        reused = sorted(
            f"{relative}: {match.group(0)}"
            for relative, text in sources()
            for match in re.finditer(GUID, text)
            if match.group(0).upper() in HOSTS_EDITOR and relative.name != Path(__file__).name
        )
        self.assertEqual(reused, [])


if __name__ == "__main__":
    unittest.main()
