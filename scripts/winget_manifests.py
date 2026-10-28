"""Render WinGet manifests for the setup bundles of a release.

The hash is read from the final setup executables, so run this after any
Authenticode signing has replaced the unsigned bundles.
"""
import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "winget" / "templates"
VARIANTS = ("C", "Rust")
TAG = re.compile(r"^v(\d+\.\d+\.\d+(?:\.\d+)?)$")
URL = "https://github.com/{repo}/releases/download/{tag}/GhidraLaunchSetup{variant}.exe"


def render(variant, version, url, sha256):
    values = {
        "Variant": variant, "Version": version,
        "DisplayVersion": ".".join(version.split(".")[:3]),
        "InstallerUrl": url, "InstallerSha256": sha256,
    }
    files = {}
    for template in sorted(TEMPLATES.glob("Package*.yaml")):
        text = template.read_text(encoding="utf-8")
        for key, value in values.items():
            text = text.replace("{{" + key + "}}", value)
        name = template.name.replace("Package", f"rpinz.GhidraLaunch{variant}", 1)
        files[name] = text
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", default="rpinz/GhidraLaunch")
    parser.add_argument("--assets", type=Path, default=ROOT / "GhidraLaunchSetup" / "bin" / "Release")
    parser.add_argument("--output", type=Path, default=ROOT / "winget" / "out")
    args = parser.parse_args(argv)

    match = TAG.match(args.tag)
    if not match:
        print(f"Skipping WinGet manifests: {args.tag} is not a stable vX.Y.Z[.W] tag")
        return 0
    version = match.group(1)
    for variant in VARIANTS:
        exe = args.assets / f"GhidraLaunchSetup{variant}.exe"
        sha256 = hashlib.sha256(exe.read_bytes()).hexdigest().upper()
        url = URL.format(repo=args.repo, tag=args.tag, variant=variant)
        folder = args.output / f"rpinz.GhidraLaunch{variant}" / version
        folder.mkdir(parents=True, exist_ok=True)
        for name, text in render(variant, version, url, sha256).items():
            (folder / name).write_text(text, encoding="utf-8", newline="\n")
        print(f"Wrote {folder}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
