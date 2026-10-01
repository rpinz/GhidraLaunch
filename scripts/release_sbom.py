#!/usr/bin/env python3
"""Generate release SBOMs from the verified inputs and final Windows artifacts."""

import argparse
import hashlib
import html
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlparse


FILES = {
    "setup": ("GhidraLaunchSetup", "GhidraLaunchSetup/bin/Release/GhidraLaunchSetup.exe"),
    "installer": ("GhidraLaunchInstaller", "GhidraLaunchInstaller/bin/Release/GhidraLaunchInstaller.msi"),
    "c": ("GhidraLaunchC", "GhidraLaunchC/x64/Release/bin/GhidraLaunchC.exe"),
    "rust": ("GhidraLaunchRS", "GhidraLaunchRS/GhidraLaunchRS.exe"),
    "helper": ("GhidraLaunchGhidraHelper", "GhidraLaunchGhidraHelper/bin/Release/net48/GhidraLaunchGhidraHelper.exe"),
}
LINKS = {
    "setup": ("installer", "helper", "ghidra", "temurin"),
    "installer": ("c", "rust"),
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def versions(path):
    text = path.read_text(encoding="utf-8-sig")
    values = {}
    for name in ("JavaVersion", "JavaDownloadUrl", "GhidraDownloadUrl"):
        match = re.search(r'<\?define ' + name + r' = "([^"]+)" \?>', text)
        if not match:
            raise ValueError(f"Missing {name} in {path}")
        values[name] = html.unescape(match.group(1))
    for name in ("JavaDownloadUrl", "GhidraDownloadUrl"):
        if urlparse(values[name]).scheme != "https":
            raise ValueError(f"{name} must use HTTPS")
    if not re.fullmatch(r"[0-9]+", values["JavaVersion"]):
        raise ValueError("Invalid JavaVersion")
    return values


def release_components(root, tag):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[0-9A-Za-z.-]+)?", tag):
        raise ValueError("Invalid release tag")
    version = tag[1:]
    files = {}
    for key, (name, relative) in FILES.items():
        path = root / relative
        files[key] = {
            "name": name,
            "version": version,
            "path": path,
            "hash": sha256(path),
            "description": "First-party release build",
        }
    metadata = versions(root / "GhidraLaunchSetup/Versions.wxi")
    ghidra_name = unquote(Path(urlparse(metadata["GhidraDownloadUrl"]).path).name)
    match = re.fullmatch(r"ghidra_(.+)_PUBLIC_[0-9]+\.zip", ghidra_name)
    if not match:
        raise ValueError(f"Unexpected Ghidra archive name: {ghidra_name}")
    jdk_name = unquote(Path(urlparse(metadata["JavaDownloadUrl"]).path).name)
    jdk_match = re.fullmatch(
        r"OpenJDK([0-9]+)U-jdk_x64_windows_hotspot_([0-9]+(?:\.[0-9]+)*)(?:_([0-9]+))?\.msi",
        jdk_name,
    )
    if not jdk_match or jdk_match.group(1) != metadata["JavaVersion"]:
        raise ValueError(f"Unexpected Temurin installer name: {jdk_name}")
    files["ghidra"] = {
        "name": "Ghidra",
        "version": match.group(1),
        "path": root / "Ghidra.zip",
        "hash": sha256(root / "Ghidra.zip"),
        "url": metadata["GhidraDownloadUrl"],
        "description": "External archive downloaded by setup at install time; not embedded",
    }
    files["temurin"] = {
        "name": "Eclipse Temurin JDK",
        "version": jdk_match.group(2) + (f"+{jdk_match.group(3)}" if jdk_match.group(3) else ""),
        "path": root / f"OpenJDK{metadata['JavaVersion']}U-jdk_x64.msi",
        "hash": sha256(root / f"OpenJDK{metadata['JavaVersion']}U-jdk_x64.msi"),
        "url": metadata["JavaDownloadUrl"],
        "description": "External installer downloaded by setup at install time; not embedded",
    }
    return files


def enrich_spdx(document, components):
    if document.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("Syft did not generate SPDX 2.3")
    ids = {key: f"SPDXRef-GhidraLaunch-{key}" for key in components}
    for key, component in components.items():
        package = {
            "SPDXID": ids[key],
            "name": component["name"],
            "versionInfo": component["version"],
            "downloadLocation": component.get("url", "NOASSERTION"),
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": component["hash"]}],
            "description": component["description"],
        }
        document["packages"].append(package)
    for key in ("setup", "installer"):
        document["relationships"].append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": ids[key],
            "relationshipType": "DESCRIBES",
        })
    for parent, children in LINKS.items():
        for child in children:
            document["relationships"].append({
                "spdxElementId": ids[parent],
                "relatedSpdxElement": ids[child],
                "relationshipType": "DEPENDS_ON",
            })
    rust = next((p for p in document["packages"] if p["name"] == "ghidra_launch"), None)
    if rust is None:
        raise ValueError("Syft did not inventory the Rust Cargo.lock")
    document["relationships"].append({
        "spdxElementId": ids["rust"],
        "relatedSpdxElement": rust["SPDXID"],
        "relationshipType": "DEPENDS_ON",
    })


def enrich_cyclonedx(document, components):
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("Syft did not generate CycloneDX")
    refs = {key: f"ghidralaunch:{key}" for key in components}
    for key, component in components.items():
        item = {
            "bom-ref": refs[key],
            "type": "file" if key in ("ghidra", "temurin") else "application",
            "name": component["name"],
            "version": component["version"],
            "description": component["description"],
            "hashes": [{"alg": "SHA-256", "content": component["hash"]}],
        }
        if "url" in component:
            item["externalReferences"] = [{"type": "distribution", "url": component["url"]}]
        document.setdefault("components", []).append(item)
    document["metadata"]["component"] = {
        "bom-ref": "ghidralaunch:release",
        "type": "application",
        "name": "GhidraLaunch",
        "version": components["setup"]["version"],
    }
    document.setdefault("dependencies", []).append({
        "ref": "ghidralaunch:release",
        "dependsOn": [refs["setup"], refs["installer"]],
    })
    rust = next((c for c in document["components"] if c["name"] == "ghidra_launch"), None)
    if rust is None:
        raise ValueError("Syft did not inventory the Rust Cargo.lock")
    for parent, children in LINKS.items():
        document.setdefault("dependencies", []).append({
            "ref": refs[parent],
            "dependsOn": [refs[child] for child in children],
        })
    document["dependencies"].append({"ref": refs["rust"], "dependsOn": [rust["bom-ref"]]})


def generate(root, output, tag, syft):
    components = release_components(root, tag)
    lock = root / "GhidraLaunchRS/Cargo.lock"
    if not lock.is_file():
        raise FileNotFoundError(lock)
    with tempfile.TemporaryDirectory(prefix="release-sbom-") as staging:
        stage = Path(staging)
        for key in FILES:
            dest = stage / components[key]["path"].relative_to(root)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(components[key]["path"], dest)
        (stage / "GhidraLaunchRS/Cargo.lock").write_bytes(lock.read_bytes())
        spdx_path = stage / "spdx.json"
        cyclonedx_path = stage / "cyclonedx.json"
        subprocess.run([
            syft, f"dir:{stage}", "--quiet",
            "--source-name", "GhidraLaunch",
            "--source-version", tag[1:],
            "--output", f"spdx-json={spdx_path}",
            "--output", f"cyclonedx-json={cyclonedx_path}",
        ], check=True)
        spdx = json.loads(spdx_path.read_text(encoding="utf-8"))
        cyclone = json.loads(cyclonedx_path.read_text(encoding="utf-8"))
        enrich_spdx(spdx, components)
        enrich_cyclonedx(cyclone, components)
    output.mkdir(parents=True, exist_ok=True)
    for name, document in (("GhidraLaunch.spdx.json", spdx), ("GhidraLaunch.cyclonedx.json", cyclone)):
        (output / name).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    validate(output, components)
    for key in ("setup", "installer"):
        dest = output / components[key]["path"].name
        shutil.copyfile(components[key]["path"], dest)
        if sha256(dest) != components[key]["hash"]:
            raise ValueError(f"Staged release asset differs from built file: {dest}")


def validate(output, components):
    spdx = json.loads((output / "GhidraLaunch.spdx.json").read_text(encoding="utf-8"))
    cyclone = json.loads((output / "GhidraLaunch.cyclonedx.json").read_text(encoding="utf-8"))
    for key, component in components.items():
        spdx_id = f"SPDXRef-GhidraLaunch-{key}"
        spdx_package = next(p for p in spdx["packages"] if p["SPDXID"] == spdx_id)
        cdx_component = next(c for c in cyclone["components"] if c["bom-ref"] == f"ghidralaunch:{key}")
        expected = sha256(component["path"])
        if expected != component["hash"]:
            raise ValueError(f"Artifact changed while generating SBOM: {component['path']}")
        if spdx_package["checksums"] != [{"algorithm": "SHA256", "checksumValue": expected}]:
            raise ValueError(f"Bad SPDX checksum for {key}")
        if cdx_component["hashes"] != [{"alg": "SHA-256", "content": expected}]:
            raise ValueError(f"Bad CycloneDX checksum for {key}")
        if "url" in component and (
            spdx_package["downloadLocation"] != component["url"]
            or cdx_component["externalReferences"][0]["url"] != component["url"]
        ):
            raise ValueError(f"Missing external reference for {key}")
    if not any(p["name"] == "windows-sys" for p in spdx["packages"]):
        raise ValueError("Rust dependencies missing from SPDX")
    if not any(c["name"] == "windows-sys" for c in cyclone["components"]):
        raise ValueError("Rust dependencies missing from CycloneDX")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=Path("release-assets"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--syft", default="syft")
    args = parser.parse_args()
    generate(args.root.resolve(), args.output.resolve(), args.tag, args.syft)


if __name__ == "__main__":
    main()
