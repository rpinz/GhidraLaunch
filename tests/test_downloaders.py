"""Offline contracts: execute the real scripts with only HTTP transport mocked."""

import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
GHIDRA_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
GHIDRA_URL = 'https://fixtures.invalid/ghidra.zip?a=1&b=<value>"quoted"'
JDK_URL = 'https://fixtures.invalid/temurin.msi?a=1&b=<jdk>"quoted"'
ASSET_NAME = "ghidra_12.0_PUBLIC_20261027.zip"
OLD_ZIP = b"previous verified archive"
OLD_MSI = b"previous verified installer"


def jdk_api(java):
    return (
        f"https://api.adoptium.net/v3/assets/latest/{java}/hotspot"
        "?architecture=x64&image_type=jdk&os=windows&vendor=eclipse"
    )


def fixture(java="25"):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(
            zipfile.ZipInfo("ghidra_current/Ghidra/application.properties"),
            f"application.java.min= {java} \r\napplication.java.max=99\r\n",
        )
    payload = archive.getvalue()
    msi = bytes(range(256)) + b"offline MSI fixture"
    return {
        "java": java,
        "zip": payload,
        "msi": msi,
        "release": {
            "assets": [{
                "name": ASSET_NAME, "browser_download_url": GHIDRA_URL,
                "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
            }],
            "body": "",
        },
        "jdk": [{"binary": {"installer": {
            "link": JDK_URL, "checksum": hashlib.sha256(msi).hexdigest(),
        }}}],
        "fail": set(),
    }


def set_archive(data, properties=None, entry="ghidra_current/Ghidra/application.properties"):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        if properties is not None:
            bundle.writestr(zipfile.ZipInfo(entry), properties)
    data["zip"] = archive.getvalue()
    data["release"]["assets"][0]["digest"] = "sha256:" + hashlib.sha256(data["zip"]).hexdigest()


def git_bash():
    if os.name != "nt":
        return shutil.which("bash")
    candidates = []
    git = shutil.which("git")
    if git:
        candidates.append(Path(git).parent.parent / "bin/bash.exe")
    for location in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        if os.environ.get(location):
            base = Path(os.environ[location])
            candidates.extend((base / "Git/bin/bash.exe", base / "Programs/Git/bin/bash.exe"))
    return next((str(path) for path in candidates if path.is_file()), None)


POWERSHELL_MOCKS = r"""
$ErrorActionPreference = 'Stop'
$global:fixtureRoutes = Get-Content -LiteralPath 'routes.json' -Raw | ConvertFrom-Json
function Get-FixtureRoute {
    param([string]$Uri)
    Add-Content -LiteralPath 'requests.txt' -Value $Uri -Encoding utf8
    $route = @($global:fixtureRoutes | Where-Object { $_.url -ceq $Uri })
    if ($route.Count -ne 1) {
        Write-Host "UNEXPECTED_REQUEST: $Uri"
        throw 'No offline route'
    }
    return $route[0]
}
function Invoke-RestMethod {
    param([string]$Uri, $Headers)
    $route = Get-FixtureRoute $Uri
    if ($route.fail) { throw 'Fixture metadata request failed' }
    Get-Content -LiteralPath $route.path -Raw -Encoding utf8 | ConvertFrom-Json
}
function Invoke-WebRequest {
    [CmdletBinding()]
    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing)
    $route = Get-FixtureRoute $Uri
    if ($route.fail) {
        Set-Content -LiteralPath $OutFile -Value 'partial download' -NoNewline
        throw 'Fixture download failed'
    }
    Copy-Item -LiteralPath $route.path -Destination $OutFile
}
& (Join-Path $PSScriptRoot 'download.ps1')
exit $LASTEXITCODE
"""

BASH_MOCK = r"""
curl() {
  local url="" output=""
  while (($#)); do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --header) shift 2 ;;
      --silent|--show-error|--fail|--location) shift ;;
      *) url="$1"; shift ;;
    esac
  done
  printf '%s\n' "$url" >> requests.txt
  case "$url" in
"""


class DownloadContract:
    def run_fixture(self, data, stage="success"):
        with tempfile.TemporaryDirectory(prefix="downloader-fixture-", dir=ROOT) as directory:
            root = Path(directory)
            shutil.copyfile(ROOT / self.script, root / self.script)
            setup = root / "GhidraLaunchSetup"
            setup.mkdir()
            versions = setup / "Versions.wxi"
            versions.write_text("stale success metadata")
            (root / "Ghidra.zip").write_bytes(OLD_ZIP)
            msi = root / f"OpenJDK{data['java']}U-jdk_x64.msi"
            msi.write_bytes(OLD_MSI)
            (root / "release.json").write_text(json.dumps(data["release"]), encoding="utf-8")
            (root / "jdk.json").write_text(json.dumps(data["jdk"]), encoding="utf-8")
            (root / "payload.zip").write_bytes(data["zip"])
            (root / "payload.msi").write_bytes(data["msi"])
            routes = [
                {"url": url, "path": path, "fail": url in data["fail"]}
                for url, path in (
                    (GHIDRA_API, "release.json"), (jdk_api(data["java"]), "jdk.json"),
                    (GHIDRA_URL, "payload.zip"), (JDK_URL, "payload.msi"),
                )
            ]
            (root / "routes.json").write_text(json.dumps(routes), encoding="utf-8")
            command = self.runner(root, routes)
            environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            environment.pop("BASH_ENV", None)
            result = subprocess.run(
                command, cwd=root, env=environment, capture_output=True,
                encoding="utf-8", errors="replace", timeout=30,
            )
            output = result.stdout + result.stderr
            self.assertNotIn("UNEXPECTED_REQUEST", output)
            if stage == "success":
                self.assertEqual(result.returncode, 0, output)
                xml_escape = lambda value: escape(value, {'"': "&quot;"})
                self.assertEqual(
                    versions.read_text(encoding="utf-8-sig"),
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<Include xmlns="http://wixtoolset.org/schemas/v4/wxs">\n'
                    f'  <?define JavaVersion = "{data["java"]}" ?>\n'
                    f'  <?define JavaDownloadUrl = "{xml_escape(JDK_URL)}" ?>\n'
                    f'  <?define GhidraDownloadUrl = "{xml_escape(GHIDRA_URL)}" ?>\n'
                    '</Include>\n',
                )
            else:
                self.assertNotEqual(result.returncode, 0, output)
                self.assertFalse(versions.exists(), output)
            expected_requests = [GHIDRA_API]
            if stage != "release":
                expected_requests.append(GHIDRA_URL)
            if stage in ("jdk-metadata", "jdk", "success"):
                expected_requests.append(jdk_api(data["java"]))
            if stage in ("jdk", "success"):
                expected_requests.append(JDK_URL)
            self.assertEqual(
                (root / "requests.txt").read_text(encoding="utf-8-sig").splitlines(),
                expected_requests, output,
            )
            self.assertEqual(
                (root / "Ghidra.zip").read_bytes(),
                OLD_ZIP if stage in ("release", "ghidra") else data["zip"],
            )
            self.assertEqual(msi.read_bytes(), data["msi"] if stage == "success" else OLD_MSI)
            self.assertEqual(list(root.glob("*.part")), [], output)

    def test_latest_release_selects_first_public_zip_and_matching_latest_jdk(self):
        for java in ("21", "25"):
            with self.subTest(java=java):
                data = fixture(java)
                selected = data["release"]["assets"][0]
                selected["digest"] = selected["digest"].upper()
                data["release"]["body"] = "SHA-256: " + ("f" * 64)
                data["release"]["assets"] = [
                    {"name": "ghidra_12_PUBLIC_20261027.ZIP"},
                    {"name": "ghidra_12_DEV_20261027.zip"},
                    selected,
                    {"name": "ghidra_older_PUBLIC_20251027.zip",
                     "browser_download_url": "https://must-not-select.invalid/older.zip"},
                ]
                data["jdk"][0]["binary"]["installer"]["checksum"] = (
                    data["jdk"][0]["binary"]["installer"]["checksum"].upper()
                )
                data["jdk"].append({"binary": {"installer": {
                    "link": "https://must-not-select.invalid/older.msi", "checksum": "f" * 64,
                }}})
                self.run_fixture(data)

    def test_release_notes_accept_only_unambiguous_hash_association(self):
        digest = hashlib.sha256(fixture()["zip"]).hexdigest()
        for body in (
            f"{ASSET_NAME} SHA-256: {digest}",
            f"`{ASSET_NAME}`\r\nSHA-256: {digest.upper()}\r\n",
            f"SHA-256: {digest}",
            f"other.zip SHA-256: {'f' * 64}\n{ASSET_NAME}\nSHA-256: {digest}",
        ):
            with self.subTest(body=body):
                data = fixture()
                data["release"]["assets"][0].pop("digest")
                data["release"]["body"] = body
                self.run_fixture(data)

    def test_invalid_digest_never_falls_back_to_release_notes(self):
        for digest in ("sha512:" + "a" * 64, "sha256:" + "a" * 65, "sha256:missing"):
            with self.subTest(digest=digest):
                data = fixture()
                data["release"]["body"] = f"SHA-256: {hashlib.sha256(data['zip']).hexdigest()}"
                data["release"]["assets"][0]["digest"] = digest
                self.run_fixture(data, "release")

    def test_ambiguous_or_unrelated_release_note_hashes_are_rejected(self):
        digest = hashlib.sha256(fixture()["zip"]).hexdigest()
        for body in (
            "",
            f"SHA-256: {digest}\nSHA-256: {digest}",
            f"{ASSET_NAME} SHA-256: {digest}\n{ASSET_NAME} SHA-256: {digest}",
            f"{ASSET_NAME} and other.zip SHA-256: {digest}",
            f"other.zip SHA-256: {digest}",
            f"{ASSET_NAME}\nother.zip SHA-256: {digest}",
            f"prefix_{ASSET_NAME} SHA-256: {digest}",
            f"{ASSET_NAME} SHA-256: {digest}0",
        ):
            with self.subTest(body=body):
                data = fixture()
                data["release"]["assets"][0].pop("digest")
                data["release"]["body"] = body
                self.run_fixture(data, "release")

    def test_missing_release_and_jdk_metadata(self):
        for field in ("assets", "ghidra-url", "jdk-assets", "jdk-url", "jdk-checksum"):
            with self.subTest(field=field):
                data = fixture()
                stage = "release"
                if field == "assets":
                    data["release"] = {}
                elif field == "ghidra-url":
                    data["release"]["assets"][0].pop("browser_download_url")
                else:
                    stage = "jdk-metadata"
                    if field == "jdk-assets":
                        data["jdk"] = []
                    else:
                        key = "link" if field == "jdk-url" else "checksum"
                        data["jdk"][0]["binary"]["installer"].pop(key)
                self.run_fixture(data, stage)

    def test_metadata_request_failures_do_not_leave_versions(self):
        for url, stage in ((GHIDRA_API, "release"), (jdk_api("25"), "jdk-metadata")):
            with self.subTest(url=url):
                data = fixture()
                data["fail"].add(url)
                self.run_fixture(data, stage)

    def test_partial_downloads_are_removed_without_replacing_verified_outputs(self):
        for url, stage in ((GHIDRA_URL, "ghidra"), (JDK_URL, "jdk")):
            with self.subTest(url=url):
                data = fixture()
                data["fail"].add(url)
                self.run_fixture(data, stage)

    def test_checksum_mismatch_never_replaces_verified_outputs(self):
        for payload, stage in (("zip", "ghidra"), ("msi", "jdk")):
            with self.subTest(payload=payload):
                data = fixture()
                data[payload] += b"tampered"
                self.run_fixture(data, stage)

    def test_java_minimum_must_be_present_and_entirely_numeric(self):
        for properties in (
            "application.java.max=25\n", "application.java.min=\n",
            "application.java.min=25-ea\n", "application.java.min=25=ignored\n",
        ):
            with self.subTest(properties=properties):
                data = fixture()
                set_archive(data, properties)
                self.run_fixture(data, "properties")

    def test_missing_or_unreadable_properties_fail_before_jdk_selection(self):
        for kind in ("missing", "wrong-case", "invalid-zip"):
            with self.subTest(kind=kind):
                data = fixture()
                if kind == "missing":
                    set_archive(data)
                elif kind == "wrong-case":
                    set_archive(data, "application.java.min=25\n",
                                "ghidra_current/Ghidra/Application.properties")
                else:
                    data["zip"] = b"not a zip file"
                    data["release"]["assets"][0]["digest"] = (
                        "sha256:" + hashlib.sha256(data["zip"]).hexdigest()
                    )
                self.run_fixture(data, "properties")


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required")
class PowerShellDownloaderTests(DownloadContract, unittest.TestCase):
    script = "download.ps1"

    def runner(self, root, routes):
        (root / "run-fixture.ps1").write_text(POWERSHELL_MOCKS, encoding="utf-8")
        return ["pwsh", "-NoProfile", "-NonInteractive", "-File", "run-fixture.ps1"]


class BashDownloaderTests(DownloadContract, unittest.TestCase):
    script = "download.sh"

    @classmethod
    def setUpClass(cls):
        cls.bash = git_bash()
        if not cls.bash:
            raise unittest.SkipTest("Bash is required (Git Bash on Windows; not WSL)")
        result = subprocess.run(
            [cls.bash, "--noprofile", "--norc", "-c",
             "command -v jq && command -v unzip && command -v awk && "
             "(command -v sha256sum || command -v shasum)"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode:
            raise unittest.SkipTest("Bash downloader fixtures require jq, unzip, awk and a SHA-256 tool")

    def runner(self, root, routes):
        lines = [BASH_MOCK]
        for route in routes:
            lines.append(f"    {shlex.quote(route['url'])})")
            if route["fail"]:
                lines.append('      [[ -z "$output" ]] || printf partial > "$output"')
                lines.append("      return 22 ;;")
            else:
                source = shlex.quote(route["path"])
                lines.append(
                    f'      if [[ -n "$output" ]]; then cp {source} "$output"; '
                    f"else cat {source}; fi ;;"
                )
        lines.extend((
            '    *) echo "UNEXPECTED_REQUEST: $url" >&2; return 22 ;;',
            "  esac\n}\nsource ./download.sh\n",
        ))
        (root / "run-fixture.sh").write_text("\n".join(lines), encoding="utf-8", newline="\n")
        return [self.bash, "--noprofile", "--norc", "run-fixture.sh"]


if __name__ == "__main__":
    unittest.main()
