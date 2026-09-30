"""Windows-process conformance tests for the native Rust Ghidra helper.

Run on Windows directly, or run this file with Windows Python under Wine.  Set
RUST_HELPER_EXE and RUST_HELPER_TEST_ROOT; optionally set
RUST_HELPER_PEER_EXE to the native C helper for marker interoperability tests.
"""

import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
import zipfile
import xml.etree.ElementTree as ET
import zlib


EXE = os.environ.get("RUST_HELPER_EXE")
PEER_EXE = os.environ.get("RUST_HELPER_PEER_EXE")
ARTIFACTS = os.environ.get("RUST_HELPER_TEST_ROOT")
WINDOWS = sys.platform == "win32"
WINE = os.environ.get("RUST_HELPER_WINE", "wine")
MARKER = ".ghidralaunch-source.sha256"


class RustHelperBuildCommandTests(unittest.TestCase):
    def test_resource_compilation_includes_shared_version_header(self):
        root = Path(__file__).resolve().parents[1] / "GhidraLaunchGhidraHelperRS"
        build = (root / "build.rs").read_text()
        resource = (root / "GhidraLaunchGhidraHelperRS.rc").read_text()

        self.assertIn("embed_resource::compile_for(", build)
        self.assertIn('"GhidraLaunchGhidraHelperRS"', build)
        self.assertIn('ParamsIncludeDirs(&["../Resources"])', build)
        self.assertIn('#include "winres.h"', resource)
        self.assertIn('#include "Version.h"', resource)
        self.assertIn('VALUE "FileVersion", GHIDRA_LAUNCH_VERSION', resource)

    @unittest.skipUnless(WINDOWS, "requires cmd.exe")
    def test_makefile_refreshes_existing_outputs_and_cleans_with_missing_debug(self):
        makefile = Path(__file__).resolve().parents[1] / "GhidraLaunchGhidraHelperRS/Makefile"
        commands = [line.strip() for line in makefile.read_text().splitlines() if line.startswith("\t")]
        self.assertTrue(commands[2].startswith("cargo clean -p ghidra_launch_helper "), commands[2])
        with tempfile.TemporaryDirectory() as directory:
            # Cargo writes to the workspace target directory beside the member project.
            workspace = Path(directory)
            project = workspace / "GhidraLaunchGhidraHelperRS"
            project.mkdir()
            name = "GhidraLaunchGhidraHelperRS"
            for configuration, command in zip(("Debug", "Release"), commands[:2]):
                command = command.split(" && ", 1)[1]
                for content in (b"first", b"changed"):
                    for extension in ("exe", "pdb"):
                        source = workspace / "target" / configuration.lower() / f"{name}.{extension}"
                        source.parent.mkdir(parents=True, exist_ok=True)
                        source.write_bytes(content + extension.encode())
                    result = subprocess.run(
                        ["cmd", "/d", "/c", command], cwd=project,
                        capture_output=True, timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    for extension in ("exe", "pdb"):
                        destination = project / "bin" / configuration / f"{name}.{extension}"
                        self.assertEqual(destination.read_bytes(), content + extension.encode())
            (project / "bin/Debug" / f"{name}.exe").unlink()
            result = subprocess.run(
                ["cmd", "/d", "/c", "ver >nul && " + commands[2].split(" && ", 1)[1]],
                cwd=project, capture_output=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(list((project / "bin").rglob("*.*")), [])
            self.assertTrue((workspace / "target/release" / f"{name}.exe").exists())

    def test_build_and_rebuild_copy_output_when_directory_exists(self):
        namespace = "{http://schemas.microsoft.com/developer/msbuild/2003}"
        checkout = Path(__file__).resolve().parents[1]
        for directory, package, name in (
            ("GhidraLaunchGhidraHelperRS", "ghidra_launch_helper", "GhidraLaunchGhidraHelperRS"),
            ("GhidraLaunchRS", "ghidra_launch", "GhidraLaunchRS"),
        ):
            project = checkout / directory / f"{directory}.vcxproj"
            root = ET.parse(project).getroot()
            for configuration in ("Debug", "Release"):
                with self.subTest(project=directory, configuration=configuration):
                    condition = f"'$(Configuration)|$(Platform)'=='{configuration}|x64'"
                    group = next(
                        element for element in root.findall(f"{namespace}PropertyGroup")
                        if element.get("Condition") == condition and
                        element.find(f"{namespace}NMakeBuildCommandLine") is not None
                    )
                    output_dir = f"bin\\{configuration}"
                    target_dir = f"..\\target\\{configuration.lower()}"
                    copy = (
                        f"(if exist {output_dir} (ver >nul) else (mkdir {output_dir})) && "
                        f"copy /y {target_dir}\\{name}.exe {output_dir}\\{name}.exe && "
                        f"copy /y {target_dir}\\{name}.pdb {output_dir}\\{name}.pdb"
                    )
                    manifest = '--manifest-path "$(MSBuildThisFileDirectory)Cargo.toml"'
                    profile = "--release" if configuration == "Release" else "--profile dev"
                    # Package-scoped clean: one project's Clean/Rebuild must not wipe the other's outputs.
                    clean = f"cargo clean {profile} -p {package} {manifest} && "
                    remove = (
                        f"(if exist {output_dir}\\{name}.exe (del /q {output_dir}\\{name}.exe)) && "
                        f"(if exist {output_dir}\\{name}.pdb (del /q {output_dir}\\{name}.pdb))"
                    )

                    for command in ("NMakeBuildCommandLine", "NMakeReBuildCommandLine"):
                        value = group.find(f"{namespace}{command}").text
                        self.assertIn(copy, value)
                        self.assertIn(f"--locked {manifest} && ", value)
                    for command in ("NMakeCleanCommandLine", "NMakeReBuildCommandLine"):
                        value = group.find(f"{namespace}{command}").text
                        self.assertTrue(value.startswith(clean + remove), value)
                    if directory == "GhidraLaunchGhidraHelperRS":
                        self.assertIn(copy, (project.parent / "Makefile").read_text())

    @unittest.skipUnless(WINDOWS, "requires cmd.exe")
    def test_rebuild_executes_with_absent_outputs_and_propagates_failures(self):
        project = Path(__file__).resolve().parents[1] / "GhidraLaunchGhidraHelperRS/GhidraLaunchGhidraHelperRS.vcxproj"
        namespace = "{http://schemas.microsoft.com/developer/msbuild/2003}"
        root = ET.parse(project).getroot()
        for configuration in ("Debug", "Release"):
            group = next(
                element for element in root.findall(f"{namespace}PropertyGroup")
                if element.get("Condition") == f"'$(Configuration)|$(Platform)'=='{configuration}|x64'"
                and element.find(f"{namespace}NMakeReBuildCommandLine") is not None
            )
            command = group.find(f"{namespace}NMakeReBuildCommandLine").text
            command = command.replace("cargo clean", "call cargo.cmd clean").replace("cargo build", "call cargo.cmd build")
            for existing, failure in ((False, ""), (True, ""), (False, "clean"), (False, "build"), (False, "copy")):
                with self.subTest(configuration=configuration, existing=existing, failure=failure), tempfile.TemporaryDirectory() as directory:
                    workspace = Path(directory)
                    work = workspace / "GhidraLaunchGhidraHelperRS"
                    work.mkdir()
                    name = "GhidraLaunchGhidraHelperRS"
                    for extension in ("exe", "pdb"):
                        source = workspace / "target" / configuration.lower() / f"{name}.{extension}"
                        source.parent.mkdir(parents=True, exist_ok=True)
                        if failure != "copy":
                            source.write_bytes(b"rebuilt")
                    destination = work / "bin" / configuration / f"{name}.exe"
                    if existing:
                        destination.parent.mkdir(parents=True)
                        destination.write_bytes(b"old")
                        destination.with_suffix(".pdb").write_bytes(b"old")
                    (work / "cargo.cmd").write_text(
                        '@echo off\n'
                        'echo %*>>calls.txt\n'
                        'if "%1"=="%FAIL_STEP%" exit /b 9\n'
                        'exit /b 0\n'
                    )
                    invocation = command.replace("call cargo.cmd", f'call "{work / "cargo.cmd"}"')
                    result = subprocess.run(
                        f'cmd /d /s /c "{invocation}"', cwd=work,
                        env={**os.environ, "FAIL_STEP": failure},
                        capture_output=True, timeout=30,
                    )
                    if failure:
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertFalse(destination.exists())
                        self.assertFalse(destination.with_suffix(".pdb").exists())
                    else:
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual(destination.read_bytes(), b"rebuilt")
                        self.assertEqual(destination.with_suffix(".pdb").read_bytes(), b"rebuilt")
                        self.assertEqual(len((work / "calls.txt").read_text().splitlines()), 2)


if EXE and ARTIFACTS:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import test_c_helper as shared_helper_contract_tests


    class RustHelperParityTests(shared_helper_contract_tests.CHelperTests):
        exe = EXE
        fault_exe = None
        peer_exe = PEER_EXE
        artifacts = ARTIFACTS
        wine = WINE

        @unittest.skip("C-specific rename lock; Rust exercises install/restore faults in its unit suite")
        def test_failed_install_rename_rolls_original_back(self):
            pass


def windows_path(value):
    if WINDOWS:
        return str(value)
    return "Z:" + str(value).replace("/", "\\")


@unittest.skipUnless(EXE and ARTIFACTS, "set RUST_HELPER_EXE and RUST_HELPER_TEST_ROOT")
class RustHelperTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(ARTIFACTS).resolve() / ("case-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root)
        self.dest = self.root / "Ghidra 日本語"
        self.zip = self.root / "fixture.zip"

    def command(self, *args, exe=None):
        exe = exe or EXE
        if WINDOWS:
            return [exe, *[str(arg) for arg in args]]
        def convert(arg):
            return windows_path(arg) if isinstance(arg, Path) else str(arg)
        return [WINE, windows_path(exe), *[convert(arg) for arg in args]]

    def run_helper(self, *args, code=0, exe=None):
        result = subprocess.run(self.command(*args, exe=exe), capture_output=True, timeout=90,
                                env={**os.environ, "LOCALAPPDATA": str(self.root / "profile")})
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        if code:
            self.assertTrue(result.stderr, "failure must have stderr diagnostics")
        return result

    def archive(self, entries=None):
        entries = entries or [
            ("ghidra_PUBLIC/ghidraRun.bat", b"run"),
            ("ghidra_PUBLIC/support/\xe9.txt", b"payload"),
        ]
        with zipfile.ZipFile(self.zip, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for name, contents in entries:
                output.writestr(name, contents)
        return self.zip

    def hash(self):
        return hashlib.sha256(self.zip.read_bytes()).hexdigest().encode("ascii")

    def marker(self):
        return (self.dest / MARKER).read_bytes()

    def unicode_path_archive(self, raw_name, unicode_name, flags):
        placeholder = "x" * len(raw_name)
        info = zipfile.ZipInfo(placeholder)
        unicode_path = (
            struct.pack("<BI", 1, zlib.crc32(raw_name))
            + unicode_name.encode("utf-8")
        )
        info.extra = struct.pack("<HH", 0x7075, len(unicode_path)) + unicode_path
        with zipfile.ZipFile(self.zip, "w") as archive:
            archive.writestr(info, b"payload")
        raw = bytearray(self.zip.read_bytes())
        for signature, name_offset, flag_offset in (
            (b"PK\x03\x04", 30, 6), (b"PK\x01\x02", 46, 8)
        ):
            start = raw.index(signature)
            raw[start + name_offset:start + name_offset + len(raw_name)] = raw_name
            struct.pack_into("<H", raw, start + flag_offset, flags)
        self.zip.write_bytes(raw)

    def test_unicode_path_extra_field_keeps_original_name_and_flags(self):
        # Match C: Unicode overrides must not replace the original central name
        # or change whether its bytes are interpreted as UTF-8 or legacy CP437.
        cases = (
            (b"bundle/caf\x82.txt", "bundle/caf\u00e9.txt", 0, "caf\u00e9.txt"),
            (b"bundle/\xc3\xa9.txt", "bundle/\u00e9.txt", 0, "\u251c\u2310.txt"),
            (b"bundle/original.txt", "bundle/override.txt", 0, "original.txt"),
            (b"bundle/caf\xc3\xa9.txt", "bundle/override.txt", 0x800, "caf\u00e9.txt"),
            (b"bundle/file.txt", "bundle/override/", 0, "file.txt"),
        )
        for index, (raw_name, unicode_name, flags, expected) in enumerate(cases):
            with self.subTest(raw_name=raw_name, unicode_name=unicode_name, flags=flags):
                self.dest = self.root / f"extra-{index}"
                self.unicode_path_archive(raw_name, unicode_name, flags)
                self.run_helper("extract", self.zip, self.dest)
                self.assertEqual((self.dest / expected).read_bytes(), b"payload")
                inventory = (self.dest / ".ghidralaunch-inventory").read_text(encoding="utf-8")
                self.assertIn(f"\t{expected}\n", inventory)
                self.assertEqual(self.marker(), self.hash())
                self.run_helper("remove", self.dest, self.zip, exe=PEER_EXE or EXE)
                self.assertFalse(self.dest.exists())

    def test_unicode_path_extra_field_cannot_override_invalid_original_name(self):
        for index, (raw_name, flags) in enumerate((
            (b"../unsafe", 0), (b"bundle/\x82.txt", 0x800),
        )):
            with self.subTest(raw_name=raw_name, flags=flags):
                self.dest = self.root / f"invalid-extra-{index}"
                self.unicode_path_archive(raw_name, "bundle/safe.txt", flags)
                self.run_helper("extract", self.zip, self.dest, code=1)
                self.assertFalse(self.dest.exists())
                self.assertFalse((self.root / "unsafe").exists())

    @unittest.skipUnless(WINDOWS, "requires native Windows UTF-16 paths")
    def test_unpaired_surrogate_destination_parent_round_trips(self):
        self.archive()
        for label, surrogate in (("high", "\ud800"), ("low", "\udc00")):
            with self.subTest(surrogate=label):
                parent = self.root / f"parent-{label}-{surrogate}"
                parent.mkdir()
                self.dest = parent / "Ghidra"
                self.run_helper("extract", self.zip, self.dest)
                self.assertEqual((self.dest / "support/\u00e9.txt").read_bytes(), b"payload")
                self.run_helper("remove", self.dest, self.zip)
                self.assertFalse(self.dest.exists())
                self.assertTrue(parent.is_dir())
                self.assertFalse((self.root / f"parent-{label}-\ufffd").exists())

    def test_extract_error_codes_unicode_and_safe_rollback(self):
        self.run_helper("unknown", code=2)
        self.run_helper("extract", code=2)
        self.zip.write_bytes(b"not a ZIP")
        self.run_helper("extract", self.zip, self.dest, code=1)
        self.assertFalse(self.dest.exists())

        self.archive()
        self.run_helper("extract", self.zip, self.dest, "bad/owner", code=2)
        self.run_helper("extract", self.zip, self.dest)
        content = self.dest / "support" / "\xe9.txt"
        self.assertEqual((self.dest / "ghidraRun.bat").read_bytes(), b"run")
        self.assertEqual(content.read_bytes(), b"payload")
        self.assertEqual(self.marker(), self.hash())

        self.zip.write_bytes(b"corrupt changed source")
        before_marker = self.marker()
        self.run_helper("extract", self.zip, self.dest, code=1)
        self.assertEqual(self.marker(), before_marker)
        self.assertEqual(content.read_bytes(), b"payload")

    def test_guid_only_owner_and_ownerless_source_removal_rules(self):
        self.archive()
        provider_key = "{FEEDFACE-0000-4000-8000-0000000000B6}"
        self.run_helper("extract", self.zip, self.dest, provider_key)
        (self.dest / "support" / "\xe9.txt").write_bytes(b"user modification")
        self.assertEqual(
            self.marker(),
            self.hash() + b"\nowner=" + provider_key.encode("ascii") + b"\n",
        )

        self.run_helper("extract", self.zip, self.dest)
        self.assertEqual((self.dest / "support" / "\xe9.txt").read_bytes(), b"user modification")
        self.run_helper("remove", self.dest)
        self.run_helper("remove", self.dest, self.zip)
        self.assertTrue(self.dest.exists())
        self.run_helper("remove", self.dest, "", "{00000000-0000-0000-0000-000000000000}")
        self.assertTrue(self.dest.exists())
        self.run_helper("remove", self.dest, "", provider_key)
        self.assertTrue(self.dest.exists())
        (self.dest / "support" / "\xe9.txt").write_bytes(b"payload")
        self.run_helper("remove", self.dest, "", provider_key)
        self.assertFalse(self.dest.exists())

    def test_local_and_central_zip64_extraction(self):
        with zipfile.ZipFile(self.zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            with archive.open("ghidra_PUBLIC/ghidraRun.bat", "w", force_zip64=True) as entry:
                entry.write(b"ZIP64 payload")
        raw = self.zip.read_bytes()
        end = raw.rfind(b"PK\x05\x06")
        fields = struct.unpack_from("<4s4H2IH", raw, end)
        _, _, _, _, count, directory_size, directory_offset, _ = fields
        zip64_end = struct.pack(
            "<IQHHIIQQQQ",
            0x06064B50,
            44,
            45,
            45,
            0,
            0,
            count,
            count,
            directory_size,
            directory_offset,
        )
        locator = struct.pack("<IIQI", 0x07064B50, 0, end, 1)
        classic_end = struct.pack(
            "<4s4H2IH",
            b"PK\x05\x06",
            0,
            0,
            0xFFFF,
            0xFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0,
        )
        self.zip.write_bytes(raw[:end] + zip64_end + locator + classic_end)

        self.run_helper("extract", self.zip, self.dest)
        self.assertEqual((self.dest / "ghidraRun.bat").read_bytes(), b"ZIP64 payload")
        self.assertEqual(self.marker(), self.hash())
        self.run_helper("remove", self.dest, self.zip)
        self.assertFalse(self.dest.exists())

    @unittest.skipUnless(PEER_EXE, "set RUST_HELPER_PEER_EXE to test C/Rust marker interoperation")
    def test_c_helper_reads_rust_guid_marker_and_removes_only_matching_owner(self):
        self.archive()
        owner = "{FEEDFACE-0000-4000-8000-0000000000B6}"
        other_owner = "{00000000-0000-0000-0000-000000000000}"
        self.run_helper("extract", self.zip, self.dest, owner)

        self.run_helper("remove", self.dest, self.zip, other_owner, exe=PEER_EXE)
        self.assertTrue(self.dest.exists())
        self.run_helper("remove", self.dest, self.zip, owner, exe=PEER_EXE)
        self.assertFalse(self.dest.exists())

        self.run_helper("extract", self.zip, self.dest, owner)
        self.run_helper("extract", self.zip, self.dest, other_owner, exe=PEER_EXE)
        self.assertEqual(
            self.marker(),
            self.hash() + b"\nowner=" + other_owner.encode("ascii") + b"\n",
        )
        self.run_helper("remove", self.dest, self.zip, owner)
        self.assertTrue(self.dest.exists())
        self.run_helper("remove", self.dest, self.zip, other_owner, exe=PEER_EXE)
        self.assertFalse(self.dest.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
