"""Integration checks for the real Windows C helper; no mocked extraction.

Set C_HELPER_EXE and C_HELPER_TEST_ROOT (an artifact directory outside the repo).
Linux hosts use Wine; Windows Python additionally runs Win32 fault injection.
"""

import hashlib
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
import unittest
import uuid
import warnings
import zipfile


EXE = os.environ.get("C_HELPER_EXE")
FAULT_EXE = os.environ.get("C_HELPER_FAULT_EXE")
PEER_EXE = os.environ.get("C_HELPER_PEER_EXE")
ARTIFACTS = os.environ.get("C_HELPER_TEST_ROOT")
WINDOWS = sys.platform == "win32"
MARKER = ".ghidralaunch-source.sha256"


@unittest.skipUnless(EXE and ARTIFACTS, "set C_HELPER_EXE and C_HELPER_TEST_ROOT")
class CHelperTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(ARTIFACTS).resolve() / ("case-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root)
        self.dest = self.root / "destination"
        self.zip = self.root / "fixture.zip"

    def command(self, *args, exe=None):
        exe = exe or EXE
        if WINDOWS:
            return [exe, *map(str, args)]
        def wine_arg(arg):
            return "Z:" + str(arg).replace("/", "\\") if isinstance(arg, Path) else str(arg)
        return [os.environ.get("C_HELPER_WINE", "wine"), exe, *map(wine_arg, args)]

    def run_helper(self, *args, code=0):
        result = subprocess.run(self.command(*args), capture_output=True, timeout=90)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        if code:
            self.assertTrue(result.stderr, "failure must have stderr diagnostics")
        return result

    def archive(self, entries=None, compression=zipfile.ZIP_DEFLATED, path=None):
        path = path or self.zip
        entries = entries if entries is not None else [
            ("ghidra_PUBLIC/ghidraRun.bat", b"run"),
            ("ghidra_PUBLIC/support/x.txt", b"first"),
        ]
        with warnings.catch_warnings(), zipfile.ZipFile(path, "w", compression=compression) as archive:
            warnings.simplefilter("ignore", UserWarning)
            for name, contents in entries:
                archive.writestr(name, contents)
        return path

    def hash(self, path=None):
        return hashlib.sha256((path or self.zip).read_bytes()).hexdigest()

    def marker(self):
        return (self.dest / MARKER).read_bytes()

    def assert_no_staging(self):
        self.assertFalse(list(self.root.glob(".extract-*")))
        self.assertFalse(list(self.root.glob(".old-*")))

    def test_usage_and_owner_validation(self):
        for args in [(), ("bad",), ("extract",), ("remove",),
                     ("remove", self.dest, "", "owner", "extra")]:
            self.run_helper(*args, code=2)
        self.archive()
        for owner in ["", "bad owner", "a/b", "a:b", "é", "a" * 129]:
            self.run_helper("extract", self.zip, self.dest, owner, code=2)
        self.run_helper("ExTrAcT", self.zip, self.dest, "a" * 128)
        self.run_helper("ReMoVe", self.dest, self.zip, "a" * 128)
        self.run_helper("extract", self.zip, self.dest, "1.0.0-C-{1234-5678}")
        self.run_helper("remove", self.dest, self.zip, "1.0.0-C-{9999-0000}")
        self.assertTrue(self.dest.exists())
        self.run_helper("remove", self.dest, self.zip, "1.0.0-C-{1234-5678}")
        owner = "{89ABCDEF-0123-4567-89AB-CDEF01234567}"
        self.run_helper("extract", self.zip, self.dest, owner)
        self.assertEqual(self.marker(), (self.hash() + "\nowner=" + owner + "\n").encode())
        self.run_helper("remove", self.dest, self.zip, owner)
        self.assertFalse(self.dest.exists())

    def test_stored_deflate_unicode_and_backslashes(self):
        for compression in [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED]:
            with self.subTest(compression=compression):
                self.archive([("bundle\\ghidraRun.bat", b"run"),
                              ("bundle/日本語/é.txt", b"data")], compression)
                self.run_helper("extract", self.zip, self.dest)
                self.assertEqual((self.dest / "日本語/é.txt").read_bytes(), b"data")
                self.assertEqual(self.marker(), self.hash().encode())
                self.run_helper("remove", self.dest)
                self.assert_no_staging()

    def test_local_zip64_and_zip64_directory(self):
        with zipfile.ZipFile(self.zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            with archive.open("bundle/ghidraRun.bat", "w", force_zip64=True) as entry:
                entry.write(b"zip64")
        raw = self.zip.read_bytes()
        eocd = raw.rfind(b"PK\x05\x06")
        fields = struct.unpack_from("<4s4H2IH", raw, eocd)
        _, _, _, count, total, size, offset, _ = fields
        end64 = struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45,
                            0, 0, count, total, size, offset)
        locator = struct.pack("<IIQI", 0x07064B50, 0, eocd, 1)
        end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF,
                          0xFFFFFFFF, 0xFFFFFFFF, 0)
        self.zip.write_bytes(raw[:eocd] + end64 + locator + end)
        self.run_helper("extract", self.zip, self.dest)
        self.assertEqual((self.dest / "ghidraRun.bat").read_bytes(), b"zip64")

    def test_flat_and_empty_archives(self):
        for entries in [[("a", b"a"), ("b/x", b"x")], [("sole", b"s")], []]:
            self.archive(entries)
            self.run_helper("extract", self.zip, self.dest)
            for name, data in entries:
                self.assertEqual((self.dest / name).read_bytes(), data)
            self.assertTrue((self.dest / MARKER).exists())
            self.run_helper("remove", self.dest)

    def test_same_hash_transfers_owner_without_changing_content(self):
        self.archive()
        self.run_helper("extract", self.zip, self.dest, "1.2.3-C")
        (self.dest / "support/x.txt").write_bytes(b"user change")
        self.run_helper("extract", self.zip, self.dest, "1.2.3-Rust")
        self.assertEqual((self.dest / "support/x.txt").read_bytes(), b"user change")
        self.assertEqual(self.marker(), (self.hash() + "\nowner=1.2.3-Rust\n").encode())
        for args in [("remove", self.dest), ("remove", self.dest, self.zip),
                     ("remove", self.dest, self.zip, "1.2.3-C")]:
            self.assertIn(b"Skipping", self.run_helper(*args).stdout)
            self.assertTrue(self.dest.exists())
        self.run_helper("extract", self.zip, self.dest)
        self.assertTrue(self.marker().endswith(b"owner=1.2.3-Rust\n"))
        self.run_helper("remove", self.dest, self.zip, "1.2.3-Rust")
        self.assertFalse(self.dest.exists())

    def test_legacy_marker_owner_upgrade_and_first_line_hash(self):
        self.archive()
        self.run_helper("extract", self.zip, self.dest)
        (self.dest / MARKER).write_bytes(self.hash().upper().encode() + b"\r\n")
        (self.dest / "ghidraRun.bat").write_bytes(b"untouched")
        self.run_helper("extract", self.zip, self.dest, "Release-C")
        self.assertEqual((self.dest / "ghidraRun.bat").read_bytes(), b"untouched")
        self.assertEqual(self.marker(), (self.hash() + "\nowner=Release-C\n").encode())
        self.run_helper("remove", self.dest, self.zip, "Release-C")
        self.assertFalse(self.dest.exists())

    def test_owner_only_remove(self):
        self.archive()
        self.run_helper("extract", self.zip, self.dest, "owner")
        self.run_helper("remove", self.dest, "", "other")
        self.assertTrue(self.dest.exists())
        self.run_helper("remove", self.dest, "", "owner")
        self.assertFalse(self.dest.exists())

    def test_changed_source_replaces_and_removes_with_matching_hash(self):
        self.archive()
        self.run_helper("extract", self.zip, self.dest, "owner")
        old = self.root / "old.zip"
        shutil.copyfile(self.zip, old)
        self.archive([("bundle/ghidraRun.bat", b"new")])
        self.run_helper("remove", self.dest, self.zip, "owner")
        self.assertTrue(self.dest.exists())
        self.run_helper("extract", self.zip, self.dest, "owner")
        self.assertEqual((self.dest / "ghidraRun.bat").read_bytes(), b"new")
        self.assertFalse((self.dest / "support").exists())
        self.run_helper("remove", self.dest, old, "owner")
        self.assertTrue(self.dest.exists())
        self.run_helper("remove", self.dest, self.zip, "owner")
        self.assertFalse(self.dest.exists())
        self.assert_no_staging()

    def test_missing_or_invalid_source_markers_skip(self):
        self.dest.mkdir()
        self.archive()
        self.run_helper("remove", self.dest, self.zip)
        self.assertTrue(self.dest.exists())
        for text in [b"bad", b"0" * 64 + b"\nowner=bad token\n", b"x" * 256]:
            (self.dest / MARKER).write_bytes(text)
            self.run_helper("remove", self.dest, self.zip)
            self.run_helper("remove", self.dest)
            self.assertTrue(self.dest.exists())
        (self.dest / MARKER).write_bytes(self.hash().encode())
        self.run_helper("remove", self.dest, self.root / "missing.zip")
        self.assertTrue(self.dest.exists())
        (self.dest / MARKER).unlink()
        (self.dest / MARKER).mkdir()
        self.run_helper("remove", self.dest, self.root / "missing.zip")
        self.assertTrue(self.dest.exists())
        (self.dest / MARKER).rmdir()
        self.run_helper("remove", self.dest)
        self.assertFalse(self.dest.exists())

    def test_missing_and_empty_remove_success(self):
        self.run_helper("remove", self.dest)
        self.dest.mkdir()
        self.run_helper("remove", self.dest)
        self.assertFalse(self.dest.exists())

    def test_invalid_zip_or_crc_never_deletes_original(self):
        self.archive()
        self.run_helper("extract", self.zip, self.dest, "original")
        before = self.marker()
        for corrupted in [b"not a zip", None]:
            if corrupted is None:
                self.archive([("bundle/ghidraRun.bat", b"corrupt me")], zipfile.ZIP_STORED)
                raw = bytearray(self.zip.read_bytes())
                name_len, extra_len = struct.unpack_from("<HH", raw, 26)
                raw[30 + name_len + extra_len] ^= 0xFF
                corrupted = raw
            self.zip.write_bytes(corrupted)
            self.run_helper("extract", self.zip, self.dest, "new", code=1)
            self.assertEqual(self.marker(), before)
            self.assertEqual((self.dest / "support/x.txt").read_bytes(), b"first")
            self.assert_no_staging()
        self.run_helper("extract", self.root / "missing.zip", self.dest, code=1)
        self.assertEqual(self.marker(), before)

    def test_unsafe_names_rejected_before_swap(self):
        self.dest.mkdir()
        (self.dest / "original").write_bytes(b"keep")
        names = ["../escape", "..\\escape", "a/../../escape", "/absolute",
                 "\\absolute", "//server/share/file", "\\\\?\\C:\\evil", "C:/evil",
                 "C:evil", "file:stream", "a//b", "a\\\\b", "./a", "a/./b",
                 "trailing.", "trailing ", "a/.. /x", "NUL", "nul.txt", "con",
                 "PRN.txt", "aux", "COM1.txt", "lpt9", "COM¹", "CONIN$",
                 "CON .txt", "CLOCK$", "LPT1 .log",
                 "CONOUT$.txt", "bad?.txt", "bad*.txt", "bad\x01.txt", "bad|x"]
        for name in names:
            with self.subTest(name=name):
                self.archive([(name, b"bad")])
                self.run_helper("extract", self.zip, self.dest, code=1)
                self.assertEqual((self.dest / "original").read_bytes(), b"keep")
                self.assert_no_staging()
        self.assertFalse((self.root / "escape").exists())

    def test_duplicate_case_alias_and_parent_conflicts_rejected(self):
        for names in [("a", "a"), ("a", "A"), ("a/x", "A/y"),
                      ("a", "a/x"), ("a/x", "a"), ("a/", "a/"),
                      ("a\\x", "a/x"), ("a/", "A/x")]:
            with self.subTest(names=names):
                self.archive([(name, b"") for name in names])
                self.run_helper("extract", self.zip, self.dest, code=1)
                self.assertFalse(self.dest.exists())
                self.assert_no_staging()

    def test_symlink_special_and_reparse_zip_entries_rejected(self):
        for attr in [(0o120777 << 16), (0o020600 << 16), 0x400]:
            with self.subTest(attr=attr):
                entry = zipfile.ZipInfo("link")
                entry.create_system = 3
                entry.external_attr = attr
                self.archive([(entry, b"../outside")])
                self.run_helper("extract", self.zip, self.dest, code=1)
                self.assertFalse(self.dest.exists())
                self.assert_no_staging()

    def test_embedded_nul_and_invalid_utf8_rejected(self):
        for replacement in [b"a\x00b", b"a\xffb"]:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("abc", b"data")
            raw = bytearray(buffer.getvalue())
            for signature, name_offset, flag_offset in [(b"PK\x03\x04", 30, 6),
                                                         (b"PK\x01\x02", 46, 8)]:
                pos = raw.index(signature)
                raw[pos + name_offset:pos + name_offset + 3] = replacement
                struct.pack_into("<H", raw, pos + flag_offset, 0x800)
            self.zip.write_bytes(raw)
            self.run_helper("extract", self.zip, self.dest, code=1)
            self.assertFalse(self.dest.exists())

    def test_long_unicode_destination(self):
        self.archive()
        self.dest = self.root / "日本語 path" / ("long" * 40) / ("path" * 40) / "ghidra"
        self.run_helper("extract", self.zip, self.dest)
        self.assertEqual((self.dest / "ghidraRun.bat").read_bytes(), b"run")
        self.run_helper("remove", self.dest, self.zip)

    def win_api(self):
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                       ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                       wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        kernel.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
        kernel.GetFileAttributesW.restype = wintypes.DWORD
        kernel.CreateSymbolicLinkW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                              wintypes.DWORD]
        kernel.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                           ctypes.c_void_p, wintypes.DWORD,
                                           ctypes.c_void_p, wintypes.DWORD,
                                           ctypes.c_void_p, ctypes.c_void_p]
        return kernel

    def lock(self, path, directory=False):
        kernel = self.win_api()
        handle = kernel.CreateFileW(str(path), 0x80, 3, None, 3,
                                    0x02200000 if directory else 0, None)
        self.assertNotEqual(handle, -1 & ((1 << (8 * struct.calcsize("P"))) - 1))
        return kernel, handle

    def require_directory_rename_sharing(self):
        probe = self.root / "share-probe"
        moved = self.root / "share-probe-moved"
        probe.mkdir()
        kernel, handle = self.lock(probe, directory=True)
        try:
            if kernel.MoveFileExW(str(probe), str(moved), 0):
                self.skipTest("runtime does not enforce directory rename sharing")
        finally:
            kernel.CloseHandle(handle)

    def directory_link(self, link, target):
        import ctypes
        kernel = self.win_api()
        kernel.CreateSymbolicLinkW(str(link), str(target), 3)
        attrs = kernel.GetFileAttributesW(str(link))
        if attrs != 0xFFFFFFFF and attrs & 0x400:
            return True
        # Some Wine versions stub CreateSymbolicLinkW, but implement junctions.
        link.mkdir(exist_ok=True)
        substitute = ("\\??\\" + str(target)).encode("utf-16-le")
        display = str(target).encode("utf-16-le")
        names = substitute + b"\0\0" + display + b"\0\0"
        data = struct.pack("<IHHHHHH", 0xA0000003, 8 + len(names), 0,
                           0, len(substitute), len(substitute) + 2, len(display)) + names
        buffer = ctypes.create_string_buffer(data)
        returned = ctypes.c_ulong()
        handle = kernel.CreateFileW(str(link), 0x40000000, 0, None, 3, 0x02200000, None)
        try:
            if not kernel.DeviceIoControl(handle, 0x900A4, buffer, len(data),
                                           None, 0, ctypes.byref(returned), None):
                return False
        finally:
            kernel.CloseHandle(handle)
        attrs = kernel.GetFileAttributesW(str(link))
        return attrs != 0xFFFFFFFF and bool(attrs & 0x400)

    @unittest.skipUnless(WINDOWS, "requires Win32 handle sharing")
    def test_atomic_owner_marker_failure_preserves_previous_marker(self):
        self.archive()
        self.run_helper("extract", self.zip, self.dest, "old")
        before = self.marker()
        kernel, handle = self.lock(self.dest / MARKER)
        try:
            self.run_helper("extract", self.zip, self.dest, "new", code=1)
            self.assertEqual(self.marker(), before)
            self.assertFalse(list(self.dest.glob(".marker-*")))
        finally:
            kernel.CloseHandle(handle)

    @unittest.skipUnless(WINDOWS, "requires Win32 directory handle sharing")
    def test_backup_rename_failure_preserves_original(self):
        self.require_directory_rename_sharing()
        self.archive()
        self.run_helper("extract", self.zip, self.dest)
        self.archive([("bundle/new", b"new")])
        before = self.marker()
        kernel, handle = self.lock(self.dest, directory=True)
        try:
            self.run_helper("extract", self.zip, self.dest, code=1)
            self.assertEqual(self.marker(), before)
            self.assertEqual((self.dest / "support/x.txt").read_bytes(), b"first")
            self.assert_no_staging()
        finally:
            kernel.CloseHandle(handle)

    @unittest.skipUnless(WINDOWS, "requires Win32 directory handle sharing")
    def test_failed_install_rename_rolls_original_back(self):
        self.require_directory_rename_sharing()
        self.archive()
        self.run_helper("extract", self.zip, self.dest)
        before = self.marker()
        self.archive([("bundle/ghidraRun.bat", b"new"),
                      ("bundle/slow.bin", b"x" * (64 * 1024 * 1024))])
        process = subprocess.Popen(self.command("extract", self.zip, self.dest),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        kernel = handle = None
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and process.poll() is None:
                candidates = list(self.root.glob(".extract-*/bundle"))
                if candidates:
                    kernel, handle = self.lock(candidates[0], directory=True)
                    break
                time.sleep(0.001)
            self.assertIsNotNone(handle, "did not acquire staged-root rename lock")
            stdout, stderr = process.communicate(timeout=90)
            self.assertEqual(process.returncode, 1, stdout + stderr)
            self.assertIn(b"Installing staged extraction", stderr)
            self.assertIn(b"Staging cleanup failed", stderr)
            self.assertEqual(self.marker(), before)
            self.assertEqual((self.dest / "support/x.txt").read_bytes(), b"first")
            self.assertFalse(list(self.root.glob(".old-*")))
        finally:
            if handle is not None:
                kernel.CloseHandle(handle)
            if process.poll() is None:
                process.kill()
                process.communicate()

    @unittest.skipUnless(WINDOWS, "requires Windows reparse-point creation")
    def test_reparse_ancestors_refused_and_child_links_not_followed(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "keep").write_bytes(b"untouched")
        link = self.root / "link"
        if not self.directory_link(link, outside):
            self.skipTest("runtime cannot create a real directory symlink or junction")
        self.archive()
        self.run_helper("extract", self.zip, link / "dest", code=1)
        self.run_helper("remove", link, code=1)
        self.dest.mkdir()
        child = self.dest / "child"
        self.assertTrue(self.directory_link(child, outside))
        self.run_helper("remove", self.dest)
        self.assertEqual((outside / "keep").read_bytes(), b"untouched")
        self.assertFalse(self.dest.exists())

    @unittest.skipUnless(FAULT_EXE, "set C_HELPER_FAULT_EXE for deterministic fault tests")
    def test_deterministic_backup_install_rollback_and_cleanup_failures(self):
        for failure in ["backup", "install", "rollback", "cleanup"]:
            with self.subTest(failure=failure):
                self.archive()
                self.run_helper("extract", self.zip, self.dest, "old")
                before = self.marker()
                self.archive([("bundle/new", b"replacement")])
                env = os.environ.copy()
                env["C_HELPER_TEST_FAILURE"] = failure
                result = subprocess.run(
                    self.command("extract", self.zip, self.dest, "new", exe=FAULT_EXE),
                    capture_output=True, timeout=90, env=env)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertTrue(result.stderr)
                backups = list(self.root.glob(".old-*"))
                if failure == "rollback":
                    self.assertIn(b"ROLLBACK FAILED", result.stderr)
                    self.assertFalse(self.dest.exists())
                    self.assertEqual(len(backups), 1)
                    self.assertEqual((backups[0] / MARKER).read_bytes(), before)
                    self.assertEqual((backups[0] / "support/x.txt").read_bytes(), b"first")
                elif failure == "cleanup":
                    self.assertIn(b"backup cleanup failed", result.stderr)
                    self.assertEqual((self.dest / "new").read_bytes(), b"replacement")
                    self.assertEqual(len(backups), 1)
                else:
                    self.assertEqual(self.marker(), before)
                    self.assertEqual((self.dest / "support/x.txt").read_bytes(), b"first")
                    self.assertFalse(backups)
                self.assertFalse(list(self.root.glob(".extract-*")))
                if self.dest.exists():
                    shutil.rmtree(self.dest)
                for backup in backups:
                    shutil.rmtree(backup)

    @unittest.skipUnless(PEER_EXE, "set C_HELPER_PEER_EXE for C/Rust interoperability")
    def test_peer_helper_owner_marker_interoperability(self):
        def peer(*args):
            result = subprocess.run(self.command(*args, exe=PEER_EXE),
                                    capture_output=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        old = "1.0.0-C-{1111}"
        new = "1.0.0-Rust-{2222}"
        replacement = "1.0.0-C-{3333}"
        self.archive()
        self.run_helper("extract", self.zip, self.dest, old)
        (self.dest / "support/x.txt").write_bytes(b"user content")
        peer("extract", self.zip, self.dest, new)
        self.assertEqual(self.marker(), (self.hash() + "\nowner=" + new + "\n").encode())
        self.run_helper("remove", self.dest, self.zip, old)
        self.run_helper("remove", self.dest)
        peer("remove", self.dest, self.zip)
        self.assertTrue(self.dest.exists())
        self.run_helper("extract", self.zip, self.dest, replacement)
        peer("extract", self.zip, self.dest)
        self.assertEqual(self.marker(), (self.hash() + "\nowner=" + replacement + "\n").encode())
        peer("remove", self.dest, self.zip, new)
        self.assertEqual((self.dest / "support/x.txt").read_bytes(), b"user content")
        self.run_helper("remove", self.dest, self.zip, replacement)
        self.assertFalse(self.dest.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
