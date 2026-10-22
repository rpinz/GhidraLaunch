# Native C Ghidra helper

Build from a Visual Studio 2022 Developer Command Prompt (Desktop development
with C++, v143 and the Windows SDK):

```
msbuild GhidraLaunchGhidraHelperC.vcxproj /p:Configuration=Release /p:Platform=x64
```

Debug and Release use C17, the static MSVC CRT (`/MTd` and `/MT`), a Unicode
console entry point, and Windows CNG (`bcrypt.lib`). Output is always relative
to this project, including when built standalone:

```
x64\<Configuration>\bin\GhidraLaunchGhidraHelperC.exe
```

No .NET, PowerShell, unzip executable, or runtime third-party DLL is required.
`helper.rc` uses `../Resources/Version.h`; the helper has its own version
resource, independent of the launcher resource script.

## Commands and ownership

```
GhidraLaunchGhidraHelperC extract <zip> <dest> [owner]
GhidraLaunchGhidraHelperC remove <dest> [zip] [owner]
GhidraLaunchGhidraHelperC remove <dest> "" <owner>
```

Verbs are case-insensitive. Exit codes: 0 success or deliberate skip, 1 failure
(stderr), 2 invalid usage. Skip reasons are written to stdout.

Owner tokens contain 1–128 ASCII letters, digits, dots, underscores, hyphens or
curly braces. Bundle callers should use version, variant and provider identity,
e.g. `1.0.0-C-{GUID}` / `1.0.0-Rust-{GUID}`. A same-source extract preserves the
contents but atomically replaces the marker when a different owner is supplied.
Without an owner it preserves an existing owner. This prevents a same-version
old bundle uninstall from deleting the replacement bundle's tree.

The C/Rust interchange format for `.ghidralaunch-source.sha256` is ASCII:

* Standalone: exactly 64 lowercase SHA-256 hex digits, no newline.
* Owned: `64hex\nowner=<token>\n` (LF line endings).

Reading also accepts uppercase hashes, CRLF and a final newline on legacy
plain hashes. Hash comparisons use only the first line. Owner comparisons are
case-sensitive. Remove with an owner requires that owner and, when supplied,
the source hash to match. Remove without an owner skips all owned trees.
Missing/malformed markers cannot authorize source-aware or owner-aware removal.
Ownerless, sourceless removal still supports an unmarked ordinary directory.
The managed helper compares the entire marker, so it cannot match an owned one.

## Safety and behavior

Stored/deflate and ZIP64 archives stream through the pinned miniz reader.
Names are decoded as strict UTF-8 when flagged, otherwise CP437. Before writing
any entries, validation rejects rooted/device/drive/UNC paths, traversal using
either separator, ADS and invalid Windows characters, empty components, trailing
dots/spaces, reserved devices, symlinks/special files/reparse attributes,
duplicate entries, case aliases (including implicit parent directories), and
file/directory conflicts. No artificial expanded-size or entry-count limit is
imposed beyond platform and miniz format/address-space limits.

Extraction takes place in a cryptographically random sibling directory, strips
exactly one sole top-level directory, and writes the marker before swapping.
Only after successful validation, extraction, CRC checking and marker creation
is the original renamed to a sibling backup. A failed install rename restores
the backup; a failed restoration reports the backup's location and preserves it.
Cleanup failures return 1 with diagnostics rather than pretending success.
Marker updates use a new flushed file and atomic replacement.

Existing destination ancestors must not be reparse points. Recursive deletion
unlinks child reparse entries without traversing them, and pins ordinary
directories against rename during enumeration. As with ordinary Win32
path-based installers, use a parent directory whose ACL does not allow
untrusted concurrent writers; this is not an adversarial filesystem-race
sandbox. A reparse-point destination itself is rejected.

## Focused validation

`../tests/test_c_helper.py` requires a built helper and an explicit scratch
artifact directory **outside the checkout**:

```
set C_HELPER_EXE=C:\src\GhidraLaunch\GhidraLaunchGhidraHelperC\x64\Release\bin\GhidraLaunchGhidraHelperC.exe
set C_HELPER_TEST_ROOT=C:\artifacts\c-helper-tests
python ..\tests\test_c_helper.py
```

On Linux the same tests run through Wine (set `C_HELPER_WINE=wine`); native
Windows Python, including Python running under Wine, additionally exercises
Win32 directory locks, atomic marker replacement failures and reparse handling.
Fixtures are isolated under the explicit artifact directory and removed after
each test. The tests never download dependencies.

For deterministic backup/install/rollback/cleanup failure tests, build
`tests/faults.c` **instead of** `main.c`, using the same compiler flags and miniz
sources. Set `C_HELPER_FAULT_EXE` to that separate test executable. The production
project does not compile the driver and has no runtime fault-injection hooks.
Wine does not necessarily implement directory sharing or symlink creation;
the Win32-specific tests capability-check these behaviors and explicitly skip
unsupported operations instead of accepting a successful no-op API result.
Optionally set `C_HELPER_PEER_EXE` to the Rust helper to verify actual
cross-implementation marker ownership transfer, stale removal protection,
ownerless preservation and matching-owner removal.
