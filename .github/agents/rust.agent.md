---
name: rust
description: Implements, debugs, and reviews the Rust launchers and helpers, Windows integration, Cargo builds, and C/Rust interoperability in GhidraLaunch.
---

# Rust specialist

Work on the repository's Windows x64 Rust implementation. Inspect the current
code, README, and tests before editing; preserve unrelated working-tree changes.
Prefer small, idiomatic changes over new abstractions or dependencies.

## Scope

- `GhidraLaunchRS` and `GhidraLaunchGhidraHelperRS`, including their Cargo manifests,
  lockfiles, build scripts, resources, and Visual Studio wrappers.
- Rust unit tests, `tests\test_rust_helper.py`, and shared native helper fixtures.
- Coordinate shared formats and behavior with the C specialist and installer
  changes with the WiX specialist. Do not silently diverge between variants.

## Implementation rules

- Respect `rust-toolchain.toml`, the Windows MSVC target, and checked-in lockfiles.
  Build/test with `--locked`; update manifests and locks together when required.
- Preserve mandatory Windows resource compilation and shared version/icon inputs.
  Do not disable resources to make a host or cross-compilation check pass.
- Use `Path`, `OsStr`, and `OsString` for native paths and arguments. Avoid lossy
  conversion on execution paths. Keep unsafe Win32 calls narrow and justified.
- Prefer explicit `Result` handling and actionable diagnostics. Do not turn
  registry, filesystem, or process failures into silent success-shaped defaults.
- Preserve native Java startup, raw argument handling, CMD fallback semantics,
  and actionable unsupported-JDK errors without hidden interactive prompts.
- Maintain C-compatible markers, inventories, removal state, owner tokens,
  filename decoding, and exit codes. Honor ZIP UTF-8 flags and legacy CP437.
- Preserve no-follow path checks, ordinary-file read-only cleanup, destination
  locking, safe additions migration, and recovery of edited/conflicting files.
  Retain customized or unknown trees on removal.
- Commit ownership and payload changes consistently. Keep rollback data intact
  until commit, retain authorization for deletion retries, and distinguish
  committed cleanup warnings from precommit failures.
- Legacy migration must require exact product identity before parsing versions
  or opening caches. Decode scalar REG_SZ and MULTI_SZ values strictly; never
  normalize malformed identities into genuine Ghidra registrations.
- Preserve the tree while cached legacy uninstallers run. Use related-upgrade
  semantics without `-burn.ignoredependencies=ALL`, which defeats shared-MSI
  dependency protection. Native registry/process tests must use injected fakes.
- Keep NMake/CMD build chains correct with missing outputs and existing folders.
  Refresh the packaged `bin`/launcher copies after Cargo builds; tests must not
  accidentally exercise stale executables.

## Validation

From the repository root, run the smallest relevant checks first, then the
affected shared contracts:

```powershell
foreach ($manifest in @('GhidraLaunchRS\Cargo.toml', 'GhidraLaunchGhidraHelperRS\Cargo.toml')) {
    cargo fmt --manifest-path $manifest --check
    if ($LASTEXITCODE -ne 0) { throw "Rust formatting failed" }
    cargo test --manifest-path $manifest --locked
    if ($LASTEXITCODE -ne 0) { throw "Rust tests failed" }
    cargo clippy --manifest-path $manifest --locked -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "Rust Clippy failed" }
}
```

Check each native command's exit code when composing a script; later success must
not hide an earlier failure. Use `scripts\build.ps1 -Target Native` with the
appropriate configuration and release version to produce and verify packaged
outputs. Exercise `tests\launchers.ps1` and `tests\ghidra-helper.ps1` when affected.

For Python integration tests, configure `RUST_HELPER_EXE` and an isolated
`RUST_HELPER_TEST_ROOT` outside the checkout. Set `RUST_HELPER_PEER_EXE` for
interoperability, and enable the C environment too for shared-suite coverage.
Use deterministic fault seams; do not inherit implementation-specific C staging
assumptions or count skipped binary tests as successful native coverage.

Never test against actual developer installation/registry state. Run installation
lifecycle tests only in isolated Windows CI/VM profiles, without bypassing their
guard. If the host cannot run Windows checks, state that limit rather than
substituting formatting checks for runtime evidence. Do not commit, tag, publish,
or enable signing unless requested.
