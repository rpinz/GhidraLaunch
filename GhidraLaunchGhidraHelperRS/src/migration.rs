//! Legacy bundle migration: exact identity matching, preflight, and running cached legacy
//! uninstallers while the incoming tree is moved out of their reach.

use crate::fs_safety::{
    DestinationLock, is_reparse_point, reject_reparse_ancestors, sibling_parent,
    unique_sibling_path, validate_destination_path,
};
#[cfg(windows)]
use crate::fs_safety::{comparable_path, to_wide_verbatim};
#[cfg(test)]
use crate::hooks::TEST_HOOKS;
use crate::hooks::fault;
#[cfg(all(windows, not(test)))]
use crate::registry::manages_owner_record;
use crate::registry::set_owner_record;
use crate::state::{MARKER_NAME, read_marker, validate_owner};
use std::collections::BTreeMap;
use std::fs;
use std::io;
// Only the native (non-test) legacy process runner creates logs in the temp directory.
use std::path::{Component, Path, PathBuf};
#[cfg(not(test))]
use std::{env, fs::OpenOptions};

pub(crate) const LEGACY_FAMILY: &str = "{DFE05126-B29E-4298-A06B-63F833BC0BF8}";

#[derive(Debug, Clone, Default)]
pub(crate) struct LegacyRegistration {
    pub(crate) location: String,
    pub(crate) name: Option<String>,
    pub(crate) publisher: Option<String>,
    pub(crate) upgrade_codes: Vec<String>,
    pub(crate) version: Option<String>,
    pub(crate) cache: Option<String>,
}

impl LegacyRegistration {
    pub(crate) fn is_ghidra_legacy(&self) -> bool {
        self.name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case("Ghidra Launch"))
            && self
                .publisher
                .as_deref()
                .is_some_and(|publisher| publisher.eq_ignore_ascii_case("rpinz"))
            && self
                .upgrade_codes
                .iter()
                .any(|code| code.eq_ignore_ascii_case(LEGACY_FAMILY))
    }
}

pub(crate) fn parse_release_version(text: &str) -> Option<[u32; 4]> {
    let parts: Vec<_> = text.split('.').collect();
    if !(3..=4).contains(&parts.len()) {
        return None;
    }
    let mut version = [0; 4];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        version[index] = part.parse().ok()?;
    }
    Some(version)
}

pub(crate) fn validate_migration_destination(dest: &Path) -> Result<(), String> {
    #[cfg(test)]
    let managed = TEST_HOOKS.with(|hooks| hooks.borrow().owner_dest.as_deref() == Some(dest));
    #[cfg(all(windows, not(test)))]
    let managed = dest.is_absolute() && manages_owner_record(dest);
    #[cfg(all(not(windows), not(test)))]
    let managed = false;
    if !managed {
        return Err(
            "legacy migration is restricted to the managed LOCALAPPDATA\\Ghidra Launch\\Ghidra destination"
                .into(),
        );
    }
    Ok(())
}

fn validate_legacy_cache(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || !path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        || path.components().any(|component| match component {
            Component::CurDir | Component::ParentDir => true,
            Component::Normal(name) => name.as_encoded_bytes().contains(&b':'),
            _ => false,
        })
    {
        return Err("BundleCachePath must name an absolute ordinary executable (.exe)".into());
    }
    reject_reparse_ancestors(sibling_parent(path))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot access BundleCachePath {}: {error}", path.display()))?;
    if !metadata.is_file() || is_reparse_point(path).map_err(|error| error.to_string())? {
        return Err(format!(
            "BundleCachePath is not an ordinary file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn preflight_legacy(
    registrations: &[LegacyRegistration],
    incoming: [u32; 4],
) -> Result<Vec<PathBuf>, String> {
    let mut caches = BTreeMap::new();
    for record in registrations
        .iter()
        .filter(|record| record.is_ghidra_legacy())
    {
        let context = || format!("genuine legacy Ghidra registration {}", record.location);
        let version = record
            .version
            .as_deref()
            .and_then(parse_release_version)
            .ok_or_else(|| {
                format!(
                    "{} has missing or invalid BundleVersion; repair its installation before retrying",
                    context()
                )
            })?;
        if version > incoming {
            return Err(format!(
                "{} is newer than this release (BundleVersion {}); install an equal or newer release instead",
                context(),
                record.version.as_deref().unwrap_or_default()
            ));
        }
        let cache = record
            .cache
            .as_deref()
            .filter(|path| !path.is_empty())
            .ok_or_else(|| {
                format!(
                    "{} has no BundleCachePath; repair its installation before retrying",
                    context()
                )
            })?;
        let cache = PathBuf::from(cache);
        validate_legacy_cache(&cache).map_err(|error| {
            format!(
                "{}: {error}; restore its cached installer or repair its installation before retrying",
                context()
            )
        })?;
        #[cfg(windows)]
        let key = comparable_path(&cache);
        #[cfg(not(windows))]
        let key = cache.clone().into_os_string();
        caches.entry(key).or_insert(cache);
    }
    Ok(caches.into_values().collect())
}

fn rename_legacy_tree(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
        let source = to_wide_verbatim(source)?;
        let destination = to_wide_verbatim(destination)?;
        // SAFETY: both paths are NUL-terminated wide strings that outlive the call.
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        if fs::symlink_metadata(destination).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "destination exists",
            ));
        }
        fs::rename(source, destination)
    }
}

fn preserve_legacy_payload(dest: &Path) -> Result<PathBuf, String> {
    for _ in 0..128 {
        let backup = unique_sibling_path(sibling_parent(dest), dest, "legacy");
        match fs::symlink_metadata(&backup) {
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", backup.display())),
        }
        rename_legacy_tree(dest, &backup)
            .map_err(|error| format!("cannot preserve incoming payload: {error}"))?;
        return Ok(backup);
    }
    Err("cannot allocate a unique legacy migration backup".into())
}

fn restore_legacy_payload(dest: &Path, backup: &Path) -> Result<DestinationLock, String> {
    let lock = fault("legacy-relock")
        .map_err(|error| error.to_string())
        .and_then(|()| DestinationLock::acquire(dest))?;
    validate_destination_path(sibling_parent(dest))?;
    match fs::symlink_metadata(dest) {
        Ok(_) => {
            return Err(format!(
                "unexpected destination {}; refusing to overwrite it",
                dest.display()
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect destination: {error}")),
    }
    fault("legacy-restore")
        .and_then(|()| rename_legacy_tree(backup, dest))
        .map_err(|error| format!("cannot restore incoming payload: {error}"))?;
    Ok(lock)
}

pub(crate) fn migrate_legacy_records(
    dest: &Path,
    owner: &str,
    incoming: [u32; 4],
    registrations: &[LegacyRegistration],
    mut runner: impl FnMut(&Path, &str) -> Result<i32, String>,
) -> Result<i32, String> {
    validate_owner(owner)?;
    validate_migration_destination(dest)?;
    let caches = preflight_legacy(registrations, incoming)?;
    if caches.is_empty() {
        return Ok(0);
    }
    validate_destination_path(dest)?;
    let lock = DestinationLock::acquire(dest)?;
    validate_destination_path(dest)?;
    let marker = read_marker(&dest.join(MARKER_NAME)).ok_or(
        "incoming payload has no valid source marker; extract this release before migration",
    )?;
    if marker.owner.as_deref() != Some(owner) {
        return Err("incoming payload owner does not match the migration owner; extract/adopt this release before migration".into());
    }
    let backup = preserve_legacy_payload(dest)?;
    // Old helpers lock this path even when absent. Never expose the incoming
    // tree (or its backup path) to those uninstallers.
    drop(lock);
    let result = (|| {
        let mut reboot = false;
        for cache in &caches {
            match runner(cache, owner)? {
                0 => {}
                3010 => reboot = true,
                code => {
                    return Err(format!(
                        "legacy uninstaller {} failed with exit code {code}",
                        cache.display()
                    ));
                }
            }
        }
        Ok(if reboot { 3010 } else { 0 })
    })();
    let _lock = restore_legacy_payload(dest, &backup).map_err(|error| {
        let operation = result.as_ref().err().map_or(String::new(), |error| format!("{error}; "));
        format!(
            "{operation}{error}. Incoming payload remains intact at {}; restore it to {} after resolving the conflict",
            backup.display(),
            dest.display()
        )
    })?;
    // A same-owner legacy helper can clear the ownership record while the
    // destination is absent. Reassert the restored incoming tree's ownership.
    set_owner_record(dest, owner).map_err(|error| {
        let operation = result.as_ref().err().map_or(String::new(), |error| format!("{error}; "));
        format!("{operation}incoming payload was restored, but its ownership record could not be restored: {error}")
    })?;
    result
}

fn legacy_uninstall_command(cache: &Path, owner: &str, log: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(cache);
    // Related-upgrade mode bypasses bundle blocking without disabling the
    // package dependency checks that protect the incoming Core's shared MSI.
    command
        .args([
            "/uninstall",
            "/quiet",
            "/norestart",
            "-burn.related.upgrade",
            "-parent",
        ])
        .arg(owner)
        .arg("/log")
        .arg(log);
    command
}

pub(crate) fn run_legacy_uninstaller(cache: &Path, owner: &str) -> Result<i32, String> {
    #[cfg(test)]
    {
        let _ = (cache, owner);
        Err("unit tests must inject a legacy process runner; native execution is forbidden".into())
    }
    #[cfg(not(test))]
    {
        validate_owner(owner)?;
        // Recheck immediately before launch as an earlier selected bundle may
        // have removed a shared cache. Never fall back to an uninstall string.
        validate_legacy_cache(cache)?;
        let log_root = env::temp_dir();
        reject_reparse_ancestors(&log_root)?;
        let log = (0..128)
            .find_map(|_| {
                let mut name = unique_sibling_path(&log_root, Path::new("GhidraLaunch"), "legacy")
                    .into_os_string();
                name.push(".log");
                let path = PathBuf::from(name);
                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(_) => Some(Ok(path)),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                    Err(error) => Some(Err(format!("cannot create legacy uninstall log: {error}"))),
                }
            })
            .unwrap_or_else(|| Err("cannot allocate a unique legacy uninstall log".into()))?;
        let status = legacy_uninstall_command(cache, owner, &log)
            .status()
            .map_err(|error| {
                format!(
                    "cannot run legacy uninstaller {} (log {}): {error}",
                    cache.display(),
                    log.display()
                )
            })?;
        println!("Legacy uninstall log: {}", log.display());
        status.code().ok_or_else(|| {
            format!(
                "legacy uninstaller {} terminated without an exit code (log {})",
                cache.display(),
                log.display()
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::LegacyRegistryValue;
    use crate::remove::remove;
    use crate::state::scan_tree;
    use crate::test_support::{Fixture, legacy_record, legacy_registry_bytes, migration_backups};
    use std::collections::BTreeSet;
    use std::ffi::OsStr;

    #[test]
    fn migration_malformed_raw_registry_identities_never_become_candidates() {
        let mut records = Vec::new();
        for (name, publisher) in [
            (
                LegacyRegistryValue::String(legacy_registry_bytes("\0Ghidra Launch\0")),
                LegacyRegistryValue::String(legacy_registry_bytes("rpinz\0")),
            ),
            (
                LegacyRegistryValue::MultiString(legacy_registry_bytes("Ghidra Launch\0\0")),
                LegacyRegistryValue::String(legacy_registry_bytes("rpinz\0")),
            ),
            (
                LegacyRegistryValue::String(legacy_registry_bytes("Ghidra Launch\0")),
                LegacyRegistryValue::String(legacy_registry_bytes("\0rpinz\0")),
            ),
            (
                LegacyRegistryValue::String(legacy_registry_bytes("Ghidra Launch\0")),
                LegacyRegistryValue::MultiString(legacy_registry_bytes("rpinz\0\0")),
            ),
        ] {
            let mut record =
                legacy_record(Path::new("must-not-access.exe"), "invalid foreign version");
            record.name = name.scalar();
            record.publisher = publisher.scalar();
            records.push(record);
        }
        for data in [
            legacy_registry_bytes(&format!("\0{LEGACY_FAMILY}\0\0")),
            legacy_registry_bytes(&format!("{LEGACY_FAMILY}\0")),
            legacy_registry_bytes(&format!("{LEGACY_FAMILY}\0\0\0")),
        ] {
            let mut record =
                legacy_record(Path::new("must-not-access.exe"), "invalid foreign version");
            record.upgrade_codes = LegacyRegistryValue::MultiString(data)
                .upgrade_codes()
                .unwrap_or_default();
            records.push(record);
        }
        assert_eq!(
            preflight_legacy(&records, [1, 0, 0, 0]).unwrap(),
            Vec::<PathBuf>::new()
        );
    }

    #[test]
    fn migration_ignores_foreign_identity_before_version_and_cache_checks() {
        let fixture = Fixture::new("migration-foreign");
        let mut records = Vec::new();
        for version in ["999.0.0.0", "foreign-invalid-version"] {
            let record = legacy_record(Path::new("missing.exe"), version);
            for name in ["Other application", "Ghidra Launch extra", "Ghidra Launch "] {
                let mut foreign = record.clone();
                foreign.name = Some(name.into());
                records.push(foreign);
            }
            let mut foreign = record.clone();
            foreign.publisher = Some("another publisher".into());
            records.push(foreign);
            let mut foreign = record.clone();
            foreign.upgrade_codes = vec![format!("prefix{LEGACY_FAMILY}suffix")];
            records.push(foreign);
            let mut foreign = record.clone();
            foreign.upgrade_codes = vec!["{D2557D9A-CD4F-4AD2-B84A-0289EF4208DE}".into()];
            records.push(foreign);
            let mut foreign = record.clone();
            foreign.name = None;
            records.push(foreign);
            let mut foreign = record;
            foreign.publisher = None;
            records.push(foreign);
        }
        let before = fs::read_dir(&fixture.root).unwrap().count();
        assert_eq!(
            migrate_legacy_records(&fixture.dest, "incoming", [1, 2, 3, 0], &records, |_, _| {
                panic!("foreign bundle must never run")
            })
            .unwrap(),
            0
        );
        assert!(!fixture.dest.exists());
        assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), before);
    }

    #[test]
    fn migration_selects_all_scopes_and_views_deduplicates_and_preserves_incoming_tree() {
        let fixture = Fixture::new("migration-views");
        fixture.install();
        fs::write(fixture.dest.join("user-data-測試.txt"), "keep these bytes").unwrap();
        let before = scan_tree(&fixture.dest, true).unwrap();
        let mut records = Vec::new();
        for (index, location) in ["HKCU32", "HKCU64", "HKLM32", "HKLM64"].iter().enumerate() {
            let cache = fixture.root.join(format!("cached bundle {index}.exe"));
            fs::write(&cache, "fake cache; never execute").unwrap();
            let mut record =
                legacy_record(&cache, if index % 2 == 0 { "1.0.0" } else { "1.2.3.0" });
            record.location = (*location).into();
            record.name = Some("gHiDrA lAuNcH".into());
            record.publisher = Some("RPINZ".into());
            record.upgrade_codes = vec!["another-family".into(), LEGACY_FAMILY.to_lowercase()];
            records.push(record.clone());
            records.push(record);
        }
        let mut calls = BTreeSet::new();
        assert_eq!(
            migrate_legacy_records(
                &fixture.dest,
                "old-owner",
                [1, 2, 3, 0],
                &records,
                |cache, parent| {
                    assert_eq!(parent, "old-owner");
                    assert!(calls.insert(cache.to_path_buf()), "duplicate uninstaller");
                    assert!(!fixture.dest.exists());
                    let backups = migration_backups(&fixture);
                    assert_eq!(backups.len(), 1);
                    assert_eq!(scan_tree(&backups[0], true).unwrap(), before);
                    // This simulates the old helper's absent-tree removal path,
                    // including its destination lock and same-owner record clear.
                    remove(&fixture.dest, None, Some("old-owner")).unwrap();
                    assert_eq!(fixture.record(), None);
                    Ok(0)
                }
            )
            .unwrap(),
            0
        );
        assert_eq!(calls.len(), 4);
        assert_eq!(scan_tree(&fixture.dest, true).unwrap(), before);
        assert_eq!(fixture.record().as_deref(), Some("old-owner"));
        assert_eq!(migration_backups(&fixture), Vec::<PathBuf>::new());
        DestinationLock::acquire(&fixture.dest).unwrap();
    }

    #[test]
    fn migration_preflights_every_genuine_candidate_and_rejects_downgrade_or_bad_cache() {
        let fixture = Fixture::new("migration-preflight");
        fixture.install();
        let cache = fixture.root.join("valid.exe");
        fs::write(&cache, "fake cache; never execute").unwrap();
        let valid = legacy_record(&cache, "1.0.0");
        let mut cases = vec![
            legacy_record(&cache, "1.2.3.1"),
            legacy_record(&cache, "invalid"),
        ];
        let mut missing_version = valid.clone();
        missing_version.version = None;
        cases.push(missing_version);
        cases.push(legacy_record(&fixture.root.join("missing.exe"), "1.0.0"));
        cases.push(legacy_record(Path::new("relative.exe"), "1.0.0"));
        let directory = fixture.root.join("directory.exe");
        fs::create_dir(&directory).unwrap();
        cases.push(legacy_record(&directory, "1.0.0"));
        let mut missing_cache = valid.clone();
        missing_cache.cache = None;
        cases.push(missing_cache);
        let before = scan_tree(&fixture.dest, true).unwrap();
        for invalid in cases {
            let expected = if invalid.version.as_deref() == Some("1.2.3.1") {
                "newer"
            } else if invalid.version.as_deref() == Some("invalid") || invalid.version.is_none() {
                "BundleVersion"
            } else {
                "BundleCachePath"
            };
            let error = migrate_legacy_records(
                &fixture.dest,
                "old-owner",
                [1, 2, 3, 0],
                &[valid.clone(), invalid],
                |_, _| panic!("all candidates must pass preflight before any child runs"),
            )
            .unwrap_err();
            assert!(error.contains(expected), "{error}");
            assert_eq!(scan_tree(&fixture.dest, true).unwrap(), before);
            assert_eq!(migration_backups(&fixture), Vec::<PathBuf>::new());
        }
    }

    #[test]
    fn migration_requires_incoming_marker_owner_and_managed_destination() {
        let fixture = Fixture::new("migration-owner");
        fixture.install();
        let cache = fixture.root.join("valid.exe");
        fs::write(&cache, "fake cache; never execute").unwrap();
        let records = [legacy_record(&cache, "1.0.0")];
        let before = scan_tree(&fixture.dest, true).unwrap();
        let error = migrate_legacy_records(
            &fixture.dest,
            "wrong-owner",
            [1, 0, 0, 0],
            &records,
            |_, _| panic!("owner mismatch must not launch"),
        )
        .unwrap_err();
        assert!(error.contains("owner"), "{error}");
        assert_eq!(scan_tree(&fixture.dest, true).unwrap(), before);
        fs::remove_file(fixture.dest.join(MARKER_NAME)).unwrap();
        assert!(
            migrate_legacy_records(
                &fixture.dest,
                "old-owner",
                [1, 0, 0, 0],
                &records,
                |_, _| { panic!("missing marker must not launch") }
            )
            .unwrap_err()
            .contains("marker")
        );
        assert!(
            migrate_legacy_records(
                &fixture.root.join("not-managed"),
                "old-owner",
                [1, 0, 0, 0],
                &[],
                |_, _| panic!("unmanaged destination must not launch"),
            )
            .unwrap_err()
            .contains("restricted")
        );
        assert_eq!(migration_backups(&fixture), Vec::<PathBuf>::new());
    }

    #[test]
    fn migration_restores_payload_after_child_failure_spawn_error_and_reboot() {
        for outcome in [Ok(3010), Ok(1603), Err("injected spawn failure".to_owned())] {
            let fixture = Fixture::new("migration-child-result");
            fixture.install();
            fs::write(fixture.dest.join("user-modification"), "retain").unwrap();
            let before = scan_tree(&fixture.dest, true).unwrap();
            let cache = fixture.root.join("valid.exe");
            fs::write(&cache, "fake cache; never execute").unwrap();
            let result = migrate_legacy_records(
                &fixture.dest,
                "old-owner",
                [1, 0, 0, 0],
                &[legacy_record(&cache, "1.0.0")],
                |_, parent| {
                    assert_eq!(parent, "old-owner");
                    assert!(!fixture.dest.exists());
                    DestinationLock::acquire(&fixture.dest).unwrap();
                    outcome.clone()
                },
            );
            match outcome {
                Ok(3010) => assert_eq!(result.unwrap(), 3010),
                Ok(1603) => assert!(result.unwrap_err().contains("1603")),
                Err(error) => assert!(result.unwrap_err().contains(&error)),
                _ => unreachable!(),
            }
            assert_eq!(scan_tree(&fixture.dest, true).unwrap(), before);
            assert_eq!(migration_backups(&fixture), Vec::<PathBuf>::new());
        }
    }

    #[test]
    fn migration_restore_failure_reports_exact_intact_backup() {
        for fault in ["legacy-relock", "legacy-restore"] {
            let fixture = Fixture::new("migration-restore-fault");
            fixture.install();
            let before = scan_tree(&fixture.dest, true).unwrap();
            let cache = fixture.root.join("valid.exe");
            fs::write(&cache, "fake cache; never execute").unwrap();
            fixture.inject(fault, 0);
            let error = migrate_legacy_records(
                &fixture.dest,
                "old-owner",
                [1, 0, 0, 0],
                &[legacy_record(&cache, "1.0.0")],
                |_, parent| {
                    assert_eq!(parent, "old-owner");
                    Ok(0)
                },
            )
            .unwrap_err();
            assert!(!fixture.dest.exists());
            let backups = migration_backups(&fixture);
            assert_eq!(backups.len(), 1);
            assert_eq!(scan_tree(&backups[0], true).unwrap(), before);
            assert!(error.contains(backups[0].to_str().unwrap()), "{error}");
            assert!(error.contains("intact"), "{error}");
        }
    }

    #[test]
    fn migration_never_overwrites_unexpected_destination_and_retains_child_error() {
        let fixture = Fixture::new("migration-collision");
        fixture.install();
        let before = scan_tree(&fixture.dest, true).unwrap();
        let cache = fixture.root.join("valid.exe");
        fs::write(&cache, "fake cache; never execute").unwrap();
        let error = migrate_legacy_records(
            &fixture.dest,
            "old-owner",
            [1, 0, 0, 0],
            &[legacy_record(&cache, "1.0.0")],
            |_, parent| {
                assert_eq!(parent, "old-owner");
                assert!(!fixture.dest.exists());
                fs::create_dir(&fixture.dest).unwrap();
                fs::write(fixture.dest.join("unexpected"), "do not replace").unwrap();
                Ok(1603)
            },
        )
        .unwrap_err();
        assert_eq!(
            fs::read(fixture.dest.join("unexpected")).unwrap(),
            b"do not replace"
        );
        let backups = migration_backups(&fixture);
        assert_eq!(backups.len(), 1);
        assert_eq!(scan_tree(&backups[0], true).unwrap(), before);
        assert!(error.contains(backups[0].to_str().unwrap()), "{error}");
        assert!(error.contains("refusing to overwrite"), "{error}");
        assert!(error.contains("1603"), "{error}");
    }

    #[test]
    fn migration_command_uses_exact_program_and_independent_windows_arguments() {
        let executable = Path::new(r"C:\cache with spaces\測試 & bundle.exe");
        let log = Path::new(r#"C:\user logs\quoted " value\legacy.log"#);
        let owner = "{FEEDFACE-0000-4000-8000-0000000000B6}";
        let command = legacy_uninstall_command(executable, owner, log);
        assert_eq!(command.get_program(), executable.as_os_str());
        let arguments: Vec<_> = command.get_args().collect();
        assert_eq!(
            arguments,
            vec![
                OsStr::new("/uninstall"),
                OsStr::new("/quiet"),
                OsStr::new("/norestart"),
                OsStr::new("-burn.related.upgrade"),
                OsStr::new("-parent"),
                OsStr::new(owner),
                OsStr::new("/log"),
                log.as_os_str(),
            ]
        );
    }
}
