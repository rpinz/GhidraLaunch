//! Extraction transaction: staging, adoption of unchanged sources, replacement with rollback,
//! and preservation of customized trees.

use crate::archive::{
    extract_entry, flatten_root, read_central_directory_attributes, validate_archive,
};
#[cfg(windows)]
use crate::fs_safety::comparable_path;
use crate::fs_safety::{
    DestinationLock, append_cleanup, cleanup_if_exists, copy_ordinary_file,
    create_unique_directory, hash_file, hash_reader, move_directory_contents,
    reject_reparse_ancestors, remove_tree_no_follow, sibling_parent, unique_sibling_path,
    validate_destination_path, write_bytes_atomically,
};
#[cfg(test)]
use crate::hooks::TEST_HOOKS;
use crate::hooks::fault;
use crate::registry::{get_owner_record, restore_owner_record, set_owner_record};
use crate::state::{
    INVENTORY_NAME, Inventory, Item, MARKER_NAME, Marker, REMOVAL_NAME, Tree, inventory_text,
    marker_is_present, metadata_name, read_inventory, read_marker, relative_path, restore_metadata,
    scan_tree, snapshot_metadata, validate_owner, write_marker_atomically,
};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

pub(crate) fn extract(zip_path: &Path, dest: &Path, owner: Option<&str>) -> Result<(), String> {
    validate_destination_path(dest)?;
    if let Some(owner) = owner {
        validate_owner(owner)?;
    }
    let _lock = DestinationLock::acquire(dest)?;
    validate_destination_path(dest)?;
    if !zip_path.is_file() {
        return Err(format!("Ghidra zip not found: {}", zip_path.display()));
    }
    let hash = hash_file(zip_path).map_err(|error| format!("cannot hash zip: {error}"))?;
    let previous_marker = read_marker(&dest.join(MARKER_NAME));
    let unchanged = previous_marker
        .as_ref()
        .is_some_and(|marker| marker.hash.eq_ignore_ascii_case(&hash));
    if unchanged && read_inventory(dest, &hash).is_ok() {
        return adopt(dest, owner, None);
    }
    let ready = stage_archive(zip_path, dest, &hash, owner)?;
    if unchanged {
        let inventory = fs::read(ready.join(INVENTORY_NAME)).map_err(|error| error.to_string());
        let result = match inventory {
            Ok(inventory) => adopt(dest, owner, Some(&inventory)),
            Err(error) => Err(error),
        };
        return match result {
            Ok(()) => {
                if let Err(error) = fault("adoption-cleanup")
                    .map_err(|error| error.to_string())
                    .and_then(|()| cleanup_if_exists(&ready))
                {
                    eprintln!(
                        "WARNING: adoption committed, but staging cleanup failed; residual staging at {}: {error}",
                        ready.display()
                    );
                }
                Ok(())
            }
            Err(error) => Err(append_cleanup(error, cleanup_if_exists(&ready))),
        };
    }
    let result = replace_destination(dest, &ready, previous_marker.as_ref(), owner);
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(append_cleanup(error, cleanup_if_exists(&ready))),
    }
}

fn stage_archive(
    zip_path: &Path,
    dest: &Path,
    hash: &str,
    owner: Option<&str>,
) -> Result<PathBuf, String> {
    let mut archive = File::open(zip_path)
        .map_err(|error| format!("cannot open zip {}: {error}", zip_path.display()))?;
    if hash_reader(&mut archive).map_err(|error| error.to_string())? != hash {
        return Err("source ZIP changed before extraction".into());
    }
    let mut zip = ZipArchive::new(&mut archive)
        .map_err(|error| format!("cannot read zip {}: {error}", zip_path.display()))?;
    let external_attributes = read_central_directory_attributes(zip_path)
        .map_err(|error| format!("cannot inspect ZIP directory attributes: {error}"))?;
    if external_attributes.len() != zip.len() {
        return Err("ZIP central-directory entry count does not match the archive index".into());
    }
    let entries = validate_archive(&mut zip, &external_attributes)?;
    let flatten_root = flatten_root(&entries);
    for entry in &entries {
        let offset = usize::from(flatten_root.is_some());
        if entry
            .components
            .first()
            .is_some_and(|name| metadata_name(name))
            || entry
                .components
                .get(offset)
                .is_some_and(|name| metadata_name(name))
        {
            return Err(format!(
                "archive collides with helper-owned metadata: {}",
                entry.path.display()
            ));
        }
    }
    let parent = sibling_parent(dest);
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "cannot create destination parent {}: {error}",
            parent.display()
        )
    })?;

    let stage = create_unique_directory(parent, dest, "extract")
        .map_err(|error| format!("cannot create extraction staging directory: {error}"))?;
    let mut additional_staging = None;
    let operation = (|| -> Result<PathBuf, String> {
        for entry in &entries {
            extract_entry(&mut zip, entry, &stage)
                .map_err(|error| format!("cannot extract {}: {error}", entry.path.display()))?;
        }
        if hash_file(zip_path).map_err(|error| error.to_string())? != hash {
            return Err("source ZIP changed during extraction".into());
        }

        let ready = if let Some(root) = flatten_root {
            let source_root = stage.join(&root);
            let ready = create_unique_directory(parent, dest, "ready")
                .map_err(|error| format!("cannot create ready directory: {error}"))?;
            additional_staging = Some(ready.clone());
            if let Err(error) = move_directory_contents(&source_root, &ready) {
                return Err(format!("cannot flatten archive root: {error}"));
            }
            fs::remove_dir(&source_root)
                .map_err(|error| format!("cannot remove flattened source root: {error}"))?;
            fs::remove_dir(&stage)
                .map_err(|error| format!("cannot remove extraction staging directory: {error}"))?;
            ready
        } else {
            stage.clone()
        };

        // Establish the upstream baseline before importing any user additions.
        let inventory = Inventory {
            source: hash.to_owned(),
            tree: scan_tree(&ready, false)?,
        };
        write_bytes_atomically(
            &ready,
            INVENTORY_NAME,
            inventory_text(&inventory).as_bytes(),
        )
        .map_err(|error| format!("cannot write inventory: {error}"))?;
        write_marker_atomically(
            &ready,
            &Marker {
                hash: hash.to_owned(),
                owner: owner.map(str::to_owned),
            },
        )
        .map_err(|error| format!("cannot write source marker: {error}"))?;
        additional_staging = None;
        Ok(ready)
    })();

    match operation {
        Ok(result) => Ok(result),
        Err(error) => {
            let mut message = append_cleanup(error, cleanup_if_exists(&stage));
            if let Some(ready) = additional_staging {
                message = append_cleanup(message, cleanup_if_exists(&ready));
            }
            Err(message)
        }
    }
}

pub(crate) fn adopt(
    dest: &Path,
    owner: Option<&str>,
    inventory: Option<&[u8]>,
) -> Result<(), String> {
    let old = snapshot_metadata(dest)?;
    let previous_owner = if owner.is_some() {
        get_owner_record(dest)?
    } else {
        None
    };
    let operation = (|| {
        if let Some(inventory) = inventory {
            write_bytes_atomically(dest, INVENTORY_NAME, inventory)
                .map_err(|error| error.to_string())?;
        }
        if let Some(owner) = owner {
            let mut marker = read_marker(&dest.join(MARKER_NAME))
                .ok_or("source marker disappeared during adoption")?;
            marker.hash.make_ascii_lowercase();
            marker.owner = Some(owner.to_owned());
            write_marker_atomically(dest, &marker).map_err(|error| error.to_string())?;
        }
        if marker_is_present(&dest.join(REMOVAL_NAME)) {
            remove_tree_no_follow(&dest.join(REMOVAL_NAME)).map_err(|error| error.to_string())?;
        }
        if let Some(owner) = owner {
            set_owner_record(dest, owner)?;
        }
        Ok::<(), String>(())
    })();
    if let Err(mut error) = operation {
        error = append_cleanup(error, restore_metadata(dest, &old));
        if let Some(owner) = owner {
            error = append_cleanup(
                error,
                restore_owner_record(dest, previous_owner.as_deref(), owner),
            );
        }
        return Err(error);
    }
    println!(
        "Ghidra already extracted at {} (unchanged); skipping.",
        dest.display()
    );
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "the commit/rollback sequence reads as one transaction"
)]
fn replace_destination(
    dest: &Path,
    ready: &Path,
    previous_marker: Option<&Marker>,
    owner: Option<&str>,
) -> Result<(), String> {
    let parent = sibling_parent(dest);
    let previous_owner = if owner.is_some() {
        get_owner_record(dest)?
    } else {
        None
    };
    let exists = match fs::symlink_metadata(dest) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("cannot inspect destination: {error}")),
    };
    if exists {
        validate_destination_path(dest)?;
        let inventory = previous_marker.and_then(|marker| read_inventory(dest, &marker.hash).ok());
        let current = scan_tree(dest, false)?;
        let customized = inventory
            .as_ref()
            .is_none_or(|inventory| inventory.tree != current);
        if customized {
            let new_marker =
                read_marker(&ready.join(MARKER_NAME)).ok_or("missing staged source marker")?;
            preserve_tree(
                dest,
                previous_marker.map(|marker| marker.hash.as_str()),
                &new_marker.hash,
            )?;
            if let Some(inventory) = inventory {
                let upstream = read_inventory(ready, &new_marker.hash)?;
                migrate_additions(dest, ready, &inventory.tree, &current, &upstream.tree)?;
            }
        }
    }
    let backup = if exists {
        let backup = unique_sibling_path(parent, dest, "old");
        if let Err(error) = fs::rename(dest, &backup) {
            return Err(format!(
                "cannot move existing destination to backup: {error}"
            ));
        }
        Some(backup)
    } else {
        None
    };

    if let Err(error) = fault("install").and_then(|()| fs::rename(ready, dest)) {
        let mut message = format!("cannot install extracted Ghidra directory: {error}");
        if let Some(backup) = &backup {
            match fault("rollback").and_then(|()| fs::rename(backup, dest)) {
                Ok(()) => {}
                Err(restore_error) => {
                    let _ = write!(
                        message,
                        "; rollback failed (original remains at {}): {restore_error}",
                        backup.display()
                    );
                }
            }
        }
        return Err(message);
    }

    if let Some(owner) = owner
        && let Err(mut error) = set_owner_record(dest, owner)
    {
        let displaced = unique_sibling_path(parent, dest, "uncommitted");
        let rollback = fault("rollback").and_then(|()| fs::rename(dest, &displaced));
        match rollback {
            Ok(()) => {
                if let Some(backup) = &backup {
                    if let Err(restore_error) = fs::rename(backup, dest) {
                        let _ = write!(
                            error,
                            "; rollback failed; original remains at {}, uncommitted tree at {}: {restore_error}",
                            backup.display(),
                            displaced.display()
                        );
                    } else {
                        error = append_cleanup(error, cleanup_if_exists(&displaced));
                    }
                } else {
                    error = append_cleanup(error, cleanup_if_exists(&displaced));
                }
            }
            Err(restore_error) => {
                if let Some(backup) = &backup {
                    let _ = write!(
                        error,
                        "; rollback failed; original remains at {}, uncommitted tree at {}: {restore_error}",
                        backup.display(),
                        dest.display()
                    );
                } else {
                    let _ = write!(
                        error,
                        "; rollback failed; no previous destination; uncommitted tree remains at {}: {restore_error}",
                        dest.display()
                    );
                }
            }
        }
        error = append_cleanup(
            error,
            restore_owner_record(dest, previous_owner.as_deref(), owner),
        );
        return Err(error);
    }
    // Ownership is committed before fallible cleanup. Never roll back a committed tree.
    if let Some(backup) = backup
        && let Err(error) = fault("cleanup").and_then(|()| remove_tree_no_follow(&backup))
    {
        eprintln!(
            "WARNING: extraction committed, but backup cleanup failed; residual backup at {}: {error}",
            backup.display()
        );
    }
    println!("Extracted Ghidra to {}.", dest.display());
    Ok(())
}

fn recovery_root() -> Result<PathBuf, String> {
    #[cfg(test)]
    if let Some(root) = TEST_HOOKS.with(|hooks| hooks.borrow().recovery.clone()) {
        return Ok(root);
    }
    #[cfg(windows)]
    {
        env::var_os("LOCALAPPDATA")
            .filter(|root| !root.is_empty())
            .map(|root| PathBuf::from(root).join("Ghidra Launch Recovery"))
            .ok_or_else(|| "LOCALAPPDATA is unavailable; cannot preserve the previous tree".into())
    }
    #[cfg(not(windows))]
    Err("recovery requires LOCALAPPDATA on Windows".into())
}

fn preserve_tree(
    dest: &Path,
    previous_source: Option<&str>,
    incoming_source: &str,
) -> Result<PathBuf, String> {
    fault("recovery").map_err(|error| error.to_string())?;
    let before = scan_tree(dest, true)?;
    let root = recovery_root()?;
    #[cfg(windows)]
    {
        let root_key = comparable_path(&root);
        let dest_key = comparable_path(dest);
        if root_key.starts_with(&dest_key)
            && root_key
                .get(dest_key.len())
                .is_none_or(|&unit| unit == u16::from(b'\\'))
        {
            return Err("recovery root cannot be inside the destination".into());
        }
    }
    #[cfg(not(windows))]
    if root.starts_with(dest) {
        return Err("recovery root cannot be inside the destination".into());
    }
    reject_reparse_ancestors(&root)?;
    fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create recovery root {}: {error}", root.display()))?;
    reject_reparse_ancestors(&root)?;
    let recovery = create_unique_directory(&root, dest, "recovery")
        .map_err(|error| format!("cannot allocate recovery directory: {error}"))?;
    let tree = recovery.join("tree");
    fs::create_dir(&tree).map_err(|error| format!("cannot create recovery tree: {error}"))?;
    let operation = (|| {
        for (name, item) in &before {
            let target = tree.join(relative_path(name));
            match item {
                Item::Directory => fs::create_dir(&target).map_err(|error| error.to_string())?,
                Item::File(hash) => {
                    fault("recovery-copy").map_err(|error| error.to_string())?;
                    copy_ordinary_file(&dest.join(relative_path(name)), &target, hash)?;
                }
            }
        }
        if scan_tree(dest, true)? != before || scan_tree(&tree, true)? != before {
            return Err("previous tree changed while preserving it".into());
        }
        let summary = format!(
            "ghidralaunch-recovery-v1\ndestination={}\nprevious-source={}\nincoming-source={incoming_source}\ncontents=tree\n",
            dest.display(),
            previous_source.unwrap_or("unknown")
        );
        write_bytes_atomically(&recovery, "recovery.txt", summary.as_bytes())
            .map_err(|error| format!("cannot record recovery summary: {error}"))?;
        Ok::<(), String>(())
    })();
    if let Err(error) = operation {
        return Err(format!(
            "cannot preserve previous tree; original remains at {}; incomplete recovery at {}: {error}",
            dest.display(),
            recovery.display()
        ));
    }
    println!("Preserved previous tree at {}.", recovery.display());
    Ok(recovery)
}

fn migrate_additions(
    source: &Path,
    ready: &Path,
    old: &Tree,
    current: &Tree,
    upstream: &Tree,
) -> Result<(), String> {
    let upstream_keys: BTreeMap<_, _> = upstream
        .iter()
        .map(|(name, item)| (name.to_lowercase(), (name, item)))
        .collect();
    let additions: BTreeSet<_> = current
        .keys()
        .filter(|name| !old.contains_key(*name))
        .collect();
    for name in &additions {
        let mut candidate = name.as_str();
        let mut safe = true;
        loop {
            if let Some((canonical, item)) = upstream_keys.get(&candidate.to_lowercase())
                && (canonical.as_str() != candidate
                    || !matches!(item, Item::Directory)
                    || (candidate == name.as_str() && !matches!(current[*name], Item::Directory)))
            {
                safe = false;
                break;
            }
            match candidate.rsplit_once('/') {
                Some((parent, _)) => candidate = parent,
                None => break,
            }
        }
        if !safe {
            continue;
        }
        let target = ready.join(relative_path(name));
        match &current[*name] {
            Item::Directory => {
                reject_reparse_ancestors(&target)?;
                fs::create_dir_all(&target).map_err(|error| error.to_string())?;
            }
            Item::File(hash) => {
                reject_reparse_ancestors(sibling_parent(&target))?;
                fs::create_dir_all(sibling_parent(&target)).map_err(|error| error.to_string())?;
                copy_ordinary_file(&source.join(relative_path(name)), &target, hash)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{exit_code, run};
    use crate::remove::remove;
    use crate::state::METADATA_NAMES;
    use crate::test_support::{Fixture, test_root, write_zip};
    use std::ffi::OsString;
    use std::io::Write;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    #[test]
    fn failed_extraction_preserves_existing_destination() {
        let root = test_root("transaction");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("Ghidra");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("user-data.txt"), "keep").unwrap();
        let archive_path = root.join("invalid.zip");
        let mut zip = ZipWriter::new(File::create(&archive_path).unwrap());
        zip.add_directory(
            format!("ghidra/{MARKER_NAME}/"),
            SimpleFileOptions::default(),
        )
        .unwrap();
        zip.finish().unwrap();

        let result = extract(&archive_path, &destination, None);
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(destination.join("user-data.txt")).unwrap(),
            "keep"
        );
        assert!(!destination.join(MARKER_NAME).exists());
        remove_tree_no_follow(&root).unwrap();
    }

    #[test]
    fn owner_updates_preserve_payload_and_guard_removal() {
        let root = test_root("owner");
        fs::create_dir_all(&root).unwrap();
        let archive_path = root.join("source.zip");
        let mut zip = ZipWriter::new(File::create(&archive_path).unwrap());
        zip.start_file("ghidra/ghidraRun.bat", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"run").unwrap();
        zip.finish().unwrap();

        let destination = root.join("Ghidra");
        extract(&archive_path, &destination, Some("original-owner")).unwrap();
        fs::write(destination.join("user-data.txt"), "customized").unwrap();
        extract(&archive_path, &destination, Some("new-owner")).unwrap();
        extract(&archive_path, &destination, None).unwrap();
        assert_eq!(
            fs::read_to_string(destination.join("user-data.txt")).unwrap(),
            "customized"
        );
        assert_eq!(
            read_marker(&destination.join(MARKER_NAME))
                .unwrap()
                .owner
                .as_deref(),
            Some("new-owner")
        );

        remove(&destination, Some(&archive_path), None).unwrap();
        assert!(destination.exists());
        remove(&destination, Some(&archive_path), Some("wrong-owner")).unwrap();
        assert!(destination.exists());
        assert_eq!(
            run(&[
                OsString::from("remove"),
                destination.as_os_str().to_owned(),
                OsString::new(),
                OsString::from("new-owner"),
            ])
            .unwrap(),
            0
        );
        assert!(destination.exists());
        fs::remove_file(destination.join("user-data.txt")).unwrap();
        remove(&destination, Some(&archive_path), Some("new-owner")).unwrap();
        assert!(!destination.exists());
        remove_tree_no_follow(&root).unwrap();
    }

    #[test]
    fn same_source_adoption_never_rebaselines_customizations() {
        let fixture = Fixture::new("adoption-baseline");
        fixture.install();
        let inventory = fs::read(fixture.dest.join(INVENTORY_NAME)).unwrap();
        fs::write(fixture.dest.join("app"), "edited").unwrap();
        fs::write(fixture.dest.join("extra"), "addition").unwrap();
        extract(&fixture.first, &fixture.dest, Some("new-owner")).unwrap();
        assert_eq!(
            fs::read(fixture.dest.join(INVENTORY_NAME)).unwrap(),
            inventory
        );
        remove(&fixture.dest, Some(&fixture.first), Some("new-owner")).unwrap();
        assert_eq!(fs::read(fixture.dest.join("app")).unwrap(), b"edited");
        assert!(fixture.dest.join("extra").exists());
        assert_eq!(fixture.record(), None);
    }

    #[test]
    fn legacy_same_source_uses_fresh_zip_baseline_without_replacing_custom_tree() {
        let fixture = Fixture::new("legacy-baseline");
        fixture.install();
        fs::remove_file(fixture.dest.join(INVENTORY_NAME)).unwrap();
        fs::write(fixture.dest.join("app"), "edited").unwrap();
        fs::write(fixture.dest.join("extension"), "keep").unwrap();
        extract(&fixture.first, &fixture.dest, Some("new-owner")).unwrap();
        let inventory = read_inventory(&fixture.dest, &hash_file(&fixture.first).unwrap()).unwrap();
        assert!(!inventory.tree.contains_key("extension"));
        assert_ne!(
            inventory.tree["app"],
            Item::File(hash_file(&fixture.dest.join("app")).unwrap())
        );
        remove(&fixture.dest, None, Some("new-owner")).unwrap();
        assert_eq!(fs::read(fixture.dest.join("extension")).unwrap(), b"keep");
    }

    #[test]
    fn legacy_uppercase_source_marker_is_normalized_on_owner_handoff() {
        let fixture = Fixture::new("uppercase-marker");
        fixture.install();
        let hash = hash_file(&fixture.first).unwrap();
        fs::write(fixture.dest.join(MARKER_NAME), hash.to_ascii_uppercase()).unwrap();
        extract(&fixture.first, &fixture.dest, Some("new-owner")).unwrap();
        assert_eq!(
            fs::read(fixture.dest.join(MARKER_NAME)).unwrap(),
            format!("{hash}\nowner=new-owner\n").as_bytes()
        );
    }

    #[test]
    fn adoption_owner_write_failure_restores_marker_and_new_metadata() {
        let fixture = Fixture::new("adoption-fault");
        fixture.install();
        fs::remove_file(fixture.dest.join(INVENTORY_NAME)).unwrap();
        let marker = fs::read(fixture.dest.join(MARKER_NAME)).unwrap();
        fixture.inject("registry-write-after", 0);
        let error = extract(&fixture.first, &fixture.dest, Some("new-owner")).unwrap_err();
        assert!(error.contains("registry-write-after"));
        fixture.assert_original();
        assert_eq!(fs::read(fixture.dest.join(MARKER_NAME)).unwrap(), marker);
        assert!(!fixture.dest.join(INVENTORY_NAME).exists());
    }

    #[test]
    fn failed_install_after_backup_restores_original() {
        let fixture = Fixture::new("install-rollback");
        fixture.install();
        fixture.inject("install", 0);
        let error = extract(&fixture.next, &fixture.dest, Some("new-owner")).unwrap_err();
        assert!(error.contains("cannot install"));
        fixture.assert_original();
        assert_eq!(fixture.backups(), Vec::<PathBuf>::new());
        assert!(fs::read_dir(&fixture.root).unwrap().all(|entry| {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            !name.contains(".extract-") && !name.contains(".ready-")
        }));
    }

    #[test]
    fn failed_restore_retains_original_backup_and_reports_path() {
        let fixture = Fixture::new("restore-fault");
        fixture.install();
        fixture.inject("install", 0);
        fixture.inject("rollback", 0);
        let error = extract(&fixture.next, &fixture.dest, Some("new-owner")).unwrap_err();
        assert!(error.contains("rollback failed"));
        assert!(!fixture.dest.exists());
        let backups = fixture.backups();
        assert_eq!(backups.len(), 1);
        assert!(error.contains(&backups[0].display().to_string()));
        assert_eq!(fs::read(backups[0].join("app")).unwrap(), b"original");
        assert_eq!(fixture.record().as_deref(), Some("old-owner"));
    }

    #[test]
    fn replacement_owner_write_failure_restores_tree_and_previous_registry() {
        let fixture = Fixture::new("owner-rollback");
        fixture.install();
        fixture.inject("registry-write-after", 0);
        let error = extract(&fixture.next, &fixture.dest, Some("new-owner")).unwrap_err();
        assert!(error.contains("registry-write-after"));
        fixture.assert_original();
        assert_eq!(fixture.backups(), Vec::<PathBuf>::new());
    }

    #[test]
    fn owner_failure_with_failed_rollback_retains_intact_original_backup() {
        let fixture = Fixture::new("owner-restore-fault");
        fixture.install();
        fixture.inject("registry-write", 0);
        fixture.inject("rollback", 0);
        let error = extract(&fixture.next, &fixture.dest, Some("new-owner")).unwrap_err();
        let backups = fixture.backups();
        assert_eq!(backups.len(), 1);
        assert!(error.contains(&backups[0].display().to_string()));
        assert_eq!(fs::read(backups[0].join("app")).unwrap(), b"original");
    }

    #[test]
    fn postcommit_cleanup_failure_keeps_new_tree_and_registry_consistent() {
        let fixture = Fixture::new("cleanup-fault");
        fixture.install();
        fixture.inject("cleanup", 0);
        assert_eq!(
            exit_code(&[
                OsString::from("extract"),
                fixture.next.as_os_str().to_owned(),
                fixture.dest.as_os_str().to_owned(),
                OsString::from("new-owner"),
            ]),
            0
        );
        assert_eq!(fs::read(fixture.dest.join("app")).unwrap(), b"new");
        assert_eq!(fixture.record().as_deref(), Some("new-owner"));
        assert_eq!(
            read_marker(&fixture.dest.join(MARKER_NAME))
                .unwrap()
                .owner
                .as_deref(),
            Some("new-owner")
        );
        assert_eq!(fixture.backups().len(), 1);
    }

    #[test]
    fn postcommit_adoption_staging_cleanup_failure_is_successful() {
        let fixture = Fixture::new("adoption-cleanup-fault");
        fixture.install();
        fs::remove_file(fixture.dest.join(INVENTORY_NAME)).unwrap();
        fixture.inject("adoption-cleanup", 0);
        assert_eq!(
            exit_code(&[
                OsString::from("extract"),
                fixture.first.as_os_str().to_owned(),
                fixture.dest.as_os_str().to_owned(),
                OsString::from("new-owner"),
            ]),
            0
        );
        assert_eq!(fixture.record().as_deref(), Some("new-owner"));
        assert_eq!(
            read_marker(&fixture.dest.join(MARKER_NAME))
                .unwrap()
                .owner
                .as_deref(),
            Some("new-owner")
        );
        read_inventory(&fixture.dest, &hash_file(&fixture.first).unwrap()).unwrap();
        assert!(fs::read_dir(&fixture.root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("Ghidra.ready-")
        }));
    }

    #[test]
    fn upgrade_preserves_custom_tree_and_imports_only_nonconflicting_additions() {
        let fixture = Fixture::new("preservation");
        fixture.install();
        fs::write(fixture.dest.join("app"), "edited upstream").unwrap();
        fs::remove_file(fixture.dest.join("bin").join("tool")).unwrap();
        fs::write(fixture.dest.join("safe-extension"), "keep").unwrap();
        fs::write(fixture.dest.join("bin").join("plugin"), "nested addition").unwrap();
        fs::create_dir(fixture.dest.join("empty-extension")).unwrap();
        fs::write(fixture.dest.join("new-file"), "old conflict").unwrap();
        fs::create_dir(fixture.dest.join("new-directory")).unwrap();
        fs::write(
            fixture.dest.join("new-directory").join("custom"),
            "conflict child",
        )
        .unwrap();
        fs::write(fixture.dest.join("CASE"), "case conflict").unwrap();
        fs::create_dir(fixture.dest.join("資料")).unwrap();
        fs::write(fixture.dest.join("資料").join("扩展"), "unicode").unwrap();
        write_zip(
            &fixture.next,
            &[
                ("ghidra/app", "new"),
                ("ghidra/bin/tool", "restored"),
                ("ghidra/new-file", "new upstream"),
                ("ghidra/new-directory", "file not directory"),
                ("ghidra/case", "new case"),
            ],
        );
        extract(&fixture.next, &fixture.dest, Some("new-owner")).unwrap();
        assert_eq!(fs::read(fixture.dest.join("app")).unwrap(), b"new");
        assert_eq!(
            fs::read(fixture.dest.join("bin").join("tool")).unwrap(),
            b"restored"
        );
        assert_eq!(
            fs::read(fixture.dest.join("safe-extension")).unwrap(),
            b"keep"
        );
        assert_eq!(
            fs::read(fixture.dest.join("bin").join("plugin")).unwrap(),
            b"nested addition"
        );
        assert!(fixture.dest.join("empty-extension").is_dir());
        assert_eq!(
            fs::read(fixture.dest.join("new-file")).unwrap(),
            b"new upstream"
        );
        assert_eq!(
            fs::read(fixture.dest.join("new-directory")).unwrap(),
            b"file not directory"
        );
        assert_eq!(fs::read(fixture.dest.join("case")).unwrap(), b"new case");
        assert_eq!(
            fs::read(fixture.dest.join("資料").join("扩展")).unwrap(),
            b"unicode"
        );
        let recovered = fixture.recovered();
        assert_eq!(recovered.len(), 1);
        let summary =
            fs::read_to_string(recovered[0].parent().unwrap().join("recovery.txt")).unwrap();
        assert!(summary.contains(&format!("destination={}", fixture.dest.display())));
        assert!(summary.contains(&format!(
            "previous-source={}",
            hash_file(&fixture.first).unwrap()
        )));
        assert!(summary.contains(&format!(
            "incoming-source={}",
            hash_file(&fixture.next).unwrap()
        )));
        assert_eq!(
            fs::read(recovered[0].join("app")).unwrap(),
            b"edited upstream"
        );
        assert_eq!(
            fs::read(recovered[0].join("new-file")).unwrap(),
            b"old conflict"
        );
        assert_eq!(
            fs::read(recovered[0].join("CASE")).unwrap(),
            b"case conflict"
        );
        let inventory = read_inventory(&fixture.dest, &hash_file(&fixture.next).unwrap()).unwrap();
        assert!(!inventory.tree.contains_key("safe-extension"));
        remove(&fixture.dest, None, Some("new-owner")).unwrap();
        assert!(fixture.dest.exists());
        assert_eq!(fixture.record(), None);
        assert!(recovered[0].exists());
    }

    #[test]
    fn added_directories_merge_without_overwriting_upstream_conflicts() {
        let fixture = Fixture::new("directory-merge");
        fixture.install();
        let shared = fixture.dest.join("shared");
        fs::create_dir_all(shared.join("nested")).unwrap();
        fs::write(shared.join("custom.txt"), "custom").unwrap();
        fs::write(shared.join("official.txt"), "old conflict").unwrap();
        fs::write(shared.join("nested").join("custom.txt"), "nested custom").unwrap();
        fs::create_dir(shared.join("file-conflict")).unwrap();
        fs::write(
            shared.join("file-conflict").join("custom.txt"),
            "directory conflict",
        )
        .unwrap();
        fs::write(shared.join("directory-conflict"), "file conflict").unwrap();
        fs::create_dir(shared.join("CASE")).unwrap();
        fs::write(shared.join("CASE").join("custom.txt"), "case conflict").unwrap();
        write_zip(
            &fixture.next,
            &[
                ("ghidra/app", "new"),
                ("ghidra/shared/official.txt", "upstream"),
                ("ghidra/shared/nested/official.txt", "nested upstream"),
                ("ghidra/shared/file-conflict", "upstream file"),
                (
                    "ghidra/shared/directory-conflict/official.txt",
                    "upstream directory",
                ),
                ("ghidra/shared/case/official.txt", "upstream case"),
            ],
        );
        extract(&fixture.next, &fixture.dest, Some("new-owner")).unwrap();
        assert_eq!(fs::read(shared.join("custom.txt")).unwrap(), b"custom");
        assert_eq!(fs::read(shared.join("official.txt")).unwrap(), b"upstream");
        assert_eq!(
            fs::read(shared.join("nested").join("custom.txt")).unwrap(),
            b"nested custom"
        );
        assert_eq!(
            fs::read(shared.join("nested").join("official.txt")).unwrap(),
            b"nested upstream"
        );
        assert_eq!(
            fs::read(shared.join("file-conflict")).unwrap(),
            b"upstream file"
        );
        assert_eq!(
            fs::read(shared.join("directory-conflict").join("official.txt")).unwrap(),
            b"upstream directory"
        );
        assert_eq!(
            fs::read(shared.join("case").join("official.txt")).unwrap(),
            b"upstream case"
        );
        assert!(!shared.join("case").join("custom.txt").exists());
        let inventory = read_inventory(&fixture.dest, &hash_file(&fixture.next).unwrap()).unwrap();
        assert!(!inventory.tree.contains_key("shared/custom.txt"));
        assert!(!inventory.tree.contains_key("shared/nested/custom.txt"));
        let recovered = fixture.recovered();
        assert_eq!(recovered.len(), 1);
        let old_shared = recovered[0].join("shared");
        assert_eq!(
            fs::read(old_shared.join("official.txt")).unwrap(),
            b"old conflict"
        );
        assert_eq!(
            fs::read(old_shared.join("file-conflict").join("custom.txt")).unwrap(),
            b"directory conflict"
        );
        assert_eq!(
            fs::read(old_shared.join("directory-conflict")).unwrap(),
            b"file conflict"
        );
        assert_eq!(
            fs::read(old_shared.join("CASE").join("custom.txt")).unwrap(),
            b"case conflict"
        );
    }

    #[test]
    fn unknown_baseline_is_recovered_whole_but_not_imported() {
        let fixture = Fixture::new("unknown");
        fs::create_dir(&fixture.dest).unwrap();
        fs::write(fixture.dest.join("custom"), "unclassified").unwrap();
        extract(&fixture.next, &fixture.dest, None).unwrap();
        assert!(!fixture.dest.join("custom").exists());
        assert_eq!(fixture.recovered().len(), 1);
        assert_eq!(
            fs::read(fixture.recovered()[0].join("custom")).unwrap(),
            b"unclassified"
        );
    }

    #[test]
    fn preservation_failure_leaves_original_tree_and_owner_intact() {
        let fixture = Fixture::new("recovery-fault");
        fixture.install();
        fs::write(fixture.dest.join("custom"), "keep").unwrap();
        fixture.inject("recovery", 0);
        assert!(extract(&fixture.next, &fixture.dest, Some("new-owner")).is_err());
        fixture.assert_original();
        assert_eq!(fs::read(fixture.dest.join("custom")).unwrap(), b"keep");
        assert_eq!(fixture.backups(), Vec::<PathBuf>::new());
    }

    #[test]
    fn incomplete_recovery_copy_never_discards_original() {
        let fixture = Fixture::new("recovery-copy-fault");
        fixture.install();
        fs::write(fixture.dest.join("custom"), "keep").unwrap();
        fixture.inject("recovery-copy", 1);
        let error = extract(&fixture.next, &fixture.dest, Some("new-owner")).unwrap_err();
        assert!(error.contains("incomplete recovery"));
        fixture.assert_original();
        assert_eq!(fs::read(fixture.dest.join("custom")).unwrap(), b"keep");
        assert_eq!(fixture.backups(), Vec::<PathBuf>::new());
        assert_eq!(fixture.recovered().len(), 1);
    }

    #[test]
    fn initial_owner_commit_failure_restores_absent_destination_and_record() {
        let fixture = Fixture::new("initial-commit-fault");
        fixture.inject("registry-write-after", 0);
        assert!(extract(&fixture.first, &fixture.dest, Some("new-owner")).is_err());
        assert!(!fixture.dest.exists());
        assert_eq!(fixture.record(), None);
        assert_eq!(fixture.backups(), Vec::<PathBuf>::new());
    }

    #[test]
    fn reserved_archive_metadata_is_rejected_before_and_after_flattening() {
        let fixture = Fixture::new("reserved-metadata");
        for metadata in METADATA_NAMES {
            for name in [
                format!("{metadata}/payload"),
                format!("ghidra/{metadata}"),
                format!("ghidra/{metadata}/payload"),
            ] {
                write_zip(&fixture.first, &[(&name, "not helper metadata")]);
                assert!(
                    extract(&fixture.first, &fixture.dest, None).is_err(),
                    "{name}"
                );
                assert!(!fixture.dest.exists());
            }
        }
    }

    #[test]
    fn unavailable_legacy_baseline_fails_without_replacing_custom_tree() {
        let fixture = Fixture::new("legacy-invalid-source");
        fs::write(&fixture.first, b"not a zip").unwrap();
        fs::create_dir(&fixture.dest).unwrap();
        fs::write(fixture.dest.join("custom"), "keep").unwrap();
        let marker = Marker {
            hash: hash_file(&fixture.first).unwrap(),
            owner: Some("old-owner".into()),
        };
        write_marker_atomically(&fixture.dest, &marker).unwrap();
        assert!(extract(&fixture.first, &fixture.dest, Some("new-owner")).is_err());
        assert_eq!(
            read_marker(&fixture.dest.join(MARKER_NAME)).unwrap(),
            marker
        );
        assert_eq!(fs::read(fixture.dest.join("custom")).unwrap(), b"keep");
        assert!(!fixture.dest.join(INVENTORY_NAME).exists());
    }
}
