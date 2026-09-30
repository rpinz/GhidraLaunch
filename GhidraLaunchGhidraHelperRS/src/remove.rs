//! Owner- and source-checked removal that retains customized or unknown trees.

use crate::fs_safety::{
    DestinationLock, append_cleanup, hash_file, is_reparse_point, read_regular_bytes,
    remove_payload_no_follow, remove_tree_no_follow, validate_destination_path,
    write_bytes_atomically,
};
use crate::hooks::fault;
use crate::registry::clear_owner_record;
use crate::state::{
    MARKER_NAME, METADATA_NAMES, REMOVAL_NAME, metadata_name, read_inventory, read_marker,
    removal_text, restore_metadata, scan_tree, snapshot_metadata, tree_is_clean, validate_owner,
};
use std::fs;
use std::io;
use std::path::Path;

#[expect(
    clippy::too_many_lines,
    reason = "the classification, authorization and deletion steps read as one transaction"
)]
pub(crate) fn remove(
    dest: &Path,
    zip_path: Option<&Path>,
    owner: Option<&str>,
) -> Result<(), String> {
    validate_destination_path(dest)?;
    if let Some(owner) = owner {
        validate_owner(owner)?;
    }
    let _lock = DestinationLock::acquire(dest)?;
    validate_destination_path(dest)?;
    let metadata = match fs::symlink_metadata(dest) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(owner) = owner {
                clear_owner_record(dest, owner)?;
            }
            return Ok(());
        }
        Err(error) => {
            return Err(format!(
                "cannot inspect destination {}: {error}",
                dest.display()
            ));
        }
    };
    if !metadata.is_dir() || is_reparse_point(dest).map_err(|error| error.to_string())? {
        return Err(format!(
            "destination is not a normal directory: {}",
            dest.display()
        ));
    }

    let marker = read_marker(&dest.join(MARKER_NAME));
    let Some(marker) = marker else {
        println!(
            "Retained {}; package marker is unavailable or invalid.",
            dest.display()
        );
        return Ok(());
    };

    if let Some(owner) = owner {
        if marker.owner.as_deref() != Some(owner) {
            println!(
                "Skipping removal of {}; it belongs to another owner.",
                dest.display()
            );
            return Ok(());
        }
    } else if marker.owner.is_some() {
        println!(
            "Skipping removal of {}; it belongs to an owner.",
            dest.display()
        );
        return Ok(());
    }

    if let Some(zip_path) = zip_path {
        if !zip_path.is_file() {
            println!(
                "Skipping removal of {}; package source is unavailable.",
                dest.display()
            );
            return Ok(());
        }
        let expected =
            hash_file(zip_path).map_err(|error| format!("cannot hash source zip: {error}"))?;
        if !marker.hash.eq_ignore_ascii_case(&expected) {
            println!(
                "Skipping removal of {}; it belongs to another Ghidra package.",
                dest.display()
            );
            return Ok(());
        }
    }

    let classification = (|| {
        let inventory = read_inventory(dest, &marker.hash)?;
        let current = scan_tree(dest, false)?;
        let removal =
            read_regular_bytes(&dest.join(REMOVAL_NAME)).map_err(|error| error.to_string())?;
        let retry = match removal {
            Some(bytes) if bytes == removal_text(&marker).as_bytes() => true,
            Some(_) => return Err("invalid or mismatched removal state".to_owned()),
            None => false,
        };
        if tree_is_clean(&inventory.tree, &current, retry) {
            Ok(())
        } else {
            Err("user additions, edits, or missing packaged files".into())
        }
    })();
    if let Err(reason) = classification {
        println!("Retained {}: {reason}.", dest.display());
        if let Some(owner) = owner {
            clear_owner_record(dest, owner)?;
        }
        return Ok(());
    }
    write_bytes_atomically(dest, REMOVAL_NAME, removal_text(&marker).as_bytes())
        .map_err(|error| format!("cannot authorize retry-safe removal: {error}"))?;
    let metadata = snapshot_metadata(dest)?;
    for entry in fs::read_dir(dest).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry.file_name().to_str().is_some_and(metadata_name) {
            remove_payload_no_follow(&entry.path()).map_err(|error| {
                format!(
                    "cannot remove {}; authorization retained for retry: {error}",
                    dest.display()
                )
            })?;
        }
    }
    let finalization = (|| {
        for name in METADATA_NAMES {
            remove_tree_no_follow(&dest.join(name))?;
        }
        fault("remove-final")?;
        fs::remove_dir(dest)
    })();
    if let Err(error) = finalization {
        return Err(append_cleanup(
            format!(
                "cannot finish removal of {}; authorization restored for retry: {error}",
                dest.display()
            ),
            restore_metadata(dest, &metadata),
        ));
    }
    if let Some(owner) = owner {
        clear_owner_record(dest, owner)?;
    }
    println!("Removed {}.", dest.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::extract;
    use crate::state::{INVENTORY_NAME, Item};
    use crate::test_support::Fixture;
    use std::path::PathBuf;

    #[test]
    fn missing_packaged_file_and_unknown_inventory_are_retained() {
        let fixture = Fixture::new("retention");
        fixture.install();
        fs::remove_file(fixture.dest.join("app")).unwrap();
        remove(&fixture.dest, None, Some("old-owner")).unwrap();
        assert!(fixture.dest.exists());
        assert_eq!(fixture.record(), None);
        fs::write(fixture.dest.join("app"), "original").unwrap();
        fs::write(fixture.dest.join(INVENTORY_NAME), "corrupt").unwrap();
        remove(&fixture.dest, None, Some("old-owner")).unwrap();
        assert!(fixture.dest.join("app").exists());
        fs::remove_file(fixture.dest.join(MARKER_NAME)).unwrap();
        remove(&fixture.dest, None, None).unwrap();
        assert!(fixture.dest.exists());
    }

    #[test]
    fn partial_removal_keeps_authorization_and_retries_missing_files() {
        let fixture = Fixture::new("removal-retry");
        fixture.install();
        fixture.inject("remove-payload", 1);
        assert!(remove(&fixture.dest, Some(&fixture.first), Some("old-owner")).is_err());
        assert!(fixture.dest.join(MARKER_NAME).exists());
        assert!(fixture.dest.join(INVENTORY_NAME).exists());
        assert!(fixture.dest.join(REMOVAL_NAME).exists());
        let current = scan_tree(&fixture.dest, false).unwrap();
        assert!(
            current
                .values()
                .filter(|item| matches!(item, Item::File(_)))
                .count()
                < 2
        );
        remove(&fixture.dest, Some(&fixture.first), Some("wrong-owner")).unwrap();
        assert!(fixture.dest.exists());
        remove(&fixture.dest, Some(&fixture.first), Some("old-owner")).unwrap();
        assert!(!fixture.dest.exists());
        assert_eq!(fixture.record(), None);
    }

    #[test]
    fn final_removal_failure_restores_metadata_for_retry() {
        let fixture = Fixture::new("removal-final");
        fixture.install();
        fixture.inject("remove-final", 0);
        assert!(remove(&fixture.dest, None, Some("old-owner")).is_err());
        assert!(fixture.dest.join(MARKER_NAME).exists());
        assert!(fixture.dest.join(INVENTORY_NAME).exists());
        assert!(fixture.dest.join(REMOVAL_NAME).exists());
        assert!(scan_tree(&fixture.dest, false).unwrap().is_empty());
        remove(&fixture.dest, None, Some("old-owner")).unwrap();
        assert!(!fixture.dest.exists());
    }

    #[test]
    fn foreign_removal_state_cannot_authorize_missing_packaged_files() {
        let fixture = Fixture::new("foreign-removal-state");
        fixture.install();
        fs::remove_file(fixture.dest.join("app")).unwrap();
        let mut marker = read_marker(&fixture.dest.join(MARKER_NAME)).unwrap();
        marker.owner = Some("different-owner".into());
        fs::write(fixture.dest.join(REMOVAL_NAME), removal_text(&marker)).unwrap();
        remove(&fixture.dest, Some(&fixture.first), Some("old-owner")).unwrap();
        assert!(fixture.dest.exists());
        assert!(fixture.dest.join("bin").join("tool").exists());
    }

    #[test]
    fn removal_retry_rechecks_new_user_edits_and_additions() {
        for edit in [false, true] {
            let fixture = Fixture::new("removal-drift");
            fixture.install();
            fixture.inject("remove-payload", 0);
            assert!(remove(&fixture.dest, None, Some("old-owner")).is_err());
            fs::write(
                fixture.dest.join(if edit { "app" } else { "custom" }),
                "keep",
            )
            .unwrap();
            remove(&fixture.dest, None, Some("old-owner")).unwrap();
            assert!(fixture.dest.exists());
            assert_eq!(fixture.record(), None);
        }
    }

    #[test]
    fn registry_clear_failure_is_retryable_when_destination_is_absent() {
        let fixture = Fixture::new("clear-retry");
        fixture.install();
        fixture.inject("registry-clear", 0);
        assert!(remove(&fixture.dest, None, Some("old-owner")).is_err());
        assert!(!fixture.dest.exists());
        assert_eq!(fixture.record().as_deref(), Some("old-owner"));
        remove(&fixture.dest, None, Some("other-owner")).unwrap();
        assert_eq!(fixture.record().as_deref(), Some("old-owner"));
        remove(&fixture.dest, None, Some("old-owner")).unwrap();
        assert_eq!(fixture.record(), None);
    }

    #[cfg(windows)]
    #[test]
    fn ordinary_readonly_files_allow_clean_removal_and_backup_cleanup() {
        for upgrade in [false, true] {
            let fixture = Fixture::new("readonly-clean");
            fixture.install();
            let path = fixture.dest.join("app");
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&path, permissions).unwrap();
            if upgrade {
                extract(&fixture.next, &fixture.dest, Some("new-owner")).unwrap();
                assert_eq!(fixture.backups(), Vec::<PathBuf>::new());
            } else {
                remove(&fixture.dest, None, Some("old-owner")).unwrap();
                assert!(!fixture.dest.exists());
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn edited_readonly_file_is_retained_without_attribute_changes() {
        let fixture = Fixture::new("readonly-edit");
        fixture.install();
        let path = fixture.dest.join("app");
        fs::write(&path, "edited").unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        remove(&fixture.dest, None, Some("old-owner")).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"edited");
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
    }
}
