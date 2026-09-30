//! Shared unit-test fixtures.

use crate::extract::extract;
use crate::fs_safety::{UNIQUE_ID, remove_tree_no_follow};
use crate::hooks::{TEST_HOOKS, TestHooks};
use crate::migration::{LEGACY_FAMILY, LegacyRegistration};
use crate::registry::get_owner_record;
use crate::state::{MARKER_NAME, read_marker};
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

pub(crate) struct Fixture {
    pub(crate) root: PathBuf,
    pub(crate) dest: PathBuf,
    pub(crate) first: PathBuf,
    pub(crate) next: PathBuf,
}

impl Fixture {
    pub(crate) fn new(label: &str) -> Self {
        let root = test_root(label);
        fs::create_dir_all(&root).unwrap();
        let fixture = Self {
            dest: root.join("Ghidra"),
            first: root.join("first.zip"),
            next: root.join("next.zip"),
            root,
        };
        write_zip(
            &fixture.first,
            &[("ghidra/app", "original"), ("ghidra/bin/tool", "tool")],
        );
        write_zip(
            &fixture.next,
            &[("ghidra/app", "new"), ("ghidra/bin/tool", "new tool")],
        );
        TEST_HOOKS.with(|hooks| {
            *hooks.borrow_mut() = TestHooks {
                owner_dest: Some(fixture.dest.clone()),
                recovery: Some(fixture.root.join("Recovery")),
                ..TestHooks::default()
            };
        });
        fixture
    }

    pub(crate) fn install(&self) {
        extract(&self.first, &self.dest, Some("old-owner")).unwrap();
    }

    #[expect(
        clippy::unused_self,
        reason = "faults are per-thread but read as an operation on the fixture"
    )]
    pub(crate) fn inject(&self, point: &'static str, after: usize) {
        TEST_HOOKS.with(|hooks| {
            hooks.borrow_mut().faults.insert(point, after);
        });
    }

    pub(crate) fn record(&self) -> Option<String> {
        get_owner_record(&self.dest).unwrap()
    }

    pub(crate) fn backups(&self) -> Vec<PathBuf> {
        fs::read_dir(&self.root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains(".old-")
            })
            .collect()
    }

    pub(crate) fn recovered(&self) -> Vec<PathBuf> {
        match fs::read_dir(self.root.join("Recovery")) {
            Ok(entries) => entries
                .map(|entry| entry.unwrap().path().join("tree"))
                .collect(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("{error}"),
        }
    }

    pub(crate) fn assert_original(&self) {
        assert_eq!(fs::read(self.dest.join("app")).unwrap(), b"original");
        assert_eq!(
            read_marker(&self.dest.join(MARKER_NAME))
                .unwrap()
                .owner
                .as_deref(),
            Some("old-owner")
        );
        assert_eq!(self.record().as_deref(), Some("old-owner"));
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        TEST_HOOKS.with(|hooks| *hooks.borrow_mut() = TestHooks::default());
        let _ = remove_tree_no_follow(&self.root);
    }
}

pub(crate) fn write_zip(path: &Path, entries: &[(&str, &str)]) {
    let mut zip = ZipWriter::new(File::create(path).unwrap());
    for (name, data) in entries {
        zip.start_file(*name, SimpleFileOptions::default()).unwrap();
        zip.write_all(data.as_bytes()).unwrap();
    }
    zip.finish().unwrap();
}

pub(crate) fn legacy_record(cache: &Path, version: &str) -> LegacyRegistration {
    LegacyRegistration {
        location: "HKCU\\Uninstall\\fixture (64-bit)".into(),
        name: Some("Ghidra Launch".into()),
        publisher: Some("rpinz".into()),
        upgrade_codes: vec![LEGACY_FAMILY.into()],
        version: Some(version.into()),
        cache: Some(cache.to_str().unwrap().into()),
    }
}

pub(crate) fn legacy_registry_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

pub(crate) fn migration_backups(fixture: &Fixture) -> Vec<PathBuf> {
    fs::read_dir(&fixture.root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .contains(".legacy-")
        })
        .collect()
}

pub(crate) fn test_root(label: &str) -> PathBuf {
    env::current_dir().unwrap().join(format!(
        ".helper-test-{label}-{}-{}",
        std::process::id(),
        UNIQUE_ID.fetch_add(1, Ordering::Relaxed)
    ))
}
