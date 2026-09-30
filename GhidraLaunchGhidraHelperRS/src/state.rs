//! Helper-owned metadata: source markers and owner tokens, upstream inventories, and
//! retry-safe removal state shared with the C helper.

use crate::archive::validate_zip_path;
use crate::fs_safety::{
    append_cleanup, atomic_replace, cleanup_if_exists, hash_file, is_reparse_point,
    read_regular_bytes, remove_tree_no_follow, unique_sibling_path, write_bytes_atomically,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub(crate) const MARKER_NAME: &str = ".ghidralaunch-source.sha256";

pub(crate) const INVENTORY_NAME: &str = ".ghidralaunch-inventory";

pub(crate) const REMOVAL_NAME: &str = ".ghidralaunch-removal";

pub(crate) const METADATA_NAMES: [&str; 3] = [MARKER_NAME, INVENTORY_NAME, REMOVAL_NAME];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Marker {
    pub(crate) hash: String,
    pub(crate) owner: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Item {
    Directory,
    File(String),
}

pub(crate) type Tree = BTreeMap<String, Item>;

#[derive(Debug)]
pub(crate) struct Inventory {
    pub(crate) source: String,
    pub(crate) tree: Tree,
}

pub(crate) fn validate_owner(owner: &str) -> Result<(), String> {
    if owner.is_empty()
        || owner.len() > 128
        || !owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-{}".contains(&byte))
    {
        return Err(
            "owner token must contain 1-128 ASCII letters, digits, '.', '_', '-' or braces".into(),
        );
    }
    Ok(())
}

pub(crate) fn metadata_name(name: &str) -> bool {
    METADATA_NAMES
        .iter()
        .any(|metadata| name.eq_ignore_ascii_case(metadata))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn relative_path(name: &str) -> PathBuf {
    name.split('/').collect()
}

pub(crate) fn scan_tree(root: &Path, include_metadata: bool) -> Result<Tree, String> {
    fn walk(
        root: &Path,
        prefix: &str,
        include_metadata: bool,
        tree: &mut Tree,
    ) -> Result<(), String> {
        let mut metadata_keys = BTreeSet::new();
        for entry in fs::read_dir(root).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-Unicode tree path")?;
            if prefix.is_empty() && !include_metadata && metadata_name(&name) {
                if !metadata_keys.insert(name.to_ascii_lowercase()) {
                    return Err(format!("case-conflicting helper metadata: {name}"));
                }
                continue;
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if is_reparse_point(&path).map_err(|error| error.to_string())? {
                return Err(format!(
                    "cannot classify or preserve reparse point: {}",
                    path.display()
                ));
            }
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            validate_zip_path(&relative, metadata.is_dir())?;
            let item = if metadata.is_dir() {
                Item::Directory
            } else if metadata.is_file() {
                Item::File(
                    hash_file(&path)
                        .map_err(|error| format!("cannot hash {}: {error}", path.display()))?,
                )
            } else {
                return Err(format!("cannot classify special file: {}", path.display()));
            };
            tree.insert(relative.clone(), item);
            if metadata.is_dir() {
                walk(&path, &relative, include_metadata, tree)?;
            }
        }
        Ok(())
    }
    let mut tree = Tree::new();
    walk(root, "", include_metadata, &mut tree)?;
    validate_tree(&tree, include_metadata)?;
    Ok(tree)
}

fn validate_tree(tree: &Tree, allow_metadata: bool) -> Result<(), String> {
    let mut keys = BTreeSet::new();
    for (name, item) in tree {
        let components = validate_zip_path(name, matches!(item, Item::Directory))?;
        if components.join("/") != *name
            || (!allow_metadata && components.first().is_some_and(|first| metadata_name(first)))
        {
            return Err(format!("unsafe or reserved inventory path: {name}"));
        }
        if !keys.insert(name.to_lowercase()) {
            return Err(format!("case-conflicting inventory path: {name}"));
        }
        let mut parent = name.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if tree.get(prefix) != Some(&Item::Directory) {
                return Err(format!(
                    "missing or conflicting inventory directory: {prefix}"
                ));
            }
            parent = prefix;
        }
    }
    Ok(())
}

pub(crate) fn inventory_text(inventory: &Inventory) -> String {
    let mut text = format!("ghidralaunch-inventory-v1\nsource={}\n", inventory.source);
    for (name, item) in &inventory.tree {
        match item {
            Item::Directory => {
                let _ = writeln!(text, "d\t-\t{name}");
            }
            Item::File(hash) => {
                let _ = writeln!(text, "f\t{hash}\t{name}");
            }
        }
    }
    text
}

fn parse_inventory(text: &str, source: &str) -> Result<Inventory, String> {
    let mut lines = text.split_terminator('\n');
    if lines.next() != Some("ghidralaunch-inventory-v1") {
        return Err("unavailable or invalid inventory version".into());
    }
    let hash = lines
        .next()
        .and_then(|line| line.strip_prefix("source="))
        .filter(|hash| valid_hash(hash) && hash.eq_ignore_ascii_case(source))
        .ok_or("invalid inventory source")?;
    let mut tree = Tree::new();
    for line in lines {
        let mut fields = line.split('\t');
        let kind = fields.next().ok_or("missing inventory kind")?;
        let digest = fields.next().ok_or("missing inventory digest")?;
        let name = fields.next().ok_or("missing inventory path")?;
        if fields.next().is_some() {
            return Err("invalid inventory record".into());
        }
        let item = match kind {
            "d" if digest == "-" => Item::Directory,
            "f" if valid_hash(digest) => Item::File(digest.to_owned()),
            _ => return Err("invalid inventory record".into()),
        };
        let name = validate_zip_path(name, matches!(item, Item::Directory))?.join("/");
        if tree.insert(name, item).is_some() {
            return Err("duplicate inventory record".into());
        }
    }
    validate_tree(&tree, false)?;
    Ok(Inventory {
        source: hash.to_owned(),
        tree,
    })
}

pub(crate) fn read_inventory(dest: &Path, source: &str) -> Result<Inventory, String> {
    let bytes = read_regular_bytes(&dest.join(INVENTORY_NAME))
        .map_err(|error| format!("cannot read inventory: {error}"))?
        .ok_or("upstream inventory is unavailable")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "inventory is not UTF-8")?;
    parse_inventory(text, source)
}

pub(crate) fn tree_is_clean(upstream: &Tree, current: &Tree, allow_missing: bool) -> bool {
    current
        .iter()
        .all(|(name, item)| upstream.get(name) == Some(item))
        && (allow_missing || upstream.len() == current.len())
}

pub(crate) fn removal_text(marker: &Marker) -> String {
    format!(
        "ghidralaunch-removal-v1\nsource={}\nowner={}\n",
        marker.hash.to_lowercase(),
        marker.owner.as_deref().unwrap_or("")
    )
}

type MetadataSnapshot = Vec<(&'static str, Option<Vec<u8>>)>;

pub(crate) fn snapshot_metadata(dest: &Path) -> Result<MetadataSnapshot, String> {
    METADATA_NAMES
        .into_iter()
        .map(|name| {
            read_regular_bytes(&dest.join(name))
                .map(|bytes| (name, bytes))
                .map_err(|error| error.to_string())
        })
        .collect()
}

pub(crate) fn restore_metadata(dest: &Path, snapshot: &MetadataSnapshot) -> Result<(), String> {
    let mut errors = Vec::new();
    for (name, bytes) in snapshot {
        let result = match bytes {
            Some(bytes) => write_bytes_atomically(dest, name, bytes),
            None => remove_tree_no_follow(&dest.join(name)),
        };
        if let Err(error) = result {
            errors.push(format!(
                "cannot restore metadata {}: {error}",
                dest.join(name).display()
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub(crate) fn read_marker(path: &Path) -> Option<Marker> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || is_reparse_point(path).ok()? {
        return None;
    }
    let contents = fs::read_to_string(path).ok()?;
    parse_marker_text(&contents)
}

pub(crate) fn marker_is_present(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) => error.kind() != io::ErrorKind::NotFound,
    }
}

fn parse_marker_text(contents: &str) -> Option<Marker> {
    let mut lines = contents.lines();
    let hash = lines.next()?.to_owned();
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let owner = match lines.next() {
        None => None,
        Some(line) => {
            let owner = line.strip_prefix("owner=")?;
            validate_owner(owner).ok()?;
            if lines.next().is_some() {
                return None;
            }
            Some(owner.to_owned())
        }
    };
    Some(Marker { hash, owner })
}

pub(crate) fn write_marker_atomically(directory: &Path, marker: &Marker) -> io::Result<()> {
    let marker_path = directory.join(MARKER_NAME);
    let temporary = unique_sibling_path(directory, Path::new(MARKER_NAME), "marker");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let write_result = match &marker.owner {
        Some(owner) => write!(file, "{}\nowner={}\n", marker.hash, owner),
        None => write!(file, "{}", marker.hash),
    }
    .and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = write_result {
        let cleanup = cleanup_if_exists(&temporary);
        return Err(io::Error::new(
            error.kind(),
            append_cleanup(format!("cannot write temporary marker: {error}"), cleanup),
        ));
    }
    match atomic_replace(&temporary, &marker_path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let cleanup = cleanup_if_exists(&temporary);
            Err(io::Error::new(
                error.kind(),
                append_cleanup(
                    format!("cannot atomically replace marker: {error}"),
                    cleanup,
                ),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_owner_and_legacy_markers() {
        let hash = "a".repeat(64);
        let provider_key = "{FEEDFACE-0000-4000-8000-0000000000B6}";
        validate_owner(provider_key).unwrap();
        assert!(validate_owner("A".repeat(129).as_str()).is_err());
        assert_eq!(
            parse_marker_text(&hash).unwrap(),
            Marker {
                hash: hash.clone(),
                owner: None
            }
        );
        assert_eq!(
            parse_marker_text(&format!("{hash}\nowner={provider_key}\n")).unwrap(),
            Marker {
                hash: hash.clone(),
                owner: Some(provider_key.to_owned())
            }
        );
        assert_eq!(
            parse_marker_text(&format!("{hash}\nowner=release_1.2-{{A1B2-C3}}\n")).unwrap(),
            Marker {
                hash: hash.clone(),
                owner: Some("release_1.2-{A1B2-C3}".into())
            }
        );
        assert!(parse_marker_text(&format!("{hash}\nowner=bad/token")).is_none());
        assert!(parse_marker_text(&format!("{hash}\nowner=valid\nextra")).is_none());
    }

    #[test]
    fn inventory_accepts_shared_order_but_rejects_unsafe_conflicting_records() {
        let source = "a".repeat(64);
        let digest = "b".repeat(64);
        let header = format!("ghidralaunch-inventory-v1\nsource={source}\n");
        let valid = format!("{header}f\t{digest}\tbin/tool\nd\t-\tbin\n");
        assert_eq!(parse_inventory(&valid, &source).unwrap().tree.len(), 2);
        for records in [
            format!("f\t{digest}\tbin/tool\n"),
            "d\t-\tbin\nd\t-\tBIN\n".into(),
            "d\t-\tbin\nd\t-\tbin\n".into(),
            format!("f\t{digest}\tbin\nd\t-\tbin/tool\n"),
            "d\t-\t../outside\n".into(),
            format!("f\t{digest}\t{MARKER_NAME}\n"),
            "f\t-\tfile\n".into(),
        ] {
            assert!(
                parse_inventory(&(header.clone() + &records), &source).is_err(),
                "{records}"
            );
        }
        assert!(parse_inventory(&valid, &"c".repeat(64)).is_err());
    }
}
