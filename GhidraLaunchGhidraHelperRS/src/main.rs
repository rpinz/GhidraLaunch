use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zip::ZipArchive;

const MARKER_NAME: &str = ".ghidralaunch-source.sha256";
static UNIQUE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Marker {
    hash: String,
    owner: Option<String>,
}

#[derive(Debug)]
struct Entry {
    index: usize,
    path: PathBuf,
    components: Vec<String>,
    is_dir: bool,
}

fn main() {
    let arguments: Vec<OsString> = env::args_os().collect();
    std::process::exit(exit_code(&arguments[1..]));
}

fn exit_code(arguments: &[OsString]) -> i32 {
    match run(arguments) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Ghidra helper: {error}");
            1
        }
    }
}

fn run(arguments: &[OsString]) -> Result<i32, String> {
    let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
        usage();
        return Ok(2);
    };

    if command.eq_ignore_ascii_case("extract") && (arguments.len() == 3 || arguments.len() == 4) {
        let owner = match arguments
            .get(3)
            .map(|value| owner_from_os(value))
            .transpose()
        {
            Ok(owner) => owner,
            Err(error) => {
                eprintln!("Invalid owner: {error}");
                return Ok(2);
            }
        };
        extract(
            Path::new(&arguments[1]),
            Path::new(&arguments[2]),
            owner.as_deref(),
        )?;
        return Ok(0);
    }

    if command.eq_ignore_ascii_case("remove") && (arguments.len() >= 2 && arguments.len() <= 4) {
        let owner = match arguments
            .get(3)
            .map(|value| owner_from_os(value))
            .transpose()
        {
            Ok(owner) => owner,
            Err(error) => {
                eprintln!("Invalid owner: {error}");
                return Ok(2);
            }
        };
        let zip_path = arguments
            .get(2)
            .filter(|value| !value.is_empty())
            .map(Path::new);
        remove(Path::new(&arguments[1]), zip_path, owner.as_deref())?;
        return Ok(0);
    }

    usage();
    Ok(2)
}

fn usage() {
    eprintln!("Usage: GhidraLaunchGhidraHelperRS extract <zipPath> <destDir> [owner]");
    eprintln!("       GhidraLaunchGhidraHelperRS remove <destDir> [zipPath] [owner]");
}

fn owner_from_os(value: &OsStr) -> Result<String, String> {
    let owner = value
        .to_str()
        .ok_or_else(|| "owner token must be ASCII".to_owned())?;
    validate_owner(owner)?;
    Ok(owner.to_owned())
}

fn validate_owner(owner: &str) -> Result<(), String> {
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

fn extract(zip_path: &Path, dest: &Path, owner: Option<&str>) -> Result<(), String> {
    validate_destination_path(dest)?;
    if let Some(owner) = owner {
        validate_owner(owner)?;
    }
    if !zip_path.is_file() {
        return Err(format!("Ghidra zip not found: {}", zip_path.display()));
    }
    let hash = hash_file(zip_path).map_err(|error| format!("cannot hash zip: {error}"))?;
    let marker_path = dest.join(MARKER_NAME);

    if is_directory(dest) {
        if let Some(marker) = read_marker(&marker_path) {
            if marker.hash.eq_ignore_ascii_case(&hash) {
                if let Some(owner) = owner {
                    if marker.owner.as_deref() != Some(owner) {
                        write_marker_atomically(
                            dest,
                            &Marker {
                                hash,
                                owner: Some(owner.to_owned()),
                            },
                        )
                        .map_err(|error| format!("cannot update ownership marker: {error}"))?;
                    }
                }
                println!(
                    "Ghidra already extracted at {} (unchanged); skipping.",
                    dest.display()
                );
                return Ok(());
            }
        }
    }

    let mut archive = File::open(zip_path)
        .map_err(|error| format!("cannot open zip {}: {error}", zip_path.display()))?;
    let mut zip = ZipArchive::new(&mut archive)
        .map_err(|error| format!("cannot read zip {}: {error}", zip_path.display()))?;
    let external_attributes = read_central_directory_attributes(zip_path)
        .map_err(|error| format!("cannot inspect ZIP directory attributes: {error}"))?;
    if external_attributes.len() != zip.len() {
        return Err("ZIP central-directory entry count does not match the archive index".into());
    }
    let entries = validate_archive(&mut zip, &external_attributes)?;
    let flatten_root = flatten_root(&entries);
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

        write_marker_atomically(
            &ready,
            &Marker {
                hash: hash.clone(),
                owner: owner.map(str::to_owned),
            },
        )
        .map_err(|error| format!("cannot write source marker: {error}"))?;
        additional_staging = None;
        Ok(ready)
    })();

    let ready = match operation {
        Ok(result) => result,
        Err(error) => {
            let mut message = append_cleanup(error, cleanup_if_exists(&stage));
            if let Some(ready) = additional_staging {
                message = append_cleanup(message, cleanup_if_exists(&ready));
            }
            return Err(message);
        }
    };

    let dest_metadata = match fs::symlink_metadata(dest) {
        Ok(metadata) => {
            let reparse = match is_reparse_point(dest) {
                Ok(reparse) => reparse,
                Err(error) => {
                    let cleanup = cleanup_if_exists(&ready);
                    return Err(append_cleanup(
                        format!("cannot inspect destination reparse status: {error}"),
                        cleanup,
                    ));
                }
            };
            if !metadata.is_dir() || reparse {
                let cleanup = cleanup_if_exists(&ready);
                return Err(append_cleanup(
                    format!("destination is not a normal directory: {}", dest.display()),
                    cleanup,
                ));
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            let cleanup = cleanup_if_exists(&ready);
            return Err(append_cleanup(
                format!("cannot inspect destination {}: {error}", dest.display()),
                cleanup,
            ));
        }
    };

    let backup = if dest_metadata {
        let backup = unique_sibling_path(parent, dest, "old");
        if let Err(error) = fs::rename(dest, &backup) {
            let cleanup = cleanup_if_exists(&ready);
            return Err(append_cleanup(
                format!("cannot move existing destination to backup: {error}"),
                cleanup,
            ));
        }
        Some(backup)
    } else {
        None
    };

    if let Err(error) = fs::rename(&ready, dest) {
        let mut message = format!("cannot install extracted Ghidra directory: {error}");
        if let Some(backup) = &backup {
            match fs::rename(backup, dest) {
                Ok(()) => {}
                Err(restore_error) => {
                    message.push_str(&format!(
                        "; rollback failed (original remains at {}): {restore_error}",
                        backup.display()
                    ));
                }
            }
        }
        let cleanup = cleanup_if_exists(&ready);
        return Err(append_cleanup(message, cleanup));
    }

    if let Some(backup) = backup {
        remove_tree_no_follow(&backup).map_err(|error| {
            format!(
                "extraction succeeded but backup cleanup failed at {}: {error}",
                backup.display()
            )
        })?;
    }
    println!("Extracted Ghidra to {}.", dest.display());
    Ok(())
}

fn remove(dest: &Path, zip_path: Option<&Path>, owner: Option<&str>) -> Result<(), String> {
    validate_destination_path(dest)?;
    if let Some(owner) = owner {
        validate_owner(owner)?;
    }
    let metadata = match fs::symlink_metadata(dest) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "cannot inspect destination {}: {error}",
                dest.display()
            ))
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
        if zip_path.is_some() || owner.is_some() {
            println!(
                "Skipping removal of {}; package marker is unavailable.",
                dest.display()
            );
            return Ok(());
        }
        if marker_is_present(&dest.join(MARKER_NAME)) {
            println!(
                "Skipping removal of {}; its package marker is invalid.",
                dest.display()
            );
            return Ok(());
        }
        remove_tree_no_follow(dest)
            .map_err(|error| format!("cannot remove {}: {error}", dest.display()))?;
        println!("Removed {}.", dest.display());
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

    remove_tree_no_follow(dest)
        .map_err(|error| format!("cannot remove {}: {error}", dest.display()))?;
    println!("Removed {}.", dest.display());
    Ok(())
}

fn validate_archive<R: Read + io::Seek>(
    zip: &mut ZipArchive<R>,
    external_attributes: &[u32],
) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::with_capacity(zip.len());
    let mut explicit = BTreeSet::new();
    let mut types: BTreeMap<String, bool> = BTreeMap::new();
    let mut canonical_dirs: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (index, attributes) in external_attributes.iter().enumerate().take(zip.len()) {
        let file = zip
            .by_index(index)
            .map_err(|error| format!("cannot inspect zip entry {index}: {error}"))?;
        let unix_type = file.unix_mode().unwrap_or(0) & 0o170000;
        if file.is_symlink()
            || attributes & 0x0400 != 0
            || (unix_type != 0 && !matches!(unix_type, 0o100000 | 0o040000))
        {
            return Err(format!(
                "archive contains a symbolic link, special file, or reparse point: {}",
                file.name()
            ));
        }
        let raw_name = std::str::from_utf8(file.name_raw())
            .map_err(|_| format!("archive entry name is not UTF-8: {}", file.name()))?;
        let is_dir = file.is_dir()
            || raw_name.ends_with('\\')
            || file
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o040000);
        let original_components = validate_zip_path(raw_name, is_dir)?;
        let mut components = Vec::with_capacity(original_components.len());
        let mut keys = Vec::with_capacity(original_components.len());

        for (position, component) in original_components.iter().enumerate() {
            let key = if position == 0 {
                component.to_lowercase()
            } else {
                format!("{}/{}", keys[position - 1], component.to_lowercase())
            };
            if position + 1 < original_components.len() || is_dir {
                match canonical_dirs.get(&key) {
                    Some(existing) => {
                        let canonical = existing.last().unwrap();
                        if canonical != component {
                            return Err(format!(
                                "archive contains case-conflicting directory names: {raw_name}"
                            ));
                        }
                        components.push(canonical.clone());
                    }
                    None => {
                        canonical_dirs.insert(key.clone(), {
                            let mut prefix = components.clone();
                            prefix.push(component.clone());
                            prefix
                        });
                        components.push(component.clone());
                    }
                }
                if types
                    .get(&key)
                    .is_some_and(|existing_is_dir| !*existing_is_dir)
                {
                    return Err(format!("archive path conflicts with a file: {raw_name}"));
                }
                types.entry(key.clone()).or_insert(true);
            } else {
                if types.contains_key(&key) {
                    return Err(format!(
                        "archive contains a duplicate or conflicting path: {raw_name}"
                    ));
                }
                types.insert(key.clone(), false);
                components.push(component.clone());
            }
            keys.push(key);
        }

        let key = keys.join("/");
        if !explicit.insert(key.clone()) {
            return Err(format!("archive contains a duplicate path: {raw_name}"));
        }
        let path = components.iter().collect::<PathBuf>();
        entries.push(Entry {
            index,
            path,
            components,
            is_dir,
        });
    }
    Ok(entries)
}

fn validate_zip_path(name: &str, is_dir: bool) -> Result<Vec<String>, String> {
    if name.is_empty() || name.starts_with('/') || name.starts_with('\\') {
        return Err(format!("unsafe absolute or empty archive path: {name:?}"));
    }
    let normalized = name.replace('\\', "/");
    let trimmed = if is_dir {
        normalized.strip_suffix('/').unwrap_or(&normalized)
    } else {
        &normalized
    };
    if trimmed.is_empty() || trimmed.starts_with('/') {
        return Err(format!("unsafe absolute or empty archive path: {name:?}"));
    }
    let components: Vec<&str> = trimmed.split('/').collect();
    let mut result = Vec::with_capacity(components.len());
    for component in components {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.ends_with('.')
            || component.ends_with(' ')
            || component.chars().any(|character| {
                character <= '\u{1f}'
                    || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
            })
        {
            return Err(format!("unsafe Windows archive path: {name:?}"));
        }
        let device_base = component
            .split('.')
            .next()
            .unwrap_or(component)
            .trim_end_matches([' ', '.'])
            .to_ascii_uppercase();
        let reserved = matches!(
            device_base.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
        ) || ["COM", "LPT"].iter().any(|prefix| {
            device_base.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        });
        if reserved {
            return Err(format!(
                "reserved Windows device name in archive path: {name:?}"
            ));
        }
        result.push(component.to_owned());
    }
    Ok(result)
}

fn flatten_root(entries: &[Entry]) -> Option<String> {
    let first = entries.first()?.components.first()?.clone();
    if entries.iter().any(|entry| {
        entry.components.first() != Some(&first) || (entry.components.len() == 1 && !entry.is_dir)
    }) {
        return None;
    }
    Some(first)
}

fn extract_entry<R: Read + io::Seek>(
    zip: &mut ZipArchive<R>,
    entry: &Entry,
    stage: &Path,
) -> io::Result<()> {
    let target = stage.join(&entry.path);
    if entry.is_dir {
        fs::create_dir_all(target)?;
        return Ok(());
    }
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "entry has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut source = zip
        .by_index(entry.index)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)?;
    io::copy(&mut source, &mut output)?;
    output.sync_all()
}

fn move_directory_contents(source: &Path, destination: &Path) -> io::Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        fs::rename(entry.path(), destination.join(entry.file_name()))?;
    }
    Ok(())
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hasher.update(&buffer[..length]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_marker(path: &Path) -> Option<Marker> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || is_reparse_point(path).ok()? {
        return None;
    }
    let contents = fs::read_to_string(path).ok()?;
    parse_marker_text(&contents)
}

fn marker_is_present(path: &Path) -> bool {
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

fn write_marker_atomically(directory: &Path, marker: &Marker) -> io::Result<()> {
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

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source = to_wide_verbatim(source)?;
    let destination = to_wide_verbatim(destination)?;
    let success = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn create_unique_directory(parent: &Path, destination: &Path, label: &str) -> io::Result<PathBuf> {
    for _ in 0..128 {
        let candidate = unique_sibling_path(parent, destination, label);
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique sibling directory",
    ))
}

fn unique_sibling_path(parent: &Path, destination: &Path, label: &str) -> PathBuf {
    let mut name = destination
        .file_name()
        .unwrap_or_else(|| OsStr::new("ghidra"))
        .to_os_string();
    name.push(format!(
        ".{label}-{}-{}",
        std::process::id(),
        UNIQUE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    parent.join(name)
}

fn sibling_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn validate_destination_path(path: &Path) -> Result<(), String> {
    if !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        return Err(format!(
            "destination must name a directory below its parent: {}",
            path.display()
        ));
    }
    reject_reparse_ancestors(path)?;
    Ok(())
}

/// Check every existing ancestor of `path`, not just the leaf, and never
/// traverse through a junction or symlink. Mirrors the C helper's
/// `directories()`/`safe_destination()` ancestor walk.
fn reject_reparse_ancestors(path: &Path) -> Result<(), String> {
    let mut ancestors: Vec<&Path> = path.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                let reparse = is_reparse_point(ancestor).map_err(|error| {
                    format!(
                        "cannot inspect destination ancestor {}: {error}",
                        ancestor.display()
                    )
                })?;
                if reparse || !metadata.is_dir() {
                    return Err(format!(
                        "destination path crosses a reparse point or non-directory: {}",
                        ancestor.display()
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(format!(
                    "cannot inspect destination ancestor {}: {error}",
                    ancestor.display()
                ))
            }
        }
    }
    Ok(())
}

fn is_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        .and_then(|is_dir| {
            if is_dir {
                is_reparse_point(path).map(|reparse| is_dir && !reparse)
            } else {
                Ok(false)
            }
        })
        .unwrap_or(false)
}

fn cleanup_if_exists(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => remove_tree_no_follow(path)
            .map_err(|error| format!("cleanup failed at {}: {error}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect cleanup path {}: {error}",
            path.display()
        )),
    }
}

fn append_cleanup(mut message: String, cleanup: Result<(), String>) -> String {
    if let Err(error) = cleanup {
        message.push_str("; ");
        message.push_str(&error);
    }
    message
}

fn remove_tree_no_follow(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let reparse = is_reparse_point(path)?;
    if reparse {
        return fs::remove_dir(path).or_else(|directory_error| {
            fs::remove_file(path).map_err(|file_error| {
                io::Error::new(
                    file_error.kind(),
                    format!(
                        "cannot remove reparse point as directory ({directory_error}) or file ({file_error})"
                    ),
                )
            })
        });
    }
    if !metadata.is_dir() {
        return fs::remove_file(path);
    }
    for entry in fs::read_dir(path)? {
        remove_tree_no_follow(&entry?.path())?;
    }
    fs::remove_dir(path)
}

fn read_central_directory_attributes(path: &Path) -> io::Result<Vec<u32>> {
    const EOCD_SIGNATURE: u32 = 0x0605_4b50;
    const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
    const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
    const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;

    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let tail_length = file_size.min(22 + u16::MAX as u64) as usize;
    let tail_start = file_size - tail_length as u64;
    file.seek(SeekFrom::Start(tail_start))?;
    let mut tail = vec![0; tail_length];
    file.read_exact(&mut tail)?;
    if tail.len() < 22 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ZIP end record is truncated",
        ));
    }
    let eocd_index = (0..=tail.len().saturating_sub(22))
        .rev()
        .find(|index| {
            read_u32_le(&tail[*index..]) == Some(EOCD_SIGNATURE)
                && index + 22 + read_u16_le(&tail[*index + 20..]).unwrap_or(u16::MAX) as usize
                    == tail.len()
        })
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "ZIP end record was not found")
        })?;
    let eocd_position = tail_start + eocd_index as u64;
    let eocd = &tail[eocd_index..];
    let mut entry_count = read_u16_le(&eocd[10..]).unwrap() as u64;
    let mut directory_size = read_u32_le(&eocd[12..]).unwrap() as u64;
    let mut directory_offset = read_u32_le(&eocd[16..]).unwrap() as u64;
    let mut directory_end = eocd_position;

    if entry_count == u16::MAX as u64
        || directory_size == u32::MAX as u64
        || directory_offset == u32::MAX as u64
    {
        if eocd_position < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ZIP64 locator is missing",
            ));
        }
        file.seek(SeekFrom::Start(eocd_position - 20))?;
        let mut locator = [0u8; 20];
        file.read_exact(&mut locator)?;
        if read_u32_le(&locator) != Some(ZIP64_LOCATOR_SIGNATURE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ZIP64 locator is invalid",
            ));
        }
        let mut zip64_position = read_u64_le(&locator[8..]).unwrap();
        file.seek(SeekFrom::Start(zip64_position))?;
        let mut zip64_header = [0u8; 56];
        let zip64_header_read = file.read_exact(&mut zip64_header);
        if zip64_header_read.is_err() || read_u32_le(&zip64_header) != Some(ZIP64_EOCD_SIGNATURE) {
            zip64_position = eocd_position.checked_sub(20 + 56).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "ZIP64 end record is truncated")
            })?;
            file.seek(SeekFrom::Start(zip64_position))?;
            file.read_exact(&mut zip64_header)?;
            let record_size = read_u64_le(&zip64_header[4..]).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "ZIP64 end record is invalid")
            })?;
            if read_u32_le(&zip64_header) != Some(ZIP64_EOCD_SIGNATURE) || record_size < 44 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ZIP64 end record is invalid",
                ));
            }
            let record_length = 12u64.checked_add(record_size).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "ZIP64 end record is too large")
            })?;
            zip64_position = eocd_position
                .checked_sub(20)
                .and_then(|position| position.checked_sub(record_length))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "ZIP64 end record is truncated")
                })?;
            file.seek(SeekFrom::Start(zip64_position))?;
            file.read_exact(&mut zip64_header)?;
        }
        if read_u32_le(&zip64_header) != Some(ZIP64_EOCD_SIGNATURE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ZIP64 end record is invalid",
            ));
        }
        entry_count = read_u64_le(&zip64_header[32..]).unwrap();
        directory_size = read_u64_le(&zip64_header[40..]).unwrap();
        directory_offset = read_u64_le(&zip64_header[48..]).unwrap();
        directory_end = zip64_position;
    }

    let directory_count = usize::try_from(entry_count)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "too many ZIP entries"))?;
    let stored_offset_is_central = if directory_offset
        .checked_add(4)
        .is_some_and(|end| end <= file_size)
    {
        file.seek(SeekFrom::Start(directory_offset))?;
        let mut signature = [0; 4];
        file.read_exact(&mut signature)?;
        read_u32_le(&signature) == Some(CENTRAL_SIGNATURE)
    } else {
        false
    };
    let central_start = if stored_offset_is_central {
        directory_offset
    } else {
        directory_end.checked_sub(directory_size).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ZIP central directory offset is invalid",
            )
        })?
    };
    file.seek(SeekFrom::Start(central_start))?;

    let mut attributes = Vec::with_capacity(directory_count);
    for _ in 0..directory_count {
        let mut header = [0u8; 46];
        file.read_exact(&mut header)?;
        if read_u32_le(&header) != Some(CENTRAL_SIGNATURE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ZIP central directory entry is invalid",
            ));
        }
        let name_length = read_u16_le(&header[28..]).unwrap() as u64;
        let extra_length = read_u16_le(&header[30..]).unwrap() as u64;
        let comment_length = read_u16_le(&header[32..]).unwrap() as u64;
        attributes.push(read_u32_le(&header[38..]).unwrap());
        file.seek(SeekFrom::Current(
            i64::try_from(name_length + extra_length + comment_length).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ZIP entry metadata is too large",
                )
            })?,
        ))?;
    }
    Ok(attributes)
}

fn read_u16_le(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?))
}

fn read_u32_le(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

fn read_u64_le(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?))
}

#[cfg(not(windows))]
fn is_reparse_point(path: &Path) -> io::Result<bool> {
    Ok(fs::symlink_metadata(path)?.file_type().is_symlink())
}

#[cfg(windows)]
fn is_reparse_point(path: &Path) -> io::Result<bool> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };

    let path = to_wide_verbatim(path)?;
    let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        Err(io::Error::last_os_error())
    } else {
        Ok(attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }
}

/// Build a `\\?\`-prefixed (extended-length) wide string for direct Win32 API
/// calls so paths beyond MAX_PATH (260 chars) are handled correctly; `fs::*`
/// already does this internally, but manual `GetFileAttributesW`/`MoveFileExW`
/// calls do not unless we prefix the path ourselves.
#[cfg(windows)]
fn to_wide_verbatim(path: &Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let text = path.as_os_str().to_string_lossy();
    if text.starts_with(r"\\?\") || text.starts_with(r"\\.\") {
        return Ok(path.as_os_str().encode_wide().chain(Some(0)).collect());
    }

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }

    let text = normalized.to_string_lossy().replace('/', "\\");
    let prefixed = match text.strip_prefix(r"\\") {
        Some(rest) => format!(r"\\?\UNC\{rest}"),
        None => format!(r"\\?\{text}"),
    };
    Ok(OsStr::new(&prefixed).encode_wide().chain(Some(0)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    #[test]
    fn validates_windows_zip_paths() {
        for path in [
            "../outside",
            "folder/../outside",
            r"folder\..\outside",
            "/absolute",
            r"C:\outside",
            r"\\server\share",
            "file:stream",
            "trailing.",
            "trailing ",
            "CON.txt",
            "COM¹",
            "dir/NUL",
        ] {
            assert!(validate_zip_path(path, false).is_err(), "accepted {path:?}");
        }
        assert_eq!(
            validate_zip_path(r"ghidra\bin\ghidraRun.bat", false).unwrap(),
            ["ghidra", "bin", "ghidraRun.bat"]
        );
    }

    #[test]
    fn parses_owner_and_legacy_markers() {
        let hash = "a".repeat(64);
        let provider_key = "{B62B45B6-22D9-47E3-8EA2-41F5B4271BF9}";
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
    fn command_exit_codes_match_the_helper_contract() {
        assert_eq!(exit_code(&[]), 2);
        assert_eq!(exit_code(&[OsString::from("unknown")]), 2);
        assert_eq!(
            exit_code(&[
                OsString::from("extract"),
                OsString::from("missing.zip"),
                OsString::from("ghidra"),
                OsString::from("bad/owner"),
            ]),
            2
        );
        assert_eq!(
            exit_code(&[
                OsString::from("remove"),
                env::current_dir()
                    .unwrap()
                    .join(".missing-測試")
                    .into_os_string(),
            ]),
            0
        );
    }

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
        assert!(!destination.exists());
        remove_tree_no_follow(&root).unwrap();
    }

    #[test]
    fn reads_central_directory_attributes() {
        let root = test_root("central-dir");
        fs::create_dir_all(&root).unwrap();
        let archive_path = root.join("attrs.zip");
        let mut zip = ZipWriter::new(File::create(&archive_path).unwrap());
        zip.start_file("file.txt", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"content").unwrap();
        zip.finish().unwrap();
        assert_eq!(
            read_central_directory_attributes(&archive_path)
                .unwrap()
                .len(),
            1
        );
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive_path)
            .unwrap();
        let central_start = {
            let metadata = file.metadata().unwrap();
            let mut tail = vec![0; metadata.len().min(22 + u16::MAX as u64) as usize];
            file.seek(SeekFrom::End(-(tail.len() as i64))).unwrap();
            file.read_exact(&mut tail).unwrap();
            let eocd = tail
                .windows(4)
                .rposition(|window| window == [0x50, 0x4b, 0x05, 0x06])
                .unwrap();
            u32::from_le_bytes(tail[eocd + 16..eocd + 20].try_into().unwrap()) as u64
        };
        file.seek(SeekFrom::Start(central_start + 38)).unwrap();
        file.write_all(&0x0400u32.to_le_bytes()).unwrap();
        drop(file);
        let mut bytes = fs::read(&archive_path).unwrap();
        insert_zip64_end_records(&mut bytes);
        fs::write(&archive_path, bytes).unwrap();
        assert_ne!(
            read_central_directory_attributes(&archive_path).unwrap()[0] & 0x0400,
            0
        );
        let mut zip = ZipArchive::new(File::open(&archive_path).unwrap()).unwrap();
        let attributes = read_central_directory_attributes(&archive_path).unwrap();
        assert!(validate_archive(&mut zip, &attributes).is_err());
        remove_tree_no_follow(&root).unwrap();
    }

    fn insert_zip64_end_records(bytes: &mut Vec<u8>) {
        let eocd = bytes
            .windows(4)
            .rposition(|window| window == [0x50, 0x4b, 0x05, 0x06])
            .unwrap();
        let count = u16::from_le_bytes(bytes[eocd + 10..eocd + 12].try_into().unwrap()) as u64;
        let directory_size =
            u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into().unwrap()) as u64;
        let directory_offset =
            u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as u64;
        let mut records = Vec::new();
        records.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
        records.extend_from_slice(&44u64.to_le_bytes());
        records.extend_from_slice(&45u16.to_le_bytes());
        records.extend_from_slice(&45u16.to_le_bytes());
        records.extend_from_slice(&0u32.to_le_bytes());
        records.extend_from_slice(&0u32.to_le_bytes());
        records.extend_from_slice(&count.to_le_bytes());
        records.extend_from_slice(&count.to_le_bytes());
        records.extend_from_slice(&directory_size.to_le_bytes());
        records.extend_from_slice(&directory_offset.to_le_bytes());
        records.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
        records.extend_from_slice(&0u32.to_le_bytes());
        records.extend_from_slice(&(eocd as u64).to_le_bytes());
        records.extend_from_slice(&1u32.to_le_bytes());
        bytes.splice(eocd..eocd, records);
        let eocd = eocd + 76;
        bytes[eocd + 8..eocd + 10].copy_from_slice(&u16::MAX.to_le_bytes());
        bytes[eocd + 10..eocd + 12].copy_from_slice(&u16::MAX.to_le_bytes());
        bytes[eocd + 12..eocd + 16].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[eocd + 16..eocd + 20].copy_from_slice(&u32::MAX.to_le_bytes());
    }

    #[test]
    fn rejects_case_insensitive_duplicate_archive_names() {
        let root = test_root("duplicate");
        fs::create_dir_all(&root).unwrap();
        let archive_path = root.join("duplicate.zip");
        let mut zip = ZipWriter::new(File::create(&archive_path).unwrap());
        zip.start_file("Ghidra/launch.bat", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"first").unwrap();
        zip.start_file("ghidra/LAUNCH.BAT", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"second").unwrap();
        zip.finish().unwrap();

        let mut zip = ZipArchive::new(File::open(&archive_path).unwrap()).unwrap();
        let attributes = read_central_directory_attributes(&archive_path).unwrap();
        assert!(validate_archive(&mut zip, &attributes).is_err());
        remove_tree_no_follow(&root).unwrap();
    }

    fn test_root(label: &str) -> PathBuf {
        env::current_dir().unwrap().join(format!(
            ".helper-test-{label}-{}-{}",
            std::process::id(),
            UNIQUE_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }
}
