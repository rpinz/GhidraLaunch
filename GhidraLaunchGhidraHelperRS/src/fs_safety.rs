//! No-follow filesystem primitives: reparse-point checks, destination locking, atomic
//! replacement, read-only-aware removal, verbatim Win32 paths and file hashing.

use crate::hooks::fault;
use sha2::{Digest, Sha256};
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) static UNIQUE_ID: AtomicU64 = AtomicU64::new(0);

pub(crate) struct DestinationLock {
    pub(crate) _file: File,
    #[cfg(not(windows))]
    pub(crate) path: PathBuf,
}

impl DestinationLock {
    pub(crate) fn acquire(dest: &Path) -> Result<Self, String> {
        let parent = sibling_parent(dest);
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create destination parent: {error}"))?;
        reject_reparse_ancestors(parent)?;
        let mut name = dest
            .file_name()
            .ok_or("destination has no directory name")?
            .to_os_string();
        name.push(".ghidralaunch.lock");
        let path = parent.join(name);
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && (!metadata.is_file()
                || is_reparse_point(&path).map_err(|error| error.to_string())?)
        {
            return Err(format!("unsafe destination lock: {}", path.display()));
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_OPEN_REPARSE_POINT,
            };
            options
                .create(true)
                .share_mode(0)
                .custom_flags(FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT);
        }
        #[cfg(not(windows))]
        options.create_new(true);
        let file = options.open(&path).map_err(|error| {
            format!(
                "cannot lock destination {}; another operation may be active: {error}",
                dest.display()
            )
        })?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
            if file
                .metadata()
                .map_err(|error| error.to_string())?
                .file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            {
                return Err("destination lock is a reparse point".into());
            }
        }
        Ok(Self {
            _file: file,
            #[cfg(not(windows))]
            path,
        })
    }
}

#[cfg(not(windows))]
impl Drop for DestinationLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub(crate) fn read_regular_bytes(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || is_reparse_point(path)? {
        return Err(io::Error::other(format!(
            "not an ordinary metadata file: {}",
            path.display()
        )));
    }
    fs::read(path).map(Some)
}

pub(crate) fn write_bytes_atomically(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let temporary = unique_sibling_path(directory, Path::new(name), "metadata");
    let operation = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&temporary, &directory.join(name))
    })();
    if let Err(error) = operation {
        return Err(io::Error::new(
            error.kind(),
            append_cleanup(error.to_string(), cleanup_if_exists(&temporary)),
        ));
    }
    Ok(())
}

pub(crate) fn copy_ordinary_file(
    source: &Path,
    target: &Path,
    expected: &str,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if !metadata.is_file() || is_reparse_point(source).map_err(|error| error.to_string())? {
        return Err(format!("cannot safely copy {}", source.display()));
    }
    reject_reparse_ancestors(sibling_parent(source))?;
    reject_reparse_ancestors(sibling_parent(target))?;
    let mut input = File::open(source).map_err(|error| error.to_string())?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|error| format!("cannot create preserved file {}: {error}", target.display()))?;
    io::copy(&mut input, &mut output)
        .and_then(|_| output.sync_all())
        .map_err(|error| format!("cannot copy {}: {error}", source.display()))?;
    drop(output);
    if hash_file(target).map_err(|error| error.to_string())? != expected
        || hash_file(source).map_err(|error| error.to_string())? != expected
    {
        return Err(format!(
            "file changed while preserving {}",
            source.display()
        ));
    }
    fs::set_permissions(target, metadata.permissions()).map_err(|error| error.to_string())
}

pub(crate) fn remove_payload_no_follow(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if is_reparse_point(path)? || (!metadata.is_dir() && !metadata.is_file()) {
        return Err(io::Error::other(
            "payload changed to a reparse point or special file",
        ));
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            remove_payload_no_follow(&entry?.path())?;
        }
        fs::remove_dir(path)
    } else {
        fault("remove-payload")?;
        remove_tree_no_follow(path)
    }
}

pub(crate) fn move_directory_contents(source: &Path, destination: &Path) -> io::Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        fs::rename(entry.path(), destination.join(entry.file_name()))?;
    }
    Ok(())
}

pub(crate) fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    hash_reader(&mut file)
}

pub(crate) fn hash_reader(reader: &mut impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let length = reader.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hasher.update(&buffer[..length]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(not(windows))]
pub(crate) fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
pub(crate) fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = to_wide_verbatim(source)?;
    let destination = to_wide_verbatim(destination)?;
    // SAFETY: both paths are NUL-terminated wide strings that outlive the call.
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

pub(crate) fn create_unique_directory(
    parent: &Path,
    destination: &Path,
    label: &str,
) -> io::Result<PathBuf> {
    for _ in 0..128 {
        let candidate = unique_sibling_path(parent, destination, label);
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique sibling directory",
    ))
}

pub(crate) fn unique_sibling_path(parent: &Path, destination: &Path, label: &str) -> PathBuf {
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

pub(crate) fn sibling_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub(crate) fn validate_destination_path(path: &Path) -> Result<(), String> {
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
pub(crate) fn reject_reparse_ancestors(path: &Path) -> Result<(), String> {
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
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn cleanup_if_exists(path: &Path) -> Result<(), String> {
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

pub(crate) fn append_cleanup(mut message: String, cleanup: Result<(), String>) -> String {
    if let Err(error) = cleanup {
        message.push_str("; ");
        message.push_str(&error);
    }
    message
}

pub(crate) fn remove_tree_no_follow(path: &Path) -> io::Result<()> {
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
        #[cfg(windows)]
        if metadata.permissions().readonly() {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_ATTRIBUTE_READONLY, SetFileAttributesW,
            };
            // SAFETY: the path temporary is NUL-terminated and lives until the end of the statement.
            if unsafe {
                SetFileAttributesW(
                    to_wide_verbatim(path)?.as_ptr(),
                    metadata.file_attributes() & !FILE_ATTRIBUTE_READONLY,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        return fs::remove_file(path);
    }
    for entry in fs::read_dir(path)? {
        remove_tree_no_follow(&entry?.path())?;
    }
    fs::remove_dir(path)
}

#[cfg(not(windows))]
pub(crate) fn is_reparse_point(path: &Path) -> io::Result<bool> {
    Ok(fs::symlink_metadata(path)?.file_type().is_symlink())
}

#[cfg(windows)]
pub(crate) fn is_reparse_point(path: &Path) -> io::Result<bool> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
    };

    let path = to_wide_verbatim(path)?;
    // SAFETY: `path` is a NUL-terminated wide string that outlives the call.
    let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        Err(io::Error::last_os_error())
    } else {
        Ok(attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }
}

/// Build a `\\?\`-prefixed (extended-length) wide string for direct Win32 API
/// calls so paths beyond `MAX_PATH` (260 chars) are handled correctly; `fs::*`
/// already does this internally, but manual `GetFileAttributesW`/`MoveFileExW`
/// calls do not unless we prefix the path ourselves.
#[cfg(windows)]
pub(crate) fn to_wide_verbatim(path: &Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    if matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if prefix.kind().is_verbatim()
                || matches!(prefix.kind(), std::path::Prefix::DeviceNS(_))
    ) {
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

    let units: Vec<_> = normalized
        .as_os_str()
        .encode_wide()
        .map(|unit| {
            if unit == u16::from(b'/') {
                u16::from(b'\\')
            } else {
                unit
            }
        })
        .collect();
    let (prefix, rest) = if units.starts_with(&[u16::from(b'\\'), u16::from(b'\\')]) {
        (r"\\?\UNC\", &units[2..])
    } else {
        (r"\\?\", units.as_slice())
    };
    Ok(prefix
        .encode_utf16()
        .chain(rest.iter().copied())
        .chain(Some(0))
        .collect())
}

#[cfg(windows)]
pub(crate) fn comparable_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir().map_or_else(|_| path.to_path_buf(), |directory| directory.join(path))
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
    let mut units: Vec<u16> = normalized
        .as_os_str()
        .encode_wide()
        .map(|unit| {
            if unit == u16::from(b'/') {
                u16::from(b'\\')
            } else {
                unit
            }
        })
        .collect();
    while units.last() == Some(&u16::from(b'\\')) {
        units.pop();
    }
    lowercase_utf16(&units)
}

/// Lowercases the valid Unicode runs of a native path and keeps unpaired UTF-16
/// surrogates as they are, so distinct native paths never compare equal through
/// a lossy U+FFFD replacement.
#[cfg(windows)]
fn lowercase_utf16(units: &[u16]) -> Vec<u16> {
    fn flush(run: &mut String, folded: &mut Vec<u16>) {
        folded.extend(run.to_lowercase().encode_utf16());
        run.clear();
    }
    let mut folded = Vec::with_capacity(units.len());
    let mut run = String::new();
    for decoded in char::decode_utf16(units.iter().copied()) {
        match decoded {
            Ok(character) => run.push(character),
            Err(error) => {
                flush(&mut run, &mut folded);
                folded.push(error.unpaired_surrogate());
            }
        }
    }
    flush(&mut run, &mut folded);
    folded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::extract;
    use crate::test_support::Fixture;
    use std::ffi::OsString;

    #[test]
    fn destination_lock_excludes_competitors_and_is_released() {
        let fixture = Fixture::new("lock");
        let lock = DestinationLock::acquire(&fixture.dest).unwrap();
        assert!(DestinationLock::acquire(&fixture.dest).is_err());
        assert!(extract(&fixture.first, &fixture.dest, None).is_err());
        drop(lock);
        extract(&fixture.first, &fixture.dest, None).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn verbatim_paths_preserve_unpaired_utf16_units() {
        use std::os::windows::ffi::OsStringExt;

        for (input, expected) in [
            (r"C:\native-", r"\\?\C:\native-"),
            (r"\\server\share\native-", r"\\?\UNC\server\share\native-"),
            (r"\\?\C:\native-", r"\\?\C:\native-"),
            (r"\\.\C:\native-", r"\\.\C:\native-"),
        ] {
            for surrogate in [0xd800, 0xdc00] {
                let input: Vec<_> = input
                    .encode_utf16()
                    .chain([surrogate])
                    .chain(r"\child".encode_utf16())
                    .collect();
                let expected: Vec<_> = expected
                    .encode_utf16()
                    .chain([surrogate])
                    .chain(r"\child".encode_utf16())
                    .chain([0])
                    .collect();
                assert_eq!(
                    to_wide_verbatim(Path::new(&OsString::from_wide(&input))).unwrap(),
                    expected
                );
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn trailing_separator_uses_same_sibling_destination_lock() {
        let fixture = Fixture::new("lock-trailing-separator");
        let lock = DestinationLock::acquire(&fixture.dest).unwrap();
        let alias = PathBuf::from(format!("{}\\", fixture.dest.display()));
        assert!(DestinationLock::acquire(&alias).is_err());
        drop(lock);
        let lock = DestinationLock::acquire(&alias).unwrap();
        assert!(DestinationLock::acquire(&fixture.dest).is_err());
        drop(lock);
    }

    #[cfg(windows)]
    #[test]
    fn comparable_paths_fold_case_without_merging_unpaired_surrogates() {
        use std::os::windows::ffi::OsStringExt;

        let native = |prefix: &str, surrogate: u16| {
            let units: Vec<u16> = prefix.encode_utf16().chain([surrogate]).collect();
            PathBuf::from(OsString::from_wide(&units))
        };
        assert_eq!(
            comparable_path(Path::new(r"C:\Users\ÄB\Ghidra Launch\Ghidra\")),
            comparable_path(Path::new(r"c:/users/äb/ghidra launch/./GHIDRA"))
        );
        assert_eq!(
            comparable_path(&native(r"C:\Data\A", 0xd800)),
            comparable_path(&native(r"c:\data\a", 0xd800))
        );
        assert_ne!(
            comparable_path(&native(r"C:\Data\", 0xd800)),
            comparable_path(&native(r"C:\Data\", 0xdc00))
        );
        assert_ne!(
            comparable_path(&native(r"C:\Data\", 0xd800)),
            comparable_path(Path::new("C:\\Data\\\u{fffd}"))
        );
    }
}
