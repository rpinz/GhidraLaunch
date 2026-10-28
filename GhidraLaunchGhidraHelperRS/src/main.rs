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
const INVENTORY_NAME: &str = ".ghidralaunch-inventory";
const REMOVAL_NAME: &str = ".ghidralaunch-removal";
const METADATA_NAMES: [&str; 3] = [MARKER_NAME, INVENTORY_NAME, REMOVAL_NAME];
const LEGACY_FAMILY: &str = "{DFE05126-B29E-4298-A06B-63F833BC0BF8}";
#[cfg(windows)]
const OWNER_KEY: &str = r"Software\rpinz\Ghidra Launch";
#[cfg(windows)]
const OWNER_VALUE: &str = "PayloadOwner";
#[cfg(windows)]
const OWNER_DESTINATION: &str = r"Ghidra Launch\Ghidra";
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Directory,
    File(String),
}

type Tree = BTreeMap<String, Item>;

#[derive(Debug)]
struct Inventory {
    source: String,
    tree: Tree,
}

#[derive(Debug)]
struct CentralEntry {
    attributes: u32,
    flags: u16,
    name: Vec<u8>,
}

struct DestinationLock {
    _file: File,
    #[cfg(not(windows))]
    path: PathBuf,
}

impl DestinationLock {
    fn acquire(dest: &Path) -> Result<Self, String> {
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
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if !metadata.is_file() || is_reparse_point(&path).map_err(|error| error.to_string())? {
                return Err(format!("unsafe destination lock: {}", path.display()));
            }
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

// Faults and fake ownership/recovery locations exist only in the unit-test binary.
#[cfg(test)]
#[derive(Default)]
struct TestHooks {
    faults: BTreeMap<&'static str, usize>,
    owner_dest: Option<PathBuf>,
    owner: Option<String>,
    recovery: Option<PathBuf>,
}

#[cfg(test)]
thread_local! {
    static TEST_HOOKS: std::cell::RefCell<TestHooks> = std::cell::RefCell::new(TestHooks::default());
}

fn fault(_point: &str) -> io::Result<()> {
    #[cfg(test)]
    return TEST_HOOKS.with(|hooks| {
        let mut hooks = hooks.borrow_mut();
        if let Some(count) = hooks.faults.get_mut(_point) {
            if *count > 0 {
                *count -= 1;
            } else {
                hooks.faults.remove(_point);
                return Err(io::Error::other(format!("injected {_point} failure")));
            }
        }
        Ok(())
    });
    #[cfg(not(test))]
    Ok(())
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

    if command.eq_ignore_ascii_case("migrate-legacy") && arguments.len() == 4 {
        let owner = match owner_from_os(&arguments[2]) {
            Ok(owner) => owner,
            Err(error) => {
                eprintln!("Invalid owner: {error}");
                return Ok(2);
            }
        };
        let version = match arguments[3].to_str().and_then(parse_release_version) {
            Some(version) => version,
            None => {
                eprintln!("Release version must have three or four normalized numeric components.");
                return Ok(2);
            }
        };
        let dest = Path::new(&arguments[1]);
        validate_migration_destination(dest)?;
        let registrations = enumerate_legacy_registrations()?;
        return migrate_legacy_records(
            dest,
            &owner,
            version,
            &registrations,
            run_legacy_uninstaller,
        );
    }

    usage();
    Ok(2)
}

fn usage() {
    eprintln!("Usage: GhidraLaunchGhidraHelperRS extract <zipPath> <destDir> [owner]");
    eprintln!("       GhidraLaunchGhidraHelperRS remove <destDir> [zipPath] [owner]");
    eprintln!(
        "       GhidraLaunchGhidraHelperRS migrate-legacy <destDir> <owner> <releaseVersion>"
    );
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

#[derive(Debug, Clone, Default)]
struct LegacyRegistration {
    location: String,
    name: Option<String>,
    publisher: Option<String>,
    upgrade_codes: Vec<String>,
    version: Option<String>,
    cache: Option<String>,
}

impl LegacyRegistration {
    fn is_ghidra_legacy(&self) -> bool {
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

#[cfg(any(windows, test))]
enum LegacyRegistryValue {
    String(Vec<u8>),
    MultiString(Vec<u8>),
    Other,
}

#[cfg(any(windows, test))]
fn legacy_registry_utf16(data: &[u8]) -> Option<Vec<u16>> {
    let (pairs, remainder) = data.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    Some(pairs.iter().copied().map(u16::from_le_bytes).collect())
}

#[cfg(any(windows, test))]
impl LegacyRegistryValue {
    fn scalar(&self) -> Option<String> {
        let Self::String(data) = self else {
            return None;
        };
        let units = legacy_registry_utf16(data)?;
        let (&terminator, text) = units.split_last()?;
        if terminator != 0 || text.contains(&0) {
            return None;
        }
        String::from_utf16(text).ok()
    }

    fn upgrade_codes(&self) -> Option<Vec<String>> {
        let Self::MultiString(data) = self else {
            return self.scalar().map(|text| vec![text]);
        };
        let units = legacy_registry_utf16(data)?;
        if !units.ends_with(&[0, 0]) {
            return None;
        }
        let body = &units[..units.len() - 2];
        if body.is_empty() {
            return Some(Vec::new());
        }
        body.split(|unit| *unit == 0)
            .map(|text| {
                if text.is_empty() {
                    None
                } else {
                    String::from_utf16(text).ok()
                }
            })
            .collect()
    }
}

fn parse_release_version(text: &str) -> Option<[u32; 4]> {
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

fn validate_migration_destination(dest: &Path) -> Result<(), String> {
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
            Component::Normal(name) => name.to_string_lossy().contains(':'),
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
        let key = cache.to_string_lossy().into_owned();
        caches.entry(key).or_insert(cache);
    }
    Ok(caches.into_values().collect())
}

fn rename_legacy_tree(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
        let source = to_wide_verbatim(source)?;
        let destination = to_wide_verbatim(destination)?;
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

fn migrate_legacy_records(
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

fn run_legacy_uninstaller(cache: &Path, owner: &str) -> Result<i32, String> {
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

#[cfg(any(not(windows), test))]
fn enumerate_legacy_registrations() -> Result<Vec<LegacyRegistration>, String> {
    Err("native legacy registry enumeration requires Windows and is forbidden in unit tests".into())
}

#[cfg(all(windows, not(test)))]
fn enumerate_legacy_registrations() -> Result<Vec<LegacyRegistration>, String> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND,
        ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_WOW64_32KEY,
        KEY_WOW64_64KEY, REG_MULTI_SZ, REG_SZ,
    };
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.0) };
        }
    }
    fn read_value(key: HKEY, name: &str) -> Result<Option<LegacyRegistryValue>, String> {
        let name = wide(name);
        let mut bytes = 0;
        let mut kind = 0;
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                std::ptr::null_mut(),
                &mut bytes,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(format!(
                "cannot query legacy registry value: {}",
                io::Error::from_raw_os_error(status as i32)
            ));
        }
        if !matches!(kind, REG_SZ | REG_MULTI_SZ) {
            return Ok(Some(LegacyRegistryValue::Other));
        }
        if bytes > 1024 * 1024 {
            return Ok(None);
        }
        let expected_kind = kind;
        let mut data = vec![0u8; bytes as usize];
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                data.as_mut_ptr(),
                &mut bytes,
            )
        };
        if status == ERROR_MORE_DATA
            || status == ERROR_FILE_NOT_FOUND
            || kind != expected_kind
            || bytes as usize > data.len()
        {
            return Err("legacy registration changed during enumeration; retry migration".into());
        }
        if status != ERROR_SUCCESS {
            return Err(format!(
                "cannot read legacy registry value: {}",
                io::Error::from_raw_os_error(status as i32)
            ));
        }
        data.truncate(bytes as usize);
        Ok(Some(match kind {
            REG_SZ => LegacyRegistryValue::String(data),
            REG_MULTI_SZ => LegacyRegistryValue::MultiString(data),
            _ => LegacyRegistryValue::Other,
        }))
    }
    fn read_string(key: HKEY, name: &str) -> Result<Option<String>, String> {
        Ok(read_value(key, name)?.and_then(|value| value.scalar()))
    }
    fn read_upgrade_codes(key: HKEY) -> Result<Vec<String>, String> {
        Ok(read_value(key, "BundleUpgradeCode")?
            .and_then(|value| value.upgrade_codes())
            .unwrap_or_default())
    }
    let mut records = Vec::new();
    for (scope, root) in [("HKCU", HKEY_CURRENT_USER), ("HKLM", HKEY_LOCAL_MACHINE)] {
        for (view, flag) in [("32", KEY_WOW64_32KEY), ("64", KEY_WOW64_64KEY)] {
            let uninstall = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
            let mut handle = std::ptr::null_mut();
            let status = unsafe {
                RegOpenKeyExW(
                    root,
                    wide(uninstall).as_ptr(),
                    0,
                    KEY_ENUMERATE_SUB_KEYS | flag,
                    &mut handle,
                )
            };
            if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(format!(
                    "cannot enumerate {scope} {view}-bit legacy bundles: {}",
                    io::Error::from_raw_os_error(status as i32)
                ));
            }
            let parent = Key(handle);
            let mut index = 0;
            loop {
                let mut name = [0u16; 256];
                let mut length = name.len() as u32;
                let status = unsafe {
                    RegEnumKeyExW(
                        parent.0,
                        index,
                        name.as_mut_ptr(),
                        &mut length,
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                if status == ERROR_NO_MORE_ITEMS {
                    break;
                }
                if status != ERROR_SUCCESS {
                    return Err(format!(
                        "cannot enumerate {scope} {view}-bit legacy bundle key: {}",
                        io::Error::from_raw_os_error(status as i32)
                    ));
                }
                index += 1;
                let location = format!(
                    "{scope}\\{uninstall}\\{} ({view}-bit)",
                    String::from_utf16_lossy(&name[..length as usize])
                );
                let mut handle = std::ptr::null_mut();
                let status = unsafe {
                    RegOpenKeyExW(
                        parent.0,
                        name.as_ptr(),
                        0,
                        KEY_QUERY_VALUE | flag,
                        &mut handle,
                    )
                };
                if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
                    return Err(format!(
                        "legacy registration {location} disappeared; retry migration"
                    ));
                }
                if status != ERROR_SUCCESS {
                    return Err(format!(
                        "cannot read legacy registration {location}: {}",
                        io::Error::from_raw_os_error(status as i32)
                    ));
                }
                let key = Key(handle);
                let mut record = LegacyRegistration {
                    location,
                    name: read_string(key.0, "DisplayName")?,
                    ..LegacyRegistration::default()
                };
                if !record
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case("Ghidra Launch"))
                {
                    continue;
                }
                record.publisher = read_string(key.0, "Publisher")?;
                if !record
                    .publisher
                    .as_deref()
                    .is_some_and(|publisher| publisher.eq_ignore_ascii_case("rpinz"))
                {
                    continue;
                }
                record.upgrade_codes = read_upgrade_codes(key.0)?;
                if !record.is_ghidra_legacy() {
                    continue;
                }
                record.version = read_string(key.0, "BundleVersion")?;
                record.cache = read_string(key.0, "BundleCachePath")?;
                records.push(record);
            }
        }
    }
    Ok(records)
}

/// The record describes the tree Setup manages, so it is maintained only for
/// that destination; standalone extractions elsewhere must never disturb an
/// installed bundle's ownership.
#[cfg(windows)]
fn manages_owner_record(dest: &Path) -> bool {
    let Some(root) = env::var_os("LOCALAPPDATA") else {
        return false;
    };
    let managed = Path::new(&root).join(OWNER_DESTINATION);
    comparable_path(dest) == comparable_path(&managed)
}

#[cfg(windows)]
fn comparable_path(path: &Path) -> String {
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
    normalized
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

/// Setup detects payload ownership through this per-user value. The helper is
/// the only package that runs whenever ownership changes, so it -- not the MSI,
/// which Burn skips when a republished bundle ships an already installed
/// package -- has to keep the record in step with the on-disk marker.
#[cfg(windows)]
fn set_owner_record_native(dest: &Path, owner: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE,
        REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    if !manages_owner_record(dest) {
        return Ok(());
    }
    require_native_registry_access()?;
    let path = wide(OWNER_KEY);
    let name = wide(OWNER_VALUE);
    let value = wide(owner);
    let mut key: HKEY = std::ptr::null_mut();
    let mut status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            path.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        )
    };
    if status == ERROR_SUCCESS {
        status = unsafe {
            RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast::<u8>(),
                (value.len() * std::mem::size_of::<u16>()) as u32,
            )
        };
        unsafe { RegCloseKey(key) };
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "cannot record payload ownership under HKCU\\{OWNER_KEY}: {}",
            io::Error::from_raw_os_error(status as i32)
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn clear_owner_record_native(dest: &Path, owner: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
        KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ,
    };

    if !manages_owner_record(dest) {
        return Ok(());
    }
    require_native_registry_access()?;
    let path = wide(OWNER_KEY);
    let name = wide(OWNER_VALUE);
    let expected = wide(owner);
    let mut key: HKEY = std::ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            path.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &mut key,
        )
    };
    if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
        return Ok(());
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "cannot open payload ownership record under HKCU\\{OWNER_KEY}: {}",
            io::Error::from_raw_os_error(status as i32)
        ));
    }

    let mut current = [0u16; 130];
    let mut kind = 0u32;
    let mut bytes = ((current.len() - 1) * std::mem::size_of::<u16>()) as u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            current.as_mut_ptr().cast::<u8>(),
            &mut bytes,
        )
    };
    // Retract only our own record; an incoming bundle may already have adopted
    // the tree, and its record has to outlive this removal.
    let mut removal = ERROR_SUCCESS;
    if status == ERROR_SUCCESS && kind == REG_SZ {
        let units = &current[..bytes as usize / std::mem::size_of::<u16>()];
        let units = match units.iter().position(|unit| *unit == 0) {
            Some(end) => &units[..end],
            None => units,
        };
        if units == &expected[..expected.len() - 1] {
            removal = unsafe { RegDeleteValueW(key, name.as_ptr()) };
            if removal == ERROR_FILE_NOT_FOUND {
                removal = ERROR_SUCCESS;
            }
        }
    }
    unsafe { RegCloseKey(key) };
    if removal != ERROR_SUCCESS {
        return Err(format!(
            "cannot clear payload ownership record under HKCU\\{OWNER_KEY}: {}",
            io::Error::from_raw_os_error(removal as i32)
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

#[cfg(windows)]
fn require_native_registry_access() -> Result<(), String> {
    #[cfg(test)]
    return Err(
        "unit tests require an injected ownership record; native HKCU access is forbidden".into(),
    );
    #[cfg(not(test))]
    Ok(())
}

#[cfg(not(windows))]
fn set_owner_record_native(_dest: &Path, _owner: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(windows))]
fn clear_owner_record_native(_dest: &Path, _owner: &str) -> Result<(), String> {
    Ok(())
}

fn set_owner_record(dest: &Path, owner: &str) -> Result<(), String> {
    fault("registry-write").map_err(|error| error.to_string())?;
    #[cfg(test)]
    let mocked = TEST_HOOKS.with(|hooks| {
        let mut hooks = hooks.borrow_mut();
        if hooks.owner_dest.as_deref() == Some(dest) {
            hooks.owner = Some(owner.to_owned());
            true
        } else {
            false
        }
    });
    #[cfg(not(test))]
    let mocked = false;
    if !mocked {
        set_owner_record_native(dest, owner)?;
    }
    fault("registry-write-after").map_err(|error| error.to_string())
}

fn clear_owner_record(dest: &Path, owner: &str) -> Result<(), String> {
    fault("registry-clear").map_err(|error| error.to_string())?;
    #[cfg(test)]
    if TEST_HOOKS.with(|hooks| {
        let mut hooks = hooks.borrow_mut();
        if hooks.owner_dest.as_deref() == Some(dest) {
            if hooks.owner.as_deref() == Some(owner) {
                hooks.owner = None;
            }
            true
        } else {
            false
        }
    }) {
        return Ok(());
    }
    clear_owner_record_native(dest, owner)
}

fn get_owner_record(dest: &Path) -> Result<Option<String>, String> {
    #[cfg(test)]
    if let Some(record) = TEST_HOOKS.with(|hooks| {
        let hooks = hooks.borrow();
        (hooks.owner_dest.as_deref() == Some(dest)).then(|| hooks.owner.clone())
    }) {
        return Ok(record);
    }
    get_owner_record_native(dest)
}

#[cfg(not(windows))]
fn get_owner_record_native(_dest: &Path) -> Result<Option<String>, String> {
    Ok(None)
}

#[cfg(windows)]
fn get_owner_record_native(dest: &Path) -> Result<Option<String>, String> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE,
        REG_SZ,
    };
    if !manages_owner_record(dest) {
        return Ok(None);
    }
    require_native_registry_access()?;
    let mut key: HKEY = std::ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            wide(OWNER_KEY).as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "cannot read previous payload owner: {}",
            io::Error::from_raw_os_error(status as i32)
        ));
    }
    let mut value = [0u16; 130];
    let mut kind = 0;
    let mut bytes = (value.len() * 2) as u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            wide(OWNER_VALUE).as_ptr(),
            std::ptr::null(),
            &mut kind,
            value.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    unsafe { RegCloseKey(key) };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS || kind != REG_SZ || !bytes.is_multiple_of(2) {
        return Err("cannot safely read previous payload ownership record".into());
    }
    let value = &value[..bytes as usize / 2];
    let end = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    let text = String::from_utf16(&value[..end]).map_err(|error| error.to_string())?;
    Ok(Some(text))
}

fn restore_owner_record(dest: &Path, previous: Option<&str>, incoming: &str) -> Result<(), String> {
    match previous {
        Some(previous) => set_owner_record(dest, previous),
        None => clear_owner_record(dest, incoming),
    }
}

fn extract(zip_path: &Path, dest: &Path, owner: Option<&str>) -> Result<(), String> {
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

fn adopt(dest: &Path, owner: Option<&str>, inventory: Option<&[u8]>) -> Result<(), String> {
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
                    message.push_str(&format!(
                        "; rollback failed (original remains at {}): {restore_error}",
                        backup.display()
                    ));
                }
            }
        }
        return Err(message);
    }

    if let Some(owner) = owner {
        if let Err(mut error) = set_owner_record(dest, owner) {
            let displaced = unique_sibling_path(parent, dest, "uncommitted");
            let rollback = fault("rollback").and_then(|()| fs::rename(dest, &displaced));
            match rollback {
                Ok(()) => {
                    if let Some(backup) = &backup {
                        if let Err(restore_error) = fs::rename(backup, dest) {
                            error.push_str(&format!("; rollback failed; original remains at {}, uncommitted tree at {}: {restore_error}", backup.display(), displaced.display()));
                        } else {
                            error = append_cleanup(error, cleanup_if_exists(&displaced));
                        }
                    } else {
                        error = append_cleanup(error, cleanup_if_exists(&displaced));
                    }
                }
                Err(restore_error) => {
                    if let Some(backup) = &backup {
                        error.push_str(&format!(
                            "; rollback failed; original remains at {}, uncommitted tree at {}: {restore_error}",
                            backup.display(), dest.display()
                        ));
                    } else {
                        error.push_str(&format!(
                            "; rollback failed; no previous destination; uncommitted tree remains at {}: {restore_error}",
                            dest.display()
                        ));
                    }
                }
            }
            error = append_cleanup(
                error,
                restore_owner_record(dest, previous_owner.as_deref(), owner),
            );
            return Err(error);
        }
    }
    // Ownership is committed before fallible cleanup. Never roll back a committed tree.
    if let Some(backup) = backup {
        if let Err(error) = fault("cleanup").and_then(|()| remove_tree_no_follow(&backup)) {
            eprintln!(
                "WARNING: extraction committed, but backup cleanup failed; residual backup at {}: {error}",
                backup.display()
            );
        }
    }
    println!("Extracted Ghidra to {}.", dest.display());
    Ok(())
}

fn remove(dest: &Path, zip_path: Option<&Path>, owner: Option<&str>) -> Result<(), String> {
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
        if !metadata_name(&entry.file_name().to_string_lossy()) {
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

fn metadata_name(name: &str) -> bool {
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

fn relative_path(name: &str) -> PathBuf {
    name.split('/').collect()
}

fn scan_tree(root: &Path, include_metadata: bool) -> Result<Tree, String> {
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
        if components.join("/") != *name || (!allow_metadata && metadata_name(&components[0])) {
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

fn inventory_text(inventory: &Inventory) -> String {
    let mut text = format!("ghidralaunch-inventory-v1\nsource={}\n", inventory.source);
    for (name, item) in &inventory.tree {
        match item {
            Item::Directory => text.push_str(&format!("d\t-\t{name}\n")),
            Item::File(hash) => text.push_str(&format!("f\t{hash}\t{name}\n")),
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

fn read_inventory(dest: &Path, source: &str) -> Result<Inventory, String> {
    let bytes = read_regular_bytes(&dest.join(INVENTORY_NAME))
        .map_err(|error| format!("cannot read inventory: {error}"))?
        .ok_or("upstream inventory is unavailable")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "inventory is not UTF-8")?;
    parse_inventory(text, source)
}

fn tree_is_clean(upstream: &Tree, current: &Tree, allow_missing: bool) -> bool {
    current
        .iter()
        .all(|(name, item)| upstream.get(name) == Some(item))
        && (allow_missing || upstream.len() == current.len())
}

fn removal_text(marker: &Marker) -> String {
    format!(
        "ghidralaunch-removal-v1\nsource={}\nowner={}\n",
        marker.hash.to_lowercase(),
        marker.owner.as_deref().unwrap_or("")
    )
}

type MetadataSnapshot = Vec<(&'static str, Option<Vec<u8>>)>;

fn read_regular_bytes(path: &Path) -> io::Result<Option<Vec<u8>>> {
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

fn snapshot_metadata(dest: &Path) -> Result<MetadataSnapshot, String> {
    METADATA_NAMES
        .into_iter()
        .map(|name| {
            read_regular_bytes(&dest.join(name))
                .map(|bytes| (name, bytes))
                .map_err(|error| error.to_string())
        })
        .collect()
}

fn restore_metadata(dest: &Path, snapshot: &MetadataSnapshot) -> Result<(), String> {
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

fn write_bytes_atomically(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
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

fn copy_ordinary_file(source: &Path, target: &Path, expected: &str) -> Result<(), String> {
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

fn preserve_tree(
    dest: &Path,
    previous_source: Option<&str>,
    incoming_source: &str,
) -> Result<PathBuf, String> {
    fault("recovery").map_err(|error| error.to_string())?;
    let before = scan_tree(dest, true)?;
    let root = recovery_root()?;
    #[cfg(windows)]
    if comparable_path(&root) == comparable_path(dest)
        || comparable_path(&root).starts_with(&(comparable_path(dest) + "\\"))
    {
        return Err("recovery root cannot be inside the destination".into());
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
                    copy_ordinary_file(&dest.join(relative_path(name)), &target, hash)?
                }
            }
        }
        if scan_tree(dest, true)? != before || scan_tree(&tree, true)? != before {
            return Err("previous tree changed while preserving it".into());
        }
        let summary = format!(
            "ghidralaunch-recovery-v1\ndestination={}\nprevious-source={}\nincoming-source={incoming_source}\ncontents=tree\n",
            dest.display(), previous_source.unwrap_or("unknown")
        );
        write_bytes_atomically(&recovery, "recovery.txt", summary.as_bytes())
            .map_err(|error| format!("cannot record recovery summary: {error}"))?;
        Ok::<(), String>(())
    })();
    if let Err(error) = operation {
        return Err(format!("cannot preserve previous tree; original remains at {}; incomplete recovery at {}: {error}", dest.display(), recovery.display()));
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
            if let Some((canonical, item)) = upstream_keys.get(&candidate.to_lowercase()) {
                if canonical.as_str() != candidate
                    || !matches!(item, Item::Directory)
                    || (candidate == name.as_str() && !matches!(current[*name], Item::Directory))
                {
                    safe = false;
                    break;
                }
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

fn remove_payload_no_follow(path: &Path) -> io::Result<()> {
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

fn validate_archive<R: Read + io::Seek>(
    zip: &mut ZipArchive<R>,
    external_attributes: &[CentralEntry],
) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::with_capacity(zip.len());
    let mut explicit = BTreeSet::new();
    let mut types: BTreeMap<String, bool> = BTreeMap::new();
    let mut canonical_dirs: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (index, central) in external_attributes.iter().enumerate().take(zip.len()) {
        let file = zip
            .by_index(index)
            .map_err(|error| format!("cannot inspect zip entry {index}: {error}"))?;
        // zip may replace name_raw() with a Unicode-path extra-field override.
        // Match C by decoding the original central name with its original flags.
        let raw_name = decode_zip_name(&central.name, central.flags)?;
        let unix_type = file.unix_mode().unwrap_or(0) & 0o170000;
        if file.is_symlink()
            || central.attributes & 0x0400 != 0
            || (unix_type != 0 && !matches!(unix_type, 0o100000 | 0o040000))
        {
            return Err(format!(
                "archive contains a symbolic link, special file, or reparse point: {raw_name}"
            ));
        }
        let is_dir = raw_name.ends_with(['/', '\\'])
            || central.attributes & 0x10 != 0
            || file
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o040000);
        let original_components = validate_zip_path(&raw_name, is_dir)?;
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

fn decode_zip_name(bytes: &[u8], flags: u16) -> Result<String, String> {
    if flags & 0x0800 != 0 {
        return std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| "flagged ZIP entry name is not valid UTF-8".into());
    }
    const CP437: &str = concat!(
        "ÇüéâäàåçêëèïîìÄÅ",
        "ÉæÆôöòûùÿÖÜ¢£¥₧ƒ",
        "áíóúñÑªº¿⌐¬½¼¡«»",
        "░▒▓│┤╡╢╖╕╣║╗╝╜╛┐",
        "└┴┬├─┼╞╟╚╔╩╦╠═╬╧",
        "╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀",
        "αßΓπΣσµτΦΘΩδ∞φε∩",
        "≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}"
    );
    let high: Vec<char> = CP437.chars().collect();
    Ok(bytes
        .iter()
        .map(|byte| {
            if *byte < 128 {
                char::from(*byte)
            } else {
                high[usize::from(*byte - 128)]
            }
        })
        .collect())
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
    hash_reader(&mut file)
}

fn hash_reader(reader: &mut impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let length = reader.read(&mut buffer)?;
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
        #[cfg(windows)]
        if metadata.permissions().readonly() {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::{
                SetFileAttributesW, FILE_ATTRIBUTE_READONLY,
            };
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

fn read_central_directory_attributes(path: &Path) -> io::Result<Vec<CentralEntry>> {
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
        let mut name = vec![0; name_length as usize];
        file.read_exact(&mut name)?;
        attributes.push(CentralEntry {
            attributes: read_u32_le(&header[38..]).unwrap(),
            flags: read_u16_le(&header[8..]).unwrap(),
            name,
        });
        file.seek(SeekFrom::Current(
            i64::try_from(extra_length + comment_length).map_err(|_| {
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
            if unit == b'/' as u16 {
                b'\\' as u16
            } else {
                unit
            }
        })
        .collect();
    let (prefix, rest) = if units.starts_with(&[b'\\' as u16, b'\\' as u16]) {
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
        assert!(destination.exists());
        fs::remove_file(destination.join("user-data.txt")).unwrap();
        remove(&destination, Some(&archive_path), Some("new-owner")).unwrap();
        assert!(!destination.exists());
        remove_tree_no_follow(&root).unwrap();
    }

    struct Fixture {
        root: PathBuf,
        dest: PathBuf,
        first: PathBuf,
        next: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
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

        fn install(&self) {
            extract(&self.first, &self.dest, Some("old-owner")).unwrap();
        }

        fn inject(&self, point: &'static str, after: usize) {
            TEST_HOOKS.with(|hooks| {
                hooks.borrow_mut().faults.insert(point, after);
            });
        }

        fn record(&self) -> Option<String> {
            get_owner_record(&self.dest).unwrap()
        }

        fn backups(&self) -> Vec<PathBuf> {
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

        fn recovered(&self) -> Vec<PathBuf> {
            match fs::read_dir(self.root.join("Recovery")) {
                Ok(entries) => entries
                    .map(|entry| entry.unwrap().path().join("tree"))
                    .collect(),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
                Err(error) => panic!("{error}"),
            }
        }

        fn assert_original(&self) {
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

    fn write_zip(path: &Path, entries: &[(&str, &str)]) {
        let mut zip = ZipWriter::new(File::create(path).unwrap());
        for (name, data) in entries {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(data.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }

    fn legacy_record(cache: &Path, version: &str) -> LegacyRegistration {
        LegacyRegistration {
            location: "HKCU\\Uninstall\\fixture (64-bit)".into(),
            name: Some("Ghidra Launch".into()),
            publisher: Some("rpinz".into()),
            upgrade_codes: vec![LEGACY_FAMILY.into()],
            version: Some(version.into()),
            cache: Some(cache.to_str().unwrap().into()),
        }
    }

    fn legacy_registry_bytes(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn migration_registry_scalars_require_exact_terminated_reg_sz() {
        for text in ["Ghidra Launch", "rpinz", "測試 🦀", ""] {
            assert_eq!(
                LegacyRegistryValue::String(legacy_registry_bytes(&format!("{text}\0"))).scalar(),
                Some(text.into())
            );
        }
        for data in [
            Vec::new(),
            legacy_registry_bytes("Ghidra Launch"),
            legacy_registry_bytes("\0Ghidra Launch\0"),
            legacy_registry_bytes("Ghidra\0 Launch\0"),
            legacy_registry_bytes("Ghidra Launch\0\0"),
            vec![b'G'],
            vec![0x00, 0xd8, 0x00, 0x00],
            vec![0x00, 0xdc, 0x00, 0x00],
        ] {
            assert!(
                LegacyRegistryValue::String(data.clone()).scalar().is_none(),
                "accepted malformed REG_SZ bytes {data:?}"
            );
        }
        assert!(
            LegacyRegistryValue::MultiString(legacy_registry_bytes("Ghidra Launch\0\0"))
                .scalar()
                .is_none()
        );
        assert!(LegacyRegistryValue::Other.scalar().is_none());
    }

    #[test]
    fn migration_registry_upgrade_lists_require_complete_strict_multi_sz() {
        assert_eq!(
            LegacyRegistryValue::MultiString(legacy_registry_bytes(&format!(
                "another-family\0{LEGACY_FAMILY}\0\0"
            )))
            .upgrade_codes(),
            Some(vec!["another-family".into(), LEGACY_FAMILY.into()])
        );
        assert_eq!(
            LegacyRegistryValue::MultiString(legacy_registry_bytes("\0\0")).upgrade_codes(),
            Some(Vec::new())
        );
        assert_eq!(
            LegacyRegistryValue::String(legacy_registry_bytes(&format!("{LEGACY_FAMILY}\0")))
                .upgrade_codes(),
            Some(vec![LEGACY_FAMILY.into()])
        );
        for data in [
            Vec::new(),
            legacy_registry_bytes("\0"),
            legacy_registry_bytes(LEGACY_FAMILY),
            legacy_registry_bytes(&format!("{LEGACY_FAMILY}\0")),
            legacy_registry_bytes(&format!("\0{LEGACY_FAMILY}\0\0")),
            legacy_registry_bytes(&format!("{LEGACY_FAMILY}\0\0\0")),
            legacy_registry_bytes(&format!("other\0\0{LEGACY_FAMILY}\0\0")),
            vec![0x00, 0xd8, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0xdc, 0x00, 0x00, 0x00, 0x00],
            vec![b'G'],
        ] {
            assert!(
                LegacyRegistryValue::MultiString(data.clone())
                    .upgrade_codes()
                    .is_none(),
                "accepted malformed REG_MULTI_SZ bytes {data:?}"
            );
        }
        assert!(LegacyRegistryValue::Other.upgrade_codes().is_none());
    }

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
        assert!(preflight_legacy(&records, [1, 0, 0, 0]).unwrap().is_empty());
    }

    fn migration_backups(fixture: &Fixture) -> Vec<PathBuf> {
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
        assert!(migration_backups(&fixture).is_empty());
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
            assert!(migration_backups(&fixture).is_empty());
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
        assert!(migrate_legacy_records(
            &fixture.dest,
            "old-owner",
            [1, 0, 0, 0],
            &records,
            |_, _| { panic!("missing marker must not launch") }
        )
        .unwrap_err()
        .contains("marker"));
        assert!(migrate_legacy_records(
            &fixture.root.join("not-managed"),
            "old-owner",
            [1, 0, 0, 0],
            &[],
            |_, _| panic!("unmanaged destination must not launch"),
        )
        .unwrap_err()
        .contains("restricted"));
        assert!(migration_backups(&fixture).is_empty());
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
            assert!(migration_backups(&fixture).is_empty());
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
    fn migration_private_cli_validates_inputs_without_native_access() {
        for (owner, version) in [
            ("bad/owner", "1.2.3"),
            ("valid", "1.2"),
            ("valid", "01.2.3"),
            ("valid", "1.2.3.4.5"),
            ("valid", "1.2.-3"),
            ("valid", "1.2.4294967296"),
        ] {
            assert_eq!(
                exit_code(&[
                    "migrate-legacy".into(),
                    "unused".into(),
                    owner.into(),
                    version.into()
                ]),
                2
            );
        }
        assert_eq!(
            parse_release_version("1.2.3"),
            parse_release_version("1.2.3.0")
        );
        assert!(enumerate_legacy_registrations().is_err());
        assert!(run_legacy_uninstaller(Path::new("never-run.exe"), "incoming-owner").is_err());
    }

    #[test]
    fn migration_command_uses_exact_program_and_independent_windows_arguments() {
        let executable = Path::new(r#"C:\cache with spaces\測試 & bundle.exe"#);
        let log = Path::new(r#"C:\user logs\quoted " value\legacy.log"#);
        let owner = "{B62B45B6-22D9-47E3-8EA2-41F5B4271BF9}";
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

    #[test]
    fn legacy_zip_encoding_uses_flags_not_utf8_guessing() {
        assert_eq!(decode_zip_name(b"caf\x82.txt", 0).unwrap(), "café.txt");
        assert_eq!(decode_zip_name(b"\xc3\xa9", 0).unwrap(), "├⌐");
        assert_eq!(
            decode_zip_name("測試/é".as_bytes(), 0x0800).unwrap(),
            "測試/é"
        );
        assert!(decode_zip_name(b"\x82", 0x0800).is_err());
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
        assert!(fixture.backups().is_empty());
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
        assert!(fixture.backups().is_empty());
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
        assert!(fixture.backups().is_empty());
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
        assert!(fixture.backups().is_empty());
        assert_eq!(fixture.recovered().len(), 1);
    }

    #[test]
    fn initial_owner_commit_failure_restores_absent_destination_and_record() {
        let fixture = Fixture::new("initial-commit-fault");
        fixture.inject("registry-write-after", 0);
        assert!(extract(&fixture.first, &fixture.dest, Some("new-owner")).is_err());
        assert!(!fixture.dest.exists());
        assert_eq!(fixture.record(), None);
        assert!(fixture.backups().is_empty());
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
                assert!(fixture.backups().is_empty());
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
            read_central_directory_attributes(&archive_path).unwrap()[0].attributes & 0x0400,
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
