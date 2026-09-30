//! Registry access: RAII keys, strict `REG_SZ`/`REG_MULTI_SZ` decoding of legacy registrations,
//! and the per-user payload ownership record.

#[cfg(windows)]
use crate::fs_safety::comparable_path;
#[cfg(test)]
use crate::hooks::TEST_HOOKS;
use crate::hooks::fault;
use crate::migration::LegacyRegistration;
use std::env;
use std::io;
use std::path::Path;

#[cfg(windows)]
const OWNER_KEY: &str = r"Software\rpinz\Ghidra Launch";

#[cfg(windows)]
const OWNER_VALUE: &str = "PayloadOwner";

#[cfg(windows)]
const OWNER_DESTINATION: &str = r"Ghidra Launch\Ghidra";

/// Closes a registry key handle when dropped.
#[cfg(windows)]
struct RegKey(windows_sys::Win32::System::Registry::HKEY);

#[cfg(windows)]
impl Drop for RegKey {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful RegOpenKeyExW/RegCreateKeyExW and is closed only here.
        unsafe { windows_sys::Win32::System::Registry::RegCloseKey(self.0) };
    }
}

#[cfg(any(windows, test))]
pub(crate) enum LegacyRegistryValue {
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
    pub(crate) fn scalar(&self) -> Option<String> {
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

    pub(crate) fn upgrade_codes(&self) -> Option<Vec<String>> {
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

#[cfg(any(not(windows), test))]
pub(crate) fn enumerate_legacy_registrations() -> Result<Vec<LegacyRegistration>, String> {
    Err("native legacy registry enumeration requires Windows and is forbidden in unit tests".into())
}

#[cfg(all(windows, not(test)))]
#[expect(
    clippy::too_many_lines,
    reason = "one linear walk over both registry hives and views; the unsafe Win32 calls stay together"
)]
pub(crate) fn enumerate_legacy_registrations() -> Result<Vec<LegacyRegistration>, String> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND,
        ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE,
        KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_MULTI_SZ, REG_SZ, RegEnumKeyExW, RegOpenKeyExW,
        RegQueryValueExW,
    };
    fn read_value(key: HKEY, name: &str) -> Result<Option<LegacyRegistryValue>, String> {
        let name = wide(name);
        let mut bytes = 0;
        let mut kind = 0;
        // SAFETY: `key` is open, `name` is NUL-terminated, and a null data pointer only queries the size.
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                std::ptr::null(),
                &raw mut kind,
                std::ptr::null_mut(),
                &raw mut bytes,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(format!(
                "cannot query legacy registry value: {}",
                io::Error::from_raw_os_error(status.cast_signed())
            ));
        }
        if !matches!(kind, REG_SZ | REG_MULTI_SZ) {
            return Ok(Some(LegacyRegistryValue::Other));
        }
        if bytes > 1024 * 1024 {
            return Ok(None);
        }
        let expected_kind = kind;
        let capacity =
            usize::try_from(bytes).map_err(|_| "legacy registry value is too large".to_owned())?;
        let mut data = vec![0u8; capacity];
        // SAFETY: `data` is writable for `bytes` bytes, the size passed to RegQueryValueExW.
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                std::ptr::null(),
                &raw mut kind,
                data.as_mut_ptr(),
                &raw mut bytes,
            )
        };
        if status == ERROR_MORE_DATA
            || status == ERROR_FILE_NOT_FOUND
            || kind != expected_kind
            || usize::try_from(bytes)
                .ok()
                .is_none_or(|length| length > data.len())
        {
            return Err("legacy registration changed during enumeration; retry migration".into());
        }
        if status != ERROR_SUCCESS {
            return Err(format!(
                "cannot read legacy registry value: {}",
                io::Error::from_raw_os_error(status.cast_signed())
            ));
        }
        data.truncate(
            usize::try_from(bytes).map_err(|_| "legacy registry value is too large".to_owned())?,
        );
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
            // SAFETY: the subkey name is a NUL-terminated temporary that outlives the call; `handle` receives the key.
            let status = unsafe {
                RegOpenKeyExW(
                    root,
                    wide(uninstall).as_ptr(),
                    0,
                    KEY_ENUMERATE_SUB_KEYS | flag,
                    &raw mut handle,
                )
            };
            if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(format!(
                    "cannot enumerate {scope} {view}-bit legacy bundles: {}",
                    io::Error::from_raw_os_error(status.cast_signed())
                ));
            }
            let parent = RegKey(handle);
            let mut index = 0;
            loop {
                let mut name = [0u16; 256];
                let mut length = u32::try_from(name.len())
                    .map_err(|_| "registry key name buffer is too large".to_owned())?;
                // SAFETY: `parent` is open and `name` is writable for `length` units; unused outputs are null.
                let status = unsafe {
                    RegEnumKeyExW(
                        parent.0,
                        index,
                        name.as_mut_ptr(),
                        &raw mut length,
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
                        io::Error::from_raw_os_error(status.cast_signed())
                    ));
                }
                index += 1;
                let location = format!(
                    "{scope}\\{uninstall}\\{} ({view}-bit)",
                    // Diagnostic text only; the key is opened from the exact UTF-16 name below.
                    String::from_utf16_lossy(
                        usize::try_from(length)
                            .ok()
                            .and_then(|length| name.get(..length))
                            .ok_or_else(|| "registry key name is too long".to_owned())?
                    )
                );
                let mut handle = std::ptr::null_mut();
                // SAFETY: `parent` is open and RegEnumKeyExW NUL-terminated `name`; `handle` receives the key.
                let status = unsafe {
                    RegOpenKeyExW(
                        parent.0,
                        name.as_ptr(),
                        0,
                        KEY_QUERY_VALUE | flag,
                        &raw mut handle,
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
                        io::Error::from_raw_os_error(status.cast_signed())
                    ));
                }
                let key = RegKey(handle);
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
pub(crate) fn manages_owner_record(dest: &Path) -> bool {
    let Some(root) = env::var_os("LOCALAPPDATA") else {
        return false;
    };
    let managed = Path::new(&root).join(OWNER_DESTINATION);
    comparable_path(dest) == comparable_path(&managed)
}

/// Setup detects payload ownership through this per-user value. The helper is
/// the only package that runs whenever ownership changes, so it -- not the MSI,
/// which Burn skips when a republished bundle ships an already installed
/// package -- has to keep the record in step with the on-disk marker.
#[cfg(windows)]
fn set_owner_record_native(dest: &Path, owner: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCreateKeyExW,
        RegSetValueExW,
    };

    if !manages_owner_record(dest) {
        return Ok(());
    }
    require_native_registry_access()?;
    let path = wide(OWNER_KEY);
    let name = wide(OWNER_VALUE);
    let value = wide(owner);
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: `path` is NUL-terminated, `key` receives the created key, and optional arguments are null.
    let mut status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            path.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &raw mut key,
            std::ptr::null_mut(),
        )
    };
    if status == ERROR_SUCCESS {
        let key = RegKey(key);
        // SAFETY: `key` is open and `value` is a NUL-terminated buffer of exactly the stated byte length.
        status = unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast::<u8>(),
                registry_byte_count(value.len())?,
            )
        };
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "cannot record payload ownership under HKCU\\{OWNER_KEY}: {}",
            io::Error::from_raw_os_error(status.cast_signed())
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn set_owner_record_native(_dest: &Path, _owner: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn clear_owner_record_native(dest: &Path, owner: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ, RegDeleteValueW,
        RegOpenKeyExW, RegQueryValueExW,
    };

    if !manages_owner_record(dest) {
        return Ok(());
    }
    require_native_registry_access()?;
    let path = wide(OWNER_KEY);
    let name = wide(OWNER_VALUE);
    let expected = wide(owner);
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: `path` is NUL-terminated and `key` receives the opened key.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            path.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &raw mut key,
        )
    };
    if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
        return Ok(());
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "cannot open payload ownership record under HKCU\\{OWNER_KEY}: {}",
            io::Error::from_raw_os_error(status.cast_signed())
        ));
    }
    let key = RegKey(key);

    let mut current = [0u16; 130];
    let mut kind = 0u32;
    let mut bytes = registry_byte_count(current.len() - 1)?;
    // SAFETY: `current` is writable for `bytes` bytes; one unit is reserved for a terminator.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            &raw mut kind,
            current.as_mut_ptr().cast::<u8>(),
            &raw mut bytes,
        )
    };
    // Retract only our own record; an incoming bundle may already have adopted
    // the tree, and its record has to outlive this removal.
    let mut removal = ERROR_SUCCESS;
    if status == ERROR_SUCCESS && kind == REG_SZ {
        let units = usize::try_from(bytes)
            .ok()
            .and_then(|bytes| current.get(..bytes / std::mem::size_of::<u16>()))
            .ok_or("payload ownership record has an invalid size")?;
        let units = match units.iter().position(|unit| *unit == 0) {
            Some(end) => &units[..end],
            None => units,
        };
        if units == &expected[..expected.len() - 1] {
            // SAFETY: `key` is open and `name` is NUL-terminated.
            removal = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
            if removal == ERROR_FILE_NOT_FOUND {
                removal = ERROR_SUCCESS;
            }
        }
    }
    drop(key);
    if removal != ERROR_SUCCESS {
        return Err(format!(
            "cannot clear payload ownership record under HKCU\\{OWNER_KEY}: {}",
            io::Error::from_raw_os_error(removal.cast_signed())
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn clear_owner_record_native(_dest: &Path, _owner: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

/// Size in bytes of `units` UTF-16 units, as the registry APIs expect it.
#[cfg(windows)]
fn registry_byte_count(units: usize) -> Result<u32, String> {
    units
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or_else(|| "registry value is too large".to_owned())
}

#[cfg(windows)]
#[cfg_attr(
    not(test),
    expect(
        clippy::unnecessary_wraps,
        reason = "the unit-test build forbids native registry access through this error"
    )
)]
fn require_native_registry_access() -> Result<(), String> {
    #[cfg(test)]
    return Err(
        "unit tests require an injected ownership record; native HKCU access is forbidden".into(),
    );
    #[cfg(not(test))]
    Ok(())
}

pub(crate) fn set_owner_record(dest: &Path, owner: &str) -> Result<(), String> {
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

pub(crate) fn clear_owner_record(dest: &Path, owner: &str) -> Result<(), String> {
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

pub(crate) fn get_owner_record(dest: &Path) -> Result<Option<String>, String> {
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
        HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, REG_SZ, RegOpenKeyExW, RegQueryValueExW,
    };
    if !manages_owner_record(dest) {
        return Ok(None);
    }
    require_native_registry_access()?;
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: the subkey name is a NUL-terminated temporary that outlives the call; `key` receives the key.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            wide(OWNER_KEY).as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &raw mut key,
        )
    };
    if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "cannot read previous payload owner: {}",
            io::Error::from_raw_os_error(status.cast_signed())
        ));
    }
    let key = RegKey(key);
    let mut value = [0u16; 130];
    let mut kind = 0;
    let mut bytes = registry_byte_count(value.len())?;
    // SAFETY: `value` is writable for `bytes` bytes and the value name temporary outlives the call.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            wide(OWNER_VALUE).as_ptr(),
            std::ptr::null(),
            &raw mut kind,
            value.as_mut_ptr().cast(),
            &raw mut bytes,
        )
    };
    drop(key);
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS || kind != REG_SZ || !bytes.is_multiple_of(2) {
        return Err("cannot safely read previous payload ownership record".into());
    }
    let value = usize::try_from(bytes)
        .ok()
        .and_then(|bytes| value.get(..bytes / 2))
        .ok_or("cannot safely read previous payload ownership record")?;
    let end = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    let text = String::from_utf16(&value[..end]).map_err(|error| error.to_string())?;
    Ok(Some(text))
}

pub(crate) fn restore_owner_record(
    dest: &Path,
    previous: Option<&str>,
    incoming: &str,
) -> Result<(), String> {
    match previous {
        Some(previous) => set_owner_record(dest, previous),
        None => clear_owner_record(dest, incoming),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::LEGACY_FAMILY;
    use crate::test_support::legacy_registry_bytes;

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
}
