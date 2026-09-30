//! ZIP validation and extraction: Windows-safe entry paths, UTF-8-flagged and legacy CP437
//! names, and an independent central-directory parse for attributes and original names.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use zip::ZipArchive;
#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) index: usize,
    pub(crate) path: PathBuf,
    pub(crate) components: Vec<String>,
    pub(crate) is_dir: bool,
}

#[derive(Debug)]
pub(crate) struct CentralEntry {
    attributes: u32,
    flags: u16,
    name: Vec<u8>,
}

pub(crate) fn validate_archive<R: Read + io::Seek>(
    zip: &mut ZipArchive<R>,
    external_attributes: &[CentralEntry],
) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::with_capacity(zip.len());
    let mut explicit = BTreeSet::new();
    let mut types: BTreeMap<String, bool> = BTreeMap::new();
    // Lowercased directory path -> spelling of its last component as first seen.
    let mut canonical_dirs: BTreeMap<String, String> = BTreeMap::new();

    for (index, central) in external_attributes.iter().enumerate().take(zip.len()) {
        let file = zip
            .by_index(index)
            .map_err(|error| format!("cannot inspect zip entry {index}: {error}"))?;
        // zip may replace name_raw() with a Unicode-path extra-field override.
        // Match C by decoding the original central name with its original flags.
        let raw_name = decode_zip_name(&central.name, central.flags)?;
        let unix_type = file.unix_mode().unwrap_or(0) & 0o170_000;
        if file.is_symlink()
            || central.attributes & 0x0400 != 0
            || (unix_type != 0 && !matches!(unix_type, 0o100_000 | 0o040_000))
        {
            return Err(format!(
                "archive contains a symbolic link, special file, or reparse point: {raw_name}"
            ));
        }
        let is_dir = raw_name.ends_with(['/', '\\'])
            || central.attributes & 0x10 != 0
            || file
                .unix_mode()
                .is_some_and(|mode| mode & 0o170_000 == 0o040_000);
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
                if let Some(canonical) = canonical_dirs.get(&key) {
                    if canonical != component {
                        return Err(format!(
                            "archive contains case-conflicting directory names: {raw_name}"
                        ));
                    }
                    components.push(canonical.clone());
                } else {
                    canonical_dirs.insert(key.clone(), component.clone());
                    components.push(component.clone());
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

pub(crate) fn validate_zip_path(name: &str, is_dir: bool) -> Result<Vec<String>, String> {
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
    if flags & 0x0800 != 0 {
        return std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| "flagged ZIP entry name is not valid UTF-8".into());
    }
    let high: Vec<char> = CP437.chars().collect();
    bytes
        .iter()
        .map(|&byte| {
            if byte < 128 {
                Ok(char::from(byte))
            } else {
                high.get(usize::from(byte - 128))
                    .copied()
                    .ok_or_else(|| "incomplete CP437 decoding table".to_owned())
            }
        })
        .collect()
}

pub(crate) fn flatten_root(entries: &[Entry]) -> Option<String> {
    let first = entries.first()?.components.first()?.clone();
    if entries.iter().any(|entry| {
        entry.components.first() != Some(&first) || (entry.components.len() == 1 && !entry.is_dir)
    }) {
        return None;
    }
    Some(first)
}

pub(crate) fn extract_entry<R: Read + io::Seek>(
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

#[expect(
    clippy::too_many_lines,
    reason = "one sequential ZIP/ZIP64 end-record and central-directory parse"
)]
pub(crate) fn read_central_directory_attributes(path: &Path) -> io::Result<Vec<CentralEntry>> {
    const EOCD_SIGNATURE: u32 = 0x0605_4b50;
    const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
    const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
    const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;

    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let tail_start = file_size.saturating_sub(22 + u64::from(u16::MAX));
    let tail_length = usize::try_from(file_size - tail_start)
        .map_err(|_| invalid_zip("ZIP end record is too large"))?;
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
                && index + 22 + usize::from(read_u16_le(&tail[*index + 20..]).unwrap_or(u16::MAX))
                    == tail.len()
        })
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "ZIP end record was not found")
        })?;
    let eocd_position = u64::try_from(eocd_index)
        .ok()
        .and_then(|index| tail_start.checked_add(index))
        .ok_or_else(|| invalid_zip("ZIP end record offset is invalid"))?;
    let eocd = &tail[eocd_index..];
    let mut entry_count = u64::from(truncated(read_u16_le(&eocd[10..]))?);
    let mut directory_size = u64::from(truncated(read_u32_le(&eocd[12..]))?);
    let mut directory_offset = u64::from(truncated(read_u32_le(&eocd[16..]))?);
    let mut directory_end = eocd_position;

    if entry_count == u64::from(u16::MAX)
        || directory_size == u64::from(u32::MAX)
        || directory_offset == u64::from(u32::MAX)
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
        let mut zip64_position = truncated(read_u64_le(&locator[8..]))?;
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
        entry_count = truncated(read_u64_le(&zip64_header[32..]))?;
        directory_size = truncated(read_u64_le(&zip64_header[40..]))?;
        directory_offset = truncated(read_u64_le(&zip64_header[48..]))?;
        directory_end = zip64_position;
    }

    // Every central-directory header is at least 46 bytes, so a count the file cannot hold is
    // corrupt; rejecting it also bounds the allocation below.
    let directory_count = usize::try_from(entry_count)
        .ok()
        .filter(|_| entry_count <= file_size / 46)
        .ok_or_else(|| invalid_zip("too many ZIP entries"))?;
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
        let name_length = truncated(read_u16_le(&header[28..]))?;
        let extra_length = u64::from(truncated(read_u16_le(&header[30..]))?);
        let comment_length = u64::from(truncated(read_u16_le(&header[32..]))?);
        let mut name = vec![0; usize::from(name_length)];
        file.read_exact(&mut name)?;
        attributes.push(CentralEntry {
            attributes: truncated(read_u32_le(&header[38..]))?,
            flags: truncated(read_u16_le(&header[8..]))?,
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

fn truncated<T>(value: Option<T>) -> io::Result<T> {
    value.ok_or_else(|| invalid_zip("ZIP record is truncated"))
}

fn invalid_zip(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_safety::remove_tree_no_follow;
    use crate::test_support::{test_root, write_zip};
    use std::io::Write;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

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
            let mut tail =
                vec![0; usize::try_from(metadata.len().min(22 + u64::from(u16::MAX))).unwrap()];
            file.seek(SeekFrom::End(-i64::try_from(tail.len()).unwrap()))
                .unwrap();
            file.read_exact(&mut tail).unwrap();
            let eocd = tail
                .windows(4)
                .rposition(|window| window == [0x50, 0x4b, 0x05, 0x06])
                .unwrap();
            u64::from(u32::from_le_bytes(
                tail[eocd + 16..eocd + 20].try_into().unwrap(),
            ))
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

    #[test]
    fn central_directory_rejects_impossible_entry_counts() {
        let root = test_root("central-count");
        fs::create_dir_all(&root).unwrap();
        let archive_path = root.join("count.zip");
        write_zip(&archive_path, &[("file.txt", "content")]);
        let mut bytes = fs::read(&archive_path).unwrap();
        insert_zip64_end_records(&mut bytes);
        let zip64 = bytes
            .windows(4)
            .rposition(|window| window == [0x50, 0x4b, 0x06, 0x06])
            .unwrap();
        bytes[zip64 + 32..zip64 + 40].copy_from_slice(&(u64::MAX / 2).to_le_bytes());
        fs::write(&archive_path, bytes).unwrap();
        let error = read_central_directory_attributes(&archive_path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        remove_tree_no_follow(&root).unwrap();
    }

    fn insert_zip64_end_records(bytes: &mut Vec<u8>) {
        let eocd = bytes
            .windows(4)
            .rposition(|window| window == [0x50, 0x4b, 0x05, 0x06])
            .unwrap();
        let count = u64::from(u16::from_le_bytes(
            bytes[eocd + 10..eocd + 12].try_into().unwrap(),
        ));
        let directory_size = u64::from(u32::from_le_bytes(
            bytes[eocd + 12..eocd + 16].try_into().unwrap(),
        ));
        let directory_offset = u64::from(u32::from_le_bytes(
            bytes[eocd + 16..eocd + 20].try_into().unwrap(),
        ));
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
        records.extend_from_slice(&u64::try_from(eocd).unwrap().to_le_bytes());
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
}
