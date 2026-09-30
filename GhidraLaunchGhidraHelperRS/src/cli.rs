//! Command-line parsing and the helper's exit-code contract (0 success, 1 failure, 2 usage).

use crate::extract::extract;
use crate::migration::{
    migrate_legacy_records, parse_release_version, run_legacy_uninstaller,
    validate_migration_destination,
};
use crate::registry::enumerate_legacy_registrations;
use crate::remove::remove;
use crate::state::validate_owner;
use std::ffi::{OsStr, OsString};
use std::path::Path;

pub(crate) fn exit_code(arguments: &[OsString]) -> i32 {
    match run(arguments) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Ghidra helper: {error}");
            1
        }
    }
}

pub(crate) fn run(arguments: &[OsString]) -> Result<i32, String> {
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
        let Some(version) = arguments[3].to_str().and_then(parse_release_version) else {
            eprintln!("Release version must have three or four normalized numeric components.");
            return Ok(2);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

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
}
