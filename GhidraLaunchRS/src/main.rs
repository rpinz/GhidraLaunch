// main.rs : Launch Ghidra ghidraRun.bat
//
#![windows_subsystem = "windows"]

use std::env;
use std::ffi::OsString;
use std::fmt::Display;
use std::io;
use std::iter::once;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{exit, Command};
use windows_sys::{
    Win32::System::SystemInformation::GetSystemDirectoryW,
    Win32::System::Threading::CREATE_NO_WINDOW,
    Win32::UI::WindowsAndMessaging::MessageBoxW, Win32::UI::WindowsAndMessaging::MB_DEFAULT_DESKTOP_ONLY, Win32::UI::WindowsAndMessaging::MB_ICONERROR, Win32::UI::WindowsAndMessaging::MB_SETFOREGROUND, Win32::UI::WindowsAndMessaging::MB_SYSTEMMODAL,
};

// constant values
const APPLICATION_NAME: &str = "GhidraLaunch";
const BATCH_FILE: &str = "ghidraRun.bat";
const EXIT_SUCCESS: i32 = 0;
const EXIT_FAILURE: i32 = 1;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_BAD_PATHNAME: i32 = 161;

// NUL-terminated UTF-16 copy of a string
fn to_wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(once(0)).collect()
}

// display message box with error message
fn show_error(message: &str, code: impl Display) {
    let text = to_wide(&format!("Failed to launch Ghidra!\n{message} {code}"));
    let caption = to_wide(APPLICATION_NAME);

    unsafe {
        _ = MessageBoxW(
            0,
            text.as_ptr(),
            caption.as_ptr(),
            MB_ICONERROR | MB_DEFAULT_DESKTOP_ONLY | MB_SYSTEMMODAL | MB_SETFOREGROUND,
        );
    }
}

// display message box for an io::Error and return a failure exit code
fn fail(message: &str, error: io::Error) -> i32 {
    show_error(message, error.raw_os_error().unwrap_or(EXIT_FAILURE) as u32);
    EXIT_FAILURE
}

// absolute path to the Windows system directory
fn system_directory() -> io::Result<PathBuf> {
    let mut buffer: Vec<u16> = vec![0; 260];

    loop {
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        if length < buffer.len() {
            buffer.truncate(length);
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        // buffer too small, length includes the terminating NUL
        buffer.resize(length, 0);
    }
}

// launch ghidraRun.bat and return the exit code
fn launch() -> i32 {
    // directory containing this launcher, ghidraRun.bat lives next to it
    let executable = match env::current_exe() {
        Ok(executable) => executable,
        Err(error) => return fail("Unable to locate the launcher, error", error),
    };
    let directory = match executable.parent() {
        Some(directory) => directory,
        None => return fail("Unable to locate the launcher, error", io::Error::from_raw_os_error(ERROR_BAD_PATHNAME)),
    };

    // make sure ghidraRun.bat exists before starting anything
    if !directory.join(BATCH_FILE).is_file() {
        return fail("ghidraRun.bat not found next to the launcher, error", io::Error::from_raw_os_error(ERROR_FILE_NOT_FOUND));
    }

    // absolute path to cmd.exe, never resolved through the search path
    let cmd = match system_directory() {
        Ok(system) => system.join("cmd.exe"),
        Err(error) => return fail("Unable to locate cmd.exe, error", error),
    };

    // create process and wait for child to infinity and beyond, /d skips cmd.exe AutoRun commands
    let status = Command::new(cmd)
        .raw_arg(format!("/d /c .\\{BATCH_FILE}"))
        .current_dir(directory)
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    match status {
        Ok(status) => match status.code() {
            Some(EXIT_SUCCESS) => EXIT_SUCCESS,
            Some(code) => {
                show_error("ghidraRun.bat exited with code", code as u32);
                code
            }
            None => {
                show_error("ghidraRun.bat exited with code", EXIT_FAILURE);
                EXIT_FAILURE
            }
        },
        Err(error) => fail("Unable to start cmd.exe, error", error),
    }
}

// main entrypoint
fn main() {
    exit(launch());
}
