// main.rs : Launch Ghidra ghidraRun.bat
//
#![windows_subsystem = "windows"]

use std::env;
use std::ffi::OsString;
use std::fmt::Display;
use std::io;
use std::iter::once;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Stdio};
use std::time::Duration;
use windows_sys::{
    Win32::Globalization::{MultiByteToWideChar, CP_ACP},
    Win32::System::Environment::GetCommandLineW,
    Win32::System::SystemInformation::GetSystemDirectoryW,
    Win32::System::Threading::CREATE_NO_WINDOW,
    Win32::UI::WindowsAndMessaging::MessageBoxW,
    Win32::UI::WindowsAndMessaging::MB_ICONERROR,
    Win32::UI::WindowsAndMessaging::MB_SETFOREGROUND,
    Win32::UI::WindowsAndMessaging::MB_SYSTEMMODAL,
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
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND,
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
        let length =
            unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
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

// text printed by a process in the ANSI code page, split into non-empty lines
fn ansi_lines(bytes: &[u8]) -> Vec<String> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let text = unsafe {
        let length = MultiByteToWideChar(
            CP_ACP,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            std::ptr::null_mut(),
            0,
        );
        let mut wide = vec![0u16; length.max(0) as usize];
        let written = MultiByteToWideChar(
            CP_ACP,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            wide.as_mut_ptr(),
            length,
        );
        wide.truncate(written.max(0) as usize);
        String::from_utf16_lossy(&wide)
    };
    text.split(['\r', '\n'])
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

// java that runs, like launch.bat: PATH first, then JAVA_HOME
fn find_java(directory: &Path) -> Option<PathBuf> {
    let runs = |java: &Path| {
        Command::new(java)
            .arg("-version")
            .current_dir(directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .is_ok_and(|status| status.success())
    };
    let path = PathBuf::from("java.exe");
    if runs(&path) {
        return Some(path);
    }
    let home = env::var_os("JAVA_HOME").filter(|value| !value.is_empty())?;
    let java = PathBuf::from(home).join("bin").join("java.exe");
    runs(&java).then_some(java)
}

// run LaunchSupport with an option and return its standard output lines
fn launch_support(
    java: &Path,
    directory: &Path,
    option: &str,
    capture: bool,
) -> Option<Vec<String>> {
    let jar = directory.join("support").join("LaunchSupport.jar");
    let mut arguments = OsString::from("-cp \"");
    arguments.push(jar);
    arguments.push("\" LaunchSupport \"");
    arguments.push(directory);
    arguments.push("\" ");
    arguments.push(option);
    let output = Command::new(java)
        .raw_arg(arguments)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    output.status.success().then(|| ansi_lines(&output.stdout))
}

// non-empty value of an environment variable
fn env_text(name: &str) -> Option<String> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string_lossy().into_owned())
}

// Start Ghidra the way ghidraRun.bat and support\launch.bat do, without cmd.exe.
// Returns None when that is not possible so the caller can fall back to ghidraRun.bat.
fn launch_native(directory: &Path, jdk_error: &mut bool) -> Option<i32> {
    // launch.bat rejects '!' in the path and a trailing backslash would escape the quotes below
    let text = directory.to_string_lossy();
    if text.ends_with('\\') || text.contains('!') {
        return None;
    }

    // only a packaged Ghidra is handled natively, not a development checkout
    let utility = directory.join(r"Ghidra\Framework\Utility\lib\Utility.jar");
    if !directory.join(r"Ghidra\application.properties").is_file()
        || !directory.join(r"support\LaunchSupport.jar").is_file()
        || !utility.is_file()
    {
        return None;
    }

    let Some(java) = find_java(directory) else {
        *jdk_error = true;
        return None;
    };
    let home = launch_support(&java, directory, "-jdk_home -save", true)
        .and_then(|lines| lines.last().cloned());
    let Some(home) = home.map(PathBuf::from) else {
        *jdk_error = true;
        return None;
    };
    let java = home.join("bin").join("java.exe");
    let javaw = home.join("bin").join("javaw.exe");
    if !java.is_file() || !javaw.is_file() {
        *jdk_error = true;
        return None;
    }

    // environment variables requested by launch.properties never override existing ones
    for line in launch_support(&java, directory, "-envvars", true)? {
        if let Some((name, value)) = line.split_once('=') {
            if !name.is_empty() && env_text(name).is_none() {
                env::set_var(name, value);
            }
        }
    }

    // command line in the order launch.bat builds it
    let mut parts: Vec<String> = Vec::new();
    parts.extend(env_text("FORCE_JAVA_VERSION"));
    parts.extend(env_text("JAVA_USER_HOME_DIR_OVERRIDE"));
    parts.extend(launch_support(&java, directory, "-vmargs", true)?);
    if let Some(profile) = env_text("USERPROFILE").filter(|profile| Path::new(profile).exists()) {
        parts.push(format!("-Duser.home=\"{profile}\""));
    }
    // GHIDRA_GUI_MAXMEM defaults to GHIDRA_MAXMEM
    if let Some(memory) = env_text("GHIDRA_GUI_MAXMEM").or_else(|| env_text("GHIDRA_MAXMEM")) {
        parts.push(format!("-Xmx{memory}"));
    }
    parts.extend(env_text("GHIDRA_JAVA_OPTIONS"));
    parts.extend(env_text("GHIDRA_GUI_JAVA_OPTIONS"));
    parts.push(format!(
        "-cp \"{}\" ghidra.Ghidra ghidra.GhidraRun",
        utility.display()
    ));

    let mut child = Command::new(javaw)
        .raw_arg(parts.join(" "))
        .args(env::args_os().skip(1))
        .current_dir(directory)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .ok()?;

    // like launch.bat, only report a Ghidra that dies right away
    for _ in 0..20 {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.code().unwrap_or(EXIT_FAILURE)),
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => return Some(EXIT_FAILURE),
        }
    }
    Some(EXIT_SUCCESS)
}

fn raw_arguments() -> OsString {
    let command = unsafe {
        let pointer = GetCommandLineW();
        let mut length = 0;
        while *pointer.add(length) != 0 {
            length += 1;
        }
        std::slice::from_raw_parts(pointer, length)
    };
    let mut index = 0;
    let mut quoted = false;
    while index < command.len() {
        if command[index] == b'"' as u16 {
            quoted = !quoted;
        } else if !quoted && matches!(command[index], 9 | 32) {
            break;
        }
        index += 1;
    }
    while index < command.len() && matches!(command[index], 9 | 32) {
        index += 1;
    }
    OsString::from_wide(&command[index..])
}

// launch ghidraRun.bat and return the exit code
fn launch() -> i32 {
    // use GHIDRA_HOME when set, otherwise look next to the launcher
    let executable = match env::current_exe() {
        Ok(executable) => executable,
        Err(error) => return fail("Unable to locate the launcher, error", error),
    };
    let directory = match executable.parent() {
        Some(directory) => env::var_os("GHIDRA_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| directory.to_path_buf()),
        None => {
            return fail(
                "Unable to locate the launcher, error",
                io::Error::from_raw_os_error(ERROR_BAD_PATHNAME),
            )
        }
    };
    // Resolve GHIDRA_HOME before using it both in Java arguments and as the
    // child's working directory; otherwise relative classpaths are doubled.
    let directory = match std::path::absolute(&directory) {
        Ok(directory) => directory,
        Err(error) => return fail("Unable to resolve the Ghidra directory, error", error),
    };

    // start Ghidra directly; fall back to ghidraRun.bat when that is not possible
    let mut jdk_error = false;
    match launch_native(&directory, &mut jdk_error) {
        Some(EXIT_SUCCESS) => return EXIT_SUCCESS,
        Some(code) => {
            show_error("Ghidra exited with code", code as u32);
            return code;
        }
        None => {}
    }
    if jdk_error {
        show_error(
            "No supported JDK could be selected. Set JAVA_HOME to a supported 64-bit JDK and restart Ghidra Launch. For manual selection, run ghidraRun.bat from a command prompt. Error",
            EXIT_FAILURE,
        );
        return EXIT_FAILURE;
    }

    // the fallback needs ghidraRun.bat
    if !directory.join(BATCH_FILE).is_file() {
        return fail(
            &format!(
                "Ghidra could not be started: ghidraRun.bat not found in {} (GHIDRA_HOME or the launcher folder), error",
                directory.display()
            ),
            io::Error::from_raw_os_error(ERROR_FILE_NOT_FOUND),
        );
    }

    // absolute path to cmd.exe, never resolved through the search path
    let cmd = match system_directory() {
        Ok(system) => system.join("cmd.exe"),
        Err(error) => return fail("Unable to locate cmd.exe, error", error),
    };

    // cmd.exe cannot use a UNC working directory; local paths stay out of its command text
    let mut directory_units = directory.as_os_str().encode_wide();
    let unc = directory_units.next() == Some(b'\\' as u16)
        && directory_units.next() == Some(b'\\' as u16);
    let batch = if unc {
        directory.join(BATCH_FILE)
    } else {
        PathBuf::from(r".\ghidraRun.bat")
    };

    // create process and wait for child to infinity and beyond
    let mut command = Command::new(cmd);
    let status = command
        .env("GL_BATCH", batch)
        .env("GL_ARGS", raw_arguments())
        .raw_arg("/d /v:on /s /c \"\"!GL_BATCH!\" !GL_ARGS!\"")
        .current_dir(&directory)
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
