// main.rs : Launch Ghidra ghidraRun.bat
//
#![windows_subsystem = "windows"]

use core::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null, null_mut};
use windows_sys::{
    self,
    Win32::Foundation::CloseHandle, Win32::Foundation::GetLastError, Win32::Foundation::HANDLE, Win32::Foundation::INVALID_HANDLE_VALUE,
    Win32::Security::SECURITY_ATTRIBUTES,
    Win32::System::Diagnostics::Debug::MessageBeep,
    Win32::System::Threading::CreateProcessA, Win32::System::Threading::GetExitCodeProcess, Win32::System::Threading::TerminateProcess, Win32::System::Threading::WaitForSingleObject, Win32::System::Threading::CREATE_NO_WINDOW, Win32::System::Threading::PROCESS_INFORMATION, Win32::System::Threading::STARTF_USESHOWWINDOW, Win32::System::Threading::STARTUPINFOA, Win32::System::Threading::WAIT_OBJECT_0,
    Win32::UI::WindowsAndMessaging::MessageBoxA, Win32::UI::WindowsAndMessaging::MB_DEFAULT_DESKTOP_ONLY, Win32::UI::WindowsAndMessaging::MB_ICONERROR, Win32::UI::WindowsAndMessaging::MB_SETFOREGROUND, Win32::UI::WindowsAndMessaging::MB_SYSTEMMODAL, Win32::UI::WindowsAndMessaging::SW_HIDE, 
};

// constant values
const INFINITE: u32 = 0xFFFFFFFF;
const EXIT_SUCCESS: u32 = 0;
const EXIT_FAILURE: u32 = 1;
const FALSE: i32 = 0;
const TRUE: i32 = 1;

// main entrypoint
fn main() {
    const APPLICATION_NAME: &[u8; 13] = b"GhidraLaunch\0";
    const COMMANDLINE: &[u8; 27] = b"cmd.exe /c .\\ghidraRun.bat\0";
    let mut return_code: u32 = EXIT_FAILURE;

    // empty STARTUPINFO struct
    let mut lp_startup_info: STARTUPINFOA = STARTUPINFOA {
        cb: 0,
        lpReserved: null_mut(),
        lpDesktop: null_mut(),
        lpTitle: null_mut(),
        dwX: 0,
        dwY: 0,
        dwXSize: 0,
        dwYSize: 0,
        dwXCountChars: 0,
        dwYCountChars: 0,
        dwFillAttribute: 0,
        dwFlags: 0,
        wShowWindow: 0,
        cbReserved2: 0,
        lpReserved2: null_mut(),
        hStdInput: INVALID_HANDLE_VALUE as isize,
        hStdOutput: INVALID_HANDLE_VALUE as isize,
        hStdError: INVALID_HANDLE_VALUE as isize,
    };
    // empty PROCESS_INFORMATION struct
    let mut lp_process_info: PROCESS_INFORMATION = PROCESS_INFORMATION {
        hProcess: 0,
        hThread: 0,
        dwProcessId: 0,
        dwThreadId: 0,
    };

    // populate STARTUPINFO struct making sure there is no console window
    lp_startup_info.cb = size_of::<STARTUPINFOA>() as u32;
    lp_startup_info.dwFlags = STARTF_USESHOWWINDOW as u32;
    lp_startup_info.wShowWindow = SW_HIDE as u16;

    unsafe {
        // create process
        if CreateProcessA(
            null() as *const u8,
            COMMANDLINE.to_owned().as_mut_ptr() as *mut u8,
            null() as *const SECURITY_ATTRIBUTES,
            null() as *const SECURITY_ATTRIBUTES,
            FALSE as i32,
            CREATE_NO_WINDOW as u32,
            null() as *const c_void,
            null() as *const u8,
            &mut lp_startup_info as *const STARTUPINFOA,
            &mut lp_process_info as *mut PROCESS_INFORMATION,
        ) == TRUE {
            //  wait for child to infinity and beyond
            let mut dw_error: u32 = WaitForSingleObject(lp_process_info.hProcess as HANDLE, INFINITE as u32);
            // if error terminate child process
            if dw_error != WAIT_OBJECT_0 {
                // terminate child process
                if TerminateProcess(lp_process_info.hProcess as HANDLE, dw_error) == TRUE {
                    // store error code
                    return_code = dw_error;
                }
            } else {
                // get child exit code
                if GetExitCodeProcess(lp_process_info.hProcess as HANDLE, &mut dw_error) == TRUE {
                    // store child exit code
                    return_code = dw_error;
                }
            }
        }

        // if process spawn failed, return_code is non-zero
        if return_code != EXIT_SUCCESS {
            // display message box with error message (error number)
            return_code = GetLastError();
            _ = MessageBoxA(
                0 as isize,
                format!("Failed to launch Ghidra!\nFatal Error: {}", return_code)
                    .as_ptr() as *const u8,
                APPLICATION_NAME.as_ptr() as *const u8,
                MB_ICONERROR | MB_DEFAULT_DESKTOP_ONLY | MB_SYSTEMMODAL | MB_SETFOREGROUND as u32,
            );
        }

        // close PROCESS_INFORMATION handles
        if CloseHandle(lp_process_info.hThread) == FALSE {
            _ = MessageBeep(MB_ICONERROR);
        }
        if CloseHandle(lp_process_info.hProcess) == FALSE {
            _ = MessageBeep(MB_ICONERROR);
        }
    }
}
