// main.rs : Launch Ghidra ghidraRun.bat
//
#![windows_subsystem = "windows"]

use std::mem::size_of;
use std::ptr::{null, null_mut};
use windows_sys::{
    self, Win32::Foundation::CloseHandle, Win32::Foundation::INVALID_HANDLE_VALUE,
    Win32::System::Threading::CreateProcessA, Win32::System::Threading::GetExitCodeProcess,
    Win32::System::Threading::TerminateProcess, Win32::System::Threading::WaitForSingleObject,
    Win32::System::Threading::CREATE_NO_WINDOW, Win32::System::Threading::PROCESS_INFORMATION,
    Win32::System::Threading::STARTF_USESHOWWINDOW, Win32::System::Threading::STARTUPINFOA,
    Win32::UI::WindowsAndMessaging::MessageBoxA, Win32::UI::WindowsAndMessaging::MB_OK,
    Win32::UI::WindowsAndMessaging::SW_HIDE,
};

fn main()  {
    let mut return_code: u32 = 1;
    const APPLICATION_NAME: &[u8] = b"GhidraLaunch";
    const COMMANDLINE_FORMAT: &[u8] = b"cmd.exe /c .\\ghidraRun.bat\0";
    const INFINITE: u32 = 0xFFFFFFFF;

    unsafe {
        // ShowWindow(GetConsoleWindow(), SW_HIDE);
        let mut lp_startup_info = STARTUPINFOA {
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
            hStdInput: INVALID_HANDLE_VALUE,
            hStdOutput: INVALID_HANDLE_VALUE,
            hStdError: INVALID_HANDLE_VALUE,
        };
        let mut lp_process_info = PROCESS_INFORMATION {
            hProcess: 0,
            hThread: 0,
            dwProcessId: 0,
            dwThreadId: 0,
        };

        lp_startup_info.cb = size_of::<STARTUPINFOA>() as u32;
        lp_startup_info.dwFlags = STARTF_USESHOWWINDOW;
        lp_startup_info.wShowWindow = SW_HIDE as u16;

        if CreateProcessA(
            null(),
            COMMANDLINE_FORMAT.as_ptr() as _,
            null(),
            null(),
            0,
            CREATE_NO_WINDOW,
            null(),
            null(),
            &mut lp_startup_info,
            &mut lp_process_info,
        ) == 1
        {
            let mut dw_error: u32 = WaitForSingleObject(lp_process_info.hProcess, INFINITE);
            if dw_error != 0x0 {
                // terminate child process
                TerminateProcess(lp_process_info.hProcess, dw_error);
                // store error code
                return_code = dw_error;
            } else {
                // get child exit code
                if GetExitCodeProcess(lp_process_info.hProcess, &mut dw_error) == 1 {
                    return_code = dw_error;
                }
            }
        }

        if return_code != 0 {
            // display message box with error message
            MessageBoxA(0, format!("Failed to launch Ghidra!\nFatal Error: {}", return_code).as_ptr(), APPLICATION_NAME.as_ptr(), MB_OK);
        }

        // close PROCESS_INFORMATION handles
        CloseHandle(lp_process_info.hThread);
        CloseHandle(lp_process_info.hProcess);
    }
}
