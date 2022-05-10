// GhidraLaunch.c : Launch Ghidra ghidraRun.bat
//

#include <windows.h>
#include <stdio.h>
#include <shlobj.h>

#define APPLICATION_NAME L"GhidraLaunch"
#define COMMANDLINE_FORMAT L"cmd.exe /c \"%s\""
#define ERROR_FORMAT L"Failed to launch Ghidra!\nFatal Error: %d"
#define GHIDRA_FILENAME L".\\ghidraRun.bat";
#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN

// no need for a console window
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:wWinMainCRTStartup")

// main entrypoint
int APIENTRY wWinMain(
  _In_ HINSTANCE hInstance,
  _In_opt_ HINSTANCE hPrevInstance,
  _In_ LPWSTR lpCmdLine,
  _In_ int nShowCmd
) {
  STARTUPINFO lpStartupInfo;
  PROCESS_INFORMATION lpProcessInfo;

  WCHAR* wCommandLine = malloc(1024);
  const WCHAR* const wApplicationName = APPLICATION_NAME;
  const WCHAR* const wCommandLineFormat = COMMANDLINE_FORMAT;
  const WCHAR* const wErrorFormat = ERROR_FORMAT;
  const WCHAR* const wGhidraFilename = GHIDRA_FILENAME;
  int returnCode = EXIT_FAILURE;

  // clear STARTUPINFO struct
  ZeroMemory(&lpStartupInfo, sizeof(STARTUPINFO));

  // clear PROCESS_INFORMATION struct
  ZeroMemory(&lpProcessInfo, sizeof(PROCESS_INFORMATION));

  // populate STARTUPINFO struct making sure there is no console window
  lpStartupInfo.cb = sizeof(STARTUPINFO);
  lpStartupInfo.dwFlags = STARTF_USESHOWWINDOW;
  lpStartupInfo.wShowWindow = SW_HIDE;

  // concatenate command line
  if (_snwprintf_s(
    wCommandLine,
    512,
    510,
    wCommandLineFormat,
    wGhidraFilename
  ) < S_OK) {
    goto done;
  }

  // create process
  if (CreateProcess(
    NULL,
    (LPWSTR)wCommandLine,
    NULL,
    NULL,
    FALSE,
    CREATE_NO_WINDOW,
    NULL,
    NULL,
    &lpStartupInfo,
    &lpProcessInfo
  )) {
    DWORD dwError = 0;

    // wait for child to infinity and beyond
    if (dwError = WaitForSingleObject(
      lpProcessInfo.hProcess,
      INFINITE
    ) != WAIT_OBJECT_0) {
      // terminate child process
      TerminateProcess(lpProcessInfo.hProcess, dwError);
      // store error code
      returnCode = dwError;
      // bail out
      goto done;
    }

    // get child exit code
    if (GetExitCodeProcess(lpProcessInfo.hProcess, &dwError)) {
      returnCode = dwError;
    }
  }

done:
  if (returnCode != EXIT_SUCCESS) {
    // allocate memory for error message
    WCHAR* wErrorMessage = malloc(1024);

    // concatenate error message
    _snwprintf_s(
      wErrorMessage,
      512,
      510,
      wErrorFormat,
      GetLastError()
    );

    // display message box with error message
    MessageBox(
      NULL,
      wErrorMessage,
      wApplicationName,
      MB_ICONERROR | MB_DEFAULT_DESKTOP_ONLY | MB_SYSTEMMODAL | MB_SETFOREGROUND
    );

    // free error message
    free(wErrorMessage);
  }

  // close PROCESS_INFORMATION handles
  CloseHandle(lpProcessInfo.hThread);
  CloseHandle(lpProcessInfo.hProcess);

  // free memory malloc'd
  free(wCommandLine); // give me freedom or give me ...

  return returnCode; // death ...
}

