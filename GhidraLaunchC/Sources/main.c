// main.c : Launch Ghidra ghidraRun.bat
//

#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#define APPLICATION_NAME L"GhidraLaunch\0"
#define COMMANDLINE L"cmd.exe /c .\\ghidraRun.bat\0"
#define ERROR_FORMAT L"Failed to launch Ghidra!\nFatal Error: %d\0"
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
  STARTUPINFOW lpStartupInfo;
  PROCESS_INFORMATION lpProcessInfo;

  WCHAR* wCommandLine = malloc(1024);
  const WCHAR* const wCommandLineString = COMMANDLINE;
  const WCHAR* const wApplicationName = APPLICATION_NAME;
  const WCHAR* const wErrorFormat = ERROR_FORMAT;
  int returnCode = EXIT_FAILURE;

  // clear STARTUPINFO struct
  ZeroMemory(&lpStartupInfo, sizeof(STARTUPINFOW));

  // clear PROCESS_INFORMATION struct
  ZeroMemory(&lpProcessInfo, sizeof(PROCESS_INFORMATION));

  // populate STARTUPINFO struct making sure there is no console window
  lpStartupInfo.cb = sizeof(STARTUPINFOW);
  lpStartupInfo.dwFlags = STARTF_USESHOWWINDOW;
  lpStartupInfo.wShowWindow = SW_HIDE;

  // prepare commandline
  if (wCommandLine != NULL) {
    wCommandLine = wmemcpy(wCommandLine, wCommandLineString, sizeof(COMMANDLINE)*2);
  } else {
    goto done;
  }

  // create process
  if (CreateProcessW(
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
    DWORD dwError = EXIT_FAILURE;

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
    MessageBoxW(
      NULL,
      wErrorMessage,
      wApplicationName,
      MB_ICONERROR | MB_DEFAULT_DESKTOP_ONLY | MB_SYSTEMMODAL | MB_SETFOREGROUND
    );

    free(wErrorMessage); // give me freedom or give me ...
  }

  if (!CloseHandle(lpProcessInfo.hThread)) {
    MessageBeep(MB_ICONERROR);
  }
  if (!CloseHandle(lpProcessInfo.hProcess)) {
    MessageBeep(MB_ICONERROR);
  }

  return returnCode; // death ...
}

