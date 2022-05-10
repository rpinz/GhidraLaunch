// GhidraLaunch.c : Launch Ghidra ghidraRun.bat
//

#include <windows.h>
#include <stdio.h>
#include <shlobj.h>

#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN

// no need for a console window
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:WinMainCRTStartup")

// main entrypoint
int APIENTRY WinMain(
  _In_ HINSTANCE hInstance,
  _In_opt_ HINSTANCE hPrevInstance,
  _In_ LPSTR lpCmdLine,
  _In_ int nShowCmd
) {
  STARTUPINFOA lpStartupInfo;
  PROCESS_INFORMATION lpProcessInfo;

  const wchar_t* wAppDataPath = NULL;
  char* cCommandLine = malloc(1024);
  char* cAppDataPath = malloc(1024);
  const char* const cApplicationName = "GhidraLaunch";
  const char* const cCommandLineFormat = "cmd.exe /c \"%s\\%s\"";
  const char* const cErrorFormat = "Failed to launch Ghidra!\nFatal Error: %d";
  const char* const cGhidraFilename = "Ghidra\\ghidraRun.bat";

  size_t len = 0;
  int returnCode = EXIT_FAILURE;

  // clear STARTUPINFO struct
  ZeroMemory(&lpStartupInfo, sizeof(STARTUPINFOA));

  // clear PROCESS_INFORMATION struct
  ZeroMemory(&lpProcessInfo, sizeof(PROCESS_INFORMATION));

  // populate STARTUPINFO struct making sure there is no console window
  lpStartupInfo.cb = sizeof(STARTUPINFOA);
  lpStartupInfo.dwFlags = STARTF_USESHOWWINDOW;
  lpStartupInfo.wShowWindow = SW_HIDE;

  // get %AppData%\Roaming PATH
  if (SHGetKnownFolderPath(&FOLDERID_RoamingAppData, 0, NULL, (PWSTR*)&wAppDataPath) != S_OK) {
    goto done;
  }

  // convert unicode to ascii
  wcstombs_s(&len, cAppDataPath, 1024, wAppDataPath, 1023);

  // concatenate command line
  if (_snprintf_s(cCommandLine, 1024, 1023, cCommandLineFormat, cAppDataPath, cGhidraFilename) < S_OK) {
    goto done;
  }

  // create process
  if (CreateProcessA(NULL, (LPSTR)cCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &lpStartupInfo, &lpProcessInfo)) {
    DWORD dwError = 0;

    // wait for child to infinity and beyond
    if (dwError = WaitForSingleObject(lpProcessInfo.hProcess, INFINITE) != WAIT_OBJECT_0) {
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
  // free task memory allocated by SHGetKnownFolderPath
  CoTaskMemFree((LPVOID)wAppDataPath);

  if (returnCode != EXIT_SUCCESS) {
    // allocate memory for error message
    char* cErrorMessage = malloc(1024);

    // concatenate error message
    _snprintf_s(cErrorMessage, 1024, 1024, cErrorFormat, GetLastError());

    // display message box with error message
    MessageBoxA(NULL, cErrorMessage, cApplicationName, MB_ICONERROR | MB_DEFAULT_DESKTOP_ONLY | MB_SYSTEMMODAL | MB_SETFOREGROUND);

    // free error message
    free(cErrorMessage);
  }

  // close PROCESS_INFORMATION handles
  CloseHandle(lpProcessInfo.hThread);
  CloseHandle(lpProcessInfo.hProcess);

  // free memory malloc'd
  free(cAppDataPath);
  free(cCommandLine); // give me freedom or give me ...

  return returnCode; // death ...
}

