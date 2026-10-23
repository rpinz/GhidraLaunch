// main.c : Launch Ghidra ghidraRun.bat
//

#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdlib.h>
#include <wchar.h>

#define APPLICATION_NAME L"GhidraLaunch"
#define BATCH_FILE L"ghidraRun.bat"
#define ERROR_FORMAT L"Failed to launch Ghidra!\n%ls %lu"
#define PATH_SIZE 32768

// no need for a console window
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:wWinMainCRTStartup")

// display message box with error message
static void ShowError(const WCHAR* const wMessage, const DWORD dwCode) {
  WCHAR wErrorMessage[1024];

  if (swprintf_s(wErrorMessage, _countof(wErrorMessage), ERROR_FORMAT, wMessage, dwCode) < 0) {
    MessageBeep(MB_ICONERROR);
    return;
  }

  MessageBoxW(
    NULL,
    wErrorMessage,
    APPLICATION_NAME,
    MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND
  );
}

// main entrypoint
int APIENTRY wWinMain(
  _In_ HINSTANCE hInstance,
  _In_opt_ HINSTANCE hPrevInstance,
  _In_ LPWSTR lpCmdLine,
  _In_ int nShowCmd
) {
  static WCHAR wDirectory[PATH_SIZE];
  static WCHAR wGhidraDirectory[PATH_SIZE];
  static WCHAR wApplicationName[PATH_SIZE];
  static WCHAR wCommandLine[PATH_SIZE];
  static WCHAR wEscapedPath[PATH_SIZE];
  STARTUPINFOW lpStartupInfo;
  PROCESS_INFORMATION lpProcessInfo;
  WCHAR* wSeparator;
  DWORD dwLength;
  DWORD dwExitCode = EXIT_FAILURE;

  UNREFERENCED_PARAMETER(hInstance);
  UNREFERENCED_PARAMETER(hPrevInstance);
  UNREFERENCED_PARAMETER(lpCmdLine);
  UNREFERENCED_PARAMETER(nShowCmd);

  // directory containing this launcher, used when GHIDRA_HOME is unset
  dwLength = GetModuleFileNameW(NULL, wDirectory, _countof(wDirectory));
  if (dwLength == 0 || dwLength >= _countof(wDirectory)) {
    ShowError(L"Unable to locate the launcher, error", GetLastError());
    return EXIT_FAILURE;
  }
  wSeparator = wcsrchr(wDirectory, L'\\');
  if (wSeparator == NULL) {
    ShowError(L"Unable to locate the launcher, error", ERROR_BAD_PATHNAME);
    return EXIT_FAILURE;
  }
  *wSeparator = L'\0';

  // use an existing Ghidra installation when configured
  dwLength = GetEnvironmentVariableW(L"GHIDRA_HOME", wGhidraDirectory, _countof(wGhidraDirectory));
  if (dwLength >= _countof(wGhidraDirectory)) {
    ShowError(L"GHIDRA_HOME path is too long, error", ERROR_FILENAME_EXCED_RANGE);
    return EXIT_FAILURE;
  }
  if (dwLength != 0 && wcscpy_s(wDirectory, _countof(wDirectory), wGhidraDirectory) != 0) {
    ShowError(L"Unable to use GHIDRA_HOME, error", ERROR_FILENAME_EXCED_RANGE);
    return EXIT_FAILURE;
  }

  // make sure ghidraRun.bat exists before starting anything
  if (swprintf_s(wCommandLine, _countof(wCommandLine), L"%ls\\%ls", wDirectory, BATCH_FILE) < 0) {
    ShowError(L"Unable to locate ghidraRun.bat, error", ERROR_FILENAME_EXCED_RANGE);
    return EXIT_FAILURE;
  }
  dwLength = GetFileAttributesW(wCommandLine);
  if (dwLength == INVALID_FILE_ATTRIBUTES || (dwLength & FILE_ATTRIBUTE_DIRECTORY)) {
    ShowError(L"ghidraRun.bat not found in GHIDRA_HOME or next to the launcher, error", ERROR_FILE_NOT_FOUND);
    return EXIT_FAILURE;
  }
  // absolute path to cmd.exe, never resolved through the search path
  dwLength = GetSystemDirectoryW(wApplicationName, _countof(wApplicationName));
  if (dwLength == 0 || dwLength >= _countof(wApplicationName)) {
    ShowError(L"Unable to locate cmd.exe, error", GetLastError());
    return EXIT_FAILURE;
  }
  if (wcscat_s(wApplicationName, _countof(wApplicationName), L"\\cmd.exe") != 0) {
    ShowError(L"Unable to locate cmd.exe, error", ERROR_FILENAME_EXCED_RANGE);
    return EXIT_FAILURE;
  }

  // cmd.exe cannot use a UNC working directory; insert its percent signs after cmd's percent-expansion pass
  if (wcsncmp(wDirectory, L"\\\\", 2) == 0 && wcschr(wDirectory, L'%') != NULL) {
    WCHAR* wOut = wEscapedPath;
    for (const WCHAR* wIn = wCommandLine; *wIn != L'\0'; ++wIn) {
      const WCHAR* wReplacement = *wIn == L'%' ? L"!GL_P!" :
                                  *wIn == L'!' ? L"!GL_B!" :
                                  *wIn == L'^' ? L"!GL_C!" : NULL;
      const size_t length = wReplacement == NULL ? 1 : wcslen(wReplacement);
      if ((size_t)(wOut - wEscapedPath) + length >= _countof(wEscapedPath)) {
        ShowError(L"Unable to prepare the command line, error", ERROR_FILENAME_EXCED_RANGE);
        return EXIT_FAILURE;
      }
      wmemcpy(wOut, wReplacement == NULL ? wIn : wReplacement, length);
      wOut += length;
    }
    *wOut = L'\0';
    if (!SetEnvironmentVariableW(L"GL_P", L"%") ||
        !SetEnvironmentVariableW(L"GL_B", L"!") ||
        !SetEnvironmentVariableW(L"GL_C", L"^")) {
      ShowError(L"Unable to prepare the command line, error", GetLastError());
      return EXIT_FAILURE;
    }
    dwLength = swprintf_s(wCommandLine, _countof(wCommandLine), L"\"%ls\" /d /v:on /c \"\"%ls\"\"", wApplicationName, wEscapedPath);
  } else if (wcsncmp(wDirectory, L"\\\\", 2) == 0) {
    dwLength = swprintf_s(wCommandLine, _countof(wCommandLine), L"\"%ls\" /d /c \"\"%ls\\%ls\"\"", wApplicationName, wDirectory, BATCH_FILE);
  } else {
    dwLength = swprintf_s(wCommandLine, _countof(wCommandLine), L"\"%ls\" /d /c .\\%ls", wApplicationName, BATCH_FILE);
  }
  if (dwLength == (DWORD)-1) {
    ShowError(L"Unable to prepare the command line, error", ERROR_FILENAME_EXCED_RANGE);
    return EXIT_FAILURE;
  }

  // clear STARTUPINFO struct
  ZeroMemory(&lpStartupInfo, sizeof(STARTUPINFOW));

  // clear PROCESS_INFORMATION struct
  ZeroMemory(&lpProcessInfo, sizeof(PROCESS_INFORMATION));

  // populate STARTUPINFO struct making sure there is no console window
  lpStartupInfo.cb = sizeof(STARTUPINFOW);
  lpStartupInfo.dwFlags = STARTF_USESHOWWINDOW;
  lpStartupInfo.wShowWindow = SW_HIDE;

  // create process
  if (!CreateProcessW(
    wApplicationName,
    wCommandLine,
    NULL,
    NULL,
    FALSE,
    CREATE_NO_WINDOW,
    NULL,
    wDirectory,
    &lpStartupInfo,
    &lpProcessInfo
  )) {
    ShowError(L"Unable to start cmd.exe, error", GetLastError());
    return EXIT_FAILURE;
  }

  CloseHandle(lpProcessInfo.hThread);

  // wait for child to infinity and beyond
  if (WaitForSingleObject(lpProcessInfo.hProcess, INFINITE) != WAIT_OBJECT_0) {
    const DWORD dwError = GetLastError();

    // terminate child process
    TerminateProcess(lpProcessInfo.hProcess, EXIT_FAILURE);
    CloseHandle(lpProcessInfo.hProcess);
    ShowError(L"Unable to wait for ghidraRun.bat, error", dwError);
    return EXIT_FAILURE;
  }

  // get child exit code
  if (!GetExitCodeProcess(lpProcessInfo.hProcess, &dwExitCode)) {
    const DWORD dwError = GetLastError();

    CloseHandle(lpProcessInfo.hProcess);
    ShowError(L"Unable to read the ghidraRun.bat exit code, error", dwError);
    return EXIT_FAILURE;
  }

  CloseHandle(lpProcessInfo.hProcess);

  if (dwExitCode != EXIT_SUCCESS) {
    ShowError(L"ghidraRun.bat exited with code", dwExitCode);
  }

  return (int)dwExitCode; // death ...
}
