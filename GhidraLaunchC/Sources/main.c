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

// append text to a buffer, FALSE when it does not fit
static BOOL Append(WCHAR* const wBuffer, const size_t count, const WCHAR* const wText) {
  return wcscat_s(wBuffer, count, wText) == 0;
}

// append " <value of environment variable>" when the variable is set
static BOOL AppendEnvironment(WCHAR* const wBuffer, const size_t count, const WCHAR* const wName) {
  static WCHAR wValue[PATH_SIZE];
  const DWORD dwLength = GetEnvironmentVariableW(wName, wValue, _countof(wValue));

  if (dwLength >= _countof(wValue)) {
    return FALSE;
  }
  return dwLength == 0 || (Append(wBuffer, count, L" ") && Append(wBuffer, count, wValue));
}

static BOOL IsFile(const WCHAR* const wPath) {
  const DWORD dwAttributes = GetFileAttributesW(wPath);
  return dwAttributes != INVALID_FILE_ATTRIBUTES && !(dwAttributes & FILE_ATTRIBUTE_DIRECTORY);
}

// run a hidden process; when wOutput is not NULL its standard output is captured as UTF-16
static BOOL RunProcess(
  const WCHAR* const wApplication,
  WCHAR* const wCommandLine,
  const WCHAR* const wDirectory,
  WCHAR* const wOutput,
  const size_t count,
  DWORD* const pdwExitCode
) {
  static char cOutput[PATH_SIZE];
  SECURITY_ATTRIBUTES lpSecurity = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
  STARTUPINFOW lpStartupInfo;
  PROCESS_INFORMATION lpProcessInfo;
  HANDLE hRead = NULL;
  HANDLE hWrite = NULL;
  HANDLE hNull;
  DWORD dwRead;
  DWORD dwUsed = 0;
  BOOL bResult = FALSE;

  hNull = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &lpSecurity, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hNull == INVALID_HANDLE_VALUE) {
    return FALSE;
  }
  if (wOutput != NULL) {
    wOutput[0] = L'\0';
    if (!CreatePipe(&hRead, &hWrite, &lpSecurity, 0) || !SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0)) {
      goto cleanup;
    }
  }

  ZeroMemory(&lpStartupInfo, sizeof(STARTUPINFOW));
  ZeroMemory(&lpProcessInfo, sizeof(PROCESS_INFORMATION));
  lpStartupInfo.cb = sizeof(STARTUPINFOW);
  lpStartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  lpStartupInfo.wShowWindow = SW_HIDE;
  lpStartupInfo.hStdInput = hNull;
  lpStartupInfo.hStdOutput = hWrite != NULL ? hWrite : hNull;
  lpStartupInfo.hStdError = hNull;

  if (!CreateProcessW(wApplication, wCommandLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, wDirectory, &lpStartupInfo, &lpProcessInfo)) {
    goto cleanup;
  }
  CloseHandle(lpProcessInfo.hThread);

  if (hWrite != NULL) {
    // the child holds the only other write end, so reads end when it exits
    CloseHandle(hWrite);
    hWrite = NULL;
    while (ReadFile(hRead, cOutput + dwUsed, (DWORD)sizeof(cOutput) - 1 - dwUsed, &dwRead, NULL) && dwRead != 0) {
      dwUsed += dwRead;
      if (dwUsed >= sizeof(cOutput) - 1) {
        // output is too large to be what we expect; stop reading and let the child end
        TerminateProcess(lpProcessInfo.hProcess, EXIT_FAILURE);
        break;
      }
    }
  }

  if (WaitForSingleObject(lpProcessInfo.hProcess, INFINITE) == WAIT_OBJECT_0 && GetExitCodeProcess(lpProcessInfo.hProcess, pdwExitCode)) {
    bResult = TRUE;
    if (wOutput != NULL) {
      cOutput[dwUsed] = '\0';
      if (dwUsed != 0 && MultiByteToWideChar(CP_ACP, 0, cOutput, (int)dwUsed + 1, wOutput, (int)count) == 0) {
        wOutput[0] = L'\0';
        bResult = FALSE;
      }
    }
  }
  CloseHandle(lpProcessInfo.hProcess);

cleanup:
  if (hRead != NULL) {
    CloseHandle(hRead);
  }
  if (hWrite != NULL) {
    CloseHandle(hWrite);
  }
  CloseHandle(hNull);
  return bResult;
}

// next line of a captured output, NUL terminated in place; NULL when finished
static WCHAR* NextLine(WCHAR** const ppwCursor) {
  WCHAR* wLine = *ppwCursor;
  WCHAR* wEnd;

  while (*wLine != L'\0') {
    wEnd = wLine + wcscspn(wLine, L"\r\n");
    *ppwCursor = *wEnd == L'\0' ? wEnd : wEnd + 1;
    *wEnd = L'\0';
    if (wEnd != wLine) {
      return wLine;
    }
    wLine = *ppwCursor;
  }
  return NULL;
}

// java.exe that runs, like launch.bat: PATH first, then JAVA_HOME
static BOOL FindJava(const WCHAR* const wDirectory, WCHAR* const wJava, const size_t count) {
  static WCHAR wCommandLine[PATH_SIZE];
  static WCHAR wHome[PATH_SIZE];
  DWORD dwExitCode;
  DWORD dwLength = SearchPathW(NULL, L"java.exe", NULL, (DWORD)count, wJava, NULL);

  if (dwLength != 0 && dwLength < count &&
      swprintf_s(wCommandLine, _countof(wCommandLine), L"\"%ls\" -version", wJava) > 0 &&
      RunProcess(wJava, wCommandLine, wDirectory, NULL, 0, &dwExitCode) && dwExitCode == EXIT_SUCCESS) {
    return TRUE;
  }

  dwLength = GetEnvironmentVariableW(L"JAVA_HOME", wHome, _countof(wHome));
  if (dwLength == 0 || dwLength >= _countof(wHome) ||
      swprintf_s(wJava, count, L"%ls\\bin\\java.exe", wHome) < 0 ||
      swprintf_s(wCommandLine, _countof(wCommandLine), L"\"%ls\" -version", wJava) < 0) {
    return FALSE;
  }
  return RunProcess(wJava, wCommandLine, wDirectory, NULL, 0, &dwExitCode) && dwExitCode == EXIT_SUCCESS;
}

// run LaunchSupport with an option; wOutput receives its standard output when not NULL
static BOOL RunLaunchSupport(
  const WCHAR* const wJava,
  const WCHAR* const wDirectory,
  const WCHAR* const wOption,
  WCHAR* const wOutput,
  const size_t count
) {
  static WCHAR wCommandLine[PATH_SIZE];
  DWORD dwExitCode;

  if (swprintf_s(
    wCommandLine,
    _countof(wCommandLine),
    L"\"%ls\" -cp \"%ls\\support\\LaunchSupport.jar\" LaunchSupport \"%ls\" %ls",
    wJava,
    wDirectory,
    wDirectory,
    wOption
  ) < 0) {
    return FALSE;
  }
  return RunProcess(wJava, wCommandLine, wDirectory, wOutput, count, &dwExitCode) && dwExitCode == EXIT_SUCCESS;
}

// Start Ghidra the way ghidraRun.bat and support\launch.bat do, without cmd.exe.
// Returns FALSE when that is not possible so the caller can fall back to ghidraRun.bat.
static BOOL LaunchNative(const WCHAR* const wDirectory, const WCHAR* const wArguments, DWORD* const pdwExitCode) {
  static WCHAR wPath[PATH_SIZE];
  static WCHAR wJava[PATH_SIZE];
  static WCHAR wJavaw[PATH_SIZE];
  static WCHAR wJavaHome[PATH_SIZE];
  static WCHAR wVmArgs[PATH_SIZE];
  static WCHAR wOutput[PATH_SIZE];
  static WCHAR wCommandLine[PATH_SIZE];
  static WCHAR wValue[PATH_SIZE];
  STARTUPINFOW lpStartupInfo;
  PROCESS_INFORMATION lpProcessInfo;
  WCHAR* wCursor;
  WCHAR* wLine;
  WCHAR* wEquals;
  DWORD dwLength;

  // launch.bat rejects '!' in the path and a trailing backslash would escape the quotes below
  const size_t length = wcslen(wDirectory);
  if (length == 0 || wDirectory[length - 1] == L'\\' || wcschr(wDirectory, L'!') != NULL) {
    return FALSE;
  }

  // only a packaged Ghidra is handled natively, not a development checkout
  if (swprintf_s(wPath, _countof(wPath), L"%ls\\Ghidra\\application.properties", wDirectory) < 0 || !IsFile(wPath) ||
      swprintf_s(wPath, _countof(wPath), L"%ls\\support\\LaunchSupport.jar", wDirectory) < 0 || !IsFile(wPath) ||
      swprintf_s(wPath, _countof(wPath), L"%ls\\Ghidra\\Framework\\Utility\\lib\\Utility.jar", wDirectory) < 0 || !IsFile(wPath)) {
    return FALSE;
  }

  if (!FindJava(wDirectory, wJava, _countof(wJava))) {
    return FALSE;
  }

  // LaunchSupport picks and remembers a supported JDK; ask the user when none is known yet
  wJavaHome[0] = L'\0';
  for (int attempt = 0; attempt < 2 && wJavaHome[0] == L'\0'; ++attempt) {
    if (attempt == 1 && !RunLaunchSupport(wJava, wDirectory, L"-jdk_home -ask", NULL, 0)) {
      return FALSE;
    }
    if (RunLaunchSupport(wJava, wDirectory, L"-jdk_home -save", wOutput, _countof(wOutput))) {
      wCursor = wOutput;
      while ((wLine = NextLine(&wCursor)) != NULL) {
        if (wcscpy_s(wJavaHome, _countof(wJavaHome), wLine) != 0) {
          return FALSE;
        }
      }
    }
  }
  if (wJavaHome[0] == L'\0' || swprintf_s(wJava, _countof(wJava), L"%ls\\bin\\java.exe", wJavaHome) < 0 || !IsFile(wJava) ||
      swprintf_s(wJavaw, _countof(wJavaw), L"%ls\\bin\\javaw.exe", wJavaHome) < 0 || !IsFile(wJavaw)) {
    return FALSE;
  }

  // environment variables requested by launch.properties never override existing ones
  if (!RunLaunchSupport(wJava, wDirectory, L"-envvars", wOutput, _countof(wOutput))) {
    return FALSE;
  }
  wCursor = wOutput;
  while ((wLine = NextLine(&wCursor)) != NULL) {
    wEquals = wcschr(wLine, L'=');
    if (wEquals == NULL || wEquals == wLine) {
      continue;
    }
    *wEquals = L'\0';
    if (GetEnvironmentVariableW(wLine, wValue, _countof(wValue)) == 0) {
      SetEnvironmentVariableW(wLine, wEquals + 1);
    }
  }

  // JVM arguments from launch.properties
  if (!RunLaunchSupport(wJava, wDirectory, L"-vmargs", wOutput, _countof(wOutput))) {
    return FALSE;
  }
  wVmArgs[0] = L'\0';
  wCursor = wOutput;
  while ((wLine = NextLine(&wCursor)) != NULL) {
    if (!Append(wVmArgs, _countof(wVmArgs), L" ") || !Append(wVmArgs, _countof(wVmArgs), wLine)) {
      return FALSE;
    }
  }

  // command line in the order launch.bat builds it
  if (swprintf_s(wCommandLine, _countof(wCommandLine), L"\"%ls\"", wJavaw) < 0 ||
      !AppendEnvironment(wCommandLine, _countof(wCommandLine), L"FORCE_JAVA_VERSION") ||
      !AppendEnvironment(wCommandLine, _countof(wCommandLine), L"JAVA_USER_HOME_DIR_OVERRIDE") ||
      !Append(wCommandLine, _countof(wCommandLine), wVmArgs)) {
    return FALSE;
  }
  dwLength = GetEnvironmentVariableW(L"USERPROFILE", wValue, _countof(wValue));
  if (dwLength >= _countof(wValue)) {
    return FALSE;
  }
  if (dwLength != 0 && GetFileAttributesW(wValue) != INVALID_FILE_ATTRIBUTES &&
      (swprintf_s(wPath, _countof(wPath), L" -Duser.home=\"%ls\"", wValue) < 0 || !Append(wCommandLine, _countof(wCommandLine), wPath))) {
    return FALSE;
  }
  // GHIDRA_GUI_MAXMEM defaults to GHIDRA_MAXMEM
  dwLength = GetEnvironmentVariableW(L"GHIDRA_GUI_MAXMEM", wValue, _countof(wValue));
  if (dwLength == 0 || dwLength >= _countof(wValue)) {
    dwLength = GetEnvironmentVariableW(L"GHIDRA_MAXMEM", wValue, _countof(wValue));
  }
  if (dwLength >= _countof(wValue)) {
    return FALSE;
  }
  if (dwLength != 0 && (!Append(wCommandLine, _countof(wCommandLine), L" -Xmx") || !Append(wCommandLine, _countof(wCommandLine), wValue))) {
    return FALSE;
  }
  if (!AppendEnvironment(wCommandLine, _countof(wCommandLine), L"GHIDRA_JAVA_OPTIONS") ||
      !AppendEnvironment(wCommandLine, _countof(wCommandLine), L"GHIDRA_GUI_JAVA_OPTIONS") ||
      swprintf_s(wPath, _countof(wPath), L" -cp \"%ls\\Ghidra\\Framework\\Utility\\lib\\Utility.jar\" ghidra.Ghidra ghidra.GhidraRun", wDirectory) < 0 ||
      !Append(wCommandLine, _countof(wCommandLine), wPath) ||
      (wArguments[0] != L'\0' && (!Append(wCommandLine, _countof(wCommandLine), L" ") || !Append(wCommandLine, _countof(wCommandLine), wArguments)))) {
    return FALSE;
  }

  ZeroMemory(&lpStartupInfo, sizeof(STARTUPINFOW));
  ZeroMemory(&lpProcessInfo, sizeof(PROCESS_INFORMATION));
  lpStartupInfo.cb = sizeof(STARTUPINFOW);
  if (!CreateProcessW(wJavaw, wCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, wDirectory, &lpStartupInfo, &lpProcessInfo)) {
    return FALSE;
  }
  CloseHandle(lpProcessInfo.hThread);

  // like launch.bat, only report a Ghidra that dies right away
  *pdwExitCode = EXIT_SUCCESS;
  if (WaitForSingleObject(lpProcessInfo.hProcess, 1000) == WAIT_OBJECT_0 && !GetExitCodeProcess(lpProcessInfo.hProcess, pdwExitCode)) {
    *pdwExitCode = EXIT_FAILURE;
  }
  CloseHandle(lpProcessInfo.hProcess);
  return TRUE;
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

  // start Ghidra directly; fall back to ghidraRun.bat when that is not possible
  if (LaunchNative(wDirectory, lpCmdLine, &dwExitCode)) {
    if (dwExitCode != EXIT_SUCCESS) {
      ShowError(L"Ghidra exited with code", dwExitCode);
    }
    return (int)dwExitCode;
  }

  // the fallback needs ghidraRun.bat
  if (swprintf_s(wCommandLine, _countof(wCommandLine), L"%ls\\%ls", wDirectory, BATCH_FILE) < 0) {
    ShowError(L"Unable to locate ghidraRun.bat, error", ERROR_FILENAME_EXCED_RANGE);
    return EXIT_FAILURE;
  }
  dwLength = GetFileAttributesW(wCommandLine);
  if (dwLength == INVALID_FILE_ATTRIBUTES || (dwLength & FILE_ATTRIBUTE_DIRECTORY)) {
    if (swprintf_s(wCommandLine, _countof(wCommandLine), L"Ghidra could not be started: ghidraRun.bat not found in %.500ls (GHIDRA_HOME or the launcher folder), error", wDirectory) < 0) {
      wcscpy_s(wCommandLine, _countof(wCommandLine), L"ghidraRun.bat not found in GHIDRA_HOME or next to the launcher, error");
    }
    ShowError(wCommandLine, ERROR_FILE_NOT_FOUND);
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
