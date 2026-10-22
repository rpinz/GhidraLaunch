/* Test-only executable: compile this instead of main.c, with the same miniz
   sources and flags. No fault injection is present in the production binary. */
#include <windows.h>
#include <wchar.h>

static wchar_t fault_mode[32];
static BOOL WINAPI fault_move(const wchar_t *source, const wchar_t *target, DWORD flags);
static BOOL WINAPI fault_delete(const wchar_t *path);

#define wmain helper_wmain
#define MoveFileExW fault_move
#define DeleteFileW fault_delete
#include "../main.c"
#undef DeleteFileW
#undef MoveFileExW
#undef wmain

static BOOL WINAPI fault_move(const wchar_t *source, const wchar_t *target, DWORD flags)
{
    BOOL install = wcsstr(source, L"\\.extract-") && !wcsstr(target, L"\\.extract-");
    BOOL backup = wcsstr(target, L"\\.old-") != NULL;
    BOOL restore = wcsstr(source, L"\\.old-") != NULL;
    if ((!wcscmp(fault_mode, L"backup") && backup) ||
        ((!wcscmp(fault_mode, L"install") || !wcscmp(fault_mode, L"rollback")) && install) ||
        (!wcscmp(fault_mode, L"rollback") && restore)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return MoveFileExW(source, target, flags);
}

static BOOL WINAPI fault_delete(const wchar_t *path)
{
    if (!wcscmp(fault_mode, L"cleanup") && wcsstr(path, L"\\.old-")) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return DeleteFileW(path);
}

int wmain(int argc, wchar_t **argv)
{
    if (GetEnvironmentVariableW(L"C_HELPER_TEST_FAILURE", fault_mode,
                               sizeof(fault_mode) / sizeof(fault_mode[0])) >=
        sizeof(fault_mode) / sizeof(fault_mode[0]))
        return 2;
    return helper_wmain(argc, argv);
}
