/* Test-only executable: compile this instead of main.c, with the same miniz
   sources and flags. No fault injection is present in the production binary. */
#include <windows.h>
#include <wchar.h>

static wchar_t fault_mode[32];
static wchar_t registry_file[32768], recovery_root[32768];
static wchar_t *fault_destination;
static BOOL registry_failed;
static BOOL WINAPI fault_move(const wchar_t *source, const wchar_t *target, DWORD flags);
static BOOL WINAPI fault_delete(const wchar_t *path);
static BOOL WINAPI fault_remove_directory(const wchar_t *path);
static LSTATUS WINAPI test_reg_open(HKEY key, LPCWSTR name, DWORD options, REGSAM access, PHKEY result);
static LSTATUS WINAPI test_reg_create(HKEY key, LPCWSTR name, DWORD reserved, LPWSTR class_name,
    DWORD options, REGSAM access, const LPSECURITY_ATTRIBUTES security, PHKEY result, LPDWORD disposition);
static LSTATUS WINAPI test_reg_query(HKEY key, LPCWSTR name, LPDWORD reserved,
    LPDWORD type, LPBYTE data, LPDWORD size);
static LSTATUS WINAPI test_reg_set(HKEY key, LPCWSTR name, DWORD reserved,
    DWORD type, const BYTE *data, DWORD size);
static LSTATUS WINAPI test_reg_delete(HKEY key, LPCWSTR name);
static LSTATUS WINAPI test_reg_close(HKEY key);
static const wchar_t *test_recovery_root(void);

#define wmain helper_wmain
#define MoveFileExW fault_move
#define DeleteFileW fault_delete
#define RemoveDirectoryW fault_remove_directory
#define RegOpenKeyExW test_reg_open
#define RegCreateKeyExW test_reg_create
#define RegQueryValueExW test_reg_query
#define RegSetValueExW test_reg_set
#define RegDeleteValueW test_reg_delete
#define RegCloseKey test_reg_close
#define HELPER_TEST_RECOVERY_ROOT test_recovery_root
#include "../main.c"
#undef HELPER_TEST_RECOVERY_ROOT
#undef RegCloseKey
#undef RegDeleteValueW
#undef RegSetValueExW
#undef RegQueryValueExW
#undef RegCreateKeyExW
#undef RegOpenKeyExW
#undef RemoveDirectoryW
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
        ((!wcscmp(fault_mode, L"rollback") || !wcscmp(fault_mode, L"registry-rollback")) && restore)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return MoveFileExW(source, target, flags);
}

static BOOL WINAPI fault_delete(const wchar_t *path)
{
    const wchar_t *leaf = wcsrchr(path, L'\\');
    BOOL payload = fault_destination &&
        !_wcsnicmp(path, fault_destination, wcslen(fault_destination)) &&
        path[wcslen(fault_destination)] == L'\\' &&
        leaf && !metadata_name(leaf + 1);
    if ((!wcscmp(fault_mode, L"cleanup") && wcsstr(path, L"\\.old-")) ||
        (!wcscmp(fault_mode, L"remove-payload") && payload) ||
        (!wcscmp(fault_mode, L"remove-final") && leaf && !wcscmp(leaf + 1, INVENTORY))) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return DeleteFileW(path);
}

static BOOL WINAPI fault_remove_directory(const wchar_t *path)
{
    if ((!wcscmp(fault_mode, L"remove-root") && fault_destination &&
         !_wcsicmp(path, fault_destination)) ||
        (!wcscmp(fault_mode, L"staging-cleanup") && wcsstr(path, L"\\.extract-"))) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return RemoveDirectoryW(path);
}

/* Fake REG_SZ storage is raw UTF-16LE (including its NUL). These wrappers never
   access HKCU, even when a test accidentally selects the managed destination. */
static LSTATUS WINAPI test_reg_open(HKEY key, LPCWSTR name, DWORD options, REGSAM access, PHKEY result)
{
    DWORD attr;
    (void)key; (void)name; (void)options; (void)access;
    if (!*registry_file)
        return ERROR_ACCESS_DENIED;
    attr = GetFileAttributesW(registry_file);
    if (attr == INVALID_FILE_ATTRIBUTES)
        return (LSTATUS)GetLastError();
    if (attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
        return ERROR_ACCESS_DENIED;
    *result = (HKEY)(ULONG_PTR)1;
    return ERROR_SUCCESS;
}

static LSTATUS WINAPI test_reg_create(HKEY key, LPCWSTR name, DWORD reserved, LPWSTR class_name,
    DWORD options, REGSAM access, const LPSECURITY_ATTRIBUTES security, PHKEY result, LPDWORD disposition)
{
    (void)key; (void)name; (void)reserved; (void)class_name;
    (void)options; (void)access; (void)security; (void)disposition;
    if (!*registry_file)
        return ERROR_ACCESS_DENIED;
    *result = (HKEY)(ULONG_PTR)1;
    return ERROR_SUCCESS;
}

static LSTATUS WINAPI test_reg_query(HKEY key, LPCWSTR name, LPDWORD reserved,
    LPDWORD type, LPBYTE data, LPDWORD size)
{
    HANDLE file;
    LARGE_INTEGER length;
    DWORD got;
    LSTATUS result = ERROR_SUCCESS;
    (void)key; (void)name; (void)reserved;
    if (!*registry_file)
        return ERROR_ACCESS_DENIED;
    file = open_input(registry_file);
    if (file == INVALID_HANDLE_VALUE)
        return (LSTATUS)GetLastError();
    if (!GetFileSizeEx(file, &length) || length.QuadPart > MAXDWORD) {
        result = ERROR_INVALID_DATA;
        goto done;
    }
    if (type)
        *type = REG_SZ;
    if (data) {
        if (*size < (DWORD)length.QuadPart) {
            result = ERROR_MORE_DATA;
        } else if (!ReadFile(file, data, (DWORD)length.QuadPart, &got, NULL) ||
                   got != (DWORD)length.QuadPart) {
            result = ERROR_READ_FAULT;
        }
    }
    *size = (DWORD)length.QuadPart;
done:
    CloseHandle(file);
    return result;
}

static LSTATUS WINAPI test_reg_set(HKEY key, LPCWSTR name, DWORD reserved,
    DWORD type, const BYTE *data, DWORD size)
{
    HANDLE file;
    DWORD wrote;
    LSTATUS result;
    (void)key; (void)name; (void)reserved; (void)type;
    if ((!wcscmp(fault_mode, L"registry-write") || !wcscmp(fault_mode, L"registry-rollback")) &&
        !registry_failed) {
        registry_failed = TRUE;
        return ERROR_ACCESS_DENIED;
    }
    if (!*registry_file)
        return ERROR_ACCESS_DENIED;
    file = CreateFileW(registry_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return (LSTATUS)GetLastError();
    result = WriteFile(file, data, size, &wrote, NULL) && wrote == size &&
             FlushFileBuffers(file) ? ERROR_SUCCESS : ERROR_WRITE_FAULT;
    CloseHandle(file);
    return result;
}

static LSTATUS WINAPI test_reg_delete(HKEY key, LPCWSTR name)
{
    (void)key; (void)name;
    if (!wcscmp(fault_mode, L"registry-clear"))
        return ERROR_ACCESS_DENIED;
    if (!*registry_file)
        return ERROR_ACCESS_DENIED;
    return DeleteFileW(registry_file) ? ERROR_SUCCESS : (LSTATUS)GetLastError();
}

static LSTATUS WINAPI test_reg_close(HKEY key)
{
    (void)key;
    return ERROR_SUCCESS;
}

static const wchar_t *test_recovery_root(void)
{
    return recovery_root;
}

static int inventory_tests(void)
{
#define TEST_HASH "0000000000000000000000000000000000000000000000000000000000000000"
#define TEST_HEADER "ghidralaunch-inventory-v1\nsource=" TEST_HASH "\n"
    const char *invalid[] = {
        TEST_HEADER "d\t-\ta\nd\t-\ta\n",
        TEST_HEADER "d\t-\tDir\nd\t-\tdir\n",
        TEST_HEADER "f\t" TEST_HASH "\ta/b\n",
        TEST_HEADER "f\t" TEST_HASH "\ta\nf\t" TEST_HASH "\ta/b\n",
        TEST_HEADER "d\t-\t../outside\n",
        TEST_HEADER "f\t" TEST_HASH "\t.ghidralaunch-inventory\n",
        TEST_HEADER "f\t" TEST_HASH "\tback\\slash\n",
        TEST_HEADER "f\t" TEST_HASH "\tbad\xff\n",
        TEST_HEADER "d\t-\ta"
    };
    const char valid[] = TEST_HEADER "f\t" TEST_HASH "\tdir/file\nd\t-\tempty\nd\t-\tdir\n";
    const char partial[] = TEST_HEADER "d\t-\tdir\n";
    Paths baseline = {0}, current = {0};
    Blob blob = {0};
    size_t i;
    BOOL ok;
    blob.exists = TRUE;
    blob.data = (char *)valid;
    blob.size = (DWORD)strlen(valid);
    ok = parse_inventory(&blob, TEST_HASH, &baseline);
    if (!ok || baseline.count != 3)
        goto failed;
    blob.data = (char *)partial;
    blob.size = (DWORD)strlen(partial);
    if (!parse_inventory(&blob, TEST_HASH, &current) ||
        !customized(&baseline, &current, FALSE) ||
        customized(&baseline, &current, TRUE))
        goto failed;
    free_paths(&current);
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        blob.data = (char *)invalid[i];
        blob.size = (DWORD)strlen(invalid[i]);
        ok = parse_inventory(&blob, TEST_HASH, &current);
        free_paths(&current);
        if (ok)
            goto failed;
    }
    blob.data = (char *)valid;
    blob.size = (DWORD)strlen(valid);
    ok = parse_inventory(&blob,
        "1111111111111111111111111111111111111111111111111111111111111111", &current);
    free_paths(&current);
    if (ok)
        goto failed;
    free_paths(&baseline);
    wprintf(L"C helper inventory and removal-retry unit checks passed.\n");
    return 0;
failed:
    free_paths(&current);
    free_paths(&baseline);
    problem(L"Inventory/removal-retry unit check failed", L"");
    return 1;
#undef TEST_HEADER
#undef TEST_HASH
}

static void zip_u16(unsigned char *out, unsigned value)
{
    out[0] = (unsigned char)value;
    out[1] = (unsigned char)(value >> 8);
}

static void zip_u32(unsigned char *out, DWORD value)
{
    zip_u16(out, value & 0xffffu);
    zip_u16(out + 2, value >> 16);
}

static BOOL fixture_zip(const wchar_t *root, const char *payload)
{
    const char name[] = "bundle/payload.txt";
    unsigned char bytes[256] = {0};
    size_t n = sizeof(name) - 1, size = strlen(payload);
    size_t local = 30 + n + size, central = 46 + n;
    unsigned char *directory = bytes + local, *end = directory + central;
    Blob blob = {0};
    DWORD crc;
    if (size > 64)
        return FALSE;
    crc = (DWORD)mz_crc32(0, (const unsigned char *)payload, size);
    zip_u32(bytes, 0x04034b50);
    zip_u16(bytes + 4, 20);
    zip_u32(bytes + 14, crc);
    zip_u32(bytes + 18, (DWORD)size);
    zip_u32(bytes + 22, (DWORD)size);
    zip_u16(bytes + 26, (unsigned)n);
    memcpy(bytes + 30, name, n);
    memcpy(bytes + 30 + n, payload, size);
    zip_u32(directory, 0x02014b50);
    zip_u16(directory + 4, 20);
    zip_u16(directory + 6, 20);
    zip_u32(directory + 16, crc);
    zip_u32(directory + 20, (DWORD)size);
    zip_u32(directory + 24, (DWORD)size);
    zip_u16(directory + 28, (unsigned)n);
    memcpy(directory + 46, name, n);
    zip_u32(end, 0x06054b50);
    zip_u16(end + 8, 1);
    zip_u16(end + 10, 1);
    zip_u32(end + 12, (DWORD)central);
    zip_u32(end + 16, (DWORD)local);
    blob.data = (char *)bytes;
    blob.size = (DWORD)(local + central + 22);
    blob.exists = TRUE;
    return write_blob(root, L"fixture.zip", &blob);
}

static BOOL same_blob(const wchar_t *root, const wchar_t *name, const Blob *expected)
{
    Blob actual = {0};
    BOOL same = read_blob(root, name, &actual) && actual.exists == expected->exists &&
        actual.size == expected->size &&
        (!actual.size || !memcmp(actual.data, expected->data, actual.size));
    free(actual.data);
    return same;
}

static BOOL missing_path(const wchar_t *path)
{
    return GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES && absent(GetLastError());
}

static wchar_t *find_residue(const wchar_t *dest, const wchar_t *glob)
{
    wchar_t *parent = parent_path(dest), *pattern = parent ? join(parent, glob) : NULL;
    wchar_t *path = NULL;
    WIN32_FIND_DATAW data = {0};
    HANDLE search = pattern ? FindFirstFileW(pattern, &data) : INVALID_HANDLE_VALUE;
    if (search != INVALID_HANDLE_VALUE) {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            !(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            path = join(parent, data.cFileName);
        FindClose(search);
    }
    free(pattern);
    free(parent);
    return path;
}

static wchar_t *ordinary_path(const wchar_t *extended)
{
    wchar_t *result;
    if (wcsncmp(extended, L"\\\\?\\UNC\\", 8))
        return copy_n(extended + 4, wcslen(extended + 4));
    result = allocate((wcslen(extended + 8) + 3) * sizeof(wchar_t));
    if (result) {
        wcscpy(result, L"\\\\");
        wcscat(result, extended + 8);
    }
    return result;
}

typedef enum {
    ADOPTION_WRITE, ADOPTION_BASELINE_WRITE, REPLACEMENT_WRITE, REPLACEMENT_ROLLBACK,
    REMOVAL_PAYLOAD, REMOVAL_FINAL, REMOVAL_ROOT, REMOVAL_REGISTRY,
    CLEANUP_BACKUP, CLEANUP_STAGE
} NativeCase;

static BOOL native_case(const wchar_t *parent, NativeCase test)
{
    static const wchar_t *modes[] = {
        L"registry-write", L"registry-write", L"registry-write", L"registry-rollback",
        L"remove-payload", L"remove-final", L"remove-root", L"registry-clear",
        L"cleanup", L"staging-cleanup"
    };
    wchar_t *root = new_directory(parent, L"case-"), *plain = NULL;
    wchar_t *dest = NULL, *zip = NULL, *record = NULL, *recovery = NULL, *residue = NULL;
    wchar_t *inventory_path = NULL;
    Blob marker = {0}, inventory = {0}, empty = {0};
    Blob old_owner = {(char *)L"old", sizeof(L"old"), TRUE};
    Blob new_owner = {(char *)L"new", sizeof(L"new"), TRUE};
    Blob old_payload = {(char *)"old", 3, TRUE}, new_payload = {(char *)"new", 3, TRUE};
    Marker original, current;
    BOOL ok = FALSE;
#define REQUIRE_NATIVE(condition) do { \
    if (!(condition)) { \
        fwprintf(stderr, L"Native selftest failed: case %u, line %u, root %ls\n", \
                 (unsigned)test, (unsigned)__LINE__, root ? root : L"(unallocated)"); \
        goto done; \
    } \
} while (0)
    fault_mode[0] = 0;
    registry_failed = FALSE;
    REQUIRE_NATIVE(root != NULL);
    plain = ordinary_path(root);
    dest = join(root, OWNER_DESTINATION);
    zip = join(root, L"fixture.zip");
    record = join(root, L"owner.bin");
    recovery = join(root, L"recovery");
    inventory_path = dest ? join(dest, INVENTORY) : NULL;
    REQUIRE_NATIVE(plain && dest && zip && record && recovery && inventory_path);
    REQUIRE_NATIVE(wcslen(record) < 32768 && wcslen(recovery) < 32768);
    wcscpy(registry_file, record);
    wcscpy(recovery_root, recovery);
    fault_destination = dest;
    REQUIRE_NATIVE(SetEnvironmentVariableW(L"LOCALAPPDATA", plain));
    REQUIRE_NATIVE(fixture_zip(root, "old") && extract(zip, dest, "old"));
    REQUIRE_NATIVE(same_blob(root, L"owner.bin", &old_owner));
    REQUIRE_NATIVE(read_blob(dest, MARKER, &marker) && read_blob(dest, INVENTORY, &inventory));
    REQUIRE_NATIVE(read_marker(dest, &original) == 1);
    if (test == ADOPTION_BASELINE_WRITE)
        REQUIRE_NATIVE(DeleteFileW(inventory_path));
    if (test == REPLACEMENT_WRITE || test == REPLACEMENT_ROLLBACK ||
        test == CLEANUP_BACKUP || test == CLEANUP_STAGE)
        REQUIRE_NATIVE(fixture_zip(root, "new"));
    wcscpy(fault_mode, modes[test]);
    if (test <= REPLACEMENT_ROLLBACK) {
        REQUIRE_NATIVE(!extract(zip, dest, "new"));
        REQUIRE_NATIVE(registry_failed && same_blob(root, L"owner.bin", &old_owner));
        if (test == REPLACEMENT_ROLLBACK) {
            residue = find_residue(dest, L".old-*");
            REQUIRE_NATIVE(residue && same_blob(residue, MARKER, &marker) &&
                           same_blob(residue, L"payload.txt", &old_payload));
        } else {
            REQUIRE_NATIVE(same_blob(dest, MARKER, &marker) &&
                           same_blob(dest, L"payload.txt", &old_payload));
            REQUIRE_NATIVE(test == ADOPTION_BASELINE_WRITE ?
                same_blob(dest, INVENTORY, &empty) : same_blob(dest, INVENTORY, &inventory));
        }
    } else if (test <= REMOVAL_REGISTRY) {
        REQUIRE_NATIVE(!remove_destination(dest, zip, "old"));
        REQUIRE_NATIVE(same_blob(root, L"owner.bin", &old_owner));
        if (test == REMOVAL_REGISTRY) {
            REQUIRE_NATIVE(missing_path(dest));
        } else {
            char text[320];
            Blob expected = {0};
            int bytes = snprintf(text, sizeof(text),
                "ghidralaunch-removal-v1\nsource=%s\nowner=old\n", original.hash);
            REQUIRE_NATIVE(bytes > 0 && (size_t)bytes < sizeof(text));
            expected.data = text;
            expected.size = (DWORD)bytes;
            expected.exists = TRUE;
            REQUIRE_NATIVE(same_blob(dest, MARKER, &marker) &&
                           same_blob(dest, INVENTORY, &inventory) &&
                           same_blob(dest, REMOVAL, &expected));
        }
        fault_mode[0] = 0;
        REQUIRE_NATIVE(remove_destination(dest, zip, "old") &&
                       missing_path(dest) && missing_path(record));
    } else {
        REQUIRE_NATIVE(extract(zip, dest, "new"));
        REQUIRE_NATIVE(read_marker(dest, &current) == 1 &&
                       !strcmp(current.owner, "new") && strcmp(current.hash, original.hash));
        REQUIRE_NATIVE(same_blob(root, L"owner.bin", &new_owner) &&
                       same_blob(dest, L"payload.txt", &new_payload));
        residue = find_residue(dest, test == CLEANUP_BACKUP ? L".old-*" : L".extract-*");
        REQUIRE_NATIVE(residue != NULL);
    }
    ok = TRUE;
done:
    fault_mode[0] = 0;
    fault_destination = NULL;
    free(marker.data);
    free(inventory.data);
    free(residue);
    free(inventory_path);
    free(recovery);
    free(record);
    free(zip);
    free(dest);
    free(plain);
    free(root);
    return ok;
#undef REQUIRE_NATIVE
}

static int native_tests(const wchar_t *scratch)
{
    wchar_t *parent = full_path(scratch), *root = NULL, *old_local = NULL;
    DWORD size = GetEnvironmentVariableW(L"LOCALAPPDATA", NULL, 0);
    BOOL ok = FALSE, started = FALSE;
    unsigned test;
    if (size) {
        old_local = allocate((size_t)size * sizeof(wchar_t));
        if (!old_local || GetEnvironmentVariableW(L"LOCALAPPDATA", old_local, size) != size - 1)
            goto done;
    }
    if (!parent || !safe_destination(parent) || !directories(parent, TRUE))
        goto done;
    root = new_directory(parent, L".selftest-");
    if (!root)
        goto done;
    started = TRUE;
    for (test = ADOPTION_WRITE; test <= CLEANUP_STAGE; ++test)
        if (!native_case(root, (NativeCase)test))
            goto done;
    ok = TRUE;
done:
    fault_mode[0] = 0;
    registry_file[0] = recovery_root[0] = 0;
    if (started && !SetEnvironmentVariableW(L"LOCALAPPDATA", old_local)) {
        win_error(L"Restoring test environment", L"LOCALAPPDATA");
        ok = FALSE;
    }
    if (ok && root && !remove_tree(root))
        ok = FALSE;
    if (!ok && root)
        problem(L"Native selftest failed; isolated artifacts retained", root);
    if (ok)
        wprintf(L"C helper registry/removal/cleanup selftests passed (fake file-backed registry only).\n");
    free(old_local);
    free(root);
    free(parent);
    return ok ? 0 : 1;
}

int wmain(int argc, wchar_t **argv)
{
    int result;
    if ((argc == 2 || argc == 3) && !wcscmp(argv[1], L"selftest")) {
        result = inventory_tests();
        if (result || argc == 2)
            return result;
        return native_tests(argv[2]);
    }
    if (GetEnvironmentVariableW(L"C_HELPER_TEST_FAILURE", fault_mode,
                               sizeof(fault_mode) / sizeof(fault_mode[0])) >=
        sizeof(fault_mode) / sizeof(fault_mode[0]) ||
        GetEnvironmentVariableW(L"C_HELPER_TEST_OWNER_RECORD", registry_file, 32768) >= 32768 ||
        GetEnvironmentVariableW(L"C_HELPER_TEST_RECOVERY_ROOT", recovery_root, 32768) >= 32768)
        return 2;
    if (argc >= 4 && !_wcsicmp(argv[1], L"extract"))
        fault_destination = full_path(argv[3]);
    else if (argc >= 3 && !_wcsicmp(argv[1], L"remove"))
        fault_destination = full_path(argv[2]);
    result = helper_wmain(argc, argv);
    free(fault_destination);
    return result;
}
