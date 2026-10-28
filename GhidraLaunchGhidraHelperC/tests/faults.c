/* Test-only executable: compile this instead of main.c, with the same miniz
   sources and flags. No fault injection is present in the production binary. */
#include <windows.h>
#include <wchar.h>

static wchar_t fault_mode[32];
static wchar_t registry_file[32768], recovery_root[32768];
static wchar_t *fault_destination;
static BOOL registry_failed;
typedef struct {
    unsigned scope, view;
    const wchar_t *name, *publisher, *family, *version, *cache;
    const wchar_t *raw_field;
    const BYTE *raw_data;
    DWORD raw_size, raw_type;
    BOOL multi_family;
    unsigned version_reads, cache_reads;
} TestLegacy;
static TestLegacy legacy_records[8];
static unsigned legacy_record_count, legacy_scopes_seen, legacy_launches;
static BOOL legacy_testing, legacy_child_checked;
static HANDLE legacy_child_lock = INVALID_HANDLE_VALUE;
static LSTATUS WINAPI test_reg_enum(HKEY key, DWORD index, LPWSTR name, LPDWORD length,
    LPDWORD reserved, LPWSTR class_name, LPDWORD class_length, PFILETIME modified);
static BOOL test_legacy_process(const wchar_t *cache, wchar_t *command, DWORD *exit_code);
static BOOL test_legacy_allowed(const wchar_t *dest);
static const wchar_t *test_legacy_log_root(void);
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
#define RegEnumKeyExW test_reg_enum
#define HELPER_TEST_RECOVERY_ROOT test_recovery_root
#define HELPER_TEST_LEGACY_PROCESS test_legacy_process
#define HELPER_TEST_LEGACY_ALLOWED test_legacy_allowed
#define HELPER_TEST_LEGACY_LOG_ROOT test_legacy_log_root
#include "../main.c"
#undef HELPER_TEST_LEGACY_LOG_ROOT
#undef HELPER_TEST_LEGACY_ALLOWED
#undef HELPER_TEST_LEGACY_PROCESS
#undef HELPER_TEST_RECOVERY_ROOT
#undef RegEnumKeyExW
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
    BOOL legacy_restore = wcsstr(source, L"\\.legacy-") != NULL;
    if ((!wcscmp(fault_mode, L"backup") && backup) ||
        ((!wcscmp(fault_mode, L"install") || !wcscmp(fault_mode, L"rollback")) && install) ||
        ((!wcscmp(fault_mode, L"rollback") || !wcscmp(fault_mode, L"registry-rollback")) && restore) ||
        (!wcscmp(fault_mode, L"legacy-restore") && legacy_restore)) {
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
    ULONG_PTR handle = (ULONG_PTR)key;
    (void)options;
    if (!wcscmp(name, LEGACY_UNINSTALL_KEY)) {
        unsigned scope = key == HKEY_CURRENT_USER ? 0 : 1;
        unsigned view = access & KEY_WOW64_64KEY ? 1 : 0;
        if (key != HKEY_CURRENT_USER && key != HKEY_LOCAL_MACHINE)
            return ERROR_INVALID_HANDLE;
        legacy_scopes_seen |= 1u << (scope * 2 + view);
        *result = (HKEY)(ULONG_PTR)(0x100 + scope * 2 + view);
        return ERROR_SUCCESS;
    }
    if (handle >= 0x100 && handle < 0x104) {
        unsigned i;
        for (i = 0; i < legacy_record_count; ++i) {
            wchar_t expected[32];
            swprintf(expected, 32, L"bundle-%u", i);
            if (!wcscmp(expected, name) &&
                handle == (ULONG_PTR)(0x100 + legacy_records[i].scope * 2 + legacy_records[i].view)) {
                *result = (HKEY)(ULONG_PTR)(0x1000 + i);
                return ERROR_SUCCESS;
            }
        }
        return ERROR_FILE_NOT_FOUND;
    }
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

static LSTATUS WINAPI test_reg_enum(HKEY key, DWORD index, LPWSTR name, LPDWORD length,
    LPDWORD reserved, LPWSTR class_name, LPDWORD class_length, PFILETIME modified)
{
    ULONG_PTR handle = (ULONG_PTR)key;
    unsigned i, found = 0;
    (void)reserved; (void)class_name; (void)class_length; (void)modified;
    if (handle < 0x100 || handle >= 0x104)
        return ERROR_INVALID_HANDLE;
    for (i = 0; i < legacy_record_count; ++i) {
        if (handle != (ULONG_PTR)(0x100 + legacy_records[i].scope * 2 + legacy_records[i].view))
            continue;
        if (found++ == index) {
            wchar_t text[32];
            DWORD size;
            swprintf(text, 32, L"bundle-%u", i);
            size = (DWORD)wcslen(text);
            if (*length <= size)
                return ERROR_MORE_DATA;
            wcscpy(name, text);
            *length = size;
            return ERROR_SUCCESS;
        }
    }
    return ERROR_NO_MORE_ITEMS;
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
    ULONG_PTR handle = (ULONG_PTR)key;
    (void)reserved;
    if (handle >= 0x1000 && handle < 0x1000 + legacy_record_count) {
        TestLegacy *record = &legacy_records[handle - 0x1000];
        const wchar_t *value = NULL;
        DWORD bytes, kind = REG_SZ;
        if (!wcscmp(name, L"DisplayName"))
            value = record->name;
        else if (!wcscmp(name, L"Publisher"))
            value = record->publisher;
        else if (!wcscmp(name, L"BundleUpgradeCode")) {
            value = record->family;
            if (record->multi_family)
                kind = REG_MULTI_SZ;
        } else if (!wcscmp(name, L"BundleVersion")) {
            value = record->version;
            ++record->version_reads;
        } else if (!wcscmp(name, L"BundleCachePath")) {
            value = record->cache;
            ++record->cache_reads;
        }
        if (record->raw_field && !wcscmp(name, record->raw_field)) {
            value = (const wchar_t *)record->raw_data;
            bytes = record->raw_size;
            kind = record->raw_type;
        } else {
            if (!value)
                return ERROR_FILE_NOT_FOUND;
            bytes = (DWORD)((wcslen(value) + 1) * sizeof(wchar_t));
            if (kind == REG_MULTI_SZ) {
                const wchar_t *p = value;
                while (*p)
                    p += wcslen(p) + 1;
                bytes = (DWORD)((p - value + 1) * sizeof(wchar_t));
            }
        }
        if (type)
            *type = kind;
        if (data && *size < bytes)
            return ERROR_MORE_DATA;
        if (data)
            memcpy(data, value, bytes);
        *size = bytes;
        return ERROR_SUCCESS;
    }
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

static BOOL test_legacy_allowed(const wchar_t *dest)
{
    return legacy_testing && fault_destination && !_wcsicmp(dest, fault_destination);
}

static const wchar_t *test_legacy_log_root(void)
{
    return legacy_testing ? recovery_root : NULL;
}

static BOOL test_legacy_process(const wchar_t *cache, wchar_t *command, DWORD *exit_code)
{
    HANDLE lock;
    wchar_t *quoted = NULL, *expected = NULL, *log = NULL;
    const wchar_t *suffix = L" /uninstall /quiet /norestart"
                            L" -burn.related.upgrade -parent \"incoming\" /log \"";
    size_t count, length;
    unsigned i;
    BOOL matched = FALSE, ok = FALSE;
    ++legacy_launches;
    if (!legacy_testing || !fault_destination ||
        GetFileAttributesW(fault_destination) != INVALID_FILE_ATTRIBUTES || !absent(GetLastError()))
        goto done;
    for (i = 0; i < legacy_record_count; ++i)
        if (legacy_records[i].cache && !wcscmp(cache, legacy_records[i].cache) &&
            legacy_records[i].name && !_wcsicmp(legacy_records[i].name, L"Ghidra Launch") &&
            legacy_records[i].publisher && !_wcsicmp(legacy_records[i].publisher, L"rpinz"))
            matched = TRUE;
    if (!matched)
        goto done;
    quoted = legacy_quote(cache);
    if (!quoted)
        goto done;
    count = wcslen(quoted) + wcslen(suffix);
    expected = allocate((count + 1) * sizeof(wchar_t));
    if (!expected)
        goto done;
    wcscpy(expected, quoted);
    wcscat(expected, suffix);
    length = wcslen(command);
    if (wcsncmp(command, expected, count) || length <= count + 1 || command[length - 1] != L'"')
        goto done;
    log = copy_n(command + count, length - count - 1);
    if (!log || _wcsnicmp(log, recovery_root, wcslen(recovery_root)) ||
        log[wcslen(recovery_root)] != L'\\' ||
        GetFileAttributesW(log) == INVALID_FILE_ATTRIBUTES)
        goto done;
    lock = destination_lock(fault_destination);
    if (lock == INVALID_HANDLE_VALUE)
        goto done;
    /* This is precisely the old helper's absent-destination behavior. */
    ok = remove_destination(fault_destination, NULL,
                            !wcscmp(fault_mode, L"legacy-clear") ? "incoming" : "old");
    CloseHandle(lock);
    if (!ok)
        goto done;
    legacy_child_checked = TRUE;
    ok = FALSE;
    if (!wcscmp(fault_mode, L"legacy-unexpected") && !directories(fault_destination, TRUE))
        goto done;
    if (!wcscmp(fault_mode, L"legacy-unexpected-file")) {
        DWORD written;
        HANDLE file = CreateFileW(fault_destination, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE)
            goto done;
        ok = WriteFile(file, "unexpected", 10, &written, NULL) && written == 10;
        CloseHandle(file);
        if (!ok)
            goto done;
    }
    if (!wcscmp(fault_mode, L"legacy-held-lock")) {
        legacy_child_lock = destination_lock(fault_destination);
        if (legacy_child_lock == INVALID_HANDLE_VALUE)
            goto done;
    }
    if (!wcscmp(fault_mode, L"legacy-spawn")) {
        ok = FALSE;
        goto done;
    }
    *exit_code = !wcscmp(fault_mode, L"legacy-child") ? 1603 :
                 !wcscmp(fault_mode, L"legacy-reboot") ? 3010 : 0;
    ok = TRUE;
done:
    free(log);
    free(expected);
    free(quoted);
    return ok;
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

typedef enum {
    LEGACY_FOREIGN, LEGACY_OLDER, LEGACY_EQUAL, LEGACY_NEWER, LEGACY_BAD_VERSION,
    LEGACY_MISSING_VERSION, LEGACY_MISSING_CACHE, LEGACY_RELATIVE_CACHE,
    LEGACY_ABSENT_CACHE, LEGACY_DIRECTORY_CACHE, LEGACY_WRONG_OWNER,
    LEGACY_PREFLIGHT_ALL, LEGACY_DUPLICATES, LEGACY_CHILD_FAILURE, LEGACY_SPAWN_FAILURE,
    LEGACY_REBOOT, LEGACY_UNEXPECTED, LEGACY_RESTORE_FAILURE, LEGACY_OWNER_REASSERT,
    LEGACY_UNEXPECTED_FILE, LEGACY_LOCK_FAILURE, LEGACY_OUTSIDE_MANAGED, LEGACY_ARGUMENTS
} LegacyCase;

static BOOL legacy_unit_tests(void)
{
    const wchar_t *invalid[] = {
        L"", L"1", L"1.2", L"1.2.3.", L"1.2.3.4.5", L"v1.2.3",
        L"01.2.3", L"1.02.3", L"1.2.-3", L"1.2.3-beta", L"1.2.4294967296",
        L"1.2.3 ", L" 1.2.3"
    };
    const wchar_t *arguments[] = {L"", L"plain", L"a b", L"a\\", L"a\\\"b"};
    const wchar_t *quoted[] = {L"\"\"", L"\"plain\"", L"\"a b\"", L"\"a\\\\\"", L"\"a\\\\\\\"b\""};
    LegacyVersion a, b;
    size_t i;
    if (!legacy_version(L"1.2.3", &a) || !legacy_version(L"1.2.3.0", &b) ||
        legacy_compare(&a, &b) || !legacy_version(L"1.2.3.1", &b) ||
        legacy_compare(&a, &b) >= 0)
        return FALSE;
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        if (legacy_version(invalid[i], &a))
            return FALSE;
    for (i = 0; i < sizeof(arguments) / sizeof(arguments[0]); ++i) {
        wchar_t *actual = legacy_quote(arguments[i]);
        BOOL same = actual && !wcscmp(actual, quoted[i]);
        free(actual);
        if (!same)
            return FALSE;
    }
    return TRUE;
}

static BOOL legacy_identity_tests(void)
{
    const struct {
        const wchar_t *field, *data;
        DWORD bytes, type;
    } malformed[] = {
        {L"DisplayName", L"Ghidra Launch\0", sizeof(L"Ghidra Launch\0"), REG_MULTI_SZ},
        {L"DisplayName", L"Ghidra Launch\0foreign", sizeof(L"Ghidra Launch\0foreign"), REG_SZ},
        {L"DisplayName", L"Ghidra Launch\0", sizeof(L"Ghidra Launch\0"), REG_SZ},
        {L"DisplayName", L"Ghidra Launch", sizeof(L"Ghidra Launch") - sizeof(wchar_t), REG_SZ},
        {L"DisplayName", L"Ghidra Launch", sizeof(L"Ghidra Launch") - 1, REG_SZ},
        {L"DisplayName", L"\0Ghidra Launch", sizeof(L"\0Ghidra Launch"), REG_SZ},
        {L"DisplayName", L"", sizeof(L""), REG_SZ},
        {L"Publisher", L"rpinz\0", sizeof(L"rpinz\0"), REG_MULTI_SZ},
        {L"Publisher", L"rpinz\0foreign", sizeof(L"rpinz\0foreign"), REG_SZ},
        {L"Publisher", L"rpinz\0", sizeof(L"rpinz\0"), REG_SZ},
        {L"Publisher", L"rpinz", sizeof(L"rpinz") - sizeof(wchar_t), REG_SZ},
        {L"Publisher", L"\0rpinz", sizeof(L"\0rpinz"), REG_SZ},
        {L"Publisher", L"rpinz", sizeof(L"rpinz"), REG_EXPAND_SZ}
    };
    LegacyVersion incoming;
    LegacyBundles bundles = {0};
    size_t i;
    BOOL ok = FALSE;
    if (!legacy_version(L"2.3.4", &incoming))
        return FALSE;
    legacy_record_count = 1;
    for (i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
        memset(legacy_records, 0, sizeof(legacy_records));
        legacy_records[0].name = L"Ghidra Launch";
        legacy_records[0].publisher = L"rpinz";
        legacy_records[0].family = LEGACY_FAMILY;
        legacy_records[0].version = L"must not be parsed";
        legacy_records[0].cache = L"must not be accessed";
        legacy_records[0].raw_field = malformed[i].field;
        legacy_records[0].raw_data = (const BYTE *)malformed[i].data;
        legacy_records[0].raw_size = malformed[i].bytes;
        legacy_records[0].raw_type = malformed[i].type;
        if (!legacy_select((HKEY)(ULONG_PTR)0x1000, L"malformed identity fixture",
                           &incoming, &bundles) || bundles.count ||
            legacy_records[0].version_reads || legacy_records[0].cache_reads) {
            fwprintf(stderr, L"Malformed legacy registry identity check failed: case %u\n", (unsigned)i);
            goto done;
        }
    }
    ok = TRUE;
done:
    legacy_free(&bundles);
    legacy_record_count = 0;
    memset(legacy_records, 0, sizeof(legacy_records));
    return ok;
}

static BOOL legacy_case(const wchar_t *parent, LegacyCase test)
{
    static const wchar_t *modes[] = {
        L"", L"", L"", L"", L"", L"", L"", L"", L"", L"", L"", L"", L"",
        L"legacy-child", L"legacy-spawn", L"legacy-reboot", L"legacy-unexpected",
        L"legacy-restore", L"legacy-clear", L"legacy-unexpected-file", L"legacy-held-lock", L"", L""
    };
    static const wchar_t families[] = L"{00000000-0000-0000-0000-000000000000}\0"
                                      LEGACY_FAMILY L"\0";
    wchar_t *root = new_directory(parent, L"legacy-case-"), *plain = NULL;
    wchar_t *dest = NULL, *zip = NULL, *record = NULL, *cache = NULL, *cache2 = NULL;
    wchar_t *residue = NULL, *dest_parent = NULL, *nested = NULL;
    Blob marker = {0}, inventory = {0};
    Blob payload = {(char *)"current", 7, TRUE};
    Blob custom = {(char *)"custom\0data", 11, TRUE};
    Blob removal = {(char *)"preserved removal metadata", 26, TRUE};
    Blob owner = {(char *)L"incoming", sizeof(L"incoming"), TRUE};
    wchar_t *argv[5] = {L"faults", L"migrate-legacy", NULL, L"incoming", L"2.3.4"};
    unsigned i, expected_launches = 0;
    int result, expected_result = 1;
    BOOL ok = FALSE;
#define REQUIRE_LEGACY(condition) do { \
    if (!(condition)) { \
        fwprintf(stderr, L"Legacy selftest failed: case %u, line %u, root %ls\n", \
                 (unsigned)test, (unsigned)__LINE__, root ? root : L"(unallocated)"); \
        goto done; \
    } \
} while (0)
    fault_mode[0] = 0;
    legacy_record_count = legacy_scopes_seen = legacy_launches = 0;
    legacy_child_checked = FALSE;
    memset(legacy_records, 0, sizeof(legacy_records));
    REQUIRE_LEGACY(root != NULL);
    plain = ordinary_path(root);
    dest = join(root, OWNER_DESTINATION);
    zip = join(root, L"fixture.zip");
    record = join(root, L"owner.bin");
    cache = join(root, L"cached legacy one.exe");
    cache2 = join(root, L"cached legacy two.exe");
    dest_parent = dest ? parent_path(dest) : NULL;
    nested = dest ? join(dest, L"nested") : NULL;
    REQUIRE_LEGACY(plain && dest && zip && record && cache && cache2 && dest_parent && nested);
    REQUIRE_LEGACY(wcslen(root) < 32768 && wcslen(record) < 32768);
    wcscpy(registry_file, record);
    wcscpy(recovery_root, root);
    fault_destination = dest;
    legacy_testing = TRUE;
    REQUIRE_LEGACY(SetEnvironmentVariableW(L"LOCALAPPDATA", plain));
    argv[2] = ordinary_path(dest);
    REQUIRE_LEGACY(argv[2] != NULL);
    REQUIRE_LEGACY(write_blob(root, L"cached legacy one.exe", &payload) &&
                   write_blob(root, L"cached legacy two.exe", &payload));
    if (test != LEGACY_FOREIGN) {
        REQUIRE_LEGACY(fixture_zip(root, "current") && extract(zip, dest, "incoming"));
        REQUIRE_LEGACY(read_blob(dest, MARKER, &marker) && read_blob(dest, INVENTORY, &inventory));
        REQUIRE_LEGACY(directories(nested, TRUE) &&
                       write_blob(nested, L"user.bin", &custom) && write_blob(dest, REMOVAL, &removal));
    }
    legacy_record_count = 1;
    legacy_records[0].name = L"GHIDRA LAUNCH";
    legacy_records[0].publisher = L"RPINZ";
    legacy_records[0].family = families;
    legacy_records[0].multi_family = TRUE;
    legacy_records[0].version = L"1.0.0";
    /* Production receives an ordinary absolute path from Burn, not \\?\ paths. */
    {
        wchar_t *plain_cache = ordinary_path(cache), *plain_cache2 = ordinary_path(cache2);
        REQUIRE_LEGACY(plain_cache && plain_cache2);
        free(cache);
        free(cache2);
        cache = plain_cache;
        cache2 = plain_cache2;
    }
    legacy_records[0].cache = cache;
    switch (test) {
    case LEGACY_FOREIGN:
        legacy_record_count = 5;
        for (i = 0; i < legacy_record_count; ++i) {
            legacy_records[i] = legacy_records[0];
            legacy_records[i].scope = i % 2;
            legacy_records[i].view = i / 2 % 2;
            legacy_records[i].version = (i % 2) ? L"not-a-version" : L"999.0.0";
            legacy_records[i].cache = L"must never be accessed";
        }
        legacy_records[0].name = L"Unrelated Application";
        legacy_records[1].publisher = L"foreign";
        legacy_records[2].name = L"Ghidra Launch Plus";
        legacy_records[3].family = L"{00000000-0000-0000-0000-000000000000}";
        legacy_records[3].multi_family = FALSE;
        legacy_records[4].family = LEGACY_FAMILY L"foreign";
        legacy_records[4].multi_family = FALSE;
        expected_result = 0;
        break;
    case LEGACY_EQUAL:
        legacy_records[0].version = L"2.3.4.0";
        expected_result = 0;
        expected_launches = 1;
        break;
    case LEGACY_NEWER:
        legacy_records[0].version = L"2.3.4.1";
        break;
    case LEGACY_BAD_VERSION:
        legacy_records[0].version = L"broken";
        break;
    case LEGACY_MISSING_VERSION:
        legacy_records[0].version = NULL;
        break;
    case LEGACY_MISSING_CACHE:
        legacy_records[0].cache = NULL;
        break;
    case LEGACY_RELATIVE_CACHE:
        legacy_records[0].cache = L"cached legacy one.exe";
        break;
    case LEGACY_ABSENT_CACHE:
        {
            wchar_t *absolute_cache = full_path(cache);
            BOOL deleted = absolute_cache && DeleteFileW(absolute_cache);
            free(absolute_cache);
            REQUIRE_LEGACY(deleted);
        }
        break;
    case LEGACY_DIRECTORY_CACHE:
        legacy_records[0].cache = plain;
        break;
    case LEGACY_WRONG_OWNER:
        argv[3] = L"wrong-owner";
        break;
    case LEGACY_PREFLIGHT_ALL:
        legacy_records[1] = legacy_records[0];
        legacy_records[1].scope = 1;
        legacy_records[1].view = 1;
        legacy_records[1].version = L"3.0.0";
        legacy_record_count = 2;
        break;
    case LEGACY_DUPLICATES:
        for (i = 1; i < 5; ++i)
            legacy_records[i] = legacy_records[0];
        for (i = 0; i < 4; ++i) {
            legacy_records[i].scope = i / 2;
            legacy_records[i].view = i % 2;
        }
        legacy_records[4].cache = cache2;
        legacy_records[4].family = LEGACY_FAMILY;
        legacy_records[4].multi_family = FALSE;
        legacy_record_count = 5;
        expected_result = 0;
        expected_launches = 2;
        break;
    case LEGACY_CHILD_FAILURE:
    case LEGACY_SPAWN_FAILURE:
    case LEGACY_UNEXPECTED:
    case LEGACY_RESTORE_FAILURE:
    case LEGACY_UNEXPECTED_FILE:
    case LEGACY_LOCK_FAILURE:
        expected_launches = 1;
        break;
    case LEGACY_REBOOT:
        expected_result = 3010;
        expected_launches = 1;
        break;
    case LEGACY_OLDER:
    case LEGACY_OWNER_REASSERT:
        expected_result = 0;
        expected_launches = 1;
        break;
    case LEGACY_OUTSIDE_MANAGED:
        REQUIRE_LEGACY(SetEnvironmentVariableW(L"LOCALAPPDATA", cache));
        break;
    case LEGACY_ARGUMENTS:
        argv[3] = L"invalid owner";
        REQUIRE_LEGACY(helper_wmain(5, argv) == 2);
        argv[3] = L"incoming";
        argv[4] = L"2.3";
        REQUIRE_LEGACY(helper_wmain(5, argv) == 2);
        REQUIRE_LEGACY(helper_wmain(4, argv) == 2);
        REQUIRE_LEGACY(!legacy_launches && !legacy_scopes_seen &&
                       same_blob(dest, MARKER, &marker));
        ok = TRUE;
        goto done;
    }
    wcscpy(fault_mode, modes[test]);
    result = helper_wmain(5, argv);
    REQUIRE_LEGACY(result == expected_result && legacy_launches == expected_launches);
    REQUIRE_LEGACY(!expected_launches || legacy_child_checked);
    if (expected_result == 0 || expected_result == 3010)
        REQUIRE_LEGACY(legacy_scopes_seen == 15);
    if (test == LEGACY_FOREIGN) {
        REQUIRE_LEGACY(missing_path(dest_parent));
        for (i = 0; i < legacy_record_count; ++i)
            REQUIRE_LEGACY(!legacy_records[i].version_reads && !legacy_records[i].cache_reads);
    } else {
        const wchar_t *restored = dest;
        if (test == LEGACY_UNEXPECTED || test == LEGACY_UNEXPECTED_FILE ||
            test == LEGACY_RESTORE_FAILURE || test == LEGACY_LOCK_FAILURE) {
            residue = find_residue(dest, L".legacy-*");
            REQUIRE_LEGACY(residue != NULL);
            restored = residue;
            if (test == LEGACY_UNEXPECTED)
                REQUIRE_LEGACY(GetFileAttributesW(dest) != INVALID_FILE_ATTRIBUTES &&
                               (GetFileAttributesW(dest) & FILE_ATTRIBUTE_DIRECTORY));
            else if (test == LEGACY_UNEXPECTED_FILE) {
                Blob unexpected = {(char *)"unexpected", 10, TRUE};
                REQUIRE_LEGACY(same_blob(dest_parent, L"Ghidra", &unexpected));
            } else
                REQUIRE_LEGACY(missing_path(dest));
        } else {
            residue = find_residue(dest, L".legacy-*");
            REQUIRE_LEGACY(residue == NULL);
        }
        REQUIRE_LEGACY(same_blob(restored, MARKER, &marker) &&
                       same_blob(restored, INVENTORY, &inventory) &&
                       same_blob(restored, REMOVAL, &removal) &&
                       same_blob(restored, L"payload.txt", &payload) &&
                       same_blob(restored, L"nested\\user.bin", &custom) &&
                       same_blob(root, L"owner.bin", &owner));
    }
    ok = TRUE;
done:
    if (legacy_child_lock != INVALID_HANDLE_VALUE) {
        CloseHandle(legacy_child_lock);
        legacy_child_lock = INVALID_HANDLE_VALUE;
    }
    legacy_testing = FALSE;
    legacy_record_count = 0;
    fault_mode[0] = 0;
    fault_destination = NULL;
    free(argv[2]);
    free(marker.data);
    free(inventory.data);
    free(nested);
    free(dest_parent);
    free(residue);
    free(cache2);
    free(cache);
    free(record);
    free(zip);
    free(dest);
    free(plain);
    free(root);
    return ok;
#undef REQUIRE_LEGACY
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
    if (!legacy_unit_tests()) {
        problem(L"Legacy version/Windows command quoting unit checks failed", root);
        goto done;
    }
    if (!legacy_identity_tests())
        goto done;
    for (test = LEGACY_FOREIGN; test <= LEGACY_ARGUMENTS; ++test)
        if (!legacy_case(root, (LegacyCase)test))
            goto done;
    wprintf(L"C helper legacy migration selftests passed (fake registry and process only).\n");
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
