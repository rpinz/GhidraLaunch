#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include "vendor/miniz/miniz.h"

#define MARKER L".ghidralaunch-source.sha256"
#define INVENTORY L".ghidralaunch-inventory"
#define REMOVAL L".ghidralaunch-removal"
#define OWNER_KEY L"Software\\rpinz\\Ghidra Launch"
#define OWNER_VALUE L"PayloadOwner"
#define OWNER_DESTINATION L"Ghidra Launch\\Ghidra"

typedef struct {
    char hash[65];
    char owner[129];
} Marker;

typedef struct {
    wchar_t *name;
    BOOL directory;
    BOOL explicit_entry;
    char hash[65];
} PathEntry;

typedef struct {
    PathEntry *items;
    size_t count, capacity;
} Paths;

typedef struct {
    char *data;
    DWORD size;
    BOOL exists;
} Blob;

typedef struct {
    Blob value;
    DWORD type;
    BOOL managed;
} OwnerRecord;

static BOOL metadata_name(const wchar_t *name);
static BOOL restore_metadata(const wchar_t *dest, const wchar_t *name, const Blob *original);

static BOOL win_error(const wchar_t *operation, const wchar_t *path)
{
    DWORD code = GetLastError();
    wchar_t *message = NULL;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, code, 0, (wchar_t *)&message, 0, NULL);
    fwprintf(stderr, L"%ls: %ls (Windows error %lu: %ls)\n",
             operation, path, (unsigned long)code, message ? message : L"unknown");
    LocalFree(message);
    return FALSE;
}

static BOOL problem(const wchar_t *message, const wchar_t *path)
{
    fwprintf(stderr, L"%ls: %ls\n", message, path);
    return FALSE;
}

static void *allocate(size_t bytes)
{
    void *p = malloc(bytes ? bytes : 1);
    if (!p)
        problem(L"Out of memory", L"");
    return p;
}

static wchar_t *copy_n(const wchar_t *s, size_t n)
{
    wchar_t *result;
    if (n > SIZE_MAX / sizeof(wchar_t) - 1)
        return NULL;
    result = allocate((n + 1) * sizeof(wchar_t));
    if (result) {
        memcpy(result, s, n * sizeof(wchar_t));
        result[n] = 0;
    }
    return result;
}

static wchar_t *join(const wchar_t *a, const wchar_t *b)
{
    size_t na = wcslen(a), nb = wcslen(b);
    wchar_t *result;
    if (na > SIZE_MAX / sizeof(wchar_t) - nb - 2)
        return NULL;
    result = allocate((na + nb + 2) * sizeof(wchar_t));
    if (result) {
        memcpy(result, a, na * sizeof(wchar_t));
        result[na] = L'\\';
        memcpy(result + na + 1, b, (nb + 1) * sizeof(wchar_t));
    }
    return result;
}

static BOOL absent(DWORD error)
{
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

/* All filesystem paths are absolute, extended-length Win32 paths. */
static size_t root_length(const wchar_t *path)
{
    if (!wcsncmp(path, L"\\\\?\\UNC\\", 8)) {
        const wchar_t *server = wcschr(path + 8, L'\\');
        const wchar_t *share = server ? wcschr(server + 1, L'\\') : NULL;
        return share ? (size_t)(share - path + 1) : wcslen(path);
    }
    return 7; /* \\?\C:\ */
}

static wchar_t *full_path(const wchar_t *path)
{
    DWORD count;
    wchar_t *plain, *result;
    size_t n;
    if (!*path || !wcsncmp(path, L"\\\\?\\", 4) ||
        !wcsncmp(path, L"\\\\.\\", 4)) {
        problem(L"Empty or device-namespace path is not allowed", path);
        return NULL;
    }
    count = GetFullPathNameW(path, 0, NULL, NULL);
    if (!count) {
        win_error(L"Resolving path", path);
        return NULL;
    }
    plain = allocate((size_t)count * sizeof(wchar_t));
    if (!plain)
        return NULL;
    if (!GetFullPathNameW(path, count, plain, NULL)) {
        win_error(L"Resolving path", path);
        free(plain);
        return NULL;
    }
    n = wcslen(plain);
    result = allocate((n + 7) * sizeof(wchar_t));
    if (result) {
        if (!wcsncmp(plain, L"\\\\", 2)) {
            wcscpy(result, L"\\\\?\\UNC\\");
            wcscpy(result + 8, plain + 2);
        } else {
            wcscpy(result, L"\\\\?\\");
            wcscpy(result + 4, plain);
        }
        n = wcslen(result);
        while (n > root_length(result) && result[n - 1] == L'\\')
            result[--n] = 0;
    }
    free(plain);
    return result;
}

/* Check every existing ancestor, not just the leaf; never traverse a junction. */
static BOOL directories(const wchar_t *path, BOOL create)
{
    size_t i, n = wcslen(path), root = root_length(path);
    wchar_t *part = copy_n(path, n);
    BOOL ok = TRUE;
    if (!part)
        return FALSE;
    for (i = root; i <= n; ++i) {
        DWORD attr;
        wchar_t saved;
        if (i < n && part[i] != L'\\')
            continue;
        saved = part[i];
        part[i] = 0;
        attr = GetFileAttributesW(part);
        if (attr == INVALID_FILE_ATTRIBUTES && absent(GetLastError())) {
            if (!create) {
                part[i] = saved;
                break;
            }
            if (!CreateDirectoryW(part, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                ok = win_error(L"Creating directory", part);
                break;
            }
            attr = GetFileAttributesW(part);
        }
        if (attr == INVALID_FILE_ATTRIBUTES) {
            ok = win_error(L"Reading directory attributes", part);
            break;
        }
        if (!(attr & FILE_ATTRIBUTE_DIRECTORY) || (attr & FILE_ATTRIBUTE_REPARSE_POINT)) {
            ok = problem(L"Expected an ordinary directory (no reparse points)", part);
            break;
        }
        part[i] = saved;
    }
    free(part);
    return ok;
}

static wchar_t *parent_path(const wchar_t *path)
{
    const wchar_t *end = wcsrchr(path, L'\\');
    size_t length = end ? (size_t)(end - path) : 0;
    if (length < root_length(path))
        length = root_length(path);
    return copy_n(path, length);
}

static BOOL safe_destination(const wchar_t *path)
{
    if (wcslen(path) <= root_length(path))
        return problem(L"A filesystem root cannot be a destination", path);
    return directories(path, FALSE);
}

/* Pin ordinary directories against rename while enumerating children. Reparse
   entries are unlinked themselves and are never enumerated. */
static BOOL remove_tree(const wchar_t *path)
{
    DWORD attr = GetFileAttributesW(path);
    HANDLE lock = INVALID_HANDLE_VALUE, search = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW data;
    wchar_t *pattern = NULL;
    BOOL ok = TRUE;
    if (attr == INVALID_FILE_ATTRIBUTES) {
        if (absent(GetLastError()))
            return TRUE;
        return win_error(L"Inspecting removal target", path);
    }
    if ((attr & FILE_ATTRIBUTE_DIRECTORY) && !(attr & FILE_ATTRIBUTE_REPARSE_POINT)) {
        BY_HANDLE_FILE_INFORMATION info;
        lock = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (lock == INVALID_HANDLE_VALUE)
            return win_error(L"Opening removal directory", path);
        if (!GetFileInformationByHandle(lock, &info)) {
            ok = win_error(L"Inspecting open removal directory", path);
            goto done;
        }
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            ok = problem(L"Removal directory changed to a reparse point", path);
            goto done;
        }
        pattern = join(path, L"*");
        if (!pattern) {
            ok = FALSE;
            goto done;
        }
        search = FindFirstFileW(pattern, &data);
        if (search == INVALID_HANDLE_VALUE) {
            if (GetLastError() != ERROR_FILE_NOT_FOUND)
                ok = win_error(L"Enumerating removal directory", path);
        } else {
            do {
                wchar_t *child;
                if (!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L".."))
                    continue;
                child = join(path, data.cFileName);
                if (!child) {
                    ok = FALSE;
                    break;
                }
                ok = remove_tree(child);
                free(child);
                if (!ok)
                    break;
            } while (FindNextFileW(search, &data));
            if (ok && GetLastError() != ERROR_NO_MORE_FILES)
                ok = win_error(L"Continuing removal enumeration", path);
        }
    }
done:
    if (search != INVALID_HANDLE_VALUE)
        FindClose(search);
    free(pattern);
    if (lock != INVALID_HANDLE_VALUE)
        CloseHandle(lock);
    if (!ok)
        return FALSE;
    if ((attr & FILE_ATTRIBUTE_READONLY) && !(attr & FILE_ATTRIBUTE_REPARSE_POINT)) {
        if (!SetFileAttributesW(path, attr & ~FILE_ATTRIBUTE_READONLY))
            return win_error(L"Clearing read-only attribute for removal", path);
    }
    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        if (!RemoveDirectoryW(path))
            return win_error(L"Removing directory", path);
    } else if (!DeleteFileW(path)) {
        return win_error(L"Removing file", path);
    }
    return TRUE;
}

static BOOL random_name(wchar_t name[50], const wchar_t *prefix)
{
    unsigned char random[16];
    size_t n = wcslen(prefix), i;
    NTSTATUS status = BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0)
        return problem(L"CNG random generation failed", prefix);
    wcscpy(name, prefix);
    for (i = 0; i < sizeof(random); ++i) {
        name[n + 2 * i] = L"0123456789abcdef"[random[i] >> 4];
        name[n + 2 * i + 1] = L"0123456789abcdef"[random[i] & 15];
    }
    name[n + 32] = 0;
    return TRUE;
}

static wchar_t *new_directory(const wchar_t *parent, const wchar_t *prefix)
{
    unsigned attempt;
    for (attempt = 0; attempt < 32; ++attempt) {
        wchar_t name[50], *path;
        if (!random_name(name, prefix))
            return NULL;
        path = join(parent, name);
        if (!path)
            return NULL;
        if (CreateDirectoryW(path, NULL))
            return path;
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            win_error(L"Creating staging directory", path);
            free(path);
            return NULL;
        }
        free(path);
    }
    problem(L"Cannot allocate a unique staging directory", parent);
    return NULL;
}

static HANDLE open_input(const wchar_t *path)
{
    BY_HANDLE_FILE_INFORMATION info;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                              FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        win_error(L"Opening input file", path);
        return file;
    }
    if (!GetFileInformationByHandle(file, &info)) {
        win_error(L"Inspecting input file", path);
        CloseHandle(file);
        return INVALID_HANDLE_VALUE;
    }
    if (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
        problem(L"Input must be an ordinary file", path);
        CloseHandle(file);
        return INVALID_HANDLE_VALUE;
    }
    return file;
}

static BOOL sha256(HANDLE file, char hex[65])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    unsigned char *buffer = NULL, digest[32];
    DWORD count;
    LARGE_INTEGER zero;
    NTSTATUS status;
    BOOL ok = FALSE;
    size_t i;
    zero.QuadPart = 0;
    if (!SetFilePointerEx(file, zero, NULL, FILE_BEGIN))
        return win_error(L"Seeking source for SHA-256", L"");
    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status < 0)
        goto done;
    status = BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0);
    if (status < 0)
        goto done;
    buffer = allocate(1024 * 1024);
    if (!buffer)
        goto done;
    for (;;) {
        if (!ReadFile(file, buffer, 1024 * 1024, &count, NULL)) {
            win_error(L"Reading source for SHA-256", L"");
            goto done;
        }
        if (!count)
            break;
        status = BCryptHashData(hash, buffer, count, 0);
        if (status < 0)
            goto done;
    }
    status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    if (status < 0)
        goto done;
    for (i = 0; i < sizeof(digest); ++i) {
        hex[i * 2] = "0123456789abcdef"[digest[i] >> 4];
        hex[i * 2 + 1] = "0123456789abcdef"[digest[i] & 15];
    }
    hex[64] = 0;
    ok = TRUE;
done:
    if (status < 0)
        fwprintf(stderr, L"CNG SHA-256 failed (NTSTATUS 0x%08lx).\n", (unsigned long)status);
    free(buffer);
    if (hash)
        BCryptDestroyHash(hash);
    if (algorithm)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

static BOOL owner_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' ||
           c == '{' || c == '}';
}

static BOOL parse_owner(const wchar_t *arg, char out[129])
{
    size_t i, n = wcslen(arg);
    if (!n || n > 128)
        return FALSE;
    for (i = 0; i < n; ++i) {
        if (arg[i] > 127 || !owner_char((unsigned char)arg[i]))
            return FALSE;
        out[i] = (char)arg[i];
    }
    out[n] = 0;
    return TRUE;
}

static void widen_owner(const char *owner, wchar_t out[129])
{
    size_t i;
    for (i = 0; owner[i]; ++i)
        out[i] = (wchar_t)(unsigned char)owner[i];
    out[i] = L'\0';
}

/* The record describes the tree Setup manages, so it is maintained only for
   that destination; standalone extractions elsewhere must never disturb an
   installed bundle's ownership. */
static BOOL manages_owner_record(const wchar_t *dest)
{
    wchar_t *root = NULL, *path = NULL, *managed = NULL;
    DWORD size;
    BOOL same = FALSE;
    size = GetEnvironmentVariableW(L"LOCALAPPDATA", NULL, 0);
    if (!size)
        return FALSE;
    root = allocate((size_t)size * sizeof(wchar_t));
    if (!root)
        return FALSE;
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", root, size) == size - 1) {
        path = join(root, OWNER_DESTINATION);
        managed = path ? full_path(path) : NULL;
        same = managed && !_wcsicmp(managed, dest);
    }
    free(managed);
    free(path);
    free(root);
    return same;
}

/* Setup detects payload ownership through this per-user value. The helper is
   the only package that runs whenever ownership changes, so it -- not the MSI,
   which Burn skips when a republished bundle ships an already installed
   package -- has to keep the record in step with the on-disk marker. */
static BOOL set_owner_record(const wchar_t *dest, const char *owner)
{
    wchar_t text[129];
    HKEY key;
    LSTATUS status;
    if (!manages_owner_record(dest))
        return TRUE;
    widen_owner(owner, text);
    status = RegCreateKeyExW(HKEY_CURRENT_USER, OWNER_KEY, 0, NULL, REG_OPTION_NON_VOLATILE,
                             KEY_SET_VALUE, NULL, &key, NULL);
    if (status == ERROR_SUCCESS) {
        status = RegSetValueExW(key, OWNER_VALUE, 0, REG_SZ, (const BYTE *)text,
                                (DWORD)((wcslen(text) + 1) * sizeof(wchar_t)));
        RegCloseKey(key);
    }
    if (status != ERROR_SUCCESS) {
        SetLastError((DWORD)status);
        return win_error(L"Recording payload ownership", OWNER_KEY);
    }
    return TRUE;
}

static BOOL clear_owner_record(const wchar_t *dest, const char *owner)
{
    wchar_t text[129], current[130];
    HKEY key;
    DWORD type = 0, bytes = (DWORD)(sizeof(current) - sizeof(wchar_t));
    LSTATUS status, removal = ERROR_SUCCESS;
    if (!manages_owner_record(dest))
        return TRUE;
    widen_owner(owner, text);
    status = RegOpenKeyExW(HKEY_CURRENT_USER, OWNER_KEY, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
        return TRUE;
    if (status != ERROR_SUCCESS) {
        SetLastError((DWORD)status);
        return win_error(L"Opening payload ownership record", OWNER_KEY);
    }
    status = RegQueryValueExW(key, OWNER_VALUE, NULL, &type, (BYTE *)current, &bytes);
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
        RegCloseKey(key);
        SetLastError((DWORD)status);
        return win_error(L"Reading payload ownership record", OWNER_KEY);
    }
    /* Retract only our own record; an incoming bundle may already have adopted
       the tree, and its record must outlive this removal. */
    if (status == ERROR_SUCCESS && type == REG_SZ && !(bytes % sizeof(wchar_t))) {
        current[bytes / sizeof(wchar_t)] = L'\0';
        if (!wcscmp(current, text)) {
            removal = RegDeleteValueW(key, OWNER_VALUE);
            if (removal == ERROR_FILE_NOT_FOUND)
                removal = ERROR_SUCCESS;
        }
    }
    RegCloseKey(key);
    if (removal != ERROR_SUCCESS) {
        SetLastError((DWORD)removal);
        return win_error(L"Clearing payload ownership record", OWNER_KEY);
    }
    return TRUE;
}

/* 1 valid, 0 absent, 2 malformed (must not grant removal), -1 I/O error. */
static int read_marker(const wchar_t *dir, Marker *marker)
{
    wchar_t *path = join(dir, MARKER);
    HANDLE file;
    DWORD bytes, attr;
    char text[256];
    size_t i, n, start;
    int result = -1;
    memset(marker, 0, sizeof(*marker));
    if (!path)
        return -1;
    attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        if (absent(GetLastError()))
            result = 0;
        else
            win_error(L"Inspecting source marker", path);
        goto done;
    }
    if (attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
        problem(L"Source marker is not an ordinary file", path);
        goto done;
    }
    file = open_input(path);
    if (file == INVALID_HANDLE_VALUE)
        goto done;
    if (!ReadFile(file, text, sizeof(text), &bytes, NULL)) {
        win_error(L"Reading source marker", path);
        CloseHandle(file);
        goto done;
    }
    CloseHandle(file);
    result = 2;
    n = bytes;
    if (n < 64 || n == sizeof(text))
        goto done;
    for (i = 0; i < 64; ++i) {
        char c = text[i];
        if (c >= 'A' && c <= 'F')
            c = (char)(c + ('a' - 'A'));
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            goto done;
        marker->hash[i] = c;
    }
    if (n == 64) {
        result = 1;
        goto done;
    }
    i = 64;
    if (text[i] == '\r')
        ++i;
    if (i >= n || text[i++] != '\n')
        goto done;
    if (i == n) {
        result = 1;
        goto done;
    }
    if (n - i < 6 || memcmp(text + i, "owner=", 6))
        goto done;
    start = i += 6;
    while (i < n && owner_char((unsigned char)text[i]))
        ++i;
    if (i == start || i - start > 128)
        goto done;
    memcpy(marker->owner, text + start, i - start);
    if (i < n && text[i] == '\r')
        ++i;
    if (i < n && text[i] == '\n')
        ++i;
    if (i == n)
        result = 1;
done:
    free(path);
    return result;
}

static BOOL write_marker(const wchar_t *dir, const char *hash, const char *owner)
{
    wchar_t name[50], *temp = NULL, *path = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    char text[202];
    DWORD length, written;
    BOOL ok = FALSE, created = FALSE;
    unsigned attempt;
    path = join(dir, MARKER);
    if (!path)
        goto done;
    for (attempt = 0; attempt < 32; ++attempt) {
        if (!random_name(name, L".marker-"))
            goto done;
        temp = join(dir, name);
        if (!temp)
            goto done;
        file = CreateFileW(temp, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, NULL);
        if (file != INVALID_HANDLE_VALUE) {
            created = TRUE;
            break;
        }
        if (GetLastError() != ERROR_FILE_EXISTS) {
            win_error(L"Creating temporary source marker", temp);
            goto done;
        }
        free(temp);
        temp = NULL;
    }
    if (file == INVALID_HANDLE_VALUE) {
        problem(L"Cannot allocate temporary source marker", dir);
        goto done;
    }
    memcpy(text, hash, 64);
    length = 64;
    if (owner && *owner) {
        memcpy(text + length, "\nowner=", 7);
        length += 7;
        memcpy(text + length, owner, strlen(owner));
        length += (DWORD)strlen(owner);
        text[length++] = '\n';
    }
    if (!WriteFile(file, text, length, &written, NULL) || written != length) {
        win_error(L"Writing temporary source marker", temp);
        goto done;
    }
    if (!FlushFileBuffers(file)) {
        win_error(L"Flushing temporary source marker", temp);
        goto done;
    }
    if (!CloseHandle(file)) {
        file = INVALID_HANDLE_VALUE;
        win_error(L"Closing temporary source marker", temp);
        goto done;
    }
    file = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(temp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        win_error(L"Replacing source marker", path);
        goto done;
    }
    ok = TRUE;
done:
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (!ok && created && temp) {
        DWORD attr = GetFileAttributesW(temp);
        if (attr != INVALID_FILE_ATTRIBUTES && !DeleteFileW(temp))
            win_error(L"Cleaning up temporary source marker", temp);
    }
    free(temp);
    free(path);
    return ok;
}

static size_t zip_read(void *opaque, mz_uint64 offset, void *buffer, size_t bytes)
{
    HANDLE file = (HANDLE)opaque;
    LARGE_INTEGER position;
    size_t total = 0;
    position.QuadPart = (LONGLONG)offset;
    if (offset > INT64_MAX || !SetFilePointerEx(file, position, NULL, FILE_BEGIN))
        return 0;
    while (total < bytes) {
        DWORD got, chunk = (DWORD)((bytes - total > 1024 * 1024) ? 1024 * 1024 : bytes - total);
        if (!ReadFile(file, (char *)buffer + total, chunk, &got, NULL) || !got)
            break;
        total += got;
    }
    return total;
}

static size_t zip_write(void *opaque, mz_uint64 offset, const void *buffer, size_t bytes)
{
    HANDLE file = (HANDLE)opaque;
    size_t total = 0;
    (void)offset; /* miniz's streaming extraction callback is sequential. */
    while (total < bytes) {
        DWORD wrote, chunk = (DWORD)((bytes - total > 1024 * 1024) ? 1024 * 1024 : bytes - total);
        if (!WriteFile(file, (const char *)buffer + total, chunk, &wrote, NULL) || !wrote) {
            win_error(L"Writing extracted file", L"");
            break;
        }
        total += wrote;
    }
    return total;
}

static BOOL reserved_component(const wchar_t *s, size_t n)
{
    size_t base = 0;
    wchar_t name[8];
    while (base < n && s[base] != L'.')
        ++base;
    while (base && s[base - 1] == L' ')
        --base;
    if (base >= sizeof(name) / sizeof(name[0]))
        return FALSE;
    memcpy(name, s, base * sizeof(wchar_t));
    name[base] = 0;
    if (!_wcsicmp(name, L"CON") || !_wcsicmp(name, L"PRN") ||
        !_wcsicmp(name, L"AUX") || !_wcsicmp(name, L"NUL") ||
        !_wcsicmp(name, L"CONIN$") || !_wcsicmp(name, L"CONOUT$") ||
        !_wcsicmp(name, L"CLOCK$"))
        return TRUE;
    if (base == 4 && (!_wcsnicmp(name, L"COM", 3) || !_wcsnicmp(name, L"LPT", 3))) {
        wchar_t c = name[3];
        return (c >= L'0' && c <= L'9') || c == 0xb9 || c == 0xb2 || c == 0xb3;
    }
    return FALSE;
}

static BOOL valid_relative(const wchar_t *name)
{
    size_t i, start = 0, n = wcslen(name);
    if (!n || name[0] == L'\\')
        return FALSE;
    for (i = 0; i <= n; ++i) {
        wchar_t c = name[i];
        if (i == n || c == L'\\') {
            size_t length = i - start;
            if (!length || name[i - 1] == L'.' || name[i - 1] == L' ' ||
                reserved_component(name + start, length))
                return FALSE;
            start = i + 1;
        } else if (c < 32 || c == 127 || wcschr(L"/:<>\"|?*", c)) {
            return FALSE;
        }
    }
    return TRUE;
}

static wchar_t *entry_name(mz_zip_archive *zip, mz_uint index, BOOL *directory)
{
    mz_zip_archive_file_stat stat;
    mz_uint bytes = mz_zip_reader_get_filename(zip, index, NULL, 0);
    char *raw = NULL;
    wchar_t *name = NULL;
    int count;
    size_t i, n;
    unsigned type;
    if (!mz_zip_reader_file_stat(zip, index, &stat) || bytes <= 1)
        goto invalid;
    type = (stat.m_external_attr >> 16) & 0170000;
    if ((type && type != 0100000 && type != 0040000) ||
        (stat.m_external_attr & FILE_ATTRIBUTE_REPARSE_POINT) ||
        stat.m_is_encrypted || !stat.m_is_supported ||
        (stat.m_method != 0 && stat.m_method != 8))
        goto invalid;
    raw = allocate(bytes);
    if (!raw)
        return NULL;
    if (mz_zip_reader_get_filename(zip, index, raw, bytes) != bytes ||
        memchr(raw, 0, bytes - 1))
        goto invalid;
    count = MultiByteToWideChar((stat.m_bit_flag & 0x800) ? CP_UTF8 : 437,
                               (stat.m_bit_flag & 0x800) ? MB_ERR_INVALID_CHARS : 0,
                               raw, (int)bytes - 1, NULL, 0);
    if (!count)
        goto invalid;
    name = allocate(((size_t)count + 1) * sizeof(wchar_t));
    if (!name)
        goto done;
    if (!MultiByteToWideChar((stat.m_bit_flag & 0x800) ? CP_UTF8 : 437,
                            (stat.m_bit_flag & 0x800) ? MB_ERR_INVALID_CHARS : 0,
                            raw, (int)bytes - 1, name, count))
        goto invalid;
    name[count] = 0;
    n = (size_t)count;
    for (i = 0; i < n; ++i)
        if (name[i] == L'/')
            name[i] = L'\\';
    *directory = stat.m_is_directory || type == 0040000 ||
                 (stat.m_external_attr & FILE_ATTRIBUTE_DIRECTORY) || name[n - 1] == L'\\';
    if (*directory && name[n - 1] == L'\\')
        name[--n] = 0;
    if (!valid_relative(name))
        goto invalid;
    goto done;
invalid:
    fwprintf(stderr, L"Unsafe or unsupported ZIP entry at index %u.\n", index);
    free(name);
    name = NULL;
done:
    free(raw);
    return name;
}

static BOOL add_path(Paths *paths, const wchar_t *name, size_t n, BOOL dir, BOOL explicit_entry)
{
    PathEntry *item;
    if (paths->count == paths->capacity) {
        size_t capacity = paths->capacity ? paths->capacity * 2 : 256;
        void *grown;
        if (capacity < paths->capacity || capacity > SIZE_MAX / sizeof(PathEntry))
            return problem(L"ZIP path table is too large", name);
        grown = realloc(paths->items, capacity * sizeof(PathEntry));
        if (!grown)
            return problem(L"Out of memory validating ZIP paths", name);
        paths->items = grown;
        paths->capacity = capacity;
    }
    item = &paths->items[paths->count];
    memset(item, 0, sizeof(*item));
    item->name = copy_n(name, n);
    if (!item->name)
        return FALSE;
    item->directory = dir;
    item->explicit_entry = explicit_entry;
    ++paths->count;
    return TRUE;
}

static int compare_paths(const void *a, const void *b)
{
    const PathEntry *pa = a, *pb = b;
    return CompareStringOrdinal(pa->name, -1, pb->name, -1, TRUE) - CSTR_EQUAL;
}

static BOOL validate_archive(mz_zip_archive *zip)
{
    Paths paths = {0};
    mz_uint index, count = mz_zip_reader_get_num_files(zip);
    size_t i;
    BOOL ok = FALSE;
    for (index = 0; index < count; ++index) {
        BOOL dir;
        wchar_t *name = entry_name(zip, index, &dir);
        wchar_t *first, *slash;
        if (!name)
            goto done;
        slash = wcschr(name, L'\\');
        first = copy_n(name, slash ? (size_t)(slash - name) : wcslen(name));
        if (!first || metadata_name(first)) {
            problem(L"ZIP collides with helper-owned root metadata", name);
            free(first);
            free(name);
            goto done;
        }
        free(first);
        for (i = 0; name[i]; ++i) {
            if (name[i] == L'\\' && !add_path(&paths, name, i, TRUE, FALSE)) {
                free(name);
                goto done;
            }
        }
        if (!add_path(&paths, name, i, dir, TRUE)) {
            free(name);
            goto done;
        }
        free(name);
    }
    if (paths.count)
        qsort(paths.items, paths.count, sizeof(PathEntry), compare_paths);
    for (i = 0; i < paths.count;) {
        size_t j = i + 1, explicit_count = paths.items[i].explicit_entry ? 1 : 0;
        while (j < paths.count && !compare_paths(&paths.items[i], &paths.items[j])) {
            explicit_count += paths.items[j].explicit_entry ? 1 : 0;
            if (wcscmp(paths.items[i].name, paths.items[j].name) ||
                !paths.items[i].directory || !paths.items[j].directory || explicit_count > 1) {
                problem(L"Duplicate, case-aliased, or conflicting ZIP path", paths.items[j].name);
                goto done;
            }
            ++j;
        }
        i = j;
    }
    ok = TRUE;
done:
    for (i = 0; i < paths.count; ++i)
        free(paths.items[i].name);
    free(paths.items);
    return ok;
}

static BOOL unpack(mz_zip_archive *zip, const wchar_t *stage)
{
    mz_uint index, count = mz_zip_reader_get_num_files(zip);
    for (index = 0; index < count; ++index) {
        BOOL directory, ok;
        wchar_t *name = entry_name(zip, index, &directory), *path, *parent;
        HANDLE file;
        if (!name)
            return FALSE;
        path = join(stage, name);
        free(name);
        if (!path)
            return FALSE;
        if (directory) {
            ok = directories(path, TRUE);
            free(path);
            if (!ok)
                return FALSE;
            continue;
        }
        parent = parent_path(path);
        ok = parent && directories(parent, TRUE);
        free(parent);
        if (!ok) {
            free(path);
            return FALSE;
        }
        file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) {
            win_error(L"Creating extracted file", path);
            free(path);
            return FALSE;
        }
        ok = mz_zip_reader_extract_to_callback(zip, index, zip_write, file, 0);
        if (!ok) {
            fwprintf(stderr, L"ZIP extraction/CRC check failed for %ls: %hs\n",
                     path, mz_zip_get_error_string(mz_zip_get_last_error(zip)));
        }
        if (!CloseHandle(file))
            ok = win_error(L"Closing extracted file", path);
        free(path);
        if (!ok)
            return FALSE;
    }
    return TRUE;
}

static wchar_t *source_root(const wchar_t *stage)
{
    wchar_t *pattern = join(stage, L"*"), *sole = NULL;
    WIN32_FIND_DATAW data;
    HANDLE search;
    size_t count = 0;
    BOOL ok = TRUE;
    if (!pattern)
        return NULL;
    search = FindFirstFileW(pattern, &data);
    free(pattern);
    if (search == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
            return copy_n(stage, wcslen(stage));
        win_error(L"Finding extracted root", stage);
        return NULL;
    }
    do {
        if (!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L".."))
            continue;
        ++count;
        if (count == 1 && (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            !(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            sole = join(stage, data.cFileName);
            if (!sole) {
                ok = FALSE;
                break;
            }
        }
    } while (FindNextFileW(search, &data));
    if (ok && GetLastError() != ERROR_NO_MORE_FILES)
        ok = win_error(L"Enumerating extracted root", stage);
    FindClose(search);
    if (!ok) {
        free(sole);
        return NULL;
    }
    if (count == 1 && sole)
        return sole;
    free(sole);
    return copy_n(stage, wcslen(stage));
}

static void free_paths(Paths *paths)
{
    size_t i;
    for (i = 0; i < paths->count; ++i)
        free(paths->items[i].name);
    free(paths->items);
    memset(paths, 0, sizeof(*paths));
}

static BOOL metadata_name(const wchar_t *name)
{
    return !_wcsicmp(name, MARKER) || !_wcsicmp(name, INVENTORY) ||
           !_wcsicmp(name, REMOVAL);
}

static PathEntry *find_path(const Paths *paths, const wchar_t *name)
{
    PathEntry key = {0};
    key.name = (wchar_t *)name;
    return paths->count ? bsearch(&key, paths->items, paths->count,
                                  sizeof(PathEntry), compare_paths) : NULL;
}

static BOOL sort_paths(Paths *paths)
{
    size_t i;
    if (paths->count)
        qsort(paths->items, paths->count, sizeof(PathEntry), compare_paths);
    for (i = 1; i < paths->count; ++i)
        if (!compare_paths(&paths->items[i - 1], &paths->items[i]))
            return problem(L"Duplicate or case-conflicting inventory path", paths->items[i].name);
    return TRUE;
}

/* Directory handles deny rename/delete while descendants are inspected. */
static BOOL scan_tree(const wchar_t *root, const wchar_t *relative, Paths *paths,
                      BOOL reject_metadata)
{
    wchar_t *dir = *relative ? join(root, relative) : copy_n(root, wcslen(root));
    wchar_t *pattern = NULL;
    HANDLE pin = INVALID_HANDLE_VALUE, search = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info;
    WIN32_FIND_DATAW data;
    BOOL ok = FALSE;
    unsigned metadata_seen = 0;
    if (!dir || !directories(dir, FALSE))
        goto done;
    pin = CreateFileW(dir, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (pin == INVALID_HANDLE_VALUE) {
        win_error(L"Opening inventory directory", dir);
        goto done;
    }
    if (!GetFileInformationByHandle(pin, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        problem(L"Cannot safely inspect inventory directory", dir);
        goto done;
    }
    pattern = join(dir, L"*");
    if (!pattern)
        goto done;
    search = FindFirstFileW(pattern, &data);
    if (search == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
            ok = TRUE;
        else
            win_error(L"Enumerating inventory directory", dir);
        goto done;
    }
    do {
        wchar_t *name, *path;
        BOOL directory;
        ok = FALSE;
        if (!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L".."))
            continue;
        if (!*relative && metadata_name(data.cFileName)) {
            unsigned bit = !_wcsicmp(data.cFileName, MARKER) ? 1u :
                           (!_wcsicmp(data.cFileName, INVENTORY) ? 2u : 4u);
            if (reject_metadata) {
                problem(L"ZIP collides with helper-owned root metadata", data.cFileName);
                goto done;
            }
            if (metadata_seen & bit) {
                problem(L"Case-conflicting helper metadata cannot be classified safely", dir);
                goto done;
            }
            metadata_seen |= bit;
            if (data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
                problem(L"Helper metadata is not an ordinary file", data.cFileName);
                goto done;
            }
            continue;
        }
        name = *relative ? join(relative, data.cFileName) :
                           copy_n(data.cFileName, wcslen(data.cFileName));
        path = name ? join(root, name) : NULL;
        if (!name || !path) {
            free(name);
            free(path);
            goto done;
        }
        directory = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !valid_relative(name)) {
            problem(L"Cannot preserve unsafe or reparse-point payload entry", path);
            free(name);
            free(path);
            goto done;
        }
        if (!add_path(paths, name, wcslen(name), directory, TRUE)) {
            free(name);
            free(path);
            goto done;
        }
        if (directory) {
            ok = scan_tree(root, name, paths, reject_metadata);
        } else {
            HANDLE file = open_input(path);
            ok = file != INVALID_HANDLE_VALUE &&
                 sha256(file, paths->items[paths->count - 1].hash);
            if (file != INVALID_HANDLE_VALUE)
                CloseHandle(file);
        }
        free(name);
        free(path);
        if (!ok)
            goto done;
    } while (FindNextFileW(search, &data));
    ok = GetLastError() == ERROR_NO_MORE_FILES;
    if (!ok)
        win_error(L"Continuing inventory enumeration", dir);
done:
    if (search != INVALID_HANDLE_VALUE)
        FindClose(search);
    if (pin != INVALID_HANDLE_VALUE)
        CloseHandle(pin);
    free(pattern);
    free(dir);
    return ok;
}

static BOOL read_blob(const wchar_t *dir, const wchar_t *name, Blob *blob)
{
    wchar_t *path = join(dir, name);
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER size;
    DWORD got, attr;
    BOOL ok = FALSE;
    memset(blob, 0, sizeof(*blob));
    if (!path)
        return FALSE;
    attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES && absent(GetLastError())) {
        ok = TRUE;
        goto done;
    }
    file = open_input(path);
    if (file == INVALID_HANDLE_VALUE)
        goto done;
    if (!GetFileSizeEx(file, &size)) {
        win_error(L"Reading metadata size", path);
        goto done;
    }
    if (size.QuadPart < 0 || size.QuadPart > 64 * 1024 * 1024) {
        problem(L"Helper metadata exceeds safe size limit", path);
        goto done;
    }
    blob->size = (DWORD)size.QuadPart;
    blob->data = allocate((size_t)blob->size + 1);
    if (!blob->data)
        goto done;
    if (!ReadFile(file, blob->data, blob->size, &got, NULL) || got != blob->size) {
        win_error(L"Reading helper metadata", path);
        goto done;
    }
    blob->data[blob->size] = 0;
    blob->exists = TRUE;
    ok = TRUE;
done:
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    free(path);
    return ok;
}

static BOOL write_bytes(HANDLE file, const void *data, DWORD size)
{
    DWORD wrote;
    if (!WriteFile(file, data, size, &wrote, NULL) || wrote != size)
        return win_error(L"Writing helper metadata", L"");
    return TRUE;
}

static BOOL write_blob(const wchar_t *dir, const wchar_t *name, const Blob *blob)
{
    wchar_t random[50], *temp = NULL, *path = join(dir, name);
    HANDLE file = INVALID_HANDLE_VALUE;
    BOOL ok = FALSE, created = FALSE;
    if (!path)
        goto done;
    if (!blob->exists) {
        DWORD attr = GetFileAttributesW(path);
        if (attr == INVALID_FILE_ATTRIBUTES && absent(GetLastError())) {
            ok = TRUE;
            goto done;
        }
        if (attr == INVALID_FILE_ATTRIBUTES ||
            (attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
            problem(L"Cannot safely restore absent metadata", path);
            goto done;
        }
        if ((attr & FILE_ATTRIBUTE_READONLY) &&
            !SetFileAttributesW(path, attr & ~FILE_ATTRIBUTE_READONLY)) {
            win_error(L"Clearing metadata read-only attribute", path);
            goto done;
        }
        ok = DeleteFileW(path);
        if (!ok)
            win_error(L"Restoring absent helper metadata", path);
        goto done;
    }
    if (!random_name(random, L".marker-"))
        goto done;
    temp = join(dir, random);
    if (!temp)
        goto done;
    file = CreateFileW(temp, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        win_error(L"Creating temporary helper metadata", temp);
        goto done;
    }
    created = TRUE;
    if (!write_bytes(file, blob->data, blob->size))
        goto done;
    if (!FlushFileBuffers(file)) {
        win_error(L"Flushing helper metadata", temp);
        goto done;
    }
    if (!CloseHandle(file)) {
        file = INVALID_HANDLE_VALUE;
        win_error(L"Closing helper metadata", temp);
        goto done;
    }
    file = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(temp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        win_error(L"Replacing helper metadata", path);
        goto done;
    }
    ok = TRUE;
done:
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (!ok && created && !DeleteFileW(temp))
        win_error(L"Cleaning temporary helper metadata", temp);
    free(temp);
    free(path);
    return ok;
}

static BOOL lower_hash(const char *hash)
{
    size_t i;
    for (i = 0; i < 64; ++i)
        if (!((hash[i] >= '0' && hash[i] <= '9') || (hash[i] >= 'a' && hash[i] <= 'f')))
            return FALSE;
    return TRUE;
}

static wchar_t *inventory_name(const char *text, size_t size)
{
    int count;
    size_t i;
    wchar_t *name;
    if (!size || size > INT_MAX || memchr(text, '\\', size))
        return NULL;
    count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, (int)size, NULL, 0);
    if (!count)
        return NULL;
    name = allocate(((size_t)count + 1) * sizeof(wchar_t));
    if (!name)
        return NULL;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, (int)size, name, count)) {
        free(name);
        return NULL;
    }
    name[count] = 0;
    for (i = 0; i < (size_t)count; ++i)
        if (name[i] == L'/')
            name[i] = L'\\';
    if (!valid_relative(name) || metadata_name(name)) {
        free(name);
        return NULL;
    }
    return name;
}

/* Unknown or malformed baselines never authorize destruction. */
static BOOL parse_inventory(const Blob *blob, const char *source, Paths *paths)
{
    const char *line, *end, *next;
    size_t i;
    const char header[] = "ghidralaunch-inventory-v1\nsource=";
    if (!blob->exists || blob->size < sizeof(header) - 1 + 65 ||
        memchr(blob->data, 0, blob->size) ||
        memcmp(blob->data, header, sizeof(header) - 1))
        return FALSE;
    line = blob->data + sizeof(header) - 1;
    if (!lower_hash(line) || memcmp(line, source, 64) || line[64] != '\n')
        return FALSE;
    line += 65;
    end = blob->data + blob->size;
    while (line < end) {
        wchar_t *name;
        BOOL directory;
        size_t prefix;
        next = memchr(line, '\n', (size_t)(end - line));
        if (!next)
            return FALSE;
        directory = *line == 'd';
        prefix = directory ? 4 : 67;
        if ((size_t)(next - line) <= prefix || line[1] != '\t' ||
            (directory ? (line[2] != '-' || line[3] != '\t') :
             (*line != 'f' || !lower_hash(line + 2) || line[66] != '\t')))
            return FALSE;
        name = inventory_name(line + prefix, (size_t)(next - line) - prefix);
        if (!name)
            return FALSE;
        if (!add_path(paths, name, wcslen(name), directory, TRUE)) {
            free(name);
            return FALSE;
        }
        free(name);
        if (!directory)
            memcpy(paths->items[paths->count - 1].hash, line + 2, 64);
        line = next + 1;
    }
    if (!sort_paths(paths))
        return FALSE;
    for (i = 0; i < paths->count; ++i) {
        wchar_t *slash = wcsrchr(paths->items[i].name, L'\\');
        if (slash) {
            wchar_t *parent = copy_n(paths->items[i].name, (size_t)(slash - paths->items[i].name));
            PathEntry *entry = parent ? find_path(paths, parent) : NULL;
            BOOL valid = entry && entry->directory && !wcscmp(entry->name, parent);
            free(parent);
            if (!valid)
                return FALSE;
        }
    }
    return TRUE;
}

static BOOL write_inventory(const wchar_t *root, const char *source, const Paths *paths)
{
    wchar_t random[50], *temp = NULL, *target = join(root, INVENTORY);
    HANDLE file = INVALID_HANDLE_VALUE;
    size_t i;
    BOOL ok = FALSE, created = FALSE;
    const char header[] = "ghidralaunch-inventory-v1\nsource=";
    if (!target || !random_name(random, L".marker-"))
        goto done;
    temp = join(root, random);
    if (!temp)
        goto done;
    file = CreateFileW(temp, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        win_error(L"Creating inventory", temp);
        goto done;
    }
    created = TRUE;
    if (!write_bytes(file, header, sizeof(header) - 1) ||
        !write_bytes(file, source, 64) || !write_bytes(file, "\n", 1))
        goto done;
    for (i = 0; i < paths->count; ++i) {
        const PathEntry *entry = &paths->items[i];
        wchar_t *name = copy_n(entry->name, wcslen(entry->name));
        char *utf8;
        size_t j;
        int bytes;
        BOOL record_ok;
        if (!name)
            goto done;
        for (j = 0; name[j]; ++j)
            if (name[j] == L'\\')
                name[j] = L'/';
        bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, -1, NULL, 0, NULL, NULL);
        if (!bytes) {
            win_error(L"Encoding inventory path as UTF-8", name);
            free(name);
            goto done;
        }
        utf8 = allocate((size_t)bytes);
        if (!utf8) {
            free(name);
            goto done;
        }
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, -1, utf8, bytes, NULL, NULL)) {
            win_error(L"Encoding inventory path as UTF-8", name);
            free(utf8);
            free(name);
            goto done;
        }
        free(name);
        record_ok = entry->directory ? write_bytes(file, "d\t-\t", 4) :
             (write_bytes(file, "f\t", 2) && write_bytes(file, entry->hash, 64) &&
              write_bytes(file, "\t", 1));
        record_ok = record_ok && write_bytes(file, utf8, (DWORD)bytes - 1) &&
                    write_bytes(file, "\n", 1);
        free(utf8);
        if (!record_ok)
            goto done;
    }
    ok = FALSE;
    if (!FlushFileBuffers(file)) {
        win_error(L"Flushing inventory", temp);
        goto done;
    }
    if (!CloseHandle(file)) {
        file = INVALID_HANDLE_VALUE;
        win_error(L"Closing inventory", temp);
        goto done;
    }
    file = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(temp, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        win_error(L"Committing inventory", target);
        goto done;
    }
    ok = TRUE;
done:
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (!ok && created && !DeleteFileW(temp))
        win_error(L"Cleaning temporary inventory", temp);
    free(temp);
    free(target);
    return ok;
}

static BOOL customized(const Paths *baseline, const Paths *current, BOOL allow_missing)
{
    size_t i;
    for (i = 0; i < current->count; ++i) {
        const PathEntry *item = &current->items[i];
        PathEntry *old = find_path(baseline, item->name);
        if (!old || wcscmp(old->name, item->name) ||
            old->directory != item->directory ||
            (!item->directory && strcmp(old->hash, item->hash)))
            return TRUE;
    }
    if (!allow_missing)
        for (i = 0; i < baseline->count; ++i)
            if (!find_path(current, baseline->items[i].name))
                return TRUE;
    return FALSE;
}

static BOOL capture_owner(const wchar_t *dest, const char *owner, OwnerRecord *record)
{
    HKEY key;
    LSTATUS status;
    DWORD size = 0;
    memset(record, 0, sizeof(*record));
    if (!owner || !manages_owner_record(dest))
        return TRUE;
    record->managed = TRUE;
    status = RegOpenKeyExW(HKEY_CURRENT_USER, OWNER_KEY, 0, KEY_QUERY_VALUE, &key);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
        return TRUE;
    if (status != ERROR_SUCCESS)
        goto failure;
    status = RegQueryValueExW(key, OWNER_VALUE, NULL, &record->type, NULL, &size);
    if (status == ERROR_FILE_NOT_FOUND) {
        RegCloseKey(key);
        return TRUE;
    }
    if (status == ERROR_SUCCESS) {
        record->value.data = allocate((size_t)size + 1);
        if (!record->value.data) {
            RegCloseKey(key);
            return FALSE;
        }
        status = RegQueryValueExW(key, OWNER_VALUE, NULL, &record->type,
                                  (BYTE *)record->value.data, &size);
        if (status == ERROR_SUCCESS) {
            record->value.size = size;
            record->value.exists = TRUE;
        }
    }
    RegCloseKey(key);
    if (status == ERROR_SUCCESS)
        return TRUE;
failure:
    SetLastError((DWORD)status);
    return win_error(L"Saving previous payload ownership", OWNER_KEY);
}

static BOOL restore_owner(const OwnerRecord *record)
{
    HKEY key;
    LSTATUS status;
    if (!record->managed)
        return TRUE;
    status = RegCreateKeyExW(HKEY_CURRENT_USER, OWNER_KEY, 0, NULL, REG_OPTION_NON_VOLATILE,
                             KEY_SET_VALUE, NULL, &key, NULL);
    if (status == ERROR_SUCCESS) {
        status = record->value.exists ?
            RegSetValueExW(key, OWNER_VALUE, 0, record->type,
                           (const BYTE *)record->value.data, record->value.size) :
            RegDeleteValueW(key, OWNER_VALUE);
        if (!record->value.exists && status == ERROR_FILE_NOT_FOUND)
            status = ERROR_SUCCESS;
        RegCloseKey(key);
    }
    if (status != ERROR_SUCCESS) {
        SetLastError((DWORD)status);
        return win_error(L"ROLLBACK FAILED restoring previous registry ownership", OWNER_KEY);
    }
    return TRUE;
}

static BOOL copy_file_verified(const wchar_t *source, const wchar_t *target)
{
    HANDLE input = INVALID_HANDLE_VALUE, output = INVALID_HANDLE_VALUE;
    unsigned char *buffer = NULL;
    DWORD bytes, wrote;
    char expected[65], actual[65];
    BOOL ok = FALSE;
    input = open_input(source);
    if (input == INVALID_HANDLE_VALUE || !sha256(input, expected))
        goto done;
    {
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        if (!SetFilePointerEx(input, zero, NULL, FILE_BEGIN)) {
            win_error(L"Seeking preservation source", source);
            goto done;
        }
    }
    output = CreateFileW(target, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (output == INVALID_HANDLE_VALUE) {
        win_error(L"Creating preservation copy", target);
        goto done;
    }
    buffer = allocate(1024 * 1024);
    if (!buffer)
        goto done;
    for (;;) {
        if (!ReadFile(input, buffer, 1024 * 1024, &bytes, NULL)) {
            win_error(L"Reading preservation source", source);
            goto done;
        }
        if (!bytes)
            break;
        if (!WriteFile(output, buffer, bytes, &wrote, NULL) || wrote != bytes) {
            win_error(L"Writing preservation copy", target);
            goto done;
        }
    }
    if (!FlushFileBuffers(output)) {
        win_error(L"Flushing preservation copy", target);
        goto done;
    }
    if (!sha256(output, actual) || strcmp(expected, actual)) {
        problem(L"Preservation verification failed; original left intact", target);
        goto done;
    }
    ok = TRUE;
done:
    free(buffer);
    if (output != INVALID_HANDLE_VALUE)
        CloseHandle(output);
    if (input != INVALID_HANDLE_VALUE)
        CloseHandle(input);
    return ok;
}

static BOOL copy_tree_verified(const wchar_t *source, const wchar_t *target)
{
    HANDLE pin = INVALID_HANDLE_VALUE, search = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info;
    WIN32_FIND_DATAW data;
    wchar_t *pattern = NULL;
    BOOL ok = FALSE;
    if (!directories(source, FALSE) || !CreateDirectoryW(target, NULL)) {
        win_error(L"Preparing recovery copy", target);
        goto done;
    }
    pin = CreateFileW(source, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (pin == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(pin, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        problem(L"Cannot safely pin recovery source; original left intact", source);
        goto done;
    }
    pattern = join(source, L"*");
    if (!pattern)
        goto done;
    search = FindFirstFileW(pattern, &data);
    if (search == INVALID_HANDLE_VALUE) {
        ok = GetLastError() == ERROR_FILE_NOT_FOUND;
        if (!ok)
            win_error(L"Enumerating recovery source", source);
        goto done;
    }
    do {
        wchar_t *from, *to;
        ok = FALSE;
        if (!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L".."))
            continue;
        from = join(source, data.cFileName);
        to = join(target, data.cFileName);
        if (!from || !to) {
            free(from);
            free(to);
            goto done;
        }
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            ok = problem(L"Cannot preserve reparse point; original left intact", from);
        } else if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ok = copy_tree_verified(from, to);
        } else {
            ok = copy_file_verified(from, to);
        }
        free(from);
        free(to);
        if (!ok)
            goto done;
    } while (FindNextFileW(search, &data));
    ok = GetLastError() == ERROR_NO_MORE_FILES;
    if (!ok)
        win_error(L"Continuing recovery enumeration", source);
done:
    if (search != INVALID_HANDLE_VALUE)
        FindClose(search);
    if (pin != INVALID_HANDLE_VALUE)
        CloseHandle(pin);
    free(pattern);
    return ok;
}

static wchar_t *preserve_tree(const wchar_t *dest, const char *previous_source, const char *incoming_source)
{
    DWORD size;
    wchar_t *local = NULL, *plain = NULL, *root = NULL, *operation = NULL, *tree = NULL;
    char *utf8 = NULL, *summary = NULL;
    size_t destination_length = wcslen(dest);
#ifdef HELPER_TEST_RECOVERY_ROOT
    const wchar_t *override = HELPER_TEST_RECOVERY_ROOT();
    if (override && *override)
        plain = copy_n(override, wcslen(override));
    else
#endif
    {
        size = GetEnvironmentVariableW(L"LOCALAPPDATA", NULL, 0);
        if (!size) {
            problem(L"LOCALAPPDATA is required for recovery; original left intact", dest);
            goto done;
        }
        local = allocate((size_t)size * sizeof(wchar_t));
        if (!local)
            goto done;
        if (GetEnvironmentVariableW(L"LOCALAPPDATA", local, size) != size - 1) {
            problem(L"Cannot resolve recovery directory; original left intact", dest);
            goto done;
        }
        plain = join(local, L"Ghidra Launch Recovery");
    }
    root = plain ? full_path(plain) : NULL;
    if (!root)
        goto done;
    /* A recovery directory inside the tree being replaced would recurse. */
    if (wcslen(root) >= destination_length && destination_length <= INT_MAX &&
        CompareStringOrdinal(root, (int)destination_length, dest, (int)destination_length,
                             TRUE) == CSTR_EQUAL &&
        (!root[destination_length] || root[destination_length] == L'\\')) {
        problem(L"Recovery directory must be outside destination", root);
        goto done;
    }
    if (!directories(root, TRUE))
        goto done;
    operation = new_directory(root, L"recovery-");
    tree = operation ? join(operation, L"tree") : NULL;
    if (!tree || !copy_tree_verified(dest, tree)) {
        if (operation)
            problem(L"Recovery incomplete; original left intact, partial copy at", operation);
        free(tree);
        tree = NULL;
        goto done;
    }
    {
        int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, dest, -1, NULL, 0, NULL, NULL);
        size_t capacity = bytes > 0 ? (size_t)bytes + 256 : 0;
        int length;
        Blob text = {0};
        utf8 = bytes > 0 ? allocate((size_t)bytes) : NULL;
        summary = capacity ? allocate(capacity) : NULL;
        if (!utf8 || !summary ||
            !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, dest, -1, utf8, bytes, NULL, NULL)) {
            problem(L"Cannot record recovery summary; original left intact", operation);
            free(tree);
            tree = NULL;
            goto done;
        }
        length = snprintf(summary, capacity,
            "ghidralaunch-recovery-v1\ndestination=%s\nprevious-source=%s\nincoming-source=%s\ncontents=tree\n",
            utf8, previous_source, incoming_source);
        if (length < 0 || (size_t)length >= capacity) {
            problem(L"Cannot format recovery summary; original left intact", operation);
            free(tree);
            tree = NULL;
            goto done;
        }
        text.data = summary;
        text.size = (DWORD)length;
        text.exists = TRUE;
        if (!write_blob(operation, L"recovery.txt", &text)) {
            problem(L"Cannot persist recovery summary; original left intact", operation);
            free(tree);
            tree = NULL;
            goto done;
        }
    }
    wprintf(L"Preserved complete previous tree in recovery: %ls\n", tree);
done:
    free(summary);
    free(utf8);
    free(operation);
    free(root);
    free(plain);
    free(local);
    return tree;
}

static BOOL migrate_additions(const wchar_t *old, const wchar_t *stage,
                             const Paths *baseline, const Paths *current, const Paths *upstream)
{
    size_t i;
    for (i = 0; i < current->count; ++i) {
        const PathEntry *entry = &current->items[i];
        wchar_t *from = NULL, *to = NULL, *parent = NULL, *part = NULL;
        size_t j;
        BOOL conflict = FALSE, ok;
        if (find_path(baseline, entry->name))
            continue;
        part = copy_n(entry->name, wcslen(entry->name));
        if (!part)
            return FALSE;
        for (j = 0;; ++j) {
            if (!part[j] || part[j] == L'\\') {
                wchar_t saved = part[j];
                PathEntry *packaged;
                part[j] = 0;
                packaged = find_path(upstream, part);
                if (packaged && (!saved || !packaged->directory || wcscmp(packaged->name, part)))
                    conflict = TRUE;
                part[j] = saved;
                if (!saved || conflict)
                    break;
            }
        }
        free(part);
        if (conflict)
            continue;
        from = join(old, entry->name);
        to = join(stage, entry->name);
        parent = to ? parent_path(to) : NULL;
        ok = from && to && parent && directories(parent, TRUE);
        if (ok)
            ok = entry->directory ? directories(to, TRUE) : copy_file_verified(from, to);
        free(parent);
        free(from);
        free(to);
        if (!ok)
            return FALSE;
    }
    return TRUE;
}

static BOOL extract(const wchar_t *zip_path, const wchar_t *dest, const char *owner)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    mz_zip_archive zip = {0};
    LARGE_INTEGER length;
    Marker marker;
    Blob old_marker = {0}, old_inventory = {0}, old_removal = {0}, staged_inventory = {0};
    OwnerRecord previous_owner = {0};
    Paths baseline = {0}, current = {0}, upstream = {0};
    char hash[65];
    wchar_t *parent = NULL, *stage = NULL, *root = NULL, *backup = NULL, *recovery = NULL;
    BOOL ok = FALSE, initialized = FALSE, backed_up = FALSE, installed = FALSE;
    BOOL existing = FALSE, same = FALSE, trusted = FALSE, committed = FALSE;
    BOOL adoption_changed = FALSE, registry_attempted = FALSE, owner_saved = FALSE;
    DWORD attr;
    int state;
    if (!safe_destination(dest))
        return FALSE;
    file = open_input(zip_path);
    if (file == INVALID_HANDLE_VALUE || !sha256(file, hash))
        goto done;
    state = read_marker(dest, &marker);
    if (state < 0)
        goto done;
    attr = GetFileAttributesW(dest);
    if (attr == INVALID_FILE_ATTRIBUTES && !absent(GetLastError())) {
        win_error(L"Inspecting extraction destination", dest);
        goto done;
    }
    existing = attr != INVALID_FILE_ATTRIBUTES;
    if (existing) {
        if (!read_blob(dest, MARKER, &old_marker) ||
            !read_blob(dest, INVENTORY, &old_inventory) ||
            !read_blob(dest, REMOVAL, &old_removal))
            goto done;
        trusted = state == 1 && parse_inventory(&old_inventory, marker.hash, &baseline);
        if (!trusted)
            free_paths(&baseline);
        same = state == 1 && !strcmp(marker.hash, hash) && !old_removal.exists;
    }
    if (!capture_owner(dest, owner, &previous_owner))
        goto done;
    owner_saved = TRUE;
    if (same && trusted)
        goto adopt;
    parent = parent_path(dest);
    if (!parent || !directories(parent, TRUE))
        goto done;
    stage = new_directory(parent, L".extract-");
    if (!stage)
        goto done;
    if (!GetFileSizeEx(file, &length)) {
        win_error(L"Reading source ZIP size", zip_path);
        goto done;
    }
    zip.m_pRead = zip_read;
    zip.m_pIO_opaque = file;
    if (!mz_zip_reader_init(&zip, (mz_uint64)length.QuadPart, 0)) {
        fwprintf(stderr, L"Cannot read ZIP: %hs\n", mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
        goto done;
    }
    initialized = TRUE;
    if (!validate_archive(&zip) || !unpack(&zip, stage))
        goto done;
    root = source_root(stage);
    if (!root || !scan_tree(root, L"", &upstream, TRUE) ||
        !sort_paths(&upstream) || !write_inventory(root, hash, &upstream) ||
        !write_marker(root, hash, owner))
        goto done;
    if (same) {
        if (!read_blob(root, INVENTORY, &staged_inventory))
            goto done;
        adoption_changed = TRUE;
        if (!write_blob(dest, INVENTORY, &staged_inventory))
            goto done;
        goto adopt;
    }
    if (existing) {
        if (!scan_tree(dest, L"", &current, FALSE) || !sort_paths(&current))
            goto done;
        if (!trusted || customized(&baseline, &current, FALSE)) {
            recovery = preserve_tree(dest, state == 1 ? marker.hash : "unknown", hash);
            if (!recovery)
                goto done;
            if (trusted && !migrate_additions(dest, root, &baseline, &current, &upstream))
                goto done;
        }
    }
    if (!safe_destination(dest))
        goto done;
    attr = GetFileAttributesW(dest);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        backup = new_directory(parent, L".old-");
        if (!backup)
            goto done;
        if (!RemoveDirectoryW(backup)) {
            win_error(L"Preparing backup name", backup);
            goto done;
        }
        if (!MoveFileExW(dest, backup, MOVEFILE_WRITE_THROUGH)) {
            win_error(L"Backing up original destination (original left intact)", dest);
            goto done;
        }
        backed_up = TRUE;
    } else if (!absent(GetLastError())) {
        win_error(L"Inspecting destination before swap", dest);
        goto done;
    }
    if (!MoveFileExW(root, dest, MOVEFILE_WRITE_THROUGH)) {
        win_error(L"Installing staged extraction", dest);
        goto done;
    }
    installed = TRUE;
    if (owner) {
        registry_attempted = TRUE;
        if (!set_owner_record(dest, owner))
            goto done;
    }
    committed = TRUE;
    ok = TRUE;
    goto done;
adopt:
    if (owner && strcmp(owner, marker.owner)) {
        adoption_changed = TRUE;
        if (!write_marker(dest, hash, owner))
            goto done;
    }
    if (owner) {
        registry_attempted = TRUE;
        if (!set_owner_record(dest, owner))
            goto done;
    }
    committed = TRUE;
    ok = TRUE;
    wprintf(L"Ghidra already extracted at %ls (unchanged); skipping.\n", dest);
done:
    if (initialized)
        mz_zip_reader_end(&zip);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (!committed && adoption_changed) {
        BOOL marker_restored = restore_metadata(dest, MARKER, &old_marker);
        BOOL inventory_restored = restore_metadata(dest, INVENTORY, &old_inventory);
        if (!marker_restored || !inventory_restored)
            problem(L"ROLLBACK FAILED restoring adoption metadata; destination retained", dest);
    }
    if (!committed && installed) {
        if (!MoveFileExW(dest, root, MOVEFILE_WRITE_THROUGH)) {
            win_error(L"ROLLBACK FAILED moving uncommitted extraction; original remains at backup",
                      backup ? backup : dest);
        } else {
            installed = FALSE;
        }
    }
    if (!committed && backed_up && !installed) {
        if (!MoveFileExW(backup, dest, MOVEFILE_WRITE_THROUGH)) {
            win_error(L"ROLLBACK FAILED; original remains at backup", backup);
            ok = FALSE;
        } else {
            backed_up = FALSE;
        }
    }
    if (!committed && owner_saved && registry_attempted && !restore_owner(&previous_owner))
        ok = FALSE;
    if (backed_up && committed && !remove_tree(backup)) {
        problem(L"WARNING: Installation committed; backup cleanup failed; residual backup", backup);
    } else if (backed_up && committed) {
        backed_up = FALSE;
    }
    if (backup && !backed_up && !remove_tree(backup)) {
        problem(committed ? L"WARNING: Installation committed; residual unused backup directory" :
                            L"Unused backup directory cleanup failed", backup);
        if (!committed)
            ok = FALSE;
    }
    if (stage && !remove_tree(stage)) {
        problem(committed ? L"WARNING: Installation committed; residual staging directory" :
                            L"Staging cleanup failed", stage);
        if (!committed)
            ok = FALSE;
    }
    if (ok && installed)
        wprintf(L"Extracted Ghidra to %ls.\n", dest);
    free_paths(&upstream);
    free_paths(&current);
    free_paths(&baseline);
    free(previous_owner.value.data);
    free(old_marker.data);
    free(old_inventory.data);
    free(old_removal.data);
    free(staged_inventory.data);
    free(recovery);
    free(backup);
    free(root);
    free(stage);
    free(parent);
    return ok;
}

static BOOL remove_payload(const wchar_t *dest)
{
    HANDLE pin, search = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info;
    WIN32_FIND_DATAW data;
    wchar_t *pattern = NULL;
    BOOL ok = FALSE;
    pin = CreateFileW(dest, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (pin == INVALID_HANDLE_VALUE)
        return win_error(L"Opening authorized removal directory", dest);
    if (!GetFileInformationByHandle(pin, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        problem(L"Removal directory changed to a reparse point", dest);
        goto done;
    }
    pattern = join(dest, L"*");
    if (!pattern)
        goto done;
    search = FindFirstFileW(pattern, &data);
    if (search == INVALID_HANDLE_VALUE) {
        ok = GetLastError() == ERROR_FILE_NOT_FOUND;
        if (!ok)
            win_error(L"Enumerating authorized removal directory", dest);
        goto done;
    }
    do {
        wchar_t *child;
        ok = FALSE;
        if (!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L"..") ||
            metadata_name(data.cFileName))
            continue;
        child = join(dest, data.cFileName);
        if (!child)
            goto done;
        ok = remove_tree(child);
        free(child);
        if (!ok)
            goto done;
    } while (FindNextFileW(search, &data));
    ok = GetLastError() == ERROR_NO_MORE_FILES;
    if (!ok)
        win_error(L"Continuing authorized removal enumeration", dest);
done:
    if (search != INVALID_HANDLE_VALUE)
        FindClose(search);
    CloseHandle(pin);
    free(pattern);
    return ok;
}

static BOOL restore_metadata(const wchar_t *dest, const wchar_t *name, const Blob *original)
{
    Blob current = {0};
    BOOL identical = read_blob(dest, name, &current) && current.exists == original->exists &&
        current.size == original->size &&
        (!original->size || !memcmp(current.data, original->data, original->size));
    free(current.data);
    return identical || write_blob(dest, name, original);
}

static BOOL finish_removal(const wchar_t *dest, const Blob *marker,
                           const Blob *inventory, const Blob *removal)
{
    const wchar_t *names[] = {MARKER, INVENTORY, REMOVAL};
    size_t i;
    DWORD attr;
    HANDLE pin;
    BY_HANDLE_FILE_INFORMATION info;
    BOOL ok = TRUE;
    pin = CreateFileW(dest, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (pin == INVALID_HANDLE_VALUE)
        return win_error(L"Pinning final removal directory", dest);
    if (!GetFileInformationByHandle(pin, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        CloseHandle(pin);
        return problem(L"Final removal directory is no longer an ordinary directory", dest);
    }
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        wchar_t *path = join(dest, names[i]);
        ok = path && remove_tree(path);
        free(path);
        if (!ok)
            break;
    }
    if (ok) {
        attr = GetFileAttributesW(dest);
        if (attr == INVALID_FILE_ATTRIBUTES ||
            ((attr & FILE_ATTRIBUTE_READONLY) &&
             !SetFileAttributesW(dest, attr & ~FILE_ATTRIBUTE_READONLY))) {
            win_error(L"Preparing final removal directory", dest);
            ok = FALSE;
        }
    }
    CloseHandle(pin);
    if (ok) {
        if (!RemoveDirectoryW(dest)) {
            win_error(L"Removing authorized destination root", dest);
            ok = FALSE;
        }
    }
    if (!ok) {
        BOOL a, b, c;
        if (!directories(dest, FALSE))
            return problem(L"Cannot safely restore removal metadata; directory changed", dest);
        pin = CreateFileW(dest, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING,
                          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (pin == INVALID_HANDLE_VALUE)
            return win_error(L"Pinning removal recovery directory", dest);
        if (!GetFileInformationByHandle(pin, &info) ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            CloseHandle(pin);
            return problem(L"Cannot safely restore metadata into changed directory", dest);
        }
        a = restore_metadata(dest, MARKER, marker);
        b = restore_metadata(dest, INVENTORY, inventory);
        c = restore_metadata(dest, REMOVAL, removal);
        CloseHandle(pin);
        if (!a || !b || !c)
            problem(L"REMOVAL RECOVERY FAILED restoring retry metadata; directory retained", dest);
    }
    return ok;
}

static BOOL retain_destination(const wchar_t *dest, const char *owner, const wchar_t *reason)
{
    wprintf(L"Retained %ls; %ls.\n", dest, reason);
    return !owner || clear_owner_record(dest, owner);
}

static BOOL remove_destination(const wchar_t *dest, const wchar_t *zip_path, const char *owner)
{
    Marker marker;
    Blob marker_blob = {0}, inventory_blob = {0}, removal_blob = {0}, authorization = {0};
    Paths baseline = {0}, current = {0};
    char removal_text[320];
    int text_size;
    int state;
    DWORD attr;
    BOOL ok = FALSE, retry = FALSE;
    if (!safe_destination(dest))
        return FALSE;
    attr = GetFileAttributesW(dest);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        if (absent(GetLastError()))
            return !owner || clear_owner_record(dest, owner);
        return win_error(L"Inspecting removal destination", dest);
    }
    if (zip_path) {
        attr = GetFileAttributesW(zip_path);
        if (attr == INVALID_FILE_ATTRIBUTES && absent(GetLastError())) {
            wprintf(L"Skipping removal of %ls; the package source is unavailable.\n", dest);
            return TRUE;
        }
    }
    state = read_marker(dest, &marker);
    if (state < 0)
        return FALSE;
    if ((owner && (state != 1 || strcmp(owner, marker.owner))) ||
        (!owner && (state == 2 || (state == 1 && *marker.owner)))) {
        wprintf(L"Skipping removal of %ls; owner does not match or ownership is unavailable.\n", dest);
        return TRUE;
    }
    if (zip_path) {
        HANDLE file;
        char expected[65];
        if (state != 1) {
            wprintf(L"Skipping removal of %ls; the package source or marker is unavailable.\n", dest);
            return TRUE;
        }
        file = open_input(zip_path);
        if (file == INVALID_HANDLE_VALUE)
            return FALSE;
        if (!sha256(file, expected)) {
            CloseHandle(file);
            return FALSE;
        }
        CloseHandle(file);
        if (strcmp(expected, marker.hash)) {
            wprintf(L"Skipping removal of %ls; it belongs to another Ghidra package.\n", dest);
            return TRUE;
        }
    }
    if (state != 1) {
        ok = retain_destination(dest, owner, L"source baseline is unavailable");
        goto done;
    }
    if (!read_blob(dest, MARKER, &marker_blob) ||
        !read_blob(dest, INVENTORY, &inventory_blob) ||
        !read_blob(dest, REMOVAL, &removal_blob) ||
        !parse_inventory(&inventory_blob, marker.hash, &baseline)) {
        ok = retain_destination(dest, owner, L"upstream inventory is unavailable or invalid");
        goto done;
    }
    text_size = snprintf(removal_text, sizeof(removal_text),
                         "ghidralaunch-removal-v1\nsource=%s\nowner=%s\n",
                         marker.hash, marker.owner);
    if (text_size < 0 || (size_t)text_size >= sizeof(removal_text)) {
        problem(L"Cannot format removal authorization", dest);
        goto done;
    }
    authorization.data = removal_text;
    authorization.size = (DWORD)text_size;
    authorization.exists = TRUE;
    if (removal_blob.exists) {
        retry = removal_blob.size == authorization.size &&
                !memcmp(removal_blob.data, authorization.data, authorization.size);
        if (!retry) {
            ok = retain_destination(dest, owner, L"removal authorization does not match");
            goto done;
        }
    }
    if (!scan_tree(dest, L"", &current, FALSE) || !sort_paths(&current) ||
        customized(&baseline, &current, retry)) {
        ok = retain_destination(dest, owner, L"user customizations or unsafe entries were detected");
        goto done;
    }
    if (!retry && !write_blob(dest, REMOVAL, &authorization))
        goto done;
    if (!remove_payload(dest) ||
        !finish_removal(dest, &marker_blob, &inventory_blob, &authorization))
        goto done;
    if (owner && !clear_owner_record(dest, owner))
        goto done;
    wprintf(L"Removed %ls.\n", dest);
    ok = TRUE;
done:
    free(marker_blob.data);
    free(inventory_blob.data);
    free(removal_blob.data);
    free_paths(&baseline);
    free_paths(&current);
    return ok;
}

static HANDLE destination_lock_mode(const wchar_t *dest, BOOL restoring)
{
    const wchar_t suffix[] = L".ghidralaunch.lock";
    size_t n = wcslen(dest);
    wchar_t *path = NULL, *parent = NULL;
    HANDLE lock = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info;
    if (!restoring && !safe_destination(dest))
        return INVALID_HANDLE_VALUE;
    parent = parent_path(dest);
    if (!parent || !directories(parent, TRUE))
        goto done;
    if (n > SIZE_MAX / sizeof(wchar_t) - sizeof(suffix) / sizeof(suffix[0]))
        goto done;
    path = allocate(n * sizeof(wchar_t) + sizeof(suffix));
    if (!path)
        goto done;
    memcpy(path, dest, n * sizeof(wchar_t));
    memcpy(path + n, suffix, sizeof(suffix));
    lock = CreateFileW(path, GENERIC_READ | GENERIC_WRITE | DELETE, 0, NULL, OPEN_ALWAYS,
                       FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (lock == INVALID_HANDLE_VALUE) {
        win_error(L"Cannot acquire destination lock (another helper may be operating)", path);
    } else if (!GetFileInformationByHandle(lock, &info) ||
               (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
        problem(L"Destination lock must be an ordinary file", path);
        CloseHandle(lock);
        lock = INVALID_HANDLE_VALUE;
    }
done:
    free(parent);
    free(path);
    return lock;
}

static HANDLE destination_lock(const wchar_t *dest)
{
    return destination_lock_mode(dest, FALSE);
}

#define LEGACY_UNINSTALL_KEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
#define LEGACY_FAMILY L"{DFE05126-B29E-4298-A06B-63F833BC0BF8}"

typedef struct {
    DWORD parts[4];
} LegacyVersion;

typedef struct {
    wchar_t *cache;
    HANDLE pin;
} LegacyBundle;

typedef struct {
    LegacyBundle *items;
    size_t count;
} LegacyBundles;

static BOOL legacy_version(const wchar_t *text, LegacyVersion *version)
{
    unsigned component = 0;
    const wchar_t *p = text;
    memset(version, 0, sizeof(*version));
    if (!p)
        return FALSE;
    for (;;) {
        DWORD number = 0;
        const wchar_t *start = p;
        if (*p < L'0' || *p > L'9')
            return FALSE;
        do {
            DWORD digit = (DWORD)(*p++ - L'0');
            if (number > (MAXDWORD - digit) / 10)
                return FALSE;
            number = number * 10 + digit;
        } while (*p >= L'0' && *p <= L'9');
        if (p - start > 1 && *start == L'0')
            return FALSE;
        version->parts[component++] = number;
        if (!*p)
            return component == 3 || component == 4;
        if (*p++ != L'.' || component == 4)
            return FALSE;
    }
}

static int legacy_compare(const LegacyVersion *a, const LegacyVersion *b)
{
    unsigned i;
    for (i = 0; i < 4; ++i)
        if (a->parts[i] != b->parts[i])
            return a->parts[i] > b->parts[i] ? 1 : -1;
    return 0;
}

/* Registry identity values are not expanded or interpreted as command lines.
   Malformed/missing identity is not evidence that an application is ours. */
static wchar_t *legacy_value(HKEY key, const wchar_t *name, BOOL multi)
{
    DWORD type = 0, bytes = 0, actual;
    wchar_t *text;
    LSTATUS status = RegQueryValueExW(key, name, NULL, &type, NULL, &bytes);
    if (status != ERROR_SUCCESS || !bytes || bytes > 1024 * 1024 ||
        bytes % sizeof(wchar_t) || (type != REG_SZ && !(multi && type == REG_MULTI_SZ)))
        return NULL;
    text = allocate((size_t)bytes + sizeof(wchar_t));
    if (!text)
        return NULL;
    actual = bytes;
    status = RegQueryValueExW(key, name, NULL, &type, (BYTE *)text, &actual);
    if (status != ERROR_SUCCESS || actual != bytes ||
        (type != REG_SZ && !(multi && type == REG_MULTI_SZ)) ||
        text[bytes / sizeof(wchar_t) - 1] ||
        (type == REG_MULTI_SZ && (bytes < 2 * sizeof(wchar_t) ||
                                  text[bytes / sizeof(wchar_t) - 2])) ||
        (type == REG_SZ && wcslen(text) + 1 != bytes / sizeof(wchar_t))) {
        free(text);
        return NULL;
    }
    text[bytes / sizeof(wchar_t)] = 0;
    return text;
}

static BOOL legacy_identity(HKEY key)
{
    wchar_t *name = legacy_value(key, L"DisplayName", FALSE);
    wchar_t *publisher = NULL, *family = NULL;
    BOOL matches = FALSE;
    const wchar_t *p;
    if (!name || _wcsicmp(name, L"Ghidra Launch"))
        goto done;
    publisher = legacy_value(key, L"Publisher", FALSE);
    if (!publisher || _wcsicmp(publisher, L"rpinz"))
        goto done;
    family = legacy_value(key, L"BundleUpgradeCode", TRUE);
    if (family) {
        for (p = family; *p; p += wcslen(p) + 1) {
            if (!_wcsicmp(p, LEGACY_FAMILY)) {
                matches = TRUE;
                break;
            }
        }
    }
done:
    free(family);
    free(publisher);
    free(name);
    return matches;
}

static void legacy_free(LegacyBundles *bundles)
{
    size_t i;
    for (i = 0; i < bundles->count; ++i) {
        free(bundles->items[i].cache);
        if (bundles->items[i].pin != INVALID_HANDLE_VALUE)
            CloseHandle(bundles->items[i].pin);
    }
    free(bundles->items);
    memset(bundles, 0, sizeof(*bundles));
}

static BOOL legacy_cache_path(const wchar_t *path)
{
    if (!path)
        return FALSE;
    if (((path[0] >= L'A' && path[0] <= L'Z') ||
         (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' && path[2] == L'\\')
        return valid_relative(path + 3);
    if (!wcsncmp(path, L"\\\\", 2) && wcsncmp(path, L"\\\\?\\", 4) &&
        wcsncmp(path, L"\\\\.\\", 4)) {
        const wchar_t *share = wcschr(path + 2, L'\\');
        return share && wcschr(share + 1, L'\\') && valid_relative(path + 2);
    }
    return FALSE;
}

static BOOL legacy_select(HKEY key, const wchar_t *registration,
                          const LegacyVersion *incoming, LegacyBundles *bundles)
{
    wchar_t *version_text = NULL, *cache = NULL, *absolute = NULL, *parent = NULL;
    LegacyVersion version;
    LegacyBundle *grown;
    HANDLE pin = INVALID_HANDLE_VALUE;
    size_t i;
    BOOL ok = FALSE;
    if (!legacy_identity(key))
        return TRUE;
    version_text = legacy_value(key, L"BundleVersion", FALSE);
    if (!legacy_version(version_text, &version)) {
        problem(L"Legacy Ghidra Launch has a missing/invalid BundleVersion; repair its registration",
                registration);
        goto done;
    }
    if (legacy_compare(&version, incoming) > 0) {
        problem(L"A newer legacy Ghidra Launch is installed; use an equal/newer release", registration);
        problem(L"Installed BundleVersion", version_text);
        goto done;
    }
    cache = legacy_value(key, L"BundleCachePath", FALSE);
    if (!legacy_cache_path(cache)) {
        problem(L"Legacy Ghidra Launch has a missing/invalid absolute BundleCachePath; repair it",
                registration);
        goto done;
    }
    absolute = full_path(cache);
    parent = absolute ? parent_path(absolute) : NULL;
    if (!parent || !directories(parent, FALSE))
        goto done;
    pin = open_input(absolute);
    if (pin == INVALID_HANDLE_VALUE) {
        problem(L"Legacy Ghidra Launch cache is unavailable; repair/re-cache its bundle", registration);
        goto done;
    }
    for (i = 0; i < bundles->count; ++i)
        if (!_wcsicmp(bundles->items[i].cache, cache)) {
            ok = TRUE;
            goto done;
        }
    if (bundles->count == SIZE_MAX / sizeof(*grown))
        goto done;
    grown = realloc(bundles->items, (bundles->count + 1) * sizeof(*grown));
    if (!grown) {
        problem(L"Out of memory enumerating legacy Ghidra Launch", registration);
        goto done;
    }
    bundles->items = grown;
    grown[bundles->count].cache = cache;
    grown[bundles->count++].pin = pin;
    cache = NULL;
    pin = INVALID_HANDLE_VALUE;
    ok = TRUE;
done:
    if (pin != INVALID_HANDLE_VALUE)
        CloseHandle(pin);
    free(parent);
    free(absolute);
    free(cache);
    free(version_text);
    return ok;
}

static BOOL legacy_enumerate(const LegacyVersion *incoming, LegacyBundles *bundles)
{
    const HKEY hives[] = {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    const wchar_t *scopes[] = {L"HKCU", L"HKLM"};
    const REGSAM views[] = {KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    unsigned hive, view;
    for (hive = 0; hive < 2; ++hive) {
        for (view = 0; view < 2; ++view) {
            HKEY root;
            DWORD index;
            LSTATUS status = RegOpenKeyExW(hives[hive], LEGACY_UNINSTALL_KEY, 0,
                                          KEY_READ | views[view], &root);
            if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
                continue;
            if (status != ERROR_SUCCESS) {
                SetLastError((DWORD)status);
                return win_error(L"Opening legacy bundle registrations", scopes[hive]);
            }
            for (index = 0;; ++index) {
                wchar_t name[256], label[512];
                DWORD length = sizeof(name) / sizeof(name[0]);
                HKEY key;
                status = RegEnumKeyExW(root, index, name, &length, NULL, NULL, NULL, NULL);
                if (status == ERROR_NO_MORE_ITEMS)
                    break;
                if (status != ERROR_SUCCESS) {
                    RegCloseKey(root);
                    SetLastError((DWORD)status);
                    return win_error(L"Enumerating legacy bundle registrations", scopes[hive]);
                }
                swprintf(label, sizeof(label) / sizeof(label[0]), L"%ls (%u-bit)\\%ls\\%ls",
                         scopes[hive], view ? 64 : 32, LEGACY_UNINSTALL_KEY, name);
                status = RegOpenKeyExW(root, name, 0, KEY_QUERY_VALUE | views[view], &key);
                if (status == ERROR_FILE_NOT_FOUND)
                    continue;
                if (status != ERROR_SUCCESS) {
                    RegCloseKey(root);
                    SetLastError((DWORD)status);
                    return win_error(L"Opening legacy bundle registration", label);
                }
                if (!legacy_select(key, label, incoming, bundles)) {
                    RegCloseKey(key);
                    RegCloseKey(root);
                    return FALSE;
                }
                RegCloseKey(key);
            }
            RegCloseKey(root);
        }
    }
    return TRUE;
}

static wchar_t *legacy_quote(const wchar_t *argument)
{
    size_t n = wcslen(argument), i = 0, written = 0;
    wchar_t *result;
    if (n > (SIZE_MAX / sizeof(wchar_t) - 3) / 2)
        return NULL;
    result = allocate((2 * n + 3) * sizeof(wchar_t));
    if (!result)
        return NULL;
    result[written++] = L'"';
    while (i < n) {
        size_t slashes = 0;
        while (argument[i] == L'\\') {
            ++slashes;
            ++i;
        }
        if (!argument[i] || argument[i] == L'"')
            slashes *= 2;
        while (slashes--)
            result[written++] = L'\\';
        if (argument[i] == L'"')
            result[written++] = L'\\';
        if (argument[i])
            result[written++] = argument[i++];
    }
    result[written++] = L'"';
    result[written] = 0;
    return result;
}

static wchar_t *legacy_log(void)
{
    wchar_t temp[32768], name[50], *root = NULL, *path = NULL;
    HANDLE file;
    unsigned attempt;
#ifdef HELPER_TEST_LEGACY_LOG_ROOT
    const wchar_t *test_root = HELPER_TEST_LEGACY_LOG_ROOT();
    if (!test_root || !*test_root)
        return NULL;
    root = copy_n(test_root, wcslen(test_root));
#else
    DWORD length = GetTempPathW(sizeof(temp) / sizeof(temp[0]), temp);
    if (!length || length >= sizeof(temp) / sizeof(temp[0])) {
        win_error(L"Finding legacy uninstaller log directory", L"");
        return NULL;
    }
    root = full_path(temp);
#endif
    (void)temp;
    if (!root || !directories(root, FALSE))
        goto done;
    for (attempt = 0; attempt < 32; ++attempt) {
        if (!random_name(name, L".legacy-log-"))
            break;
        wcscat(name, L".log");
        path = join(root, name);
        if (!path)
            break;
        file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (file != INVALID_HANDLE_VALUE) {
            CloseHandle(file);
            break;
        }
        if (GetLastError() != ERROR_FILE_EXISTS) {
            win_error(L"Reserving legacy uninstaller log", path);
            free(path);
            path = NULL;
            break;
        }
        free(path);
        path = NULL;
    }
done:
    free(root);
    return path;
}

static BOOL legacy_execute(const wchar_t *cache, wchar_t *command, HANDLE *pin, DWORD *exit_code)
{
#ifdef HELPER_TEST_LEGACY_PROCESS
    CloseHandle(*pin);
    *pin = INVALID_HANDLE_VALUE;
    return HELPER_TEST_LEGACY_PROCESS(cache, command, exit_code);
#else
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    BOOL ok;
    startup.cb = sizeof(startup);
    if (!CreateProcessW(cache, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process))
        return win_error(L"Launching cached legacy Ghidra Launch uninstaller", cache);
    /* Keep the preflighted image pinned until CreateProcess opens it, but let
       Burn remove its own cached executable while uninstalling. */
    CloseHandle(*pin);
    *pin = INVALID_HANDLE_VALUE;
    CloseHandle(process.hThread);
    ok = WaitForSingleObject(process.hProcess, INFINITE) == WAIT_OBJECT_0 &&
         GetExitCodeProcess(process.hProcess, exit_code);
    if (!ok)
        win_error(L"Waiting for legacy Ghidra Launch uninstaller", cache);
    CloseHandle(process.hProcess);
    return ok;
#endif
}

static BOOL legacy_uninstall(LegacyBundle *bundle, const char *owner, DWORD *exit_code)
{
    /* Keep package dependency checks enabled: the incoming Core may own the
       same MSI. Related-upgrade mode bypasses only bundle-level blocking. */
    const wchar_t arguments[] = L" /uninstall /quiet /norestart -burn.related.upgrade -parent ";
    const wchar_t *cache = bundle->cache;
    wchar_t parent[129];
    wchar_t *log = legacy_log(), *quoted_cache = NULL, *quoted_log = NULL, *command = NULL;
    wchar_t *quoted_parent = NULL;
    size_t count;
    BOOL ok = FALSE;
    if (!log)
        goto done;
    quoted_cache = legacy_quote(cache);
    quoted_log = legacy_quote(log);
    widen_owner(owner, parent);
    quoted_parent = legacy_quote(parent);
    if (!quoted_cache || !quoted_log || !quoted_parent)
        goto done;
    count = wcslen(quoted_cache) + wcslen(arguments) + wcslen(quoted_parent) +
            wcslen(L" /log ") + wcslen(quoted_log) + 1;
    command = allocate(count * sizeof(wchar_t));
    if (!command)
        goto done;
    swprintf(command, count, L"%ls%ls%ls /log %ls", quoted_cache, arguments, quoted_parent, quoted_log);
    wprintf(L"Removing legacy Ghidra Launch: %ls (log: %ls)\n", cache, log);
    if (!legacy_execute(cache, command, &bundle->pin, exit_code))
        goto done;
    ok = *exit_code == 0 || *exit_code == 3010;
    if (!ok)
        fwprintf(stderr, L"Legacy Ghidra Launch uninstall failed (exit %lu): %ls; log: %ls\n",
                 (unsigned long)*exit_code, cache, log);
done:
    free(command);
    free(quoted_parent);
    free(quoted_log);
    free(quoted_cache);
    free(log);
    return ok;
}

static int migrate_legacy(const wchar_t *dest, const char *owner, const LegacyVersion *incoming)
{
    LegacyBundles bundles = {0};
    Marker marker;
    HANDLE lock = INVALID_HANDLE_VALUE;
    wchar_t *parent = NULL, *backup = NULL;
    BOOL moved = FALSE, ok = FALSE, reboot = FALSE;
    size_t i;
    DWORD attr;
#ifdef HELPER_TEST_LEGACY_ALLOWED
    if (!HELPER_TEST_LEGACY_ALLOWED(dest)) {
        problem(L"Test migration requires an isolated selftest fixture", dest);
        return 1;
    }
#endif
    if (!manages_owner_record(dest)) {
        problem(L"Legacy migration is restricted to LOCALAPPDATA\\Ghidra Launch\\Ghidra", dest);
        goto done;
    }
    if (!legacy_enumerate(incoming, &bundles))
        goto done;
    if (!bundles.count) {
        ok = TRUE;
        goto done;
    }
    lock = destination_lock(dest);
    if (lock == INVALID_HANDLE_VALUE)
        goto done;
    if (read_marker(dest, &marker) != 1 || strcmp(marker.owner, owner)) {
        problem(L"Legacy migration requires the current payload marker to match the incoming owner", dest);
        goto done;
    }
    parent = parent_path(dest);
    backup = parent ? new_directory(parent, L".legacy-") : NULL;
    if (!backup)
        goto done;
    if (!RemoveDirectoryW(backup)) {
        win_error(L"Preparing legacy payload preservation name (original left intact)", backup);
        goto done;
    }
    if (!MoveFileExW(dest, backup, MOVEFILE_WRITE_THROUGH)) {
        win_error(L"Preserving current payload for legacy migration (original left intact)", dest);
        goto done;
    }
    moved = TRUE;
    CloseHandle(lock);
    lock = INVALID_HANDLE_VALUE;
    ok = TRUE;
    for (i = 0; i < bundles.count; ++i) {
        DWORD exit_code = 0;
        attr = GetFileAttributesW(dest);
        if (attr != INVALID_FILE_ATTRIBUTES || !absent(GetLastError())) {
            problem(L"Legacy migration stopped: an unexpected destination appeared", dest);
            ok = FALSE;
            break;
        }
        if (!legacy_uninstall(&bundles.items[i], owner, &exit_code)) {
            ok = FALSE;
            break;
        }
        reboot = reboot || exit_code == 3010;
    }
done:
    if (moved) {
        /* Old helpers must be able to lock the absent destination. Conversely,
           restoration must not run unlocked, even if a child failed. */
        lock = destination_lock_mode(dest, TRUE);
        if (lock == INVALID_HANDLE_VALUE) {
            ok = FALSE;
        } else {
            attr = GetFileAttributesW(dest);
            if (attr != INVALID_FILE_ATTRIBUTES || !absent(GetLastError())) {
                problem(L"Refusing to overwrite an unexpected destination during legacy restoration", dest);
                ok = FALSE;
            } else if (!safe_destination(backup) ||
                       !MoveFileExW(backup, dest, MOVEFILE_WRITE_THROUGH)) {
                win_error(L"Restoring current payload after legacy migration", dest);
                ok = FALSE;
            } else {
                moved = FALSE;
                if (!set_owner_record(dest, owner))
                    ok = FALSE;
            }
        }
        if (moved)
            problem(L"LEGACY RESTORATION FAILED; complete current payload remains intact at", backup);
    }
    if (lock != INVALID_HANDLE_VALUE)
        CloseHandle(lock);
    legacy_free(&bundles);
    free(backup);
    free(parent);
    return ok ? (reboot ? 3010 : 0) : 1;
}

int wmain(int argc, wchar_t **argv)
{
    BOOL extracting, removing, ok;
    char owner[129];
    const char *owner_arg = NULL;
    wchar_t *dest, *zip = NULL;
    HANDLE lock;
    if (argc >= 2 && !_wcsicmp(argv[1], L"migrate-legacy")) {
        LegacyVersion incoming;
        int result;
        if (argc != 5)
            goto usage;
        if (!parse_owner(argv[3], owner) || !legacy_version(argv[4], &incoming)) {
            problem(L"Migration requires a valid owner and normalized numeric version (3 or 4 components)",
                    argv[3]);
            return 2;
        }
        dest = full_path(argv[2]);
        if (!dest)
            return 1;
        result = migrate_legacy(dest, owner, &incoming);
        free(dest);
        return result;
    }
    extracting = argc >= 2 && !_wcsicmp(argv[1], L"extract");
    removing = argc >= 2 && !_wcsicmp(argv[1], L"remove");
    if ((!extracting && !removing) || (extracting && argc != 4 && argc != 5) ||
        (removing && (argc < 3 || argc > 5)))
        goto usage;
    if (argc == 5) {
        if (!parse_owner(argv[4], owner)) {
            problem(L"Invalid owner: use 1-128 ASCII letters, digits, '.', '_', '-', '{' or '}'", argv[4]);
            return 2;
        }
        owner_arg = owner;
    }
    dest = full_path(argv[extracting ? 3 : 2]);
    if (!dest)
        return 1;
    if (extracting || (argc >= 4 && *argv[3])) {
        zip = full_path(argv[extracting ? 2 : 3]);
        if (!zip) {
            free(dest);
            return 1;
        }
    }
    lock = destination_lock(dest);
    ok = lock != INVALID_HANDLE_VALUE &&
        (extracting ? extract(zip, dest, owner_arg) : remove_destination(dest, zip, owner_arg));
    if (lock != INVALID_HANDLE_VALUE)
        CloseHandle(lock);
    free(zip);
    free(dest);
    return ok ? 0 : 1;
usage:
    fwprintf(stderr, L"Usage: GhidraLaunchGhidraHelperC extract <zip> <dest> [owner]\n"
                     L"       GhidraLaunchGhidraHelperC remove <dest> [zip] [owner]\n"
                     L"       GhidraLaunchGhidraHelperC migrate-legacy <dest> <owner> <releaseVersion>\n"
                     L"Use an empty zip argument to remove by owner alone.\n");
    return 2;
}
