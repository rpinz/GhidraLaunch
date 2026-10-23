#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include "vendor/miniz/miniz.h"

#define MARKER L".ghidralaunch-source.sha256"

typedef struct {
    char hash[65];
    char owner[129];
} Marker;

typedef struct {
    wchar_t *name;
    BOOL directory;
    BOOL explicit_entry;
} PathEntry;

typedef struct {
    PathEntry *items;
    size_t count, capacity;
} Paths;

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

static wchar_t *entry_name(mz_zip_archive *zip, mz_uint index, BOOL *directory)
{
    mz_zip_archive_file_stat stat;
    mz_uint bytes = mz_zip_reader_get_filename(zip, index, NULL, 0);
    char *raw = NULL;
    wchar_t *name = NULL;
    int count;
    size_t i, start, n;
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
    if (!n || name[0] == L'\\')
        goto invalid;
    start = 0;
    for (i = 0; i <= n; ++i) {
        wchar_t c = name[i];
        if (i == n || c == L'\\') {
            size_t length = i - start;
            if (!length || name[i - 1] == L'.' || name[i - 1] == L' ' ||
                reserved_component(name + start, length))
                goto invalid;
            start = i + 1;
        } else if (c < 32 || c == 127 || wcschr(L":<>\"|?*", c)) {
            goto invalid;
        }
    }
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
        if (!name)
            goto done;
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

static BOOL extract(const wchar_t *zip_path, const wchar_t *dest, const char *owner)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    mz_zip_archive zip = {0};
    LARGE_INTEGER length;
    Marker marker;
    char hash[65];
    wchar_t *parent = NULL, *stage = NULL, *root = NULL, *backup = NULL;
    BOOL ok = FALSE, initialized = FALSE, backed_up = FALSE, installed = FALSE;
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
    if (state == 1 && !strcmp(marker.hash, hash)) {
        if (owner && strcmp(owner, marker.owner) && !write_marker(dest, hash, owner))
            goto done;
        wprintf(L"Ghidra already extracted at %ls (unchanged); skipping.\n", dest);
        ok = TRUE;
        goto done;
    }
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
    if (!root || !write_marker(root, hash, owner))
        goto done;
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
    ok = TRUE;
done:
    if (initialized)
        mz_zip_reader_end(&zip);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (backed_up && !installed) {
        if (!MoveFileExW(backup, dest, MOVEFILE_WRITE_THROUGH)) {
            win_error(L"ROLLBACK FAILED; original remains at backup", backup);
            ok = FALSE;
        } else {
            backed_up = FALSE;
        }
    }
    if (backed_up && installed && !remove_tree(backup)) {
        problem(L"Installed successfully, but backup cleanup failed", backup);
        ok = FALSE;
    }
    if (backup && !backed_up && !remove_tree(backup)) {
        problem(L"Unused backup directory cleanup failed", backup);
        ok = FALSE;
    }
    if (stage && !remove_tree(stage)) {
        problem(L"Staging cleanup failed", stage);
        ok = FALSE;
    }
    if (ok && installed)
        wprintf(L"Extracted Ghidra to %ls.\n", dest);
    free(backup);
    free(root);
    free(stage);
    free(parent);
    return ok;
}

static BOOL remove_destination(const wchar_t *dest, const wchar_t *zip_path, const char *owner)
{
    Marker marker;
    int state;
    DWORD attr;
    if (!safe_destination(dest))
        return FALSE;
    attr = GetFileAttributesW(dest);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        if (absent(GetLastError()))
            return TRUE;
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
    if (!remove_tree(dest))
        return FALSE;
    wprintf(L"Removed %ls.\n", dest);
    return TRUE;
}

int wmain(int argc, wchar_t **argv)
{
    BOOL extracting, removing, ok;
    char owner[129];
    const char *owner_arg = NULL;
    wchar_t *dest, *zip = NULL;
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
    ok = extracting ? extract(zip, dest, owner_arg) : remove_destination(dest, zip, owner_arg);
    free(zip);
    free(dest);
    return ok ? 0 : 1;
usage:
    fwprintf(stderr, L"Usage: GhidraLaunchGhidraHelperC extract <zip> <dest> [owner]\n"
                     L"       GhidraLaunchGhidraHelperC remove <dest> [zip] [owner]\n"
                     L"Use an empty zip argument to remove by owner alone.\n");
    return 2;
}
