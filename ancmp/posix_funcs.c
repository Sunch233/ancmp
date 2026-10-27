#include "posix_funcs.h"

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

typedef LONG (NTAPI *query_object_fn)(HANDLE, ULONG, void *, ULONG, ULONG *);

typedef struct {
    ULONG attributes;
    ACCESS_MASK granted_access;
    ULONG handle_count;
    ULONG pointer_count;
    ULONG reserved[10];
} object_access_info;

#if defined(_MSC_VER) && _MSC_VER >= 1900
static void ignore_invalid_parameter(const wchar_t *expression, const wchar_t *function,
        const wchar_t *file, unsigned int line, uintptr_t reserved) {
    (void)expression;
    (void)function;
    (void)file;
    (void)line;
    (void)reserved;
}
#endif

static int file_error(DWORD error) {
    switch (error) {
    case ERROR_INVALID_HANDLE: return EBADF;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION: return EACCES;
    case ERROR_INVALID_PARAMETER: return EINVAL;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
    case ERROR_NOT_ENOUGH_QUOTA: return ENOMEM;
    case ERROR_NOACCESS:
    case ERROR_INVALID_USER_BUFFER: return EFAULT;
    case ERROR_OPERATION_ABORTED: return EINTR;
    default: return EIO;
    }
}

long pread(int fd, void *buf, size_t count, off_t offset) {
    intptr_t native;
    HANDLE original;
    HANDLE file;
    HMODULE ntdll;
    FARPROC procedure;
    query_object_fn query_object;
    object_access_info access_info;
    OVERLAPPED operation;
    DWORD received;
    DWORD error;
    BOOL success;
#if defined(_MSC_VER) && _MSC_VER >= 1900
    _invalid_parameter_handler previous;
#endif

    if (fd < 0) { errno = EBADF; return -1; }
    if (offset < 0 || count > LONG_MAX) { errno = EINVAL; return -1; }
    if (!buf && count) { errno = EFAULT; return -1; }
#if defined(_MSC_VER) && _MSC_VER >= 1900
    previous = _set_thread_local_invalid_parameter_handler(ignore_invalid_parameter);
#endif
    native = _get_osfhandle(fd);
#if defined(_MSC_VER) && _MSC_VER >= 1900
    _set_thread_local_invalid_parameter_handler(previous);
#endif
    if (native == -1 || native == -2) { errno = EBADF; return -1; }
    original = (HANDLE)native;
    if (GetFileType(original) != FILE_TYPE_DISK) { errno = ESPIPE; return -1; }
    ntdll = GetModuleHandleA("ntdll.dll");
    procedure = ntdll ? GetProcAddress(ntdll, "NtQueryObject") : NULL;
    if (!procedure) { errno = ENOSYS; return -1; }
    memcpy(&query_object, &procedure, sizeof(query_object));
    if (query_object(original, 0, &access_info, sizeof(access_info), NULL) < 0) {
        errno = EIO;
        return -1;
    }
    if (!(access_info.granted_access & FILE_READ_DATA)) { errno = EBADF; return -1; }
    if (!count) return 0;
    file = ReOpenFile(original, FILE_READ_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_FLAG_OVERLAPPED | FILE_FLAG_RANDOM_ACCESS);
    if (file == INVALID_HANDLE_VALUE) { errno = file_error(GetLastError()); return -1; }
    memset(&operation, 0, sizeof(operation));
    operation.Offset = (DWORD)((uint64_t)offset & 0xffffffffu);
    operation.OffsetHigh = (DWORD)((uint64_t)offset >> 32);
    received = 0;
    success = ReadFile(file, buf, (DWORD)count, &received, &operation);
    error = success ? ERROR_SUCCESS : GetLastError();
    if (!success && error == ERROR_IO_PENDING) {
        success = GetOverlappedResult(file, &operation, &received, TRUE);
        error = success ? ERROR_SUCCESS : GetLastError();
    }
    CloseHandle(file);
    if (error == ERROR_HANDLE_EOF) return 0;
    if (!success) { errno = file_error(error); return -1; }
    return (long)received;
}
#endif
