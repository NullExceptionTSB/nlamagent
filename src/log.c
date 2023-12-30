#include <Windows.h>

#include <log.h>

#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>

BOOL        _bInited = FALSE;

LPCSTR      _lpszOutFile = NULL;
LOG_MODE    _modeLog;

FILE*       _fileLog;
VOID WINAPI LogSetOutFile(LPCSTR lpFile) {
    _lpszOutFile = lpFile;
}

VOID WINAPI LogInit(LOG_MODE mode) {
    if (_bInited) return;

    if (_lpszOutFile && (mode & LOG_FILE)) 
        _fileLog = fopen(_lpszOutFile, "a");
    
    _bInited = TRUE;
    _modeLog = mode;
}

VOID WINAPI iLogMessageA(LPCSTR lpMessage, va_list args) {
    if (!_bInited) return;

    if (_lpszOutFile && (_modeLog & LOG_FILE))
        vfprintf(_fileLog, lpMessage, args);

    if (_modeLog & LOG_STDIO)
        vprintf(lpMessage, args);
}

VOID WINAPI iLogMessageW(LPCWSTR lpMessage, va_list args) {
    if (!_bInited) return;

    if (_lpszOutFile && (_modeLog & LOG_FILE))
        vfwprintf(_fileLog, lpMessage, args);

    if (_modeLog & LOG_STDIO)
        vwprintf(lpMessage, args);
}

VOID WINAPI LogMessageA(LPCSTR lpMessage, ...) {
    va_list ptr;
    va_start(ptr, lpMessage);

    iLogMessageA(lpMessage, ptr);

    va_end(ptr);
}

VOID WINAPI LogMessageW(LPCWSTR lpMessage, ...) {
    va_list ptr;
    va_start(ptr, lpMessage);

    iLogMessageW(lpMessage, ptr);

    va_end(ptr);
}

VOID WINAPI LogVerboseA(LPCSTR lpMessage, ...) {
    if (!(_modeLog & LOG_VERBOSE))
        return;

    va_list ptr;
    va_start(ptr, lpMessage);

    iLogMessageA(lpMessage, ptr);

    va_end(ptr);
}

VOID WINAPI LogVerboseW(LPCWSTR lpMessage, ...) {
    if (!(_modeLog & LOG_VERBOSE))
        return;

    va_list ptr;
    va_start(ptr, lpMessage);

    iLogMessageW(lpMessage, ptr);

    va_end(ptr);
}

VOID WINAPI LogDebugA(LPCSTR lpMessage, ...) {
    if (!(_modeLog & LOG_DEBUG))
        return;

    va_list ptr;
    va_start(ptr, lpMessage);

    iLogMessageA(lpMessage, ptr);

    va_end(ptr);
}

VOID WINAPI LogDebugW(LPCWSTR lpMessage, ...) {
    if (!(_modeLog & LOG_VERBOSE))
        return;

    va_list ptr;
    va_start(ptr, lpMessage);

    iLogMessageW(lpMessage, ptr);

    va_end(ptr);
}

VOID WINAPI LogClose() {
    if (_fileLog);
        fclose(_fileLog);

    _bInited = FALSE;
    _modeLog = 0;
}