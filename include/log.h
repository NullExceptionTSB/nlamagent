#pragma once
#include <Windows.h>

typedef enum _NLAM_LOG_MODE {
    //! if set, enables file logging
    LOG_FILE        = 0x00000001, 
    //! stub
    LOG_EVENTVWR    = 0x00000002, 
    //! if set, logs into STDIO
    LOG_STDIO       = 0x00000004,
    //! if set, enables verbose logging
    LOG_VERBOSE     = 0x00000008,
    //! if set, enables debug logging
    LOG_DEBUG       = 0x00000010
}LOG_MODE;

/**
 * @brief sets the path to a log output file
 * only has an impact if called <b>before</b> LogInit
 * 
 * @param lpFile file path in wstring
 * @return VOID 
 */
VOID WINAPI LogSetOutFile(LPCSTR lpFile);
//! initializes the logger
VOID WINAPI LogInit(LOG_MODE mode);


//! logs a format-stringed message
VOID WINAPI LogMessageA(LPCSTR lpMessage, ...);
//! logs a format-stringed widechar message
VOID WINAPI LogMessageW(LPCWSTR lpMessage, ...);

//! logs a format-stringed message with verbose priority
VOID WINAPI LogVerboseA(LPCSTR lpMessage, ...);
//! logs a format-stringed widechar message with verbose priority
VOID WINAPI LogVerboseW(LPCWSTR lpMessage, ...);

//! logs a format-stringed debug message
VOID WINAPI LogDebugA(LPCSTR lpMessage, ...);
//! logs a format-stringed widechar debug message
VOID WINAPI LogDebugW(LPCWSTR lpMessage, ...);

//! uninitializes logger, needed for reinitialization
VOID WINAPI LogClose();