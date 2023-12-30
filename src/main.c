#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

//windows moment
//#include <sys/socket.h>
#include <winsock2.h>

//#include <arpa/inet.h>

#include <net.h>
#include <log.h>
#include <config.h>
#include <ssl.h>
#include <opts.h>

//makes exe a standalone executable instead of a service executable
#define SKIPSERVICE

SERVICE_STATUS ServStatus = { 0 };
SERVICE_STATUS_HANDLE hServStatus = NULL;
BOOLEAN bStop = FALSE;
HANDLE hStopEvent = NULL, hStopReadyEvent = NULL;

/**
 * @brief WinAPI service control message handler
 * 
 * @param dwReason Contains the control message
 * @return VOID 
 */

VOID WINAPI SrvControlHandler(DWORD dwReason) {
	switch (dwReason) {
        case SERVICE_CONTROL_STOP:
            LogMessageA("Server stopping...");
            SetEvent(hStopEvent);
            bStop = TRUE;
            ServStatus.dwCurrentState = SERVICE_STOPPED;


            SetServiceStatus(hServStatus, &ServStatus);	
            WaitForSingleObject(hStopReadyEvent, -1);
            //ExitProcess(0);
            break;
        case SERVICE_CONTROL_CONTINUE:
            ServStatus.dwCurrentState = SERVICE_RUNNING;
            SetServiceStatus(hServStatus, &ServStatus);
            break;
	}	
}

VOID WINAPI SrvError(LPCWSTR lpError, DWORD dwCode) {
    LogMessageW(lpError);
    SetEvent(hStopEvent);
    WaitForSingleObject(hStopReadyEvent, STOP_TIMEOUT);
    ExitProcess(dwCode);
}

/**
 * @brief Windows service entry point, contains init code
 * 
 * @return VOID 
 */
VOID WINAPI SrvMain() {
    #ifndef SKIPSERVICE
    //fixes an issue with NTAUTH setting cdir to System32 on all processes
    //by default
    WCHAR fn[MAX_PATH];
    WCHAR fn2[MAX_PATH];
    LPWSTR* slash;
    GetModuleFileNameW(NULL, fn, sizeof(WCHAR)*MAX_PATH);
    GetFullPathNameW(fn, sizeof(WCHAR)*MAX_PATH, fn2, &slash);
    *slash = L'\0';
    SetCurrentDirectoryW(fn2);

    //service initialization stuff
	hServStatus = RegisterServiceCtrlHandlerW(SRV_NAME,
         SrvControlHandler);
	ServStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ServStatus.dwControlsAccepted = 
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServStatus.dwCurrentState = SERVICE_START_PENDING;
	ServStatus.dwServiceSpecificExitCode = 0;
	ServStatus.dwCheckPoint = 0;
	ServStatus.dwWaitHint = 0;
	ServStatus.dwWin32ExitCode = 0;
	SetServiceStatus(hServStatus, &ServStatus);
    #endif

    //init stop signalization
	hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    hStopReadyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (!hStopEvent || !hStopReadyEvent)
        ExitProcess(-1);
	
    //open config 
    INT32 cfg_code = CfgInit();
    if (cfg_code < 0)
        ExitProcess(cfg_code);
    
    //init logger
    int file_log_flag = 1;
    char* log_file = CFG_LOG_DEFAULT;

    LOG_MODE logmode = 0;

    config_setting_t* log_setting =
        config_setting_lookup(_CONFIG->root, "FileLogging");
    if (log_setting)
        file_log_flag = config_setting_get_bool(log_setting);
    
    log_setting = config_setting_lookup(_CONFIG->root, "LogFilename");
    if (log_setting)
        log_file = config_setting_get_string(log_setting);

    logmode |= (log_setting && file_log_flag) ? LOG_FILE : 0;

    log_setting = config_setting_lookup(_CONFIG->root, "StdioLogging");
    if (log_setting)
        logmode |= config_setting_get_bool(log_setting) ? LOG_STDIO : 0;

    LogSetOutFile(log_file);
    LogInit(logmode);

    //init libssl and libcrypto
    INT32 ssl_code = SslInit();
    if (ssl_code < 0)
        ExitProcess(ssl_code);
    ssl_code = CrpInit();
    if (ssl_code < 0)
        ExitProcess(ssl_code);

    int use_cert = CONFIG_FALSE;
    
    int confstat = config_lookup_bool(_CONFIG, "UseCert", &use_cert);
    use_cert &= confstat;

    if (use_cert == CONFIG_TRUE) {
        //this library straight up doesn't work correctly :-], isn't that nice
        char* cert_path = CFG_CERT_DEFAULT, *key_path = CFG_KEY_DEFAULT;

        config_setting_t* cert_setting = 
            config_setting_lookup(_CONFIG->root, "CertFile");
        
        if (cert_setting)
            cert_path = config_setting_get_string(cert_setting);

        cert_setting = config_setting_lookup(_CONFIG->root, "CertKeyFile");
        if (cert_setting)
            key_path = config_setting_get_string(cert_setting);

        if ((!cert_path) || (!key_path)) 
            LogMessageA("Invalid certificate paths");
        
        //printf("cert_path %s, key_path %p\n", cert_path, key_path);
        SslInitPem(cert_path, key_path);
    } else {
        LogMessageA("Certificates disabled.\
There is no fallback, connections will fail!");
    }

    //start ipv4 socket listener
    DWORD dwIpv4Tid = 0;
    CreateThread(NULL, 0, NetIpv4Listener, 16969, 0, &dwIpv4Tid);
    if (dwIpv4Tid)
        LogMessageA(
            "Failed to open IPv4 listener! Lasterror: 0x%08x\n", 
            GetLastError()
        );

    //start ipv6 socket listener

    //
    //there is on ipv6 support yet!
    //

    #ifndef SKIPSERVICE
    //init finished, singal that srv is running
    ServStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hServStatus, &ServStatus);

    HANDLE hListeners[2] = { 
            OpenThread(SYNCHRONIZE | THREAD_TERMINATE, FALSE, dwIpv4Tid),
            NULL //OpenThread(SYNCHRONIZE | THREAD_TERMINATE, FALSE, dwIpv6Tid)
        };
    #endif 

    //test for exit signal
    #ifdef SKIPSERVICE
        Sleep(-1);
    #else
        while (WaitForSingleObject(hStopEvent, -1) == WAIT_TIMEOUT);

        DWORD dwWaitStatus = 
            WaitForMultipleObjects(2, hListeners, TRUE, STOP_TIMEOUT);

        if (dwWaitStatus == WAIT_TIMEOUT) {
            LogMessageA("Listeners hung, force quitting...\n");
            TerminateThread(hListeners[0], WAIT_TIMEOUT);
            TerminateThread(hListeners[0], WAIT_TIMEOUT);
        }
    #endif
    
    LogClose();
    CloseHandle(hStopEvent);

    LogMessageA("Exitting gracefully...\n");
    SetEvent(hStopReadyEvent);
    CloseHandle(hStopReadyEvent);
}
/**
 * @brief WinMain entry point for windows, tranfers control to SrvMain
 * 
 * @param hInstance 
 * @param hPrevInstance 
 * @param lpString 
 * @param bShowCmd 
 * @return INT 
 */
INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     LPSTR lpString, INT bShowCmd) {
    DWORD a;

    #ifndef SKIPSERVICE
    SERVICE_TABLE_ENTRYW stEntry[] = { 
        {SRV_NAME, SrvMain},
        {NULL, NULL} 
    };
    StartServiceCtrlDispatcherW(stEntry);
    #endif
    SrvMain();
}