#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

//windows moment
//#include <sys/socket.h>
#include <winsock2.h>

//#include <arpa/inet.h>

#include <config.h>
#include <ssl.h>
#include <crypto.h>
#include <opts.h>

SERVICE_STATUS ServStatus = { 0 };
SERVICE_STATUS_HANDLE hServStatus = NULL;
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
            SetEvent(hStopEvent);
            ServStatus.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(hServStatus, &ServStatus);	
            WaitForSingleObject(hStopReadyEvent, STOP_TIMEOUT);
            ExitProcess(0);
            break;
        case SERVICE_CONTROL_CONTINUE:
            ServStatus.dwCurrentState = SERVICE_RUNNING;
            SetServiceStatus(hServStatus, &ServStatus);
            break;
	}	
}

VOID WINAPI SrvError(LPCWSTR lpError, DWORD dwCode) {

}

VOID WINAPI SrvCallbackHandler(SSL* s, void* arg) {
    char* buffer = calloc(PKT_MAX, 1);
    char* reply = "!What";
    int datarecv = 0;
    size_t read = SSL_read(s, buffer, PKT_MAX);
    //receive data
    datarecv = read > 0;
    if (read < 128) goto end;
    



    end:
    if (datarecv) 
        SSL_write(s, reply, strlen(reply));
    free(buffer);
}

VOID WINAPI SrvIpv4Listener(DWORD port) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.S_un.S_addr = htonl(0); 

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) 
        ExitThread(sock);

    int status = 
        bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));

    if (status < 0)
        ExitThread(status);

    status = listen(status, 1);

    for (;;) {
        struct sockaddr_in cl_addr;
        size_t addrsz = sizeof(cl_addr);
        SSL* ssl;

        int client = accept(sock, (struct sockaddr*)&cl_addr, &addrsz);

        ssl = SSL_new(_SSLCONTEXT);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            // accept failed, handle
            puts(":-[");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
        }

        if (!SslVerifyVersion(SSL_get_version(ssl))) {
            // SSL version unacceptable, return error
            SSL_write(ssl, "!Insecure", 10);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
        }

        // SSL accepted, set callback and return waiting signal
        SSL_set_async_callback(ssl, SrvCallbackHandler);
        SSL_write(ssl, "?", 1);
        
        
    }
}

/**
 * @brief Windows service entry point, contains init code
 * 
 * @return VOID 
 */
VOID WINAPI SrvMain() {
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

    //init stop signalization
	hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    hStopReadyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (!hStopEvent || !hStopReadyEvent)
        ExitProcess(-1);
	
    //open config 
    INT32 cfg_code = CfgInit();
    if (cfg_code < 0)
        ExitProcess(cfg_code);
    
    //init libssl and libcrypto
    INT32 ssl_code = SslInit();
    if (ssl_code < 0)
        ExitProcess(ssl_code);
    ssl_code = CrpInit();
    if (ssl_code < 0)
        ExitProcess(ssl_code);

    int use_key = CONFIG_FALSE;
    config_lookup_bool(_CONFIG, "UseKey", &use_key);
    if (use_key = CONFIG_TRUE) {
        char* cert_path = NULL, key_path = NULL;
        config_lookup_string(_CONFIG, "CertFile", &cert_path);
        config_lookup_string(_CONFIG, "CertKeyFile", &key_path);

        if (!cert_path || !key_path) 
            ExitProcess(-9);
        SslInitPem(cert_path, key_path);
    }

    //start ipv4 socket listener
    CreateThread(NULL, 0, SrvIpv4Listener, 16969, 0, NULL);

    //open ipv6 socket

    //init finished, singal that srv is running
    ServStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hServStatus, &ServStatus);

    //test for exit signal
    while (WaitForSingleObject(hStopEvent, -1) == WAIT_TIMEOUT);

    //kill all children and exit
    CloseHandle(hStopEvent);
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

    SERVICE_TABLE_ENTRYW stEntry[] = { 
        {SRV_NAME, SrvMain},
        {NULL, NULL} 
    };
    StartServiceCtrlDispatcherW(stEntry);
    SrvMain();
    
}