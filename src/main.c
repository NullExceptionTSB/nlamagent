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
#include <packet.h>
#include <perform.h>

//makes exe a standalone executable instead of a service executable
#define SKIPSERVICE

SERVICE_STATUS ServStatus = { 0 };
SERVICE_STATUS_HANDLE hServStatus = NULL;
HANDLE hStopEvent = NULL, hStopReadyEvent = NULL;

typedef struct _NET_CLIENT {
    int socket;
    SSL* ssl;
}NET_CLIENT, *LPNET_CLIENT;

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
// do not use
VOID WINAPI SrvCallbackHandler(SSL* s, void* arg) {
    char* buffer = calloc(PKT_MAX, 1);
    char* reply = "!What";
    int datarecv = 0;
    size_t read = SSL_read(s, buffer, PKT_MAX);
    //receive data
    datarecv = read > 0;
    if (read < 128) goto end;
    printf("[V4CH] %s\n", buffer);

    end:
    if (datarecv) 
        SSL_write(s, reply, strlen(reply));
    free(buffer);
}

VOID WINAPI SrvIpv4Server(LPNET_CLIENT lpClient) {
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_SPEED_OVER_MEMORY);
    
    SSL* ssl = lpClient->ssl;
    char* buffer = calloc(PKT_MAX, 1);
    char* reply = "!What\n";

    int terminated = 0;
    while (!terminated) {
        reply = "!What\n";
        size_t read = SSL_read(ssl, buffer, PKT_MAX);

        if (read == -1) { 
            int ssl_error = SSL_get_error(ssl, read);
            if (ssl_error == SSL_ERROR_SYSCALL) {
                switch (WSAGetLastError()) {
                    case WSAETIMEDOUT:
                        puts("[V4SV] timed out");
                        reply = "!TimedOut\n";
                        terminated = 1;
                        break;
                }
            } else {
                reply = "!NetErr\n";
                goto end;
            }
        }
        if (terminated) break;
        //receive data
        if (read == 0) 
            break;

        printf("[V4SV]: %s", buffer);
        if (buffer[0] == '{') {
            NLPACKET* pkt = PktParse(buffer, read);
            if (!pkt) {
                reply = "!PktInvalid\n";
                printf("[V4SV] Packet parser error 0x%08X\n", GetLastError());
                goto end;
            }

            HRESULT hr = PerformPacket(pkt);
            
            reply = (hr != S_OK) ? "!OpFail\n" : ".OK\n";
            printf("[V4SV] Operation %u HRESULT: 0x%08X\n", pkt->opCode, hr);

            PktFree(pkt);
        }
        else if (!strncmp(buffer, "END", 3)) {
            reply = ".OK\n";
            terminated = 1;
        }

        end:
        SSL_write(ssl, reply, strlen(reply));
        memset(buffer, 0, PKT_MAX);
    }
    puts("[V4SV] server instance shutting down");
    SSL_shutdown(ssl);
    close(lpClient->socket);
    SSL_free(ssl);
    free(buffer);
}

VOID WINAPI SrvIpv4Listener(DWORD port) {
    puts(">>IPV4");
    puts("IPV4: init WinSock");

    int mode = 1;
    struct timeval timeout;
    timeout.tv_sec = SOCK_TIMEOUT;
    timeout.tv_usec = 0;

    WSADATA winsockData;
    int status = WSAStartup(MAKEWORD(2,2), &winsockData);
    if (status) {
        status = WSAGetLastError();
        printf("WSAStartup returned %i, <<IPV4\n", status);
        ExitThread(status);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.S_un.S_addr = htonl(0); 

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("socket returned %i, <<IPV4\n", sock);
        ExitThread(sock);
    }

    status = 
        bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));

    if (status < 0) {
        printf("bind returned %i, <<IPV4\n", WSAGetLastError());
        ExitThread(status);
    }

    status = listen(sock, 1);

    if (status < 0) {
        printf("listen returned %i, <<IPV4\n", WSAGetLastError());
        ExitThread(status);
    }

    puts("IPV4: Init OK, waiting for inbounds");
    WSASetLastError(0);
    for (;;) {
        struct sockaddr_in cl_addr;
        int sockaddrsz = sizeof(cl_addr);

         
        SSL* ssl;
        int client = accept(sock, &cl_addr, &sockaddrsz);
        
        if (client < 0) {
            int wsa_gla = WSAGetLastError();
            if (wsa_gla == 0) {
                //no inbound connections
                Sleep(100);
                continue;
            }

            printf("IPV4: accept failed, %i (ret %i)\n", 
                wsa_gla, client);
            continue;
            //ExitThread(client);
        }

        char* cl_ip = inet_ntoa(cl_addr.sin_addr);
        printf("IPV4: Inbound connection from %s\n", 
            cl_ip);

        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        //ioctlsocket(client, FIONBIO, &mode);

        ssl = SSL_new(_SSLCONTEXT);
        if (!ssl) {
            printf("[V4:%s] SSL_new failed, %s\n", cl_ip,
                ERR_error_string(ERR_get_error(), NULL));
            continue;
        }

        if (!SSL_set_fd(ssl, client)) {
            printf("[V4:%s] SSL_set_fd failed, %s\n", cl_ip,
                ERR_error_string(ERR_get_error(), NULL));
            continue;
        }

        if (SSL_accept(ssl) <= 0) {
            // accept failed, handle
            printf("[V4:%s] SSL_accept failed, %s\n", cl_ip,
                ERR_error_string(ERR_get_error(), NULL));
            if (ssl) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }

            if (client)
                close(client);

            continue;
        }

        if (!SslVerifyVersion(SSL_get_version(ssl))) {
            // SSL version unacceptable, return error
            SSL_write(ssl, "!Insecure", 10);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
        }

        // SSL accepted, set callback and return waiting signal
        //SSL_set_async_callback(ssl, SrvCallbackHandler);
        LPNET_CLIENT netclient = calloc(1, sizeof(NET_CLIENT));
        netclient->socket = client;
        netclient->ssl = ssl;
        CreateThread(NULL, 0, SrvIpv4Server, netclient, 0, NULL);
        SSL_write(ssl, "?\n", 1);
    }
}

/**
 * @brief Windows service entry point, contains init code
 * 
 * @return VOID 
 */
VOID WINAPI SrvMain() {
    #ifndef SKIPSERVICE
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
    
    //init libssl and libcrypto
    INT32 ssl_code = SslInit();
    if (ssl_code < 0)
        ExitProcess(ssl_code);
    ssl_code = CrpInit();
    if (ssl_code < 0)
        ExitProcess(ssl_code);

    int use_key = CONFIG_FALSE;
    
    int confstat = config_lookup_bool(_CONFIG, "UseCert", &use_key);
    use_key &= confstat;

    if (use_key == CONFIG_TRUE) {
        //this library straight up doesn't work correctly :-], isn't that nice
        char* cert_path = "cert.pem", *key_path = "key.pem";

        config_setting_t* set = 
            config_setting_lookup(_CONFIG->root, "CertFile");
        
        if (set)
            cert_path = config_setting_get_string(set);

        set = config_setting_lookup(_CONFIG->root, "CertKeyFile");
        if (set)
            key_path = config_setting_get_string(set);

        if ((!cert_path) || (!key_path)) 
            puts("Invalid certificate paths");
        
        //printf("cert_path %s, key_path %p\n", cert_path, key_path);
        SslInitPem(cert_path, key_path);
    }

    //start ipv4 socket listener
    CreateThread(NULL, 0, SrvIpv4Listener, 16969, 0, NULL);

    //open ipv6 socket

    #ifndef SKIPSERVICE
    //init finished, singal that srv is running
    ServStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hServStatus, &ServStatus);
    #endif 

    //test for exit signal
    #ifdef SKIPSERVICE
        Sleep(-1);
    #else
        while (WaitForSingleObject(hStopEvent, -1) == WAIT_TIMEOUT);
    #endif
    
    

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

    #ifndef SKIPSERVICE
    SERVICE_TABLE_ENTRYW stEntry[] = { 
        {SRV_NAME, SrvMain},
        {NULL, NULL} 
    };
    StartServiceCtrlDispatcherW(stEntry);
    #endif
    SrvMain();
    
}