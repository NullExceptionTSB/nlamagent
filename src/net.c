#include <winsock2.h>
#include <Windows.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <winsock2.h>

#include <net.h>
#include <ssl.h>
#include <log.h>
#include <opts.h>
#include <packet.h>
#include <perform.h>

extern BOOLEAN bStop;

DWORD _dwNet4Clients = 0, _dwNet6Clients = 0;

VOID WINAPI iNetIpv4LogPacket(NLPACKET* pkt, char* addr) {
    NLP_SETPASSWD* pex_set_passwd = pkt->specData;
    NLP_CHANGEPASSWD* pex_ch_passwd = pkt->specData;
    NLP_DELUSER* pex_deluser = pkt->specData;
    NLP_ADDUSER* pex_adduser = pkt->specData;
    switch (pkt->opCode) {
        case OP_NOOP:
            LogVerboseA("[V4S:%s] Received noop\n", addr);
            break;
        case OP_SET_PASSWD:
            LogVerboseA(
                "[V4S:%s] Setting password for %s\n", addr,
                pex_set_passwd->user_dn
            );
            break;
        case OP_CHANGE_PASSWD:
            LogVerboseA(
                "[V4S:%s] Changing password for %s\n", addr,
                pex_ch_passwd->user_dn
            );
            break;
        case OP_DEL_USER:
            LogVerboseA(
                "[V4S:%s] Deleting user at %s\n", addr,
                pex_deluser->user_dn
            );
            break;
        case OP_ADD_USER:
            LogVerboseA(
                "[V4S:%s] Creating user '%s' at %s\n", addr,
                pex_adduser->user_cn,
                pex_adduser->path_dn
            );
            break;
        default:
            LogVerboseA("[V4S:%s] Reveived unsupported packet\n", addr);
            break;
    }
}

VOID WINAPI iNetIpv4Server(LPNET_CLIENT lpClient) {
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_SPEED_OVER_MEMORY);
    _dwNet4Clients++;
    
    SSL* ssl = lpClient->ssl;
    char* buffer = calloc(PKT_MAX, 1);
    char* reply = "!What\n";
    char* client_ip = inet_ntoa(lpClient->cl_addr.sin_addr);

    int terminated = 0;
    while (!terminated) {
        reply = "!What\n";
        size_t read = SSL_read(ssl, buffer, PKT_MAX);

        if (read == -1) { 
            int ssl_error = SSL_get_error(ssl, read);
            if (ssl_error == SSL_ERROR_SYSCALL) {
                switch (WSAGetLastError()) {
                    case WSAETIMEDOUT:
                        LogVerboseA("[V4S:%s] Timed out\n", client_ip);
                        reply = "!TimedOut\n";
                        terminated = 1;
                        break;
                }
            } else {
                LogVerboseA("[V4S:%s] Network error\n", client_ip);
                reply = "!NetErr\n";
                goto end;
            }
        }
        if (terminated) break;
        //receive data
        if (read == 0) 
            break;

        LogDebugA("[V4S:%s]: %s", client_ip, buffer);
        if (buffer[0] == '{') {
            NLPACKET* pkt = PktParse(buffer, read);
            if (!pkt) {
                DWORD dwErr = GetLastError();
                snprintf(buffer, PKT_MAX, "!PktInvalid:0x%08X\n", dwErr);

                reply = buffer;
                LogDebugA
                    ("[V4S:%s] Packet parser error 0x%08X\n", 
                        client_ip, dwErr
                    );
                LogVerboseA("[V4S:%s] Invalid packet received\n", client_ip);
                goto end;
            }

            iNetIpv4LogPacket(pkt, client_ip);
            HRESULT hr = PerformPacket(pkt);
            
            if (hr != S_OK) {
                snprintf(buffer, PKT_MAX, "!OpFail:0x%08X\n", hr);
                reply = buffer;
            } else reply = ".OK\n";
            
            LogDebugA("[V4SV] Operation %u HRESULT: 0x%08X\n", pkt->opCode, hr);

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
    LogVerboseA("[V4S:%s] Disconnected\n", client_ip);

    CoUninitialize();
    SSL_shutdown(ssl);
    closesocket(lpClient->socket);
    SSL_free(ssl);
    free(buffer);
    _dwNet4Clients--;
}

DWORD WINAPI NetIpv4Listener(DWORD port) {
    LogDebugA(">>IPV4\n");

    int mode = 1;
    struct timeval timeout;
    timeout.tv_sec = SOCK_TIMEOUT;
    timeout.tv_usec = 0;

    WSADATA winsockData;
    int status = WSAStartup(MAKEWORD(2,2), &winsockData);
    if (status) {
        status = WSAGetLastError();
        LogDebugA("WSAStartup returned %i, <<IPV4\n", status);
        ExitThread(status);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.S_un.S_addr = htonl(0); 

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LogDebugA("socket returned %i, <<IPV4\n", sock);
        ExitThread(sock);
    }

    status = 
        bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));

    if (status < 0) {
        LogDebugA("bind returned %i, <<IPV4\n", WSAGetLastError());
        ExitThread(status);
    }

    status = listen(sock, 1);

    if (status < 0) {
        LogDebugA("listen returned %i, <<IPV4\n", WSAGetLastError());
        ExitThread(status);
    }

    LogDebugA("IPV4: Init OK, waiting for inbounds\n");
    WSASetLastError(0);
    for (;;) {
        if (bStop) break;
        
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

            LogDebugA("[V4] accept failed, %i (ret %i)\n", 
                wsa_gla, client);
            continue;
            //ExitThread(client);
        }

        char* cl_ip = inet_ntoa(cl_addr.sin_addr);
        LogVerboseA("[V4] Inbound connection from %s\n", 
            cl_ip);

        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        ssl = SSL_new(_SSLCONTEXT);
        if (!ssl) {
            LogDebugA("[V4:%s] SSL_new failed, %s\n", cl_ip,
                ERR_error_string(ERR_get_error(), NULL));
            continue;
        }

        if (!SSL_set_fd(ssl, client)) {
            LogDebugA("[V4:%s] SSL_set_fd failed, %s\n", cl_ip,
                ERR_error_string(ERR_get_error(), NULL));
            continue;
        }

        if (SSL_accept(ssl) <= 0) {
            // accept failed, handle
            LogDebugA("[V4:%s] SSL_accept failed, %s\n", cl_ip,
                ERR_error_string(ERR_get_error(), NULL));
            if (ssl) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }

            if (client)
                closesocket(client);

            continue;
        }

        if (!SslVerifyVersion(SSL_get_version(ssl))) {
            // SSL version unacceptable, return error
            SSL_write(ssl, "!Insecure", 10);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            closesocket(client);
        }

        //SSL OK, create a server
        LPNET_CLIENT netclient = calloc(1, sizeof(NET_CLIENT));
        netclient->socket = client;
        netclient->ssl = ssl;
        netclient->cl_addr = cl_addr;
        CreateThread(NULL, 0, iNetIpv4Server, netclient, 0, NULL);
        SSL_write(ssl, "?\n", 1);
    }

    shutdown(sock, SD_RECEIVE);

    LogMessageA( 
        "[V4] Got stop event, waiting for %u clients to finish...\n", 
        _dwNet4Clients
    );

    DWORD dwTicks = 0;
    while (_dwNet4Clients) {
        if (!(++dwTicks % 50))
            LogMessageA(
                "[V4] Waiting for %u clients...\n"
            );
        Sleep(100);
    }

    closesocket(sock);
    WSACleanup();

    LogMessageA("[V4] Exitting gracefully...\n");

    return 0;
}