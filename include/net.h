#pragma once
#include <openssl/ssl.h>

typedef struct _NET_CLIENT {
    int socket;
    SSL* ssl;
}NET_CLIENT, *LPNET_CLIENT;

DWORD WINAPI NetIpv4Listener(DWORD port);