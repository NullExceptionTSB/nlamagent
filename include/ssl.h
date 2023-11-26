#pragma once
#include <Windows.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

extern SSL_CTX* _SSLCONTEXT;

BOOL WINAPI SslVerifyVersion(char* lpSslVersion);
INT WINAPI SslInitPem(char* cert_path, char* key_path);