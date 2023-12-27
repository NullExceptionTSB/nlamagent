#include <Windows.h>

#include <config.h>
#include <ssl.h>
#include <opts.h>

SSL_CTX* _SSLCONTEXT = NULL;

/**
 * @brief Verifies wheather a given SSL version is sufficient
 * 
 * 
 * @param lpSslVersion \
 *  The string containing the SSL version (from SSL_get_version())
 * @return BOOL True if the connection may be accepted, false if not
 */
BOOL WINAPI SslVerifyVersion(char* lpSslVersion) {
    if (!strcmp(lpSslVersion, "SSLv2") || !strcmp(lpSslVersion, "SSLv3") ||
        !strcmp(lpSslVersion, "TLSv1")) return FALSE;
    
    //TLSv1.1 is accepted only if enabled in config
    if (!strcmp(lpSslVersion, "TLSv1.1")) {
        int support_tls11 = CONFIG_FALSE;
        config_lookup_bool(_CONFIG, "SupportTsl11", &support_tls11);

        return support_tls11 == CONFIG_TRUE;
    }

    if (!strcmp(lpSslVersion, "TLSv1.2") || !strcmp(lpSslVersion, "TLSv1.3")) 
        return TRUE;

    //unknown TLS version
    return FALSE;
}

INT WINAPI SslInit() {
    SSL_load_error_strings();
    SSL_library_init();

    const SSL_METHOD* ssl_method = TLS_server_method();
    _SSLCONTEXT = SSL_CTX_new(ssl_method);
    //SSL_CTX_set_timeout(_SSLCONTEXT, SSL_TIMEOUT);
    SSL_CTX_set_options(_SSLCONTEXT, 
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    /*
    SSL_CTX_set_cipher_list(_SSLCONTEXT, 
        "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4");
    */
    if (_SSLCONTEXT == NULL) {
        puts(ERR_error_string(ERR_get_error(), NULL));
        return -3;
    }
    return 0;
}

INT WINAPI SslInitPem(char* cert_path, char* key_path) {
    if (SSL_CTX_use_certificate_file(_SSLCONTEXT, cert_path, SSL_FILETYPE_PEM)
        <= 0) return -10;
    
    if (SSL_CTX_use_PrivateKey_file(_SSLCONTEXT, key_path, SSL_FILETYPE_PEM)
        <= 0) return -11;
        
}