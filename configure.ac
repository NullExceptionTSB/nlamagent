AC_INIT([NLAMAgent], [0.1], [nullexceptiontsb@proton.me])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_AUX_DIR([mkaux])

AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects foreign])

AC_PROG_CC
AC_SEARCH_LIBS([SSL_CTX_new], [ssl libssl], [], [ AC_MSG_ERROR([required library libssl not found]) ])
AC_SEARCH_LIBS([AES_encrypt], [crypto libcrypto], [], [ AC_MSG_ERROR([required library libcrypto not found]) ])
AC_SEARCH_LIBS([json_tokener_new], [json-c libjson-c], [], [ AC_MSG_ERROR([required library json-c not found]) ])
AC_SEARCH_LIBS([config_init], [config libconfig], [], [ AC_MSG_ERROR([required library libconfig not found]) ])
AC_SEARCH_LIBS([__imp_bind], [ws2_32 ws2 ws2_64], [], [ AC_MSG_ERROR([required library winsock not found]) ])
AC_SEARCH_LIBS([__imp_CoInitializeEx], [ole32], [], [ AC_MSG_ERROR([required library ole32 not found]) ])
AC_SEARCH_LIBS([__imp_SysAllocString], [oleaut32], [], [ AC_MSG_ERROR([required library oleaut32 not found]) ])
AC_SEARCH_LIBS([ADsGetObject], [activeds], [], [ AC_MSG_ERROR([required library ADSI not found]) ])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
