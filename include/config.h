#pragma once
#include <libconfig.h>

#define CFG_CERT_DEFAULT    "cert.pem"
#define CFG_KEY_DEFAULT     "key.pem"
#define CFG_LOG_DEFAULT     "nlamagent.log"

#define CFG_FILENAME        "nlamagent.conf"

extern config_t* _CONFIG;
extern int CfgInit();