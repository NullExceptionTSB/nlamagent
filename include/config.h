#pragma once
#include <libconfig.h>

#define CFG_FILENAME "nlamagent.conf"

extern config_t* _CONFIG;
extern int CfgInit();