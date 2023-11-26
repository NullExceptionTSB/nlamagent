#include <stdlib.h>

#include <config.h>

config_t* _CONFIG;

void CfgInitDefaults() {

}

int CfgInit() {
    _CONFIG = calloc(sizeof(config_t), 1);
    if (!_CONFIG) 
        return -2;
    config_init(_CONFIG);
    if (config_read_file(_CONFIG, CFG_FILENAME) == CONFIG_FALSE) {
        CfgInitDefaults();
        return 1;
    }
    return 0;
}