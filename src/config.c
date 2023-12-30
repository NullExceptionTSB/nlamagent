#include <stdlib.h>

#include <config.h>

config_t* _CONFIG;



void CfgInitDefaults() {
    config_setting_t* root = config_root_setting(_CONFIG);

    config_setting_t
        *use_cert = config_setting_add(root, "UseCert", CONFIG_TYPE_BOOL),
        *cert_file = config_setting_add(root, "CertFile", CONFIG_TYPE_STRING),
        *cert_key = config_setting_add(root, "CertKeyFile", CONFIG_TYPE_STRING),
        *log_into_file = 
            config_setting_add(root, "FileLogging", CONFIG_TYPE_BOOL),
        *log_file =
            config_setting_add(root, "LogFilename", CONFIG_TYPE_STRING),
        *log_into_stdio =
            config_setting_add(root, "StdioLogging", CONFIG_TYPE_BOOL);

    config_setting_set_bool(use_cert, CONFIG_TRUE);
    config_setting_set_bool(log_into_file, CONFIG_TRUE);
    config_setting_set_string(cert_file, CFG_CERT_DEFAULT);
    config_setting_set_string(cert_key, CFG_KEY_DEFAULT);
    config_setting_set_string(log_file, CFG_LOG_DEFAULT);
    config_setting_set_string(log_into_stdio, CONFIG_TRUE);

    config_write_file(_CONFIG, CFG_FILENAME);
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