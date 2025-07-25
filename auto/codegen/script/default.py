from enum import Enum

CFG_FILE_COMMENT_SYMBOL = "#"
VAR_START_REGEX_SYNTAX = r"\{{3,}"  # left-end syntax should be {{{
VAR_END_REGEX_SYNTAX   = r"\}{3,}"  # right-end syntax should be }}}
VAR_START_OR_END_REGEX_SYNTAX = r"[\{\}]{3,}"
ARB_CHARS_REGEX_LAZY   = ".*?"
TEMPLATE_VAR_HIER_SEPERATOR  = r"\."  # seperator syntax in variable hierarchy of a template file
TEMPLATE_VAR_MICROOPS_SYNTAX = "@"  # syntax to indicate micro operations(s) the code generator must do, in a template file
TEMPLATE_VAR_WILDCARD_SYNTAX = "*"

CONFIG_PARAM_NAME_MIDDLEWARE = "middleware"
CONFIG_PARAM_NAME_CRYPTOLIB  = "cryptolib"
CONFIG_PARAM_NAME_UNITESTLIB = "unitestlib"

CONFIG_PARAM_NAME_SYSINITHOUR    = "sysinithour"   
CONFIG_PARAM_NAME_SYSINITMINUTES = "sysinitminutes" 
CONFIG_PARAM_NAME_SYSINITSECONDS = "sysinitseconds" 
CONFIG_PARAM_NAME_SYSINITMONTH   = "sysinitmonth"   
CONFIG_PARAM_NAME_SYSINITDATE    = "sysinitdate"    
CONFIG_PARAM_NAME_SYSINITYEAR    = "sysinityear"    

CONFIG_PARAM_NAME_OS = "os"
CONFIG_PARAM_NAME_HW_PLATFORM = "hw_platform"
CONFIG_PARAM_NAME_RTOS_HW_BUILD_PATH = "rtos_hw_build_path"
CONFIG_PARAM_NAME_TOOLCHAIN_BASEPATH = "toolchain_basepath"
CONFIG_PARAM_NAME_ESP_PROJ_HOME = "esp_proj_home" # specific to middleware ESP8266-AT-parser

file_types = Enum("File Type", "make c_header c_src")

err_types  = Enum("Error Type", "ok    null_not_allowed    target_not_exist   \
                                 incomplete_param_pair     invalid_param_name \
                                 duplicate_param_name      metadata_decode_error \
                                 param_not_applicable      invalid_micro_op \
                  ")


PROJECT_HOME = "../../../"

CONFIG_FILE_PATH = PROJECT_HOME + "mqttclient.conf"

COMMON_CFG_PARAMS = [
    CONFIG_PARAM_NAME_MIDDLEWARE,
    CONFIG_PARAM_NAME_CRYPTOLIB,
    CONFIG_PARAM_NAME_UNITESTLIB,
    "tls"            , 
    "path_cacert_broker",
    "path_client_cert",
    "path_client_privkey", 
    "brokeraddr"     , 
    "brokerport"     , 
    "brokerusername" , 
    "brokeruserpasswd",
    CONFIG_PARAM_NAME_SYSINITHOUR,
    CONFIG_PARAM_NAME_SYSINITMINUTES,
    CONFIG_PARAM_NAME_SYSINITSECONDS,
    CONFIG_PARAM_NAME_SYSINITMONTH,
    CONFIG_PARAM_NAME_SYSINITDATE,
    CONFIG_PARAM_NAME_SYSINITYEAR   
]

CONFIG_VALID_PARAMS = {
    CONFIG_PARAM_NAME_MIDDLEWARE : {"value":"default_os_name",        },
    CONFIG_PARAM_NAME_CRYPTOLIB  : {"value":"default_crypto_lib_name",},
    CONFIG_PARAM_NAME_UNITESTLIB : {"value":"Unity"                   },
    "tls"              : {"value":"yes",  "c_define":["MQTT_CFG_USE_TLS", "MQTT_CFG_ENABLE_TLS_V1_3"], },
    "path_cacert_broker" : {"value":"/path/to/your/default_cert4broker_file",},
    "path_client_cert"   : {"value":"/path/to/your/default_client_cert_file",},
    "path_client_privkey": {"value":"/path/to/your/default_client_privkey_file",},
    "brokeraddr"       : {"value":"broker.ip.domain"},
    "brokerport"       : {"value":1883,             },
    "brokerusername"   : {"value":"default_broker_user_name",},
    "brokeruserpasswd" : {"value":"default_broker_passwd",   },

    "wifiusername"     : {"value":"default_wifi_uname",      },
    "wifiuserpasswd"   : {"value":"default_wifi_pass",       },
    CONFIG_PARAM_NAME_OS: {"value":"unknown", },
    CONFIG_PARAM_NAME_HW_PLATFORM : {"value":"unknown", },
    CONFIG_PARAM_NAME_RTOS_HW_BUILD_PATH : {"value":"/path/to/your/rtos_hw_build", },
    CONFIG_PARAM_NAME_TOOLCHAIN_BASEPATH : {"value":"/path/to/your/toolchain", },
    CONFIG_PARAM_NAME_ESP_PROJ_HOME    : {"value":"/path/to/your/esp_project", }, 

    CONFIG_PARAM_NAME_SYSINITHOUR     : {"value":1,   },
    CONFIG_PARAM_NAME_SYSINITMINUTES  : {"value":2,   },
    CONFIG_PARAM_NAME_SYSINITSECONDS  : {"value":3,   },
    CONFIG_PARAM_NAME_SYSINITMONTH    : {"value":4,   },
    CONFIG_PARAM_NAME_SYSINITDATE     : {"value":5,   },
    CONFIG_PARAM_NAME_SYSINITYEAR     : {"value":1999,},
    CONFIG_PARAM_NAME_SYSINITYEAR     : {"value":1999,},
} # end of CONFIG_VALID_PARAMS

MIDDLEWARE_MAKEFILE_PATH  = PROJECT_HOME + "auto/middleware"
METADATA_PATH  = PROJECT_HOME + "auto/codegen/metadata"
TEMPLATE_PATH  = PROJECT_HOME + "auto/codegen/template"

TEMPLATE_FILES = [
    {"type": file_types.make    , "name":"makefile"},
    {"type": file_types.c_header, "name":"mqtt_third_party_include.h"},
    {"type": file_types.c_header, "name":"mqtt_third_party_system_config.h"},
    {"type": file_types.c_src   , "name":"mqtt_generate.c"},
] # end of TEMPLATE_FILES

OUTPUT_PATH = {
    file_types.make     : PROJECT_HOME + "generate/auto",
    file_types.c_header : PROJECT_HOME + "generate/include",
    file_types.c_src    : PROJECT_HOME + "generate/src",
} # end of OUTPUT_PATH

