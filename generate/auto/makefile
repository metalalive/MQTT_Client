
OPENOCD_HOME ?= /PATH/TO/YOUR_OPENOCD_INSTALL

# supported middleware : ESP8266_AT_parser, Linux
MIDDLEWARE ?= Linux

# supported platform : STM32F4 (currently STM32F446 Nucleo board, ARM-v7M CPU), 
#                      RaspBerry PI 3B+ (ARM-v8A CPU)
PLATFORM ?= unknown

C_DEFS += \
    -DMGTT_CFG_HASH_STATE_STRUCT=hash_state \
    -DMGTT_CFG_HASH_SHA256_FN_INIT=sha256_init \
    -DMGTT_CFG_HASH_SHA384_FN_INIT=sha384_init \
    -DMGTT_CFG_HASH_SHA256_FN_UPDATE=sha256_process \
    -DMGTT_CFG_HASH_SHA384_FN_UPDATE=sha384_process \
    -DMGTT_CFG_HASH_SHA256_FN_DONE=sha256_done  \
    -DMGTT_CFG_HASH_SHA384_FN_DONE=sha384_done  \
    -DMQTT_CFG_MPBINT_FN_BIN2MPINT=mp_from_ubin \
    -DMQTT_CFG_MPBINT_FN_MPINT2BIN=mp_to_ubin   \
    -DMQTT_CFG_MPBINT_FN_CAL_UBINSIZE=mp_ubin_size \
    -DMQTT_CFG_MPBINT_FN_INIT=mp_init \
    -DMQTT_CFG_MPBINT_FN_CLEAR=mp_clear    \
    -DMQTT_CFG_MPBINT_FN_ADD=mp_add        \
    -DMQTT_CFG_MPBINT_FN_ADDDG=mp_add_d    \

# TODO:
#### -DMQTT_CFG_USE_TLS  \
#### -DMQTT_CFG_ENABLE_TLS_V1_3 \


# users can add new third-party crypto library they will use, but users MUST check/handle the
# difference, e.g. structure of the function (e.g. the order of each argument, data type
# of each argument, data type of return value) , between the selected crypto library and this
# MQTT implementation

COMMON_3PARTY_DOWNLOAD_CMD = git clone https://github.com/libtom/libtomcrypt.git; \
                             git clone https://github.com/libtom/libtommath.git;

# for building libmqttclient.a  with common third-party libraries
C_INCLUDES += -Igenerate/include  -Ithird_party/libtomcrypt/src/headers  -Ithird_party/libtommath

# built third-party libraries that will be used in linking process of a test image
THIRD_PARTY_LIBS_PATH = third_party/libtomcrypt/libtomcrypt.a   third_party/libtommath/libtommath.a

