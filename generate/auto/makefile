
OPENOCD_HOME ?= /PATH/TO/YOUR_OPENOCD_INSTALL

# supported middleware : ESP8266_AT_parser, Linux
MIDDLEWARE ?= Linux

# supported platform : STM32F4 (currently STM32F446 Nucleo board, ARM-v7M CPU), 
#                      RaspBerry PI 3B+ (ARM-v8A CPU)
PLATFORM ?= unknown

C_DEFS += \


# users can add new third-party crypto library they will use, but users MUST check/handle the
# difference, e.g. structure of the function (e.g. the order of each argument, data type
# of each argument, data type of return value) , between the selected crypto library and this
# MQTT implementation

COMMON_3PARTY_DOWNLOAD_CMD = git clone https://github.com/libtom/libtomcrypt.git; \
                             cd  libtomcrypt ; \
                             git checkout 0c30412a669d37451341ec871c08974da2451eca; \
                             cd  .. ; \
                             git clone https://github.com/libtom/libtommath.git; \
                             cd  libtommath ; \
                             git checkout 6378a90a70404a58d5b4ef20e81d9f817ba021c7; \
                             cd  .. ; \
                             git clone https://github.com/ThrowTheSwitch/Unity.git; \
                             cd  Unity; \
                             git checkout c3d7662a1e692aa0934fa61a2a67229f3b73a5a2; \
                             cd  .. ; \


# for building libmqttclient.a  with common third-party libraries
C_INCLUDES += -Igenerate/include  -Ithird_party/libtomcrypt/src/headers  -Ithird_party/libtommath

ifeq ($(MAKECMDGOALS), utest_helper)
    C_INCLUDES += \
        -Ithird_party/Unity/src \
        -Ithird_party/Unity/extras/fixture/src \
        -Ithird_party/Unity/extras/memory/src

    TEST_COMMON_SOURCES +=  \
        tests/unit/third_party/mqtt_libtommath_ut.c \
        tests/unit/third_party/mqtt_libtomcrypt_ut.c \
        third_party/Unity/src/unity.c \
        third_party/Unity/extras/fixture/src/unity_fixture.c  \
        third_party/Unity/extras/memory/src/unity_memory.c
else
    # built third-party libraries that will be used in linking process of a test image
    THIRD_PARTY_LIBS_PATH = third_party/libtomcrypt/libtomcrypt.a   third_party/libtommath/libtommath.a
endif # end of if MAKECMDGOALS is utest_helper

