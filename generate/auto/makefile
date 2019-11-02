
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

# for building libmqttclient.a  with common third-party libraries
C_INCLUDES += -Igenerate/include  -Ithird_party/libtomcrypt/src/headers  -Ithird_party/libtommath

# built third-party libraries that will be used in linking process of a test image
THIRD_PARTY_LIBS_PATH = third_party/libtomcrypt/libtomcrypt.a   third_party/libtommath/libtommath.a

