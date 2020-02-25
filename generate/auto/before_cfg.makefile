
OPENOCD_HOME ?= /PATH/TO/YOUR_OPENOCD_INSTALL

# supported middleware : ESP8266_AT_parser, Linux
MIDDLEWARE ?= Linux

# supported platform : STM32F4 (currently STM32F446 Nucleo board, ARM-v7M CPU), 
#                      RaspBerry PI 3B+ (ARM-v8A CPU)
PLATFORM ?= unknown

C_DEFS += \

COMMON_3PARTY_FILE_SUBST_CMD=
COMMON_3PARTY_CLEAN_BUILT_CMD=

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

COMMON_3PARTY_FILE_SUBST_CMD += \
cp -rf ../generate/include/mqtt_third_party_system_config.h                 ./libtommath/mqtt_third_party_system_config.h; \
cp -rf ../include/substitution/third_party/libtommath/mqtt_third_party_config.h    ./libtommath/mqtt_third_party_config.h; \
cp -rf ../include/substitution/third_party/libtommath/tommath_private.h            ./libtommath/tommath_private.h;         \
cp -rf ../src/substitution/third_party/libtommath/mp_rand.c                        ./libtommath/mp_rand.c                    ; \
cp -rf ../src/substitution/third_party/libtommath/s_mp_mul_digs_fast.c             ./libtommath/s_mp_mul_digs_fast.c         ; \
cp -rf ../src/substitution/third_party/libtommath/s_mp_mul_high_digs_fast.c        ./libtommath/s_mp_mul_high_digs_fast.c    ; \
cp -rf ../src/substitution/third_party/libtommath/s_mp_sqr_fast.c                  ./libtommath/s_mp_sqr_fast.c              ; \
cp -rf ../src/substitution/third_party/libtommath/s_mp_exptmod.c                   ./libtommath/s_mp_exptmod.c               ; \
cp -rf ../src/substitution/third_party/libtommath/s_mp_exptmod_fast.c              ./libtommath/s_mp_exptmod_fast.c          ; \
cp -rf ../src/substitution/third_party/libtommath/s_mp_montgomery_reduce_fast.c    ./libtommath/s_mp_montgomery_reduce_fast.c; \

COMMON_3PARTY_FILE_SUBST_CMD += \
cp -rf  ../generate/include/mqtt_third_party_system_config.h        ./libtomcrypt/src/headers/mqtt_third_party_system_config.h; \
cp -rf  ../include/substitution/third_party/libtomcrypt/headers/mqtt_third_party_config.h   ./libtomcrypt/src/headers/mqtt_third_party_config.h; \
cp -rf  ../include/substitution/third_party/libtomcrypt/headers/tomcrypt_custom.h  ./libtomcrypt/src/headers/tomcrypt_custom.h; \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/hashes/sha2/sha512.c       ./libtomcrypt/src/hashes/sha2/sha512.c;     \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/ec25519/ec25519_export.c  ./libtomcrypt/src/pk/ec25519/ec25519_export.c;   \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/ec25519/tweetnacl.c     ./libtomcrypt/src/pk/ec25519/tweetnacl.c;   \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/rsa/rsa_verify_hash.c   ./libtomcrypt/src/pk/rsa/rsa_verify_hash.c; \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/rsa/rsa_sign_hash.c     ./libtomcrypt/src/pk/rsa/rsa_sign_hash.c;   \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/asn1/der/printable_string/der_length_printable_string.c    ./libtomcrypt/src/pk/asn1/der/printable_string/der_length_printable_string.c; \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/asn1/der/ia5/der_length_ia5_string.c       ./libtomcrypt/src/pk/asn1/der/ia5/der_length_ia5_string.c; \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/asn1/der/teletex_string/der_length_teletex_string.c    ./libtomcrypt/src/pk/asn1/der/teletex_string/der_length_teletex_string.c;


COMMON_3PARTY_FILE_SUBST_CMD += \
cp -rf  ../include/substitution/third_party/Unity/extras/memory/src/unity_memory.h  ./Unity/extras/memory/src/unity_memory.h; \

# clean up built common third-party libraries
COMMON_3PARTY_CLEAN_BUILT_CMD += make clean -C ./libtommath ;
COMMON_3PARTY_CLEAN_BUILT_CMD += make clean -C ./libtomcrypt ;



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

