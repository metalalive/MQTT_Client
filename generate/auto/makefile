OPENOCD_HOME ?= /PATH/TO/YOUR_OPENOCD_INSTALL

MIDDLEWARE ?= Linux

PLATFORM ?= unknown

COMMON_3PARTY_DOWNLOAD_CMD = git clone https://github.com/libtom/libtomcrypt.git;cd  libtomcrypt;git checkout 0c30412a669d37451341ec871c08974da2451eca;cd  ..;git clone https://github.com/libtom/libtommath.git;cd  libtommath;git checkout 6378a90a70404a58d5b4ef20e81d9f817ba021c7;cd  ..;git clone https://github.com/ThrowTheSwitch/Unity.git;cd  Unity;git checkout c3d7662a1e692aa0934fa61a2a67229f3b73a5a2;cd  ..;

COMMON_3PARTY_FILE_SUBST_CMD = cp -rf ../generate/include/mqtt_third_party_system_config.h                      ./libtommath;cp -rf ../include/substitution/third_party/libtommath/mqtt_third_party_config.h  ./libtommath;cp -rf ../include/substitution/third_party/libtommath/tommath_private.h          ./libtommath;cp -rf ../src/substitution/third_party/libtommath/mp_rand.c                      ./libtommath;cp -rf ../src/substitution/third_party/libtommath/s_mp_mul_digs_fast.c           ./libtommath;cp -rf ../src/substitution/third_party/libtommath/s_mp_mul_high_digs_fast.c      ./libtommath;cp -rf ../src/substitution/third_party/libtommath/s_mp_sqr_fast.c                ./libtommath;cp -rf ../src/substitution/third_party/libtommath/s_mp_exptmod.c                 ./libtommath;cp -rf ../src/substitution/third_party/libtommath/s_mp_exptmod_fast.c            ./libtommath;cp -rf ../src/substitution/third_party/libtommath/s_mp_montgomery_reduce_fast.c  ./libtommath;cp -rf ../generate/include/mqtt_third_party_system_config.h  ./libtomcrypt/src/headers;cp -rf ../include/substitution/third_party/libtomcrypt/headers/mqtt_third_party_config.h  ./libtomcrypt/src/headers;cp -rf ../include/substitution/third_party/libtomcrypt/headers/tomcrypt_custom.h          ./libtomcrypt/src/headers;cp -rf ../src/substitution/third_party/libtomcrypt/src/hashes/sha2/sha512.c           ./libtomcrypt/src/hashes/sha2;cp -rf ../src/substitution/third_party/libtomcrypt/src/pk/ec25519/ec25519_export.c  ./libtomcrypt/src/pk/ec25519;cp -rf ../src/substitution/third_party/libtomcrypt/src/pk/ec25519/tweetnacl.c    ./libtomcrypt/src/pk/ec25519;cp -rf ../src/substitution/third_party/libtomcrypt/src/pk/rsa/rsa_verify_hash.c  ./libtomcrypt/src/pk/rsa;cp -rf ../src/substitution/third_party/libtomcrypt/src/pk/rsa/rsa_sign_hash.c    ./libtomcrypt/src/pk/rsa;cp -rf ../src/substitution/third_party/libtomcrypt/src/pk/asn1/der/printable_string/der_length_printable_string.c  ./libtomcrypt/src/pk/asn1/der/printable_string;cp -rf ../src/substitution/third_party/libtomcrypt/src/pk/asn1/der/ia5/der_length_ia5_string.c   ./libtomcrypt/src/pk/asn1/der/ia5;cp -rf ../src/substitution/third_party/libtomcrypt/src/pk/asn1/der/teletex_string/der_length_teletex_string.c  ./libtomcrypt/src/pk/asn1/der/teletex_string;cp -rf ../include/substitution/third_party/Unity/extras/memory/src/unity_memory.h  ./Unity/extras/memory/src;

COMMON_3PARTY_CLEAN_BUILT_CMD = make clean -C ./libtommath;make clean -C ./libtomcrypt;

C_INCLUDES += -Igenerate/include  -Ithird_party/libtomcrypt/src/headers -Ithird_party/libtommath \
                -Iinclude/system/middleware/Linux \
               

ifeq ($(MAKECMDGOALS), utest_helper)
    C_INCLUDES          +=  -Ithird_party/Unity/src -I third_party/Unity/extras/fixture/src -Ithird_party/Unity/extras/memory/src
    TEST_COMMON_SOURCES += tests/unit/third_party/mqtt_libtommath_ut.c tests/unit/third_party/mqtt_libtomcrypt_ut.c third_party/Unity/src/unity.c third_party/Unity/extras/fixture/src/unity_fixture.c third_party/Unity/extras/memory/src/unity_memory.c 
else
    C_SOURCES  += src/system/middleware/Linux/mqtt_sys.c  \
                  
    # built third-party libraries that will be used in linking process of a test image
    THIRD_PARTY_LIBS_PATH = third_party/libtomcrypt/libtomcrypt.a third_party/libtommath/libtommath.a 
endif # end of if MAKECMDGOALS is utest_helper

ifeq ($(MAKECMDGOALS), utest_helper)
    include  ${PWD}/auto/middleware/unknown.makefile
else  # if unit test is NOT enabled
    #### include hardware platfrom specific files, (NOTE) don't use cross-compile toolchain in unit test
    include  ${PWD}/auto/platform/$(PLATFORM).makefile
    #### include middleware files, the middleware can be any API software integrated
    #### with OS (e.g. RTOS, Linux kernel) .
    include  ${PWD}/auto/middleware/$(MIDDLEWARE).makefile
endif

COMMON_3PARTY_BUILD_CMD = make libtommath.a V=1  CROSS_COMPILE=$(C_TOOLCHAIN_PREFIX)  CFLAGS="$(CPU_ARCH_FLAGS) $(DBGCFLAGS) $(PLUS_C_DEFS)" -C ./libtommath;make  V=1 CROSS_COMPILE=$(C_TOOLCHAIN_PREFIX) EXTRALIBS="../libtommath/libtommath.a"  CFLAGS="$(CPU_ARCH_FLAGS) $(DBGCFLAGS) $(PLUS_C_DEFS) -I../../include -I../libtommath"  -C ./libtomcrypt;

