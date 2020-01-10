COMMON_3PARTY_BUILD_CMD=
COMMON_3PARTY_CLEAN_BUILT_CMD=


# build math library libtommath.a for specific CPU platform
COMMON_3PARTY_BUILD_CMD += \
cp -rf ../generate/include/mqtt_third_party_config.h                     ./libtommath/mqtt_third_party_config.h; \
cp -rf ../generate/include/mqtt_third_party_system_config.h              ./libtommath/mqtt_third_party_system_config.h; \
cp -rf ../include/substitution/third_party/libtommath/tommath_private.h  ./libtommath/tommath_private.h;\
cp -rf ../src/substitution/third_party/libtommath/mp_rand.c                        ./libtommath/mp_rand.c                    ; \
cp -rf ../src/substitution/third_party/libtommath/s_mp_mul_digs_fast.c             ./libtommath/s_mp_mul_digs_fast.c         ; \
cp -rf ../src/substitution/third_party/libtommath/s_mp_mul_high_digs_fast.c        ./libtommath/s_mp_mul_high_digs_fast.c    ; \
cp -rf ../src/substitution/third_party/libtommath/s_mp_sqr_fast.c                  ./libtommath/s_mp_sqr_fast.c              ; \
cp -rf ../src/substitution/third_party/libtommath/s_mp_exptmod.c                   ./libtommath/s_mp_exptmod.c               ; \
cp -rf ../src/substitution/third_party/libtommath/s_mp_exptmod_fast.c              ./libtommath/s_mp_exptmod_fast.c          ; \
cp -rf ../src/substitution/third_party/libtommath/s_mp_montgomery_reduce_fast.c    ./libtommath/s_mp_montgomery_reduce_fast.c; \


COMMON_3PARTY_BUILD_CMD += make libtommath.a V=1  CROSS_COMPILE=$(C_TOOLCHAIN_PREFIX)  CFLAGS="$(CPU_ARCH_FLAGS) $(DBGCFLAGS) $(PLUS_C_DEFS)" -C ./libtommath ;


COMMON_3PARTY_BUILD_CMD += \
cp -rf  ../generate/include/mqtt_third_party_config.h               ./libtomcrypt/src/headers/mqtt_third_party_config.h; \
cp -rf  ../generate/include/mqtt_third_party_system_config.h        ./libtomcrypt/src/headers/mqtt_third_party_system_config.h; \
cp -rf  ../include/substitution/third_party/libtomcrypt/headers/tomcrypt_custom.h  ./libtomcrypt/src/headers/tomcrypt_custom.h; \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/hashes/sha2/sha512.c       ./libtomcrypt/src/hashes/sha2/sha512.c;     \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/ec25519/ec25519_export.c  ./libtomcrypt/src/pk/ec25519/ec25519_export.c;   \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/ec25519/tweetnacl.c     ./libtomcrypt/src/pk/ec25519/tweetnacl.c;   \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/rsa/rsa_verify_hash.c   ./libtomcrypt/src/pk/rsa/rsa_verify_hash.c; \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/rsa/rsa_sign_hash.c     ./libtomcrypt/src/pk/rsa/rsa_sign_hash.c;   \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/asn1/der/printable_string/der_length_printable_string.c    ./libtomcrypt/src/pk/asn1/der/printable_string/der_length_printable_string.c; \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/asn1/der/ia5/der_length_ia5_string.c       ./libtomcrypt/src/pk/asn1/der/ia5/der_length_ia5_string.c; \
cp -rf  ../src/substitution/third_party/libtomcrypt/src/pk/asn1/der/teletex_string/der_length_teletex_string.c    ./libtomcrypt/src/pk/asn1/der/teletex_string/der_length_teletex_string.c;



# build crypto library libtomcrypto.a
COMMON_3PARTY_BUILD_CMD += make  V=1 CROSS_COMPILE=$(C_TOOLCHAIN_PREFIX) EXTRALIBS="../libtommath/libtommath.a"  CFLAGS="$(CPU_ARCH_FLAGS) $(DBGCFLAGS) $(PLUS_C_DEFS) -I../../include -I../libtommath"  -C ./libtomcrypt ;
# [NOTE]
# TAB_SIZE indicates that number of random number generator (RNG) implemented in the
# application, in this MQTT implementation there is ONLY one RNG implementation, that
# is , the TAB_SIZE must be 2.


# clean up built common third-party libraries
COMMON_3PARTY_CLEAN_BUILT_CMD += make clean -C ./libtommath ;
COMMON_3PARTY_CLEAN_BUILT_CMD += make clean -C ./libtomcrypt ;


