COMMON_3PARTY_HEAPMEM_FNAMES_C_DEF=
COMMON_3PARTY_BUILD_CMD=
COMMON_3PARTY_CLEAN_BUILT_CMD=

ifeq ($(COMMON_3PARTY_HEAPMEM_FN_CHANGE), yes)
    COMMON_3PARTY_HEAPMEM_FNAMES_C_DEF = -DMP_MALLOC=$(COMMON_3PARTY_HEAPMEM_FN_MALLOC) -DMP_FREE=$(COMMON_3PARTY_HEAPMEM_FN_FREE) -DMP_REALLOC=$(COMMON_3PARTY_HEAPMEM_FN_REALLOC) -DMP_CALLOC=$(COMMON_3PARTY_HEAPMEM_FN_CALLOC)
endif # end of COMMON_3PARTY_HEAPMEM_FN_CHANGE == yes


# build math library libtommath.a for specific CPU platform, TODO: parameterize memory functions
COMMON_3PARTY_BUILD_CMD += make libtommath.a V=1  CROSS_COMPILE=$(C_TOOLCHAIN_PREFIX)  CFLAGS="$(CPU_ARCH_FLAGS) $(DBGCFLAGS) $(PLUS_C_DEFS) $(COMMON_3PARTY_HEAPMEM_FNAMES_C_DEF) " -C ./libtommath ;


ifeq ($(COMMON_3PARTY_HEAPMEM_FN_CHANGE), yes)
    COMMON_3PARTY_HEAPMEM_FNAMES_C_DEF = -DXMALLOC=$(COMMON_3PARTY_HEAPMEM_FN_MALLOC) -DXFREE=$(COMMON_3PARTY_HEAPMEM_FN_FREE) -DXREALLOC=$(COMMON_3PARTY_HEAPMEM_FN_REALLOC) -DXCALLOC=$(COMMON_3PARTY_HEAPMEM_FN_CALLOC)
endif # end of COMMON_3PARTY_HEAPMEM_FN_CHANGE == yes

# TODO: this will be generated configuration files for libtomcrypto
COMMON_3PARTY_BUILD_CMD += cp -rf ../generate/include/tomcrypt_custom.h  ./libtomcrypt/src/headers/tomcrypt_custom.h;

# build crypto library libtomcrypto.a
COMMON_3PARTY_BUILD_CMD += make  V=1 CROSS_COMPILE=$(C_TOOLCHAIN_PREFIX) EXTRALIBS="../libtommath/libtommath.a"  CFLAGS="$(CPU_ARCH_FLAGS) $(DBGCFLAGS) $(PLUS_C_DEFS) $(COMMON_3PARTY_HEAPMEM_FNAMES_C_DEF)  -DLTC_NO_PRNGS -DLTC_NO_TABLES -DTAB_SIZE=1 -DLTC_NO_TEST -DUSE_LTM -DLTM_DESC -I../libtommath"  -C ./libtomcrypt ;
# [NOTE]
# TAB_SIZE indicates that number of random number generator (RNG) implemented in the
# application, in this MQTT implementation there is ONLY one RNG implementation, that
# is , the TAB_SIZE must be 1.


# clean up built common third-party libraries
COMMON_3PARTY_CLEAN_BUILT_CMD += make clean -C ./libtommath ;
COMMON_3PARTY_CLEAN_BUILT_CMD += make clean -C ./libtomcrypt ;


