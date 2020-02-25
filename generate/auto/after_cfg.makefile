COMMON_3PARTY_BUILD_CMD=

# build math library libtommath.a for specific CPU platform
COMMON_3PARTY_BUILD_CMD += make libtommath.a V=1  CROSS_COMPILE=$(C_TOOLCHAIN_PREFIX)  CFLAGS="$(CPU_ARCH_FLAGS) $(DBGCFLAGS) $(PLUS_C_DEFS)" -C ./libtommath ;

# build crypto library libtomcrypto.a
COMMON_3PARTY_BUILD_CMD += make  V=1 CROSS_COMPILE=$(C_TOOLCHAIN_PREFIX) EXTRALIBS="../libtommath/libtommath.a"  CFLAGS="$(CPU_ARCH_FLAGS) $(DBGCFLAGS) $(PLUS_C_DEFS) -I../../include -I../libtommath"  -C ./libtomcrypt ;


