#-------------------------------------------------
# integration files for this MQTT implementation
#-------------------------------------------------
C_SOURCES += src/system/middleware/Linux/mqtt_sys.c

C_DEFS += -DMQTT_CFG_SYS_LINUX

CFLAGS += -Wint-to-pointer-cast  -Wpointer-to-int-cast  -pthread

EXTRA_LIBS =  -pthread

GDB_CMD = gdb

DBG_CLIENT_CMD = $(GDB_CMD)

#-------------------------------------------------------------------------------------
# integration parameters for this MQTT implementation & common third-party libraries
#-------------------------------------------------------------------------------------
# memory operation functions should be consistent with underlying OS, for the platforms
# that provide their own heap memory operations with different function names, developers
# can sepcify the memory function names that meet their platform requirement.
COMMON_3PARTY_HEAPMEM_FN_CHANGE=no
COMMON_3PARTY_HEAPMEM_FN_MALLOC=
COMMON_3PARTY_HEAPMEM_FN_FREE=
COMMON_3PARTY_HEAPMEM_FN_REALLOC=
COMMON_3PARTY_HEAPMEM_FN_CALLOC=


