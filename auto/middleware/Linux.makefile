#-------------------------------------------------
# integration files for this MQTT implementation
#-------------------------------------------------
C_SOURCES += src/system/middleware/Linux/mqtt_sys.c

C_DEFS += -DMQTT_CFG_SYS_LINUX

CFLAGS += -Wint-to-pointer-cast  -Wpointer-to-int-cast  -pthread

EXTRA_LIBS =  -pthread

GDB_CMD = gdb

DBG_CLIENT_CMD = $(GDB_CMD)



