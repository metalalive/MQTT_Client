#-------------------------------------------------
# integration files for this MQTT implementation
#-------------------------------------------------
C_SOURCES += src/system/middleware/Linux/mqtt_sys.c

CFLAGS += -Wint-to-pointer-cast  -Wpointer-to-int-cast  -pthread

C_INCLUDES += -Iinclude/system/middleware/Linux

EXTRA_LIBS =  -pthread

GDB_CMD = gdb

DBG_CLIENT_CMD = $(GDB_CMD)



