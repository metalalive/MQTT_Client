#-------------------------------------------------
# integration files for this MQTT implementation
#-------------------------------------------------

CFLAGS += -Wint-to-pointer-cast  -Wpointer-to-int-cast  -pthread

EXTRA_LIBS =  -pthread

GDB_CMD = gdb

DBG_CLIENT_CMD = $(GDB_CMD)

