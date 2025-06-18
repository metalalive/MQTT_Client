# Linux integration with this MQTT implementation

# assume GCC tools are installed in default system path
CC = gcc
AS = gcc -x assembler-with-cpp
AR = ar
SZ = size
HEX = objcopy -O ihex
BIN = objcopy -O binary -S
DUMP = objdump

CFLAGS += -Wint-to-pointer-cast  -Wpointer-to-int-cast  -pthread

EXTRA_LIBS =  -pthread

ifneq ($(MAKECMDGOALS), utest_helper)
	C_INCLUDES += -I$(MQC_PROJ_HOME)/include/system/middleware/Linux
	LIB_C_SRCS += $(MQC_PROJ_HOME)/src/system/middleware/Linux/mqtt_sys.c
endif

GDB_CMD = gdb

DBG_CLIENT_CMD = $(GDB_CMD)

demo : $(TARGET_LIB_PATH)  $(TEST_COMMON_OBJECTS)  $(TEST_ENTRY_OBJECTS) $(ITEST_ASM_OBJS) \
       $(foreach atest, $(TEST_ENTRY_OBJECTS), $(atest:.o=).elf  $(atest:.o=).hex  $(atest:.o=).text  $(atest:.o=).bin)


# --------- for generating executable test cases ---------
%.elf:  %.o  $(TEST_COMMON_OBJECTS) $(TARGET_LIB_PATH)  $(THIRD_PARTY_LIBS_PATH)
	$(CC) $^  $(LDFLAGS) -o $@ 
	$(SZ) $@

%.hex: %.elf | $(BUILD_DIR)
	$(HEX) $< $@

%.bin: %.elf | $(BUILD_DIR)
	$(BIN) $< $@

%.text: %.elf | $(BUILD_DIR)
	$(DUMP) -Dh $< > $@

