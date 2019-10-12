######################################
# building variables
######################################

# extra defined parameters users want to specify
PLUS_C_DEFS ?= 

DEBUG ?= no

BUILD_DIR = build

TARGET_LIB_PATH = $(BUILD_DIR)/libmqttclient.a

######################################
# source
######################################
# C sources
C_SOURCES =  \
src/mqtt/mqtt_client_conn.c \
src/mqtt/mqtt_packet.c      \
src/mqtt/mqtt_util.c        \
src/mqtt/mqtt_auth.c        \


# ASM sources
ASM_SOURCES = 

# macros for gcc
# AS defines
AS_DEFS = 

# C defines
C_DEFS = $(foreach def, $(PLUS_C_DEFS), $(addprefix -D, $(def)) )

# C includes
C_INCLUDES = -Iinclude \


# include generated build script
include  ./generate/auto/makefile

#### include hardware platfrom specific files
include  ./auto/platform/$(PLATFORM).makefile

#### include middleware files, the middleware can be any API software integrated
#### with OS (e.g. RTOS, Linux kernel) .
include  ./auto/middleware/$(MIDDLEWARE).makefile


#---------------------------------------------------------
# different files & paths for unit test, integration test 
#---------------------------------------------------------
TEST_COMMON_SOURCES = tests/integration/pattern_generator.c  generate/src/mqtt_generate.c

ifeq ($(MAKECMDGOALS), check) # if unit test is enabled
# TODO: complete unit test after completing integration tests.
    TEST_ENTRY_SOURCES += 
else
    ifeq ($(MAKECMDGOALS), tests) # if make goal is 'test', then it is integration test
        TEST_ENTRY_SOURCES += tests/integration/mqtt_client_tcp.c 
        C_INCLUDES += -Itests/integration
    endif #### end of tests
endif #### end of check

TEST_ENTRY_OBJECTS  = $(addprefix $(BUILD_DIR)/,$(notdir $(TEST_ENTRY_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(TEST_ENTRY_SOURCES)))

TEST_COMMON_OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(TEST_COMMON_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(TEST_COMMON_SOURCES)))

#--------------------------------------------------------------------------------------
# The gcc compiler bin path can be either defined in make command via GCC_PATH variable 
# (> make GCC_PATH=xxx) either it can be added to the PATH environment variable.
ifdef GCC_PATH
    CC = $(GCC_PATH)/$(C_TOOLCHAIN_PREFIX)gcc
    AS = $(GCC_PATH)/$(C_TOOLCHAIN_PREFIX)gcc -x assembler-with-cpp
    CP = $(GCC_PATH)/$(C_TOOLCHAIN_PREFIX)objcopy
    SZ = $(GCC_PATH)/$(C_TOOLCHAIN_PREFIX)size
    AR = $(GCC_PATH)/$(C_TOOLCHAIN_PREFIX)ar
    DUMP = $(GCC_PATH)/$(C_TOOLCHAIN_PREFIX)objdump
else
    CC = $(C_TOOLCHAIN_PREFIX)gcc
    AS = $(C_TOOLCHAIN_PREFIX)gcc -x assembler-with-cpp
    CP = $(C_TOOLCHAIN_PREFIX)objcopy
    SZ = $(C_TOOLCHAIN_PREFIX)size
    AR = $(C_TOOLCHAIN_PREFIX)ar
    DUMP = $(C_TOOLCHAIN_PREFIX)objdump
endif

HEX = $(CP) -O ihex

BIN = $(CP) -O binary -S

# optimization
OPT = -Og

# compile gcc flags
ASFLAGS = $(MCU) $(AS_DEFS) $(AS_INCLUDES) $(OPT) -Wall -fdata-sections -ffunction-sections

CFLAGS = $(MCU) $(C_DEFS) $(C_INCLUDES) $(OPT) -Wall -fdata-sections -ffunction-sections -Wint-to-pointer-cast

ifeq ($(DEBUG), yes)
CFLAGS += -g -gdwarf-2
endif

# Generate dependency information
CFLAGS += -MMD -MP -MF"$(@:%.o=%.d)"

#######################################
# LDFLAGS
#######################################

# libraries
LIBS += -lc -lm $(EXTRA_LIBS)

LIBDIR =

# TODO: xxx.map should be platform-specific 
LDFLAGS = $(MCU) $(LD_SPECS_FILE)  $(LDSCRIPT) $(LIBDIR) $(LIBS) -Wl,-Map=$<.map,--cref -Wl,--gc-sections




#######################################
# build the application
#######################################
# collect compiled objects from C source files
C_ASM_OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))
# collect compiled objects from assembly source files
C_ASM_OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.s=.o)))
vpath %.s $(sort $(dir $(ASM_SOURCES)))

# ----------------- Goals -------------------
gen_lib: $(BUILD_DIR)  $(TARGET_LIB_PATH)   

tests:  $(TARGET_LIB_PATH)  $(TEST_COMMON_OBJECTS)  $(TEST_ENTRY_OBJECTS) \
        $(foreach atest, $(TEST_ENTRY_OBJECTS), $(atest:.o=).elf  $(atest:.o=).hex  $(atest:.o=).text  $(atest:.o=).bin )

$(BUILD_DIR)/%.o: %.c makefile | $(BUILD_DIR) 
	$(CC) -c $(CFLAGS) -Wa,-a,-ad,-alms=$(BUILD_DIR)/$(notdir $(<:.c=.lst)) $< -o $@

$(BUILD_DIR)/%.o: %.s makefile | $(BUILD_DIR)
	$(AS) -c $(CFLAGS) $< -o $@

$(TARGET_LIB_PATH): $(C_ASM_OBJECTS)
	$(AR)  rcs $@  $^



# --------- for generating executable test cases ---------
%.elf:  %.o  $(TEST_COMMON_OBJECTS) $(TARGET_LIB_PATH)
	$(CC) $^  $(LDFLAGS) -o $@ 
	$(SZ) $@

%.hex: %.elf | $(BUILD_DIR)
	$(HEX) $< $@

%.bin: %.elf | $(BUILD_DIR)
	$(BIN) $< $@

%.text: %.elf | $(BUILD_DIR)
	$(DUMP) -Dh $< > $@

$(BUILD_DIR):
	@mkdir $@

#######################################
# clean up
#######################################
clean:
	-rm -fR $(BUILD_DIR)
  
download_3party:
	@make download_3party -C  third_party


# optional function for those who use code navigation tools e.g. ctags
update_navigator:
	@ctags -R ./generate ./include ./src ./tests ./third_party

dbg_server:
	@$(DBG_SERVER_CMD)

dbg_client:
	@$(DBG_CLIENT_CMD)




