######################################
# building variables
######################################

# extra defined parameters users want to specify
PLUS_C_DEFS ?= 

DEBUG ?= no

######################################
# source
######################################
# C sources
C_SOURCES =  \
src/mqtt/mqtt_client_conn.c \
src/mqtt/mqtt_packet.c      \
src/mqtt/mqtt_util.c        \
src/mqtt/mqtt_drbg.c        \
src/mqtt/mqtt_auth.c        \
src/tls/core/tls_util.c           \
src/tls/core/tls_client.c         \
src/tls/core/tls_handshake.c      \
src/tls/core/tls_hkdf.c           \
src/tls/core/tls_key_exchange.c   \
src/tls/core/tls_key_schedule.c   \
src/tls/core/tls_pkt_decode.c     \
src/tls/core/tls_pkt_decode_ext.c \
src/tls/core/tls_pkt_encode.c     \
src/tls/core/tls_pkt_encode_ext.c \
src/tls/core/tls_pkt_transmit.c   \
src/tls/crypto/tls_ciphersuite.c  \
src/tls/crypto/tls_encrypt.c      \
src/tls/crypto/tls_hash.c         \
src/tls/crypto/tls_asn1.c         \
src/tls/crypto/tls_x509.c         \
src/tls/crypto/tls_x509_ext.c     \
src/tls/crypto/tls_certs.c        \
src/tls/crypto/tls_rsa.c          \


# ASM sources
ASM_SOURCES = 

# macros for gcc
# AS defines
AS_DEFS = 

# C defines
C_DEFS = $(foreach def, $(PLUS_C_DEFS), $(addprefix -D, $(def)) )

# C includes
C_INCLUDES = -Iinclude \

BUILD_DIR_TOP=build

# include generated build script
include  ./generate/auto/makefile

ifeq ($(MAKECMDGOALS), utest_helper)
    include  ./auto/middleware/unknown.makefile
else  # if unit test is NOT enabled
    #### include hardware platfrom specific files, (NOTE) don't use cross-compile toolchain in unit test
    include  ./auto/platform/$(PLATFORM).makefile
    #### include middleware files, the middleware can be any API software integrated
    #### with OS (e.g. RTOS, Linux kernel) .
    include  ./auto/middleware/$(MIDDLEWARE).makefile
    include  ./generate/auto/after_cfg.makefile
endif

#---------------------------------------------------------
# different files & paths for unit test, integration test 
#---------------------------------------------------------

ifeq ($(MAKECMDGOALS), utest_helper) # if unit test is enabled
# TODO: complete unit test after completing integration tests.
    BUILD_DIR=$(BUILD_DIR_TOP)/utest
    TEST_ENTRY_SOURCES += $(addprefix tests/unit/, $(C_SOURCES:src/%.c=%_ut.c))
else
    BUILD_DIR=$(BUILD_DIR_TOP)/itest
    ifeq ($(MAKECMDGOALS), itest) # if make goal is 'test', then it is integration test
        TEST_COMMON_SOURCES = tests/integration/pattern_generator.c \
                              generate/src/mqtt_generate.c
        TEST_ENTRY_SOURCES += tests/integration/mqtt_pub_subs_test.c \
                              tests/integration/mqtt_connect_test.c \
                              tests/integration/mqtt_publish_test.c \
                              tests/integration/mqtt_subscribe_test.c \
                              tests/integration/rand.c
        C_INCLUDES += -Itests/integration
    endif #### end of itest
endif #### end of utest_helper


TEST_ENTRY_OBJECTS  = $(addprefix $(BUILD_DIR)/,$(notdir $(TEST_ENTRY_SOURCES:.c=.o)))
TEST_COMMON_OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(TEST_COMMON_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(TEST_ENTRY_SOURCES)))
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
    CCOV = $(GCC_PATH)/$(C_TOOLCHAIN_PREFIX)gcov
    DUMP = $(GCC_PATH)/$(C_TOOLCHAIN_PREFIX)objdump
else
    CC = $(C_TOOLCHAIN_PREFIX)gcc
    AS = $(C_TOOLCHAIN_PREFIX)gcc -x assembler-with-cpp
    CP = $(C_TOOLCHAIN_PREFIX)objcopy
    SZ = $(C_TOOLCHAIN_PREFIX)size
    AR = $(C_TOOLCHAIN_PREFIX)ar
    CCOV = $(C_TOOLCHAIN_PREFIX)gcov
    DUMP = $(C_TOOLCHAIN_PREFIX)objdump
endif

HEX = $(CP) -O ihex

BIN = $(CP) -O binary -S

# optimization
OPT = -Og

# compile gcc flags
ASFLAGS += $(CPU_ARCH_FLAGS) $(AS_DEFS) $(AS_INCLUDES) $(OPT) -Wall -fdata-sections -ffunction-sections

CFLAGS += $(CPU_ARCH_FLAGS) $(C_DEFS) $(C_INCLUDES) $(OPT) -Wall -fdata-sections -ffunction-sections -Wint-to-pointer-cast

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
LDFLAGS = $(CPU_ARCH_FLAGS) $(LD_SPECS_FILE)  $(LDSCRIPT) $(LIBDIR) $(LIBS) -Wl,-Map=$<.map,--cref -Wl,--gc-sections

ifeq ($(MAKECMDGOALS), utest_helper) # if unit test is enabled
CFLAGS  += -coverage
LDFLAGS += -coverage
endif


#######################################
# build the application
#######################################
# collect C/assembly objects compiled for library (may be built by cross-compile toolchain)
C_ASM_OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

C_ASM_OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.s=.o)))
vpath %.s $(sort $(dir $(ASM_SOURCES)))

ifeq ($(MAKECMDGOALS), itest) # only link the library when building images for integration test
    TARGET_LIB_NAME=libmqttclient.a
    TARGET_LIB_PATH=$(BUILD_DIR)/$(TARGET_LIB_NAME)
endif


# ----------------- Goals -------------------
gen_lib: $(BUILD_DIR)  $(TARGET_LIB_PATH)

# for unit test, no need to build library and test images using cross-compiler
# TODO: for few integration tests, no need to build test images with cross-compiler
itest : $(TARGET_LIB_PATH)  $(TEST_COMMON_OBJECTS)  $(TEST_ENTRY_OBJECTS) \
        $(foreach atest, $(TEST_ENTRY_OBJECTS), $(atest:.o=).elf  $(atest:.o=).hex  $(atest:.o=).text  $(atest:.o=).bin)
	@rm -rf $(BUILD_DIR_TOP)/$(TARGET_LIB_NAME);
	@ln -s  itest/$(TARGET_LIB_NAME)  $(BUILD_DIR_TOP)/$(TARGET_LIB_NAME);

utest_helper : $(C_ASM_OBJECTS) $(TEST_COMMON_OBJECTS)  $(TEST_ENTRY_OBJECTS)
	$(foreach atest, $(TEST_ENTRY_OBJECTS), $(CC) $(LDFLAGS) $(atest) $(atest:%_ut.o=%.o) $(TEST_COMMON_OBJECTS) -o $(atest:.o=.out);)
	$(foreach atest, $(TEST_ENTRY_OBJECTS), $(atest:.o=.out);)

utest:
	@make file_subst -C third_party;
	@make utest_helper DEBUG=$(DEBUG);

$(BUILD_DIR)/%.o: %.c makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -Wa,-a,-ad,-alms=$(BUILD_DIR)/$(notdir $(<:.c=.lst)) $< -o $@

$(BUILD_DIR)/%.o: %.s makefile | $(BUILD_DIR)
	$(AS) -c $(CFLAGS) $< -o $@

$(TARGET_LIB_PATH): $(C_ASM_OBJECTS)
	$(AR)  rcs $@  $^



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

$(BUILD_DIR):
	@mkdir -p $@

#######################################
# clean up
#######################################
clean:
	-rm -fR $(BUILD_DIR_TOP)
  
download_3party:
	@make download_3party -C  third_party

# TODO: configure will read through all configuration options in configuration file
config:


# optional function for those who use code navigation tools e.g. ctags
update_navigator:
	@rm -rf ./tags; ctags -R ./generate ./include ./src ./tests/integration ./third_party

dbg_server:
	@$(DBG_SERVER_CMD)

dbg_client:
	@$(DBG_CLIENT_CMD)




