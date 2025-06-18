######################################
# building variables
######################################

# extra defined parameters users want to specify
EXTRA_C_DEFS ?=

DEBUG ?= no

MQC_PROJ_HOME = $(shell pwd)

######################################
# source
######################################
# C sources
LIB_C_SRCS =  \
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
src/tls/crypto/tls_rsa.c

# macros for gcc
AS_DEFS = 

C_DEFS = $(foreach def, $(EXTRA_C_DEFS), $(addprefix -D, $(def)) )

C_INCLUDES = -Iinclude

BUILD_DIR=build

#---------------------------------------------------------
# different files & paths for unit test, integration test 
#---------------------------------------------------------

ifeq ($(MAKECMDGOALS), utest_helper) # if unit test is enabled
    TEST_ENTRY_SOURCES = $(addprefix tests/unit/, $(LIB_C_SRCS:src/%.c=%_ut.c))
else
    ifeq ($(MAKECMDGOALS), demo)
        TEST_COMMON_SOURCES = tests/integration/pattern_generator.c \
                              generate/src/mqtt_generate.c
        TEST_ENTRY_SOURCES = tests/integration/mqtt_pub_subs.c \
                             tests/integration/mqtt_connect.c \
                             tests/integration/mqtt_publish.c \
                             tests/integration/mqtt_subscribe.c \
                             tests/integration/rand.c
        C_INCLUDES += -Itests/integration
    endif #### end of demo
endif #### end of utest_helper


TEST_ENTRY_OBJECTS  = $(addprefix $(BUILD_DIR)/, $(TEST_ENTRY_SOURCES:.c=.o))
TEST_COMMON_OBJECTS = $(addprefix $(BUILD_DIR)/, $(TEST_COMMON_SOURCES:.c=.o))
vpath %.c $(sort $(dir $(TEST_ENTRY_SOURCES)))
vpath %.c $(sort $(dir $(TEST_COMMON_SOURCES)))

# ----
TARGET_LIB_NAME=libmqttclient.a
TARGET_LIB_PATH=$(BUILD_DIR)/$(TARGET_LIB_NAME)

# ----
ifdef APPCFG_BASEPATH
	include  $(APPCFG_BASEPATH)/config.mk
endif
# include generated build script
include  ./generate/auto/makefile

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
# linking flags
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
LIB_C_OBJS = $(addprefix $(BUILD_DIR)/, $(LIB_C_SRCS:.c=.o))
vpath %.c $(sort $(dir $(LIB_C_SRCS)))

ITEST_ASM_OBJS = $(addprefix $(BUILD_DIR)/, $(ITEST_ASM_SRCS:.s=.o))
vpath %.s $(sort $(dir $(ITEST_ASM_SRCS)))

# ----------------- Goals -------------------

$(BUILD_DIR)/%.o: %.c makefile | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -Wa,-a,-ad,-alms=$(BUILD_DIR)/$(<:.c=.lst) $< -o $@

$(BUILD_DIR)/%.o: %.s makefile | $(BUILD_DIR)
	$(AS) -c $(CFLAGS) $< -o $@

$(TARGET_LIB_PATH): $(LIB_C_OBJS)
	$(AR)  rcs $@  $^

gen_lib: $(BUILD_DIR)  $(TARGET_LIB_PATH)

utest_helper : $(LIB_C_OBJS) $(TEST_COMMON_OBJECTS)  $(TEST_ENTRY_OBJECTS)
	$(foreach atest, $(TEST_ENTRY_OBJECTS), $(CC) $(LDFLAGS) $(atest) $(atest:%_ut.o=%.o) $(TEST_COMMON_OBJECTS) -o $(atest:.o=.out);)
	$(foreach atest, $(TEST_ENTRY_OBJECTS), $(atest:.o=.out);)

# for unit test, no need to build library and test images using cross-compiler
utest:
	@make file_subst -C third_party;
	@make utest_helper EXTRA_C_DEFS="MQTT_UNIT_TEST_MODE" DEBUG=$(DEBUG);


$(BUILD_DIR):
	@mkdir -p $@

clean:
	@rm -fR $(BUILD_DIR)
  
download_3party:
	@make download_3party -C  third_party

config:
	@make config -C  auto/codegen/script

dbg_server:
	@$(DBG_SERVER_CMD)

dbg_client:
	@$(DBG_CLIENT_CMD)

