ITEST_REL_PATH = tests/integration
ITEST_FULLPATH = $(MQC_PROJ_HOME)/$(ITEST_REL_PATH)

include  $(ITEST_FULLPATH)/cfg-os-hw/config.mk

include  $(ESP_PROJ_HOME)/common.mk
include  $(RTOS_HW_BUILD_PATH)/Inc/build-cfg/mk/os/$(OS).mk

APPCFG_C_INCLUDES = \
	$(MQC_PROJ_HOME)/include \
	$(MQC_PROJ_HOME)/generate/include \
	$(MQC_PROJ_HOME)/third_party/libtomcrypt/src/headers \
	$(MQC_PROJ_HOME)/third_party/libtommath \
	$(MQC_PROJ_HOME)/include/system/middleware/ESP_AT_parser \
    $(ESP_C_INCLUDES) \
	$(OS_C_INCLUDES) \
	$(APPCFG_MIDDLEWARE_C_INCLUDES) \
    $(APPCFG_HW_C_INCLUDES)

# TODO, FIXME, remove redundant variables
TEST_COMMON_SOURCES = $(ITEST_REL_PATH)/pattern_generator.c \
					  generate/src/mqtt_generate.c

APPCFG_C_SOURCES = \
	$(ITEST_FULLPATH)/$(APP_NAME).c \
	$(addprefix $(MQC_PROJ_HOME)/, $(TEST_COMMON_SOURCES)) \
	$(HW4TST_C_SOURCES) \
	$(ESP_C_SOURCES)

APPCFG_LIBS_PATHS = \
	$(MQC_PROJ_HOME)/$(TARGET_LIB_PATH) \
	$(addprefix $(MQC_PROJ_HOME)/, $(THIRD_PARTY_LIBS_PATH))

