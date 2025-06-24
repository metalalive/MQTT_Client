ifneq ($(strip $(filter gen_lib buildapp, $(MAKECMDGOALS))), )
	include  $(ESP_PROJ_HOME)/common.mk
	include  $(RTOS_HW_BUILD_PATH)/Inc/build-cfg/mk/os/$(OS).mk
	C_HEADERS_PATHS += $(MQC_PROJ_HOME)/include/system/middleware/ESP_AT_parser \
			      $(APPCFG_MIDDLEWARE_C_INCLUDES) \
				  $(ESP_C_INCLUDES)  $(OS_C_INCLUDES)
endif

ifeq ($(MAKECMDGOALS), gen_lib)
	LIB_C_SRCS += ./src/system/middleware/ESP_AT_parser/mqtt_sys.c
endif

# $(info ----- MQTT ESP8266-AT-parser integration start -----)
# $(info HW_PLATFORM : $(HW_PLATFORM))
# $(info OS : $(OS))
# $(info RTOS_HW_BUILD_PATH : $(RTOS_HW_BUILD_PATH))
# $(info APP_NAME : $(APP_NAME))
# $(info APP_BASEPATH : $(APP_BASEPATH))
# $(info TOOLCHAIN_BASEPATH : $(TOOLCHAIN_BASEPATH))
# $(info ESP_PROJ_HOME : $(ESP_PROJ_HOME))
# FILTERED_GOALS = $(strip $(filter utest_helper clean config, $(MAKECMDGOALS)))
# $(info FILTERED_GOALS : $(FILTERED_GOALS))
# $(info ----- MQTT ESP8266-AT-parser integration end -----)

_APPCFG_LIBS_PATHS = $(MQC_PROJ_HOME)/$(TARGET_LIB_PATH) \
					 $(addprefix $(MQC_PROJ_HOME)/, $(THIRD_PARTY_LIBS_PATH))

# Get the list of application names from TEST_ENTRY_SOURCES
# TEST_ENTRY_SOURCES is defined in the main makefile, which includes this one.
# We need to strip the path and the .c extension.
DEMO_APPS_NAME = $(patsubst %.c,%,$(notdir $(TEST_ENTRY_SOURCES)))

demo:
	@echo "Building demo applications: $(DEMO_APPS_NAME)"
	@for appn in $(DEMO_APPS_NAME); do \
		echo "--- Building $$app ---"; \
		$(MAKE) buildapp \
			DEBUG=$(DEBUG) OS=$(OS)  HW_PLATFORM=$(HW_PLATFORM) \
			RTOS_HW_BUILD_PATH=$(RTOS_HW_BUILD_PATH) \
			TOOLCHAIN_BASEPATH=$(TOOLCHAIN_BASEPATH) \
			ESP_PROJ_HOME=$(ESP_PROJ_HOME) \
			APP_NAME=$$appn \
			APP_BASEPATH=$(MQC_PROJ_HOME)/tests/integration; \
	done

buildapp: export MQC_PROJ_HOME := $(MQC_PROJ_HOME)
buildapp: export ESP_PROJ_HOME := $(ESP_PROJ_HOME)
buildapp: export RTOS_HW_BUILD_PATH := $(RTOS_HW_BUILD_PATH)
buildapp: export APP_REQUIRED_C_HEADER_PATHS := $(C_HEADERS_PATHS)
buildapp: export APP_REQUIRED_C_SOURCE_FILES := $(ESP_C_SOURCES)
buildapp:
	@make -C $(RTOS_HW_BUILD_PATH)  startbuild \
          DEBUG=$(DEBUG)  BUILD_DIR=$(MQC_PROJ_HOME)/$(BUILD_DIR) OS=$(OS) \
		  HW_PLATFORM=$(HW_PLATFORM) APP_NAME=$(APP_NAME) APPCFG_PATH=$(APP_BASEPATH) \
		  TOOLCHAIN_BASEPATH=$(TOOLCHAIN_BASEPATH) \
		  APPCFG_LIBS_PATHS="$(_APPCFG_LIBS_PATHS)"

