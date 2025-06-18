
ifeq ($(MAKECMDGOALS), gen_lib)
	include  $(ESP_PROJ_HOME)/common.mk
	include  $(RTOS_HW_BUILD_PATH)/Inc/build-cfg/mk/os/$(OS).mk
	C_INCLUDES += -I$(MQC_PROJ_HOME)/include/system/middleware/ESP_AT_parser \
			      $(addprefix -I, $(APPCFG_MIDDLEWARE_C_INCLUDES)) \
				  $(addprefix -I, $(ESP_C_INCLUDES)) \
				  $(addprefix -I, $(OS_C_INCLUDES))
	LIB_C_SRCS += ./src/system/middleware/ESP_AT_parser/mqtt_sys.c
endif

$(info ----- MQTT ESP8266-AT-parser integration start -----)
$(info HW_PLATFORM : $(HW_PLATFORM))
$(info OS : $(OS))
$(info RTOS_HW_BUILD_PATH : $(RTOS_HW_BUILD_PATH))
$(info APP_NAME : $(APP_NAME))
$(info APP_BASEPATH : $(APP_BASEPATH))
$(info TOOLCHAIN_BASEPATH : $(TOOLCHAIN_BASEPATH))
$(info ESP_PROJ_HOME : $(ESP_PROJ_HOME))
FILTERED_GOALS = $(strip $(filter utest_helper clean config, $(MAKECMDGOALS)))
$(info FILTERED_GOALS : $(FILTERED_GOALS))
$(info ----- MQTT ESP8266-AT-parser integration end -----)

demo:
	@make buildapp APP_BASEPATH=$(MQC_PROJ_HOME)/tests/integration

buildapp: export MQC_PROJ_HOME := $(MQC_PROJ_HOME)
buildapp: export ESP_PROJ_HOME := $(ESP_PROJ_HOME)
buildapp: export RTOS_HW_BUILD_PATH := $(RTOS_HW_BUILD_PATH)
buildapp: export TARGET_LIB_PATH := $(TARGET_LIB_PATH)
buildapp: export THIRD_PARTY_LIBS_PATH := $(THIRD_PARTY_LIBS_PATH)
buildapp:
	@make -C $(RTOS_HW_BUILD_PATH)  startbuild \
          DEBUG=$(DEBUG)  BUILD_DIR=$(MQC_PROJ_HOME)/$(BUILD_DIR) OS=$(OS) \
		  HW_PLATFORM=$(HW_PLATFORM) APP_NAME=$(APP_NAME) APPCFG_PATH=$(APP_BASEPATH) \
		  TOOLCHAIN_BASEPATH=$(TOOLCHAIN_BASEPATH)


