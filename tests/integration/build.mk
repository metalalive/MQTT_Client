ITEST_REL_PATH = tests/integration
ITEST_FULLPATH = $(MQC_PROJ_HOME)/$(ITEST_REL_PATH)

include  $(ITEST_FULLPATH)/cfg-os-hw/config.mk

APPCFG_C_INCLUDES = \
	$(APP_REQUIRED_C_HEADER_PATHS) \
	$(APPCFG_MIDDLEWARE_C_INCLUDES) \
    $(APPCFG_HW_C_INCLUDES)

TEST_COMMON_SOURCES = $(ITEST_REL_PATH)/pattern_generator.c \
					  generate/src/mqtt_generate.c

APPCFG_C_SOURCES = \
	$(APP_REQUIRED_C_SOURCE_FILES) \
	$(ITEST_FULLPATH)/$(APP_NAME).c \
	$(addprefix $(MQC_PROJ_HOME)/, $(TEST_COMMON_SOURCES)) \
	$(HW4TST_C_SOURCES)

# append more paths for libraries to build-in variable `APPCFG_LIBS_PATHS`
# for application requirement .

#$(info EXTRA_C_DEFS : $(EXTRA_C_DEFS))
#$(info APPCFG_C_DEFS : $(APPCFG_C_DEFS))

