OPENOCD_HOME ?= /PATH/TO/YOUR_OPENOCD_INSTALL

MIDDLEWARE ?= {{{ middleware.value }}}

# Middleware-specific configuration parameters (will be empty if not set in mqttclient.conf)

HW_PLATFORM ?= {{{ hw_platform.value }}}
OS ?= {{{ os.value }}}

RTOS_HW_BUILD_PATH ?= {{{ rtos_hw_build_path.value }}}

TOOLCHAIN_BASEPATH ?= {{{ toolchain_basepath.value }}}

ESP_PROJ_HOME ?= {{{ esp_proj_home.value }}}

COMMON_3PARTY_DOWNLOAD_CMD = {{{ *.metadata.cmd.download@ListAppendSemicolon }}}

COMMON_3PARTY_FILE_SUBST_CMD = {{{ *.metadata.cmd.substitute@ListAppendSemicolon }}}

COMMON_3PARTY_CLEAN_BUILT_CMD = {{{*.metadata.cmd.clean@ListAppendSemicolon }}}

COMMON_C_HEADER_PATHS = include  generate/include \
	{{{ cryptolib.metadata.path.include.compile@ListAppendWhitespace }}}

C_HEADERS_PATHS += $(addprefix $(MQC_PROJ_HOME)/, $(COMMON_C_HEADER_PATHS))

ifeq ($(MAKECMDGOALS), utest_helper)
    C_HEADERS_PATHS     += {{{ unitestlib.metadata.path.include.compile@ListAppendWhitespace }}}
    TEST_COMMON_SOURCES += {{{ *.metadata.path.src.unittest@ListAppendWhitespace }}}
else
    # built third-party libraries that will be used in linking process of a test image
    THIRD_PARTY_LIBS_PATH = {{{ *.metadata.path.include.libs@ListAppendWhitespace }}}
endif # end of if MAKECMDGOALS is utest_helper

_EXCLUDE_CMDS_MIDDLEWARE_INCLUDE = utest utest_helper clean config

ifeq ($(strip $(filter $(_EXCLUDE_CMDS_MIDDLEWARE_INCLUDE), $(MAKECMDGOALS))), )
    #### include hardware platfrom specific files, (NOTE) don't use cross-compile toolchain in unit test
    include  ${PWD}/auto/platform/$(HW_PLATFORM).makefile
    #### include middleware files, the middleware can be any API software integrated
    #### with OS (e.g. RTOS, Linux kernel) .
    include  ${PWD}/auto/middleware/$(MIDDLEWARE).makefile
else  # when running unit-test, clean, config
    include  ${PWD}/auto/middleware/unknown.makefile
endif

COMMON_3PARTY_BUILD_CMD = {{{ *.metadata.cmd.build@ListAppendSemicolon }}}

