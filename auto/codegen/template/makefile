OPENOCD_HOME ?= /PATH/TO/YOUR_OPENOCD_INSTALL

MIDDLEWARE ?= {{{ middleware.value }}}

HW_PLATFORM ?= unknown

COMMON_3PARTY_DOWNLOAD_CMD = {{{ *.metadata.cmd.download@ListAppendSemicolon }}}

COMMON_3PARTY_FILE_SUBST_CMD = {{{ *.metadata.cmd.substitute@ListAppendSemicolon }}}

COMMON_3PARTY_CLEAN_BUILT_CMD = {{{*.metadata.cmd.clean@ListAppendSemicolon }}}

C_INCLUDES += -Igenerate/include {{{ cryptolib.metadata.path.include.compile@GCCincludeOpt }}}

ifeq ($(MAKECMDGOALS), utest_helper)
    C_INCLUDES          += {{{ unitestlib.metadata.path.include.compile@GCCincludeOpt }}}
    TEST_COMMON_SOURCES += {{{ *.metadata.path.src.unittest@ListAppendWhitespace }}}
else
    # built third-party libraries that will be used in linking process of a test image
    THIRD_PARTY_LIBS_PATH = {{{ *.metadata.path.include.libs@ListAppendWhitespace }}}
endif # end of if MAKECMDGOALS is utest_helper

ifeq ($(strip $(filter utest_helper clean config, $(MAKECMDGOALS))), )
    #### include hardware platfrom specific files, (NOTE) don't use cross-compile toolchain in unit test
    include  ${PWD}/auto/platform/$(HW_PLATFORM).makefile
    #### include middleware files, the middleware can be any API software integrated
    #### with OS (e.g. RTOS, Linux kernel) .
    include  ${PWD}/auto/middleware/$(MIDDLEWARE).makefile
else  # when running unit-test, clean, config
    include  ${PWD}/auto/middleware/unknown.makefile
endif

COMMON_3PARTY_BUILD_CMD = {{{ *.metadata.cmd.build@ListAppendSemicolon }}}

