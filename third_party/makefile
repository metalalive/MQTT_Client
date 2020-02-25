PLUS_C_DEFS ?=

DEBUG ?= no

ifeq ($(DEBUG), yes)
DBGCFLAGS = -g -gdwarf-2
endif

include  ../generate/auto/before_cfg.makefile

include  ../auto/platform/$(PLATFORM).makefile

include  ../auto/middleware/$(MIDDLEWARE).makefile

include  ../generate/auto/after_cfg.makefile

gen_lib: file_subst
	$(COMMON_3PARTY_BUILD_CMD)

file_subst:
	$(COMMON_3PARTY_FILE_SUBST_CMD)

clean:
	$(COMMON_3PARTY_CLEAN_BUILT_CMD)

download_3party:
	@$(MIDDLEWARE_3PARTY_DOWNLOAD_CMD)
	@$(PLATFORM_3PARTY_DOWNLOAD_CMD)
	@$(COMMON_3PARTY_DOWNLOAD_CMD)


