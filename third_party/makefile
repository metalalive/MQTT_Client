EXTRA_C_DEFS ?=

DEBUG ?= no

ifeq ($(DEBUG), yes)
DBGCFLAGS = -g -gdwarf-2
endif

include  ../generate/auto/makefile


gen_lib: file_subst
	$(COMMON_3PARTY_BUILD_CMD)

file_subst:
	$(COMMON_3PARTY_FILE_SUBST_CMD)

clean:
	$(COMMON_3PARTY_CLEAN_BUILT_CMD)

download_3party:
	@$(COMMON_3PARTY_DOWNLOAD_CMD)


