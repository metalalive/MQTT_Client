GENED_CODE_BASEPATH = $(MQC_PROJ_HOME)/generate

GENED_SUB_FOLDERS = auto include src

GENED_FULLPATHS = $(addprefix $(GENED_CODE_BASEPATH)/, $(GENED_SUB_FOLDERS))

config:
	@mkdir -p  $(GENED_FULLPATHS)
	@python3 codegen.py

clean:
	@rm -rf  $(GENED_FULLPATHS)

