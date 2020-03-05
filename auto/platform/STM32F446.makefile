#----------------------------------
# core functions of ESP_AT_parser
#----------------------------------

#--------------------------------------------------------
# fireware implementation of the STM32F446 Nucleo board
#--------------------------------------------------------

# C defines
C_DEFS +=  \
-DUSE_HAL_DRIVER \
-DSTM32F446xx 

# ASM sources
ASM_SOURCES += ./src/system/platform/arm/armv7m/stm/bootcode_stm32f446.s

C_DEFS += -DMQTT_CFG_PLATFORM_STM32F446

# link script
LDSCRIPT = -T./src/system/platform/arm/armv7m/stm/stm32f446_flash.ld

LD_SPECS_FILE = -specs=nano.specs

EXTRA_LIBS =  -lnosys

#------------------------------------------------
#                  toolchain setup
#------------------------------------------------
C_TOOLCHAIN_PREFIX = arm-none-eabi-

# cpu
CPU = -mcpu=cortex-m4

# fpu
FPU = -mfpu=fpv4-sp-d16

# float-abi
FLOAT-ABI = -mfloat-abi=hard

# mcu
CPU_ARCH_FLAGS = $(CPU) -mthumb $(FPU) $(FLOAT-ABI)

# Debug
OPENOCD_CFG_FILES =  -f $(OPENOCD_HOME)/tcl/board/st_nucleo_f4.cfg \
                     -f $(OPENOCD_HOME)/tcl/interface/stlink-v2-1.cfg 

REMOTE_DEBUGGER_CMD = openocd

DBG_SERVER_CMD = $(REMOTE_DEBUGGER_CMD) $(OPENOCD_CFG_FILES)  -c init -c "reset init"

GDB_CMD = gdb-multiarch

GDB_SCRIPT_PATH = ./auto/platform/utility.gdb

DBG_CLIENT_CMD = $(GDB_CMD) -x $(GDB_SCRIPT_PATH)


