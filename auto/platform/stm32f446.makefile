# TODO, move some parameters to demo (integration test) section
include  $(RTOS_HW_BUILD_PATH)/Inc/build-cfg/mk/hw/stm32f446.mk
include  $(RTOS_HW_BUILD_PATH)/Inc/build-cfg/mk/toolchain/gcc-arm-cortex-m4.mk

# GNU_CMD_PREFIX, HW_C_DEFS come from build system in RTOS_HW_BUILD_PATH
CC = $(GNU_CMD_PREFIX)gcc
AS = $(GNU_CMD_PREFIX)gcc -x assembler-with-cpp
AR = $(GNU_CMD_PREFIX)ar

C_DEFS +=  $(HW_C_DEFS) -DMQTT_CFG_PLATFORM_STM32F446

C_INCLUDES += $(addprefix -I, $(HW_C_INCLUDES)) \
			  $(addprefix -I, $(APPCFG_HW_C_INCLUDES)) \
			  -I$(MQC_PROJ_HOME)/include/system/platform/arm/armv7m/stm

LIB_C_SRCS += ./src/system/platform/arm/armv7m/stm/stm32f446.c \
			  ./src/system/platform/arm/armv7m/stm/system_stm32f4xx.c

#------------------------------------------------
#                  toolchain setup
#------------------------------------------------
# mcu
CPU_ARCH_FLAGS = $(GCC_MCU) # from remote toolchain make file

# Debug
OPENOCD_CFG_FILES =  -f $(OPENOCD_HOME)/tcl/board/st_nucleo_f4.cfg \
                     -f $(OPENOCD_HOME)/tcl/interface/stlink-v2-1.cfg 

REMOTE_DEBUGGER_CMD = openocd

DBG_SERVER_CMD = $(REMOTE_DEBUGGER_CMD) $(OPENOCD_CFG_FILES)  -c init -c "reset init"

GDB_CMD = $(GNU_CMD_PREFIX)gdb

GDB_SCRIPT_PATH = ./auto/platform/utility.gdb

DBG_CLIENT_CMD = $(GDB_CMD) -x $(GDB_SCRIPT_PATH)

