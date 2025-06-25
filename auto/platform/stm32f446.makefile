include  $(RTOS_HW_BUILD_PATH)/Inc/build-cfg/mk/hw/stm32f446.mk
include  $(RTOS_HW_BUILD_PATH)/Inc/build-cfg/mk/toolchain/gcc-arm-cortex-m4.mk

# GNU_CMD_PREFIX, HW_C_DEFS come from build system in RTOS_HW_BUILD_PATH
CC = $(GNU_CMD_PREFIX)gcc
AS = $(GNU_CMD_PREFIX)gcc -x assembler-with-cpp
AR = $(GNU_CMD_PREFIX)ar

C_DEFS +=  $(HW_C_DEFS) -DMQTT_CFG_PLATFORM_STM32F446

C_HEADERS_PATHS += $(HW_C_INCLUDES)  $(APPCFG_HW_C_INCLUDES) \
			  $(MQC_PROJ_HOME)/include/system/platform/arm/armv7m/stm

LIB_C_SRCS += ./src/system/platform/arm/armv7m/stm/stm32f446.c \
			  ./src/system/platform/arm/armv7m/stm/system_stm32f4xx.c

#------------------------------------------------
#                  toolchain setup
#------------------------------------------------
# mcu
CPU_ARCH_FLAGS = $(GCC_MCU) # from remote toolchain make file

# Debug
DBG_SERVER_CMD = make dbg_server  -C $(RTOS_HW_BUILD_PATH)

GDB_SCRIPT_PATH ?= ./auto/platform/utility.gdb

DBG_CLIENT_CMD = $(GNU_CMD_PREFIX)gdb -x $(GDB_SCRIPT_PATH)

