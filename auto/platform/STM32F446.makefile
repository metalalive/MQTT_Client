#----------------------------------
# core functions of ESP_AT_parser
#----------------------------------
PLATFORM_3PARTY_DOWNLOAD_CMD =  

PLATFORM_3PARTY_HOME:=third_party/ESP8266_AT_parser/Drivers/

#--------------------------------------------------------
# fireware implementation of the STM32F446 Nucleo board
#--------------------------------------------------------
C_SOURCES +=  \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_tim.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_tim_ex.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_uart.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_rcc.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_rcc_ex.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_flash.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_flash_ex.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_flash_ramfunc.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_gpio.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_dma_ex.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_dma.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_pwr.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_pwr_ex.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_cortex.c \
    $(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Src/stm32f4xx_hal.c \


# C includes
C_INCLUDES +=  \
-I$(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Inc \
-I$(PLATFORM_3PARTY_HOME)STM32F4xx_HAL_Driver/Inc/Legacy \
-I$(PLATFORM_3PARTY_HOME)CMSIS/Device/ST/STM32F4xx/Include \
-I$(PLATFORM_3PARTY_HOME)CMSIS/Include \


# C defines
C_DEFS +=  \
-DUSE_HAL_DRIVER \
-DSTM32F446xx 

#------------------------------------------------
# integration files for this MQTT implementation
#------------------------------------------------
C_SOURCES +=  \
    ./src/system/platform/arm/armv7m/stm/stm32f446.c         \
    ./src/system/platform/arm/armv7m/stm/system_stm32f4xx.c 

# ASM sources
ASM_SOURCES += ./src/system/platform/arm/armv7m/stm/bootcode_stm32f446.s

C_INCLUDES +=  -Iinclude/system/platform/arm/armv7m/stm

C_DEFS += -DMQTT_CFG_PLATFORM_STM32F446

# link script
LDSCRIPT = ./src/system/platform/arm/armv7m/stm/stm32f446_flash.ld


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
MCU = $(CPU) -mthumb $(FPU) $(FLOAT-ABI)

# Debug
OPENOCD_CFG_FILES =  -f $(OPENOCD_HOME)/tcl/board/st_nucleo_f4.cfg \
                     -f $(OPENOCD_HOME)/tcl/interface/stlink-v2-1.cfg 

REMOTE_DEBUGGER_CMD = openocd

DBG_SERVER_CMD = $(REMOTE_DEBUGGER_CMD) $(OPENOCD_CFG_FILES)  -c init -c "reset init"

GDB_CMD = gdb-multiarch

GDB_SCRIPT_PATH = ./auto/platform/utility.gdb

DBG_CLIENT_CMD = $(GDB_CMD) -x $(GDB_SCRIPT_PATH)


