#ifndef __ESP_CONFIG_H
#define __ESP_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#define  ESP_CFG_DEV_ESP01  1
// in this project we apply ESP-01, FreeRTOS port for STM32 Cortex-M4, turn off AT echo function
#define  ESP_CFG_SYS_PORT   ESP_SYS_PORT_FREERTOS
#define  ESP_CFG_PING       1

// specify hardware reset pin instead of running AT+RST command
#define  ESP_CFG_RST_PIN

// initialize underlying platform (especially UART Tx/Rx) every time when  reset function is called.
#define  ESP_CFG_PLATFORM_REINIT_ON_RST

// DO NOT automatically reset / restore ESP device in eESPinit()
// we will do it manually separately
#define  ESP_CFG_RESTORE_ON_INIT  0
#define  ESP_CFG_RST_ON_INIT      0

// used FreeRTOS heap memory functions here because it seems more stable than
// the memory functions provided by cross-compile toolchain.
#define  ESP_MALLOC( sizebytes )         pvPortMalloc( (size_t)(sizebytes) )
#define  ESP_MEMFREE( mptr )             vPortFree( (void *)(mptr) )
#define  ESP_CALLOC( nmemb, size )       pvPortCalloc( nmemb, (size_t)(size) )
#define  ESP_REALLOC( memptr, newsize)   pvPortRealloc( memptr, (size_t)(newsize) )

#ifdef __cplusplus
}
#endif
#endif // end of  __ESP_CONFIG_H 

