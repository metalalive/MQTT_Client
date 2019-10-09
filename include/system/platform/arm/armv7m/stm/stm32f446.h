#ifndef MQTT_PLATFORM_ARM_V7M_STM32F446_H
#define MQTT_PLATFORM_ARM_V7M_STM32F446_H

#ifdef __cplusplus
extern "C" {
#endif

// these come from third-party STM32CubeMX library
#include "stm32f4xx_hal.h"
#include "stm32f4xx_hal_tim.h"

// maximum number of payload bytes that can be stored & handled in the memory of this platform
#define  MQTT_PLATFORM_PKT_MAXBYTES   2880


// enable function that receives raw bytes in the platform
mqttRespStatus   mqttPlatformPktRecvEnable( void );

mqttRespStatus   mqttPlatformPktRecvDisable( void );

// send packet out
mqttRespStatus  mqttPlatformPktSend( void* data, size_t len, uint32_t timeout );

// reset network module in the platform, optional function for those MCU board which
// externally wires to another network device e.g. ESP wifi module.
mqttRespStatus  mqttPlatformNetworkModRst( uint8_t state );

// hardware random number generator, developers can wire any external device (e.g. sersor) 
// to their target embedded system board generate source of random number
word32  mqttPlatformRNG( word32 maxnum );

mqttRespStatus  mqttPlatformInit( void );

mqttRespStatus  mqttPlatformDeInit( void );


#ifdef __cplusplus
}
#endif
#endif // end of MQTT_PLATFORM_ARM_V7M_STM32F446_H

