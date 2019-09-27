#ifndef MQTT_INCLUDE_H
#define MQTT_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

// DO NOT modify the order of extended header files which are included in this file, 
// otherwise you would end up with compile/runtime error

#include "mqtt/mqtt_types.h"
#include "mqtt/mqtt_util.h"
#include "mqtt/mqtt_auth.h"

// start checking the operating system / middleware used in the implementation
#if defined(MQTT_CFG_SYS_ESP_AT_PARSER)
    #include "system/middleware/ESP_AT_parser/mqtt_sys.h"
#else
#endif // end of middleware configuration


// start checking the hardware platform used in the implementation
#if defined(MQTT_CFG_PLATFORM_STM32F446)
    #include "system/platform/arm/armv7m/stm/stm32f446.h"
#else
    // TODO: support ARMv8A CPU
#endif // end of platform configuration

#include "mqtt/mqtt_packet.h"
#include "mqtt/mqtt_client_conn.h"
#include "system/mqtt_sys_common.h"



#ifdef __cplusplus
}
#endif
#endif // end of MQTT_INCLUDE_H


