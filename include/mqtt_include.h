#ifndef MQTT_INCLUDE_H
#define MQTT_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

// DO NOT modify the order of extended header files which are included in this file,
// otherwise you would end up with compile/runtime error

// header which collects all include files of common third-party libraries
#include "mqtt_third_party_include.h"

#include "mqtt/mqtt_types.h"
#include "mqtt/mqtt_util.h"
#include "mqtt/mqtt_drbg.h"
#include "mqtt/mqtt_auth.h"

// checking the operating system / middleware used in the implementation
#include "mqtt_sys.h"

// start checking the hardware platform used in the implementation
#if defined(MQTT_CFG_PLATFORM_STM32F446)
    #include "system/platform/arm/armv7m/stm/stm32f446.h"
#else
// TODO: support ARMv8A CPU
#endif // end of platform configuration

#include "mqtt/mqtt_packet.h"
#include "mqtt/mqtt_client_conn.h"
#include "system/mqtt_sys_common.h"

#ifdef MQTT_CFG_USE_TLS
    #if defined(MQTT_CFG_ENABLE_TLS_V1_3)
        #include "tls/tls_include.h"
    #else
        #error \
            "There must be at least one version of TLS protocol to be enabled if MQTT_CFG_USE_TLS is defined."
    #endif // end of MQTT_CFG_ENABLE_TLS_V1_3
#endif     // end of MQTT_CFG_USE_TLS

#ifdef __cplusplus
}
#endif
#endif // end of MQTT_INCLUDE_H
