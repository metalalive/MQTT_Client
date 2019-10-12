#ifndef MQTT_SYS__ESP_AT_PARSER_H
#define MQTT_SYS__ESP_AT_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "esp/esp.h"

// macros used in core implementation of the MQTT client
#define  XMEMSET   ESP_MEMSET

#define  XMALLOC   ESP_MALLOC

#define  XMEMCPY   ESP_MEMCPY

#define  XMEMFREE  ESP_MEMFREE

#define  XSTRLEN   ESP_STRLEN

#define  XASSERT  ESP_ASSERT

// minimum application thread priority
#define  MQTT_APPS_THREAD_PRIO_MIN   ESP_APPS_THREAD_PRIO
// maximum timeout in milliseconds for core implementation & test
#define  MQTT_SYS_MAX_TIMEOUT        ESP_SYS_MAX_TIMEOUT 


// data types used in core implementation of the MQTT client
typedef  espSysThreFunc  mqttSysThreFn;

typedef  espSysThread_t  mqttSysThre_t;

#ifdef __cplusplus
}
#endif
#endif // end of MQTT_SYS__ESP_AT_PARSER_H 
