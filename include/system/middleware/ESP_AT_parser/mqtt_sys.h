#ifndef MQTT_SYS__ESP_AT_PARSER_H
#define MQTT_SYS__ESP_AT_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "esp/esp.h"

// macros used in core implementation of the MQTT client
#define  MQTT_SYS_PKT_MAXBYTES  4000

#undef   XMALLOC
#define  XMALLOC   ESP_MALLOC

#undef   XCALLOC
#define  XCALLOC   ESP_CALLOC

#undef   XREALLOC
#define  XREALLOC  ESP_REALLOC

#undef   XMEMFREE
#define  XMEMFREE  ESP_MEMFREE

#undef   XMEMSET
#define  XMEMSET   ESP_MEMSET

#undef   XMEMCPY
#define  XMEMCPY   ESP_MEMCPY

#undef   XSTRLEN
#define  XSTRLEN   ESP_STRLEN

#undef   XASSERT
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
