#ifndef _MQTT_THIRD_PARTY_SYS_CONFIG_H_
#define _MQTT_THIRD_PARTY_SYS_CONFIG_H_


#define MP_MALLOC(size) pvPortMalloc(size)
#define MP_REALLOC(mem, oldsize, newsize) pvPortRealloc(mem, newsize)
#define MP_CALLOC(nmemb, size) pvPortCalloc(nmemb, size)
#define MP_FREE(mem, size) vPortFree(mem)
#define XMALLOC pvPortMalloc
#define XREALLOC pvPortRealloc
#define XCALLOC pvPortCalloc
#define XFREE vPortFree


#endif // end of _MQTT_THIRD_PARTY_SYS_CONFIG_H_
