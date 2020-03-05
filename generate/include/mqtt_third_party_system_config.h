#ifndef _MQTT_THIRD_PARTY_SYS_CONFIG_H_
#define _MQTT_THIRD_PARTY_SYS_CONFIG_H_


#define MP_MALLOC(size) malloc(size)
#define MP_REALLOC(mem, oldsize, newsize) realloc(mem, newsize)
#define MP_CALLOC(nmemb, size) calloc(nmemb, size)
#define MP_FREE(mem, size) free(mem)
#define XMALLOC malloc
#define XREALLOC realloc
#define XCALLOC calloc
#define XFREE free


#endif // end of _MQTT_THIRD_PARTY_SYS_CONFIG_H_
