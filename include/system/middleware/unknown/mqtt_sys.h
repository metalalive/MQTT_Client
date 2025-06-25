#ifndef MQTT_SYS__UNKNOWN_H
#define MQTT_SYS__UNKNOWN_H

#ifdef __cplusplus
extern "C" {
#endif

// reset all defined values on heap operations
#ifdef XMALLOC
    #undef XMALLOC
#endif

#ifdef XMEMFREE
    #undef XMEMFREE
#endif

#ifdef XCALLOC
    #undef XCALLOC
#endif

#ifdef XREALLOC
    #undef XREALLOC
#endif

typedef void *mqttSysThreFn;

typedef void *mqttSysThre_t;

#ifdef __cplusplus
}
#endif
#endif // end of MQTT_SYS__UNKNOWN_H
