#ifndef MQTT_SYS__LINUX_H
#define MQTT_SYS__LINUX_H

#ifdef __cplusplus
extern "C" {
#endif

#include  <stdio.h>
#include  <stdlib.h>
#include  <string.h>
#include  <errno.h>

// for network connection 
#include  <sys/types.h>
#include  <sys/socket.h>
#include  <netdb.h>
#include  <arpa/inet.h>
#include  <netinet/in.h>
#include  <unistd.h>
#include  <fcntl.h>

//for multithreading scenarios
#include  <pthread.h>
#include  <sched.h>

// --- macros used in core implementation of the MQTT client ---

// minimum application thread priority,
// We apply Round-Robin scheduling polity as default in this MQTT system implementation
#define  MQTT_APPS_THREAD_PRIO_MIN   sched_get_priority_min(SCHED_RR)
// maximum timeout in milliseconds for core implementation & test
#define  MQTT_SYS_MAX_TIMEOUT        0xffff0000


// the type used in threading implementation
typedef void *(* pthreadFn_t)(void* params);

typedef  pthreadFn_t  mqttSysThreFn;

typedef  pthread_t    mqttSysThre_t;


#ifdef __cplusplus
}
#endif
#endif // end of MQTT_SYS__LINUX_H 
