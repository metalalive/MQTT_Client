#ifndef MQTT_SYS__LINUX_H
#define MQTT_SYS__LINUX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// operations for file descriptors
#include <fcntl.h>
#include <sys/poll.h>

// for network connection
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

// for threading / scheduling
#include <pthread.h>
#include <limits.h>
#include <sched.h>

// for getting system date/time
#include <time.h>

// --- macros used in core implementation of the MQTT client ---

#define MQTT_SYS_PKT_MAXBYTES 8192
// minimum application thread priority,
// get scheduling policy from current running thread first
// then retrieve the minimum allowable priority in that policy.
#define MQTT_APPS_THREAD_PRIO_MIN sched_get_priority_min(sched_getscheduler(0))
// maximum timeout in milliseconds for core implementation & test
#define MQTT_SYS_MAX_TIMEOUT 0xffff0000

// the type used in threading implementation
typedef void *(*pthreadFn_t)(void *params);

typedef pthreadFn_t mqttSysThreFn;

typedef pthread_t mqttSysThre_t;

#ifdef __cplusplus
}
#endif
#endif // end of MQTT_SYS__LINUX_H
