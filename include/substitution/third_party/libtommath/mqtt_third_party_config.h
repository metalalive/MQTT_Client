#ifndef _MQTT_THIRD_PARTY_CONFIG_H_
#define _MQTT_THIRD_PARTY_CONFIG_H_

#include "mqtt_third_party_system_config.h"

// ---- for libtommath
#define    MP_LOW_MEM // reduce static memory usage (on stack)
#define    MP_RAND_REDEFINE

#endif // end of _MQTT_THIRD_PARTY_CONFIG_H_
