#ifndef MQTT_THIRD_PARTY_INCLUDE_H
#define MQTT_THIRD_PARTY_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif
// TODO: write script to automatically generate these define parameters

// ------ user configuations for this MQTT implementation ------
#define    MQTT_CFG_USE_TLS
#define    MQTT_CFG_ENABLE_TLS_V1_3

#include "integration/libtommath/mqtt_third_party_include.h"
#include "integration/libtomcrypt/mqtt_third_party_include.h"


#ifdef __cplusplus
}
#endif
#endif // end of MQTT_THIRD_PARTY_INCLUDE_H
