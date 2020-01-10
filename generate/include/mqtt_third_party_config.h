#ifndef _MQTT_THIRD_PARTY_CONFIG_H_
#define _MQTT_THIRD_PARTY_CONFIG_H_

// #-------------------------------------------------------------------------------------
// # integration parameters for this MQTT implementation & common third-party libraries
// #-------------------------------------------------------------------------------------
// # memory operation functions should be consistent with underlying OS, for the platforms
// # that provide their own heap memory operations with different function names, developers
// # can sepcify the memory function names that meet their platform requirement.
#include "mqtt_third_party_system_config.h"

// ---- for libtommath
#define    MP_LOW_MEM // reduce static memory usage (on stack)
#define    MP_RAND_REDEFINE


// ---- for libtomcrypto
// use libtommath
#define USE_LTM

#define LTC_NO_TABLES
#define LTC_NO_TEST
#define TAB_SIZE   2
#define ARGTYPE    4

#define LTC_NO_PRNGS

#define LTC_NO_PKCS
#define LTC_PKCS_1
#define LTC_PKCS_5
#define LTC_RSA_VERIFY_SIG_PKCS_1_V1_5_OVERWRITE
#define LTC_RSA_SIGN_NO_PKCS_1_V1_5

#define LTC_DER
#define LTC_DER_MAX_RECURSION  16

#define LTC_NO_MODES
#define LTC_GCM_MODE
#define LTC_CBC_MODE

#define LTC_NO_HASHES
#define LTC_SHA512
#define LTC_SHA384
#define LTC_SHA256
#define LTC_HASH_HELPERS

#define LTC_NO_CIPHERS
#define LTC_RIJNDAEL
#define LTC_CHACHA

#define LTC_NO_MACS
#define LTC_HMAC
#define LTC_POLY1305
#define LTC_CHACHA20POLY1305_MODE

#define LTC_NO_PK
#define LTC_MRSA
#define LTC_CURVE25519
#define LTC_MECC

#define LTC_NO_CURVES
#define LTC_ECC_SECP256R1
#define LTC_ECC_SECP384R1
#define LTC_ECC_SECP521R1

#define LTC_NO_MISC
#define LTC_PADDING


#endif // end of _MQTT_THIRD_PARTY_CONFIG_H_
