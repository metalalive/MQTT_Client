#ifndef MQTT_THIRD_PARTY_LIBTOMMATH_INCLUDE_H
#define MQTT_THIRD_PARTY_LIBTOMMATH_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "tommath.h"

typedef  mp_int        multiBint_t;
// multiple-byte integer arithmetic functions
#define    MQTT_CFG_MPBINT_FN_BIN2MPINT(mp_int_p, inbuf, size)                 mp_from_ubin((mp_int_p), (inbuf), (size))
#define    MQTT_CFG_MPBINT_FN_MPINT2BIN(mp_int_p, outbuf, size, nbytes_wr)     mp_to_ubin((mp_int_p), (outbuf), (size), (nbytes_wr))

#define    MQTT_CFG_MPBINT_FN_CAL_UBINSIZE(mp_int_p)       mp_ubin_size((mp_int_p))
#define    MQTT_CFG_MPBINT_FN_INIT(mp_int_p)               mp_init((mp_int_p))
#define    MQTT_CFG_MPBINT_FN_CLEAR(mp_int_p)              mp_clear((mp_int_p))
#define    MQTT_CFG_MPBINT_FN_ADD(in1, in2, out)           mp_add((in1), (in2), (out))
#define    MQTT_CFG_MPBINT_FN_ADDDG(in1, in2_digit, out)   mp_add_d((in1), (in2_digit), (out))

#ifdef __cplusplus
}
#endif
#endif // end of MQTT_THIRD_PARTY_LIBTOMMATH_INCLUDE_H
