#ifndef MQTT_THIRD_PARTY_INCLUDE_H
#define MQTT_THIRD_PARTY_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "tomcrypt.h"

// TODO: write script to interact with users & automatically generate these define parameters


// ------ user configuations for this MQTT implementation ------
//// #define    MQTT_CFG_USE_TLS
//// #define    MQTT_CFG_ENABLE_TLS_V1_3

// ------ configuration integration with third-party crypto library ------
// multiple-byte integer arithmetic functions
#define    MQTT_CFG_MPBINT_FN_BIN2MPINT       mp_from_ubin
#define    MQTT_CFG_MPBINT_FN_MPINT2BIN       mp_to_ubin
#define    MQTT_CFG_MPBINT_FN_CAL_UBINSIZE    mp_ubin_size
#define    MQTT_CFG_MPBINT_FN_INIT            mp_init
#define    MQTT_CFG_MPBINT_FN_CLEAR           mp_clear
#define    MQTT_CFG_MPBINT_FN_ADD             mp_add
#define    MQTT_CFG_MPBINT_FN_ADDDG           mp_add_d

// ------ configuration integration with third-party math library ------
////#define    LTC_ARGCHK                         XASSERT
// hash functions used in DRBG and MAC
#define    MGTT_CFG_HASH_STATE_STRUCT         hash_state
#define    MGTT_CFG_HASH_SHA256_FN_INIT       sha256_init
#define    MGTT_CFG_HASH_SHA384_FN_INIT       sha384_init
#define    MGTT_CFG_HASH_SHA256_FN_UPDATE     sha256_process
#define    MGTT_CFG_HASH_SHA384_FN_UPDATE     sha384_process
#define    MGTT_CFG_HASH_SHA256_FN_DONE       sha256_done
#define    MGTT_CFG_HASH_SHA384_FN_DONE       sha384_done

// key structure for symmetric encryption in TLS
#define    TLS_CFG_CIPHER_SYM_STRUCT          symmetric_key
// key structure for key-exchange mechanism in TLS
#define    TLS_CFG_KEYEX_DH_STRUCT         dh_key
#define    TLS_CFG_KEYEX_ECC_STRUCT        ecc_key
#define    TLS_CFG_KEYEX_X25519_STRUCT     curve25519_key


#define    TLS_CFG_KEYEX_ECC_GEN_KEY_FN( tlsstatus, drbg, key, keysize ) \
{ \
    if((key) == NULL) { \
        (key) = XMALLOC(sizeof(tlsECCkey_t)); \
        XMEMSET((key), 0x00, sizeof(tlsECCkey_t)); \
    } \
    const int  prng_list_idx = 0; \
    int __status = ecc_make_key((prng_state *)(drbg), prng_list_idx, (keysize), (key)); \
    (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK: TLS_RESP_ERR); \
}


#define    TLS_CFG_KEYEX_ECC_FREE_KEY_FN( key ) \
{ \
    ecc_free((key)); \
    (key)->dp.base.x  = NULL; \
    (key)->dp.base.y  = NULL; \
    (key)->dp.base.z  = NULL; \
    (key)->dp.prime   = NULL; \
    (key)->dp.A       = NULL; \
    (key)->dp.B       = NULL; \
    (key)->dp.order   = NULL; \
    (key)->pubkey.x = NULL;   \
    (key)->pubkey.y = NULL;   \
    (key)->pubkey.z = NULL;   \
    (key)->k        = NULL;   \
    XMEMFREE((void *)(key));  \
}


// TODO: examine key export function
#define  TLS_CFG_KEYEX_ECC_EXPORT_PUBVAL_FN( tlsstatus, outbuf, key, keysize ) \
{ \
    word32  export_size = (keysize); \
    int     __status    = ecc_ansi_x963_export((const tlsECCkey_t *)(key), (outbuf), (word32 *)&export_size); \
    XASSERT(export_size == (keysize)); \
    (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK: TLS_RESP_ERR); \
}


#define   TLS_CFG_KEYEX_X25519_GEN_KEY_FN( tlsstatus, drbg, key ) \
{ \
    if((key) == NULL) { \
        (key) = XMALLOC(sizeof(tlsX25519Key_t)); \
        XMEMSET((key), 0x00, sizeof(tlsX25519Key_t)); \
    } \
    const int  prng_list_idx = 0; \
    int __status = x25519_make_key((prng_state *)(drbg), prng_list_idx, (key)); \
    (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK: TLS_RESP_ERR); \
}


#define  TLS_CFG_KEYEX_X25519_FREE_KEY_FN( key ) \
{ \
    XMEMFREE((key)); \
}


#define  TLS_CFG_KEYEX_X25519_EXPORT_PUBVAL_FN( tlsstatus, outbuf, key, keysize )  \
{ \
    int __status = x25519_export((outbuf), (word32 *)&(keysize), PK_PUBLIC, (key)); \
    (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK: TLS_RESP_ERR); \
}


#define    TLS_CFG_3PARTY_USE_RNG_FN(wrapper_fn)      \
struct ltc_prng_descriptor;                           \
extern struct ltc_prng_descriptor  prng_descriptor[];            \
static  word32  tlsRNGread(byte *out, word32 outlen, void *prng) \
{                                                                \
    if((out==NULL) || (outlen==0) || (outlen>0xffff) || (prng==NULL)) { \
        return 0;                                                       \
    }                                                                   \
    mqttRespStatus  status = MQTT_RESP_OK;                              \
    status = mqttUtilRandByteSeq((mqttDRBG_t *)prng, out, (word16)outlen); \
    return (status==MQTT_RESP_OK ? outlen: 0); \
}                                       \
static tlsRespStatus wrapper_fn( void ) \
{                                       \
    prng_descriptor[0].name        = "MQTT_TLS_DRBG";  \
    prng_descriptor[0].export_size = 0;          \
    prng_descriptor[0].add_entropy = NULL;       \
    prng_descriptor[0].read        = tlsRNGread; \
    prng_descriptor[0].start       = NULL;       \
    prng_descriptor[0].ready       = NULL;       \
    prng_descriptor[0].done        = NULL;       \
    prng_descriptor[0].pexport     = NULL;       \
    prng_descriptor[0].pimport     = NULL;       \
    prng_descriptor[0].test        = NULL;       \
    return TLS_RESP_OK; \
}


#ifdef __cplusplus
}
#endif
#endif // end of MQTT_THIRD_PARTY_INCLUDE_H
