#ifndef MQTT_THIRD_PARTY_LIBTOMCRYPT_INCLUDE_H
#define MQTT_THIRD_PARTY_LIBTOMCRYPT_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "tomcrypt.h"

// ------ configuration integration with third-party crypto library ------
// structure for multi-byte integer
// [IMPORTANT NOTE]
// if developers integrate this MQTT implementation with any third-party math library.
// the chosen math library must define the same function/data structure as shwon below for
// multiple-bytes integer arithmetic operations.
// The naming/data type of each struct member, and the order of the members should be the same.

// hash functions used in DRBG and MAC
typedef hash_state mqttHash_t;
typedef hash_state tlsHash_t;
#define MGTT_CFG_HASH_SHA256_FN_INIT   sha256_init
#define MGTT_CFG_HASH_SHA384_FN_INIT   sha384_init
#define MGTT_CFG_HASH_SHA256_FN_UPDATE sha256_process
#define MGTT_CFG_HASH_SHA384_FN_UPDATE sha384_process
#define MGTT_CFG_HASH_SHA256_FN_DONE   sha256_done
#define MGTT_CFG_HASH_SHA384_FN_DONE   sha384_done

// Both ECC and X25519 are used to derive handshake traffic secret at key-exchange phase of TLS v1.3
// ECC key structure (Elliptic Curve Cryptography)
typedef ecc_key tlsECCkey_t;
// ECC curve structure
typedef ltc_ecc_curve tlsECCcurve_t;
// x25519 key structure
typedef curve25519_key tlsX25519Key_t;
// RSA key structure
typedef rsa_key tlsRSAkey_t;

// structure for symmetric encryption
typedef gcm_state              tlsAESgcm_t;
typedef chacha20poly1305_state tlsCha20Poly1305_t;

// clang-format off

// HMAC function declaration
// perform HMAC & write it to given block of memory
#define TLS_CFG_HMAC_MEMBLOCK_FN(tlsstatus, hashAlgoID, key, keylen, in, inlen, out, outlen) \
{ \
    int hash_idx = TAB_SIZE;   \
    switch ((hashAlgoID)) {    \
    case TLS_HASH_ALGO_SHA256: \
        hash_idx = 0;          \
        break;                 \
    case TLS_HASH_ALGO_SHA384: \
        hash_idx = 1;          \
        break;                 \
    default:                   \
        break;                 \
    }                          \
    unsigned long outlen_tmp = (outlen);   \
    int __status = hmac_memory(  \
        hash_idx, (const byte *)(key), (word32)(keylen), (const byte *)(in), (word32)(inlen), \
        (byte *)(out), (unsigned long *)&outlen_tmp  \
    );   \
    XASSERT(outlen_tmp == (unsigned long)(outlen));  \
    (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_HASH); \
}
// clang-format on

// select curve with respect to keysize, then generate a new ephemeral ECC key
#define TLS_CFG_KEYEX_ECC_GEN_KEY_FN(tlsstatus, drbg, key, keysize) \
    { \
        const int prng_list_idx = 0; \
        int       __status = \
            ecc_make_key((prng_state *)(drbg), prng_list_idx, (keysize), (tlsECCkey_t *)(key)); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

#define TLS_CFG_KEYEX_ECC_FREE_KEY_FN(key) \
    { \
        ecc_free((tlsECCkey_t *)(key)); \
        ((tlsECCkey_t *)(key))->dp.base.x = NULL; \
        ((tlsECCkey_t *)(key))->dp.base.y = NULL; \
        ((tlsECCkey_t *)(key))->dp.base.z = NULL; \
        ((tlsECCkey_t *)(key))->dp.prime = NULL; \
        ((tlsECCkey_t *)(key))->dp.A = NULL; \
        ((tlsECCkey_t *)(key))->dp.B = NULL; \
        ((tlsECCkey_t *)(key))->dp.order = NULL; \
        ((tlsECCkey_t *)(key))->pubkey.x = NULL; \
        ((tlsECCkey_t *)(key))->pubkey.y = NULL; \
        ((tlsECCkey_t *)(key))->pubkey.z = NULL; \
        ((tlsECCkey_t *)(key))->k = NULL; \
    }

#define TLS_CFG_KEYEX_ECC_EXPORT_PUBVAL_FN(tlsstatus, outbuf, key, keysize) \
    { \
        unsigned long export_sz = (keysize); \
        int           __status = ecc_ansi_x963_export( \
            (const tlsECCkey_t *)(key), (outbuf), (unsigned long *)&export_sz \
        ); \
        XASSERT(export_sz == (unsigned long)(keysize)); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

#define TLS_CFG_KEYEX_ECC_IMPORT_PUBVAL_FN(tlsstatus, inbuf, inbuflen, key, cu) \
    { \
        int __status = ecc_ansi_x963_import_ex( \
            (const byte *)(inbuf), (word32)(inbuflen), (tlsECCkey_t *)(key), (cu) \
        ); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

// TODO: find better way to implement this ID-to-name conversion
#define TLS_CFG_KEYEX_ECC_GET_CURVE_FN(tlsstatus, grpid, cu) \
    { \
        int         __status = CRYPT_OK; \
        const char *curve_name = NULL; \
        switch ((grpid)) { \
        case TLS_NAMED_GRP_SECP256R1: \
            curve_name = "SECP256R1"; \
            break; \
        case TLS_NAMED_GRP_SECP384R1: \
            curve_name = "SECP384R1"; \
            break; \
        case TLS_NAMED_GRP_SECP521R1: \
            curve_name = "SECP521R1"; \
            break; \
        default: \
            __status = CRYPT_INVALID_ARG; \
            break; \
        } \
        if (__status == CRYPT_OK) { \
            __status = ecc_find_curve(curve_name, (cu)); \
        } \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

#define TLS_CFG_GEN_SHARED_SECRET_ECC_FN(tlsstatus, local_key, remote_key, outbuf, outbuflen) \
    { \
        unsigned long outlen_tmp = (outbuflen); \
        int           __status = ecc_shared_secret( \
            (const tlsECCkey_t *)(local_key), (const tlsECCkey_t *)(remote_key), (byte *)(outbuf), \
            &outlen_tmp \
        ); \
        XASSERT(outlen_tmp == (unsigned long)(outbuflen)); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

#define TLS_CFG_KEYEX_X25519_GEN_KEY_FN(tlsstatus, drbg, key) \
    { \
        const int prng_list_idx = 0; \
        int       __status = \
            x25519_make_key((prng_state *)(drbg), prng_list_idx, (tlsX25519Key_t *)(key)); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

#define TLS_CFG_KEYEX_X25519_FREE_KEY_FN(key)

#define TLS_CFG_KEYEX_X25519_EXPORT_PUBVAL_FN(tlsstatus, outbuf, key, keysize) \
    { \
        unsigned long export_sz = (keysize); \
        int __status = x25519_export((outbuf), &export_sz, PK_PUBLIC, (tlsX25519Key_t *)(key)); \
        XASSERT(export_sz == (unsigned long)(keysize)); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

#define TLS_CFG_GEN_SHARED_SECRET_X25519_FN(tlsstatus, local_key, remote_key, outbuf, outbuflen) \
    { \
        unsigned long outlen_tmp = (outbuflen); \
        int           __status = x25519_shared_secret( \
            (const tlsX25519Key_t *)(local_key), (const tlsX25519Key_t *)(remote_key), \
            (byte *)(outbuf), &outlen_tmp \
        ); \
        XASSERT(outlen_tmp == (unsigned long)(outbuflen)); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

#define TLS_CFG_KEYEX_X25519_IMPORT_PUBVAL_FN(tlsstatus, inbuf, inbuflen, key) \
    { \
        int __status = x25519_import_raw( \
            (const byte *)(inbuf), (word32)(inbuflen), PK_PUBLIC, (tlsX25519Key_t *)(key) \
        ); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

#define TLS_CFG_RSA_INIT_PUBKEY_FN(tlsstatus, pubkey) \
    { \
        tlsRSAkey_t *key = (tlsRSAkey_t *)(pubkey); \
        mp_int      *tmp = (mp_int *)XMALLOC(sizeof(mp_int) * 2); \
        key->type = PK_PUBLIC; \
        key->e = (void *)&tmp[0]; \
        key->N = (void *)&tmp[1]; \
        mp_err __status = MP_OKAY; \
        __status |= mp_init((mp_int *)key->e); \
        __status |= mp_init((mp_int *)key->N); \
        (tlsstatus) = (__status == MP_OKAY ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

#define TLS_CFG_RSA_INIT_PRIVKEY_FN(tlsstatus, privkey) \
    { \
        tlsRSAkey_t *key = (tlsRSAkey_t *)(privkey); \
        mp_int      *tmp = (mp_int *)XMALLOC(sizeof(mp_int) * 8); \
        key->type = PK_PRIVATE; \
        key->e = (void *)&tmp[0]; \
        key->N = (void *)&tmp[1]; \
        key->d = (void *)&tmp[2]; \
        key->p = (void *)&tmp[3]; \
        key->q = (void *)&tmp[4]; \
        key->qP = (void *)&tmp[5]; \
        key->dP = (void *)&tmp[6]; \
        key->dQ = (void *)&tmp[7]; \
        mp_err __status = MP_OKAY; \
        __status |= mp_init((mp_int *)key->e); \
        __status |= mp_init((mp_int *)key->N); \
        __status |= mp_init((mp_int *)key->d); \
        __status |= mp_init((mp_int *)key->p); \
        __status |= mp_init((mp_int *)key->q); \
        __status |= mp_init((mp_int *)key->qP); \
        __status |= mp_init((mp_int *)key->dP); \
        __status |= mp_init((mp_int *)key->dQ); \
        (tlsstatus) = (__status == MP_OKAY ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

#define TLS_CFG_RSA_FREE_PUBKEY_FN(pubkey) \
    { \
        tlsRSAkey_t *key = (tlsRSAkey_t *)(pubkey); \
        mp_int      *tmp = key->e; \
        mp_clear((mp_int *)&tmp[0]); \
        mp_clear((mp_int *)&tmp[1]); \
        XMEMFREE(key->e); \
        XMEMSET(key, 0x00, sizeof(tlsRSAkey_t)); \
    }

#define TLS_CFG_RSA_FREE_PRIVKEY_FN(privkey) \
    { \
        tlsRSAkey_t *key = (tlsRSAkey_t *)(privkey); \
        mp_int      *tmp = key->e; \
        mp_clear((mp_int *)&tmp[0]); \
        mp_clear((mp_int *)&tmp[1]); \
        mp_clear((mp_int *)&tmp[2]); \
        mp_clear((mp_int *)&tmp[3]); \
        mp_clear((mp_int *)&tmp[4]); \
        mp_clear((mp_int *)&tmp[5]); \
        mp_clear((mp_int *)&tmp[6]); \
        mp_clear((mp_int *)&tmp[7]); \
        XMEMFREE(key->e); \
        XMEMSET(key, 0x00, sizeof(tlsRSAkey_t)); \
    }

#define TLS_CFG_RSA_IMPORT_PUBKEY_FN(tlsstatus, pubkey, start_N, sz_N, start_e, sz_e) \
    { \
        tlsRSAkey_t *key = (tlsRSAkey_t *)(pubkey); \
        mp_err       __status = MP_OKAY; \
        __status |= mp_from_ubin((mp_int *)key->N, (start_N), (sz_N)); \
        __status |= mp_from_ubin((mp_int *)key->e, (start_e), (sz_e)); \
        (tlsstatus) = (__status == MP_OKAY ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

// 1. (N)  The modulus
// 2. (e)  The public exponent
// 3. (d)  The private exponent
// 4. (p)  The p factor of N
// 5. (q)  The q factor of N
// 6. (dP) The d mod (p - 1) CRT param
// 7. (dQ) The d mod (q - 1) CRT param
// 8. (qP) The 1/q mod p CRT param
#define TLS_CFG_RSA_IMPORT_PRIVKEY_FN( \
    tlsstatus, privkey, start_N, sz_N, start_e, sz_e, start_d, sz_d, start_p, sz_p, start_q, sz_q, \
    start_dP, sz_dP, start_dQ, sz_dQ, start_qP, sz_qP \
) \
    { \
        tlsRSAkey_t *key = (tlsRSAkey_t *)(privkey); \
        mp_err       __status = MP_OKAY; \
        __status |= mp_from_ubin((mp_int *)key->e, (start_e), (sz_e)); \
        __status |= mp_from_ubin((mp_int *)key->N, (start_N), (sz_N)); \
        __status |= mp_from_ubin((mp_int *)key->d, (start_d), (sz_d)); \
        __status |= mp_from_ubin((mp_int *)key->p, (start_p), (sz_p)); \
        __status |= mp_from_ubin((mp_int *)key->q, (start_q), (sz_q)); \
        __status |= mp_from_ubin((mp_int *)key->qP, (start_qP), (sz_qP)); \
        __status |= mp_from_ubin((mp_int *)key->dP, (start_dP), (sz_dP)); \
        __status |= mp_from_ubin((mp_int *)key->dQ, (start_dQ), (sz_dQ)); \
        (tlsstatus) = (__status == MP_OKAY ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

#define TLS_CFG_RSA_SIGN_SIGNATURE_FN( \
    tlsstatus, drbg, indata, inlen, signalgo, outdata, outlen, key, rsapss_hash_id, rsapss_saltlen \
) \
    { \
        unsigned long outlen_tmp = (outlen); \
        const int     prng_idx = 0; \
        int           hash_idx = TAB_SIZE; \
        int           padding_mthd = 0; \
        switch ((signalgo)) { \
        case TLS_ALGO_OID_RSASSA_PSS: { \
            padding_mthd = LTC_PKCS_1_PSS; \
            switch ((rsapss_hash_id)) { \
            case TLS_HASH_ALGO_SHA256: \
                hash_idx = 0; \
                break; \
            case TLS_HASH_ALGO_SHA384: \
                hash_idx = 1; \
                break; \
            default: \
                break; \
            } \
            break; \
        } \
        case TLS_ALGO_OID_SHA256_RSA_SIG: \
            padding_mthd = LTC_PKCS_1_V1_5; \
            hash_idx = 0; \
            break; \
        case TLS_ALGO_OID_SHA384_RSA_SIG: \
            padding_mthd = LTC_PKCS_1_V1_5; \
            hash_idx = 1; \
            break; \
        default: \
            break; \
        } \
        int __status = rsa_sign_hash_ex( \
            (const byte *)(indata), (inlen), (byte *)(outdata), &outlen_tmp, padding_mthd, \
            (prng_state *)(drbg), prng_idx, hash_idx, (rsapss_saltlen), (const rsa_key *)(key) \
        ); \
        XASSERT(outlen_tmp <= (outlen)); \
        (outlen) = outlen_tmp; \
        (tlsstatus) = ((__status == CRYPT_OK) ? TLS_RESP_OK : TLS_RESP_CERT_AUTH_FAIL); \
    }

#define TLS_CFG_RSA_VERIFY_SIGN_FN( \
    tlsstatus, signdata, signlen, signalgo, hashdata, hashlen, key, rsapss_hash_id, rsapss_saltlen \
) \
    { \
        int match_status = 0; \
        int hash_idx = TAB_SIZE; \
        int padding_mthd = 0; \
        switch ((signalgo)) { \
        case TLS_ALGO_OID_RSASSA_PSS: { \
            padding_mthd = LTC_PKCS_1_PSS; \
            switch ((rsapss_hash_id)) { \
            case TLS_HASH_ALGO_SHA256: \
                hash_idx = 0; \
                break; \
            case TLS_HASH_ALGO_SHA384: \
                hash_idx = 1; \
                break; \
            default: \
                break; \
            } \
            break; \
        } \
        case TLS_ALGO_OID_SHA256_RSA_SIG: \
            padding_mthd = LTC_PKCS_1_V1_5; \
            hash_idx = 0; \
            break; \
        case TLS_ALGO_OID_SHA384_RSA_SIG: \
            padding_mthd = LTC_PKCS_1_V1_5; \
            hash_idx = 1; \
            break; \
        default: \
            break; \
        } \
        int __status = rsa_verify_hash_ex( \
            (const byte *)(signdata), (signlen), (const byte *)(hashdata), (hashlen), \
            padding_mthd, hash_idx, (rsapss_saltlen), &match_status, (const tlsRSAkey_t *)(key) \
        ); \
        (tlsstatus) = \
            ((__status == CRYPT_OK) && (match_status == 1) ? TLS_RESP_OK : TLS_RESP_CERT_AUTH_FAIL \
            ); \
    }

#define TLS_CFG_AES_GCM_INIT_FN(tlsstatus, ctx, key_str, keysize) \
    { \
        const word16 cipher_idx = 0; \
        int          __status = \
            gcm_init((gcm_state *)(ctx), cipher_idx, (const byte *)(key_str), (int)(keysize)); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_ENCRYPT); \
    }

#define TLS_CFG_AES_GCM_RESET_FN(tlsstatus, ctx) \
    { \
        int __status = gcm_reset((gcm_state *)(ctx)); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_ENCRYPT); \
    }

#define TLS_CFG_AES_GCM_SET_IV_FN(tlsstatus, ctx, iv_str, iv_size) \
    { \
        int __status = \
            gcm_add_iv((gcm_state *)(ctx), (const byte *)(iv_str), (unsigned long)(iv_size)); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_ENCRYPT); \
    }

#define TLS_CFG_AES_GCM_SET_AAD_FN(tlsstatus, ctx, aad_str, aad_size) \
    { \
        int __status = \
            gcm_add_aad((gcm_state *)(ctx), (const byte *)(aad_str), (unsigned long)(aad_size)); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_ENCRYPT); \
    }

#define TLS_CFG_AES_GCM_PROCESS_FN(tlsstatus, ctx, ct, pt, len, is_decrypt) \
    { \
        int direction = ((is_decrypt) == 0) ? GCM_ENCRYPT : GCM_DECRYPT; \
        int __status = \
            gcm_process((gcm_state *)(ctx), (pt), (unsigned long)(len), (ct), direction); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_ENCRYPT); \
    }

#define TLS_CFG_AES_GCM_GET_TAG_FN(tlsstatus, ctx, tag, tag_sz) \
    { \
        unsigned long tag_sz_tmp = (tag_sz); \
        int           __status = gcm_done((gcm_state *)(ctx), (byte *)(tag), &tag_sz_tmp); \
        XASSERT((tag_sz) == tag_sz_tmp); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_ENAUTH_FAIL); \
    }

#define TLS_CFG_CHACHA_POLY_INIT_FN(tlsstatus, key_ctx, key_str, keysize) \
    { \
        int __status = chacha20poly1305_init( \
            (chacha20poly1305_state *)(key_ctx), (const byte *)(key_str), (word32)(keysize) \
        ); \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_KEYGEN); \
    }

// for removing implicit declaration warning
int der_decode_asn1_length(const unsigned char *in, unsigned long *inlen, unsigned long *outlen);

#define TLS_CFG_ASN1_GET_LEN_FN(tlsstatus, in, inlenp, outlenp) \
    { \
        unsigned long inlen_tmp = *(inlenp); \
        unsigned long outlen_tmp = *(outlenp); \
        int __status = der_decode_asn1_length((const byte *)(in), &inlen_tmp, &outlen_tmp); \
        *(inlenp) = inlen_tmp; \
        *(outlenp) = outlen_tmp; \
        (tlsstatus) = (__status == CRYPT_OK ? TLS_RESP_OK : TLS_RESP_ERR_DECODE); \
    }

// register third-party crypto functions during MQTT/TLS initialization
#define TLS_CFG_REG_3PARTY_CRYPTO_FN(wrapper_fn) \
    extern struct ltc_prng_descriptor   prng_descriptor[]; \
    extern struct ltc_cipher_descriptor cipher_descriptor[]; \
    extern struct ltc_hash_descriptor   hash_descriptor[]; \
    void                              **tls_drbg_src_obj; \
    word32                              tlsRNGread(byte *out, word32 outlen, void *prng) { \
        if ((out == NULL) || (outlen == 0) || (outlen > 0xffff) || (prng == NULL)) { \
            return 0; \
        } \
        mqttRespStatus status = MQTT_RESP_OK; \
        status = mqttUtilRandByteSeq((mqttDRBG_t *)prng, out, (word16)outlen); \
        return (status == MQTT_RESP_OK ? outlen : 0); \
    } \
    static unsigned long tlsRNGreadWrapper( \
        unsigned char *out, unsigned long outlen, prng_state *prng \
    ) { \
        word32 result = tlsRNGread(out, (word32)outlen, (void *)prng); \
        return (unsigned long)result; \
    } \
    static tlsRespStatus wrapper_fn(mqttCtx_t *mctx) { \
        tls_drbg_src_obj = (void **)&mctx->drbg; \
        XMEMSET(&prng_descriptor[0], 0x0, sizeof(struct ltc_prng_descriptor)); \
        prng_descriptor[0].name = "MQTT_TLS_DRBG"; \
        prng_descriptor[0].export_size = 0; \
        prng_descriptor[0].add_entropy = NULL; \
        prng_descriptor[0].read = tlsRNGreadWrapper; \
        XMEMSET(&cipher_descriptor[0], 0x0, sizeof(struct ltc_cipher_descriptor)); \
        cipher_descriptor[0].name = "aes"; \
        cipher_descriptor[0].ID = 6; \
        cipher_descriptor[0].min_key_length = 16; \
        cipher_descriptor[0].max_key_length = 32; \
        cipher_descriptor[0].block_length = 16; \
        cipher_descriptor[0].default_rounds = 10; \
        cipher_descriptor[0].setup = rijndael_enc_setup; \
        cipher_descriptor[0].ecb_encrypt = rijndael_ecb_encrypt; \
        cipher_descriptor[0].ecb_decrypt = rijndael_ecb_decrypt; \
        cipher_descriptor[0].done = rijndael_done; \
        cipher_descriptor[0].keysize = rijndael_enc_keysize; \
        XMEMSET(&hash_descriptor[0], 0x0, sizeof(struct ltc_hash_descriptor)); \
        XMEMSET(&hash_descriptor[1], 0x0, sizeof(struct ltc_hash_descriptor)); \
        hash_descriptor[0].name = "sha256"; \
        hash_descriptor[0].ID = 0; \
        hash_descriptor[0].hashsize = 32; \
        hash_descriptor[0].blocksize = 64; \
        hash_descriptor[0].OID[0] = 2; \
        hash_descriptor[0].OID[1] = 16; \
        hash_descriptor[0].OID[2] = 840; \
        hash_descriptor[0].OID[3] = 1; \
        hash_descriptor[0].OID[4] = 101; \
        hash_descriptor[0].OID[5] = 3; \
        hash_descriptor[0].OID[6] = 4; \
        hash_descriptor[0].OID[7] = 2; \
        hash_descriptor[0].OID[8] = 1; \
        hash_descriptor[0].OIDlen = 9; \
        hash_descriptor[0].init = sha256_init; \
        hash_descriptor[0].process = sha256_process; \
        hash_descriptor[0].done = sha256_done; \
        hash_descriptor[1].name = "sha384"; \
        hash_descriptor[1].ID = 4; \
        hash_descriptor[1].hashsize = 48; \
        hash_descriptor[1].blocksize = 128; \
        hash_descriptor[1].OID[0] = 2; \
        hash_descriptor[1].OID[1] = 16; \
        hash_descriptor[1].OID[2] = 840; \
        hash_descriptor[1].OID[3] = 1; \
        hash_descriptor[1].OID[4] = 101; \
        hash_descriptor[1].OID[5] = 3; \
        hash_descriptor[1].OID[6] = 4; \
        hash_descriptor[1].OID[7] = 2; \
        hash_descriptor[1].OID[8] = 2; \
        hash_descriptor[1].OIDlen = 9; \
        hash_descriptor[1].init = sha384_init; \
        hash_descriptor[1].process = sha512_process; \
        hash_descriptor[1].done = sha384_done; \
        XMEMCPY(&ltc_mp, &ltm_desc, sizeof(ltc_math_descriptor)); \
        return TLS_RESP_OK; \
    }

#ifdef __cplusplus
}
#endif
#endif // end of MQTT_THIRD_PARTY_LIBTOMCRYPT_INCLUDE_H
