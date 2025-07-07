#include "mqtt_include.h"

tlsRespStatus tlsRSAgetPubKey(const byte *in, word32 *inlen, void **pubkey_p, word32 *datalen) {
    word32 obj_idlen_sz = 0, obj_data_sz = 0, remain_sz = *inlen;
    word16 N_len = 0, e_len = 0;

    const byte   *N_start = NULL, *e_start = NULL;
    tlsRespStatus status = TLS_RESP_OK;

    obj_idlen_sz = remain_sz;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_BIT_STRING), &obj_data_sz);
    if (status < 0) {
        goto done;
    }
    *inlen = obj_idlen_sz;
    *datalen = obj_data_sz;
    remain_sz -= (obj_idlen_sz + 1);
    in += (obj_idlen_sz + 1); // skip one useless NULL byte

    obj_idlen_sz = remain_sz;
    status = tlsASN1GetIDlen(
        in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz
    );
    if (status < 0) {
        goto done;
    }
    remain_sz -= obj_idlen_sz;
    in += obj_idlen_sz;

    obj_idlen_sz = remain_sz;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_INTEGER), &obj_data_sz);
    if (status < 0) {
        goto done;
    }
    remain_sz -= obj_idlen_sz;
    in += obj_idlen_sz;
    N_start = in;
    N_len = obj_data_sz;

    obj_idlen_sz = remain_sz - N_len;
    status = tlsASN1GetIDlen(&in[N_len], &obj_idlen_sz, (ASN_PRIMDATA_INTEGER), &obj_data_sz);
    if (status < 0) {
        goto done;
    }
    e_start = &in[N_len] + obj_idlen_sz;
    e_len = obj_data_sz;
    // initialize RSA key
    if (*pubkey_p == NULL) {
        *pubkey_p = XCALLOC(0x1, sizeof(tlsRSAkey_t));
    }
    TLS_CFG_RSA_INIT_PUBKEY_FN(status, *pubkey_p);
    if (status < 0) {
        goto done;
    }
    TLS_CFG_RSA_IMPORT_PUBKEY_FN(status, *pubkey_p, N_start, N_len, e_start, e_len);
    if (status < 0) {
        goto done;
    }
done:
    return status;
} // end of tlsRSAgetPubKey

static tlsRespStatus tlsRSAparsePKCS8version(const byte **in_ptr, word16 *remain_sz_ptr) {
    word32 obj_idlen_sz = *remain_sz_ptr, obj_data_sz = 0;
    // the field `Version` no longer means whether it's two-prime or multi-prime
    //
    //     Version ::= INTEGER { v1(0), v2(1) }
    //
    // for decoding detail of the field `version`, please refer to RFC5958
    // , RFC5208, RFC3447 (for `RSAPrivateKey`)
    //
    // Also, note this application accepts only bi-prime version of RSA key,
    // and does not process multi-prime key, TODO / FIXME: should return error
    tlsRespStatus status =
        tlsASN1GetIDlen(*in_ptr, &obj_idlen_sz, ASN_PRIMDATA_INTEGER, &obj_data_sz);
    if (status < 0) {
        return status;
    }
    *remain_sz_ptr -= obj_idlen_sz - 1;
    *in_ptr += obj_idlen_sz;
#define ASYM_KEY_SUPPORTED_VERSION 0x0
    if (obj_data_sz != 1 || *(*in_ptr)++ != ASYM_KEY_SUPPORTED_VERSION) {
        return TLS_RESP_ERR_NOT_SUPPORT;
    }
#undef ASYM_KEY_SUPPORTED_VERSION
    return TLS_RESP_OK;
}

//    Parse a a private key structure in DER-encoded ASN.1 memory buffer
//
//    RSAPrivateKey ::= SEQUENCE {
//        version Version,
//        modulus INTEGER, -- n
//        publicExponent INTEGER, -- e
//        privateExponent INTEGER, -- d
//        prime1 INTEGER, -- p
//        prime2 INTEGER, -- q
//        exponent1 INTEGER, -- d mod (p-1)
//        exponent2 INTEGER, -- d mod (q-1)
//        coefficient INTEGER, -- (inverse of q) mod p
//        otherPrimeInfos OtherPrimeInfos OPTIONAL
//    }

tlsRespStatus tlsRSAgetPrivKey(const byte *in, word16 inlen, void **privkey_p) {
    tlsRespStatus status = TLS_RESP_OK;
#define NUM_PKEY_ELMS 8
    word32 obj_idlen_sz = 0, obj_data_sz = 0;
    word16 remain_sz = inlen;
    byte   idx = 0;
    // 1. (N)  The modulus
    // 2. (e)  The public exponent
    // 3. (d)  The private exponent
    // 4. (p)  The p factor of N
    // 5. (q)  The q factor of N
    // 6. (dP) The d mod (p - 1) CRT param
    // 7. (dQ) The d mod (q - 1) CRT param
    // 8. (qP) The 1/q mod p CRT param
    const byte *element_offset[NUM_PKEY_ELMS];
    word16      element_sz[NUM_PKEY_ELMS];

    obj_idlen_sz = remain_sz;
    status = tlsASN1GetIDlen(
        in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz
    );
    if (status < 0) {
        goto done;
    }
    remain_sz -= obj_idlen_sz;
    in += obj_idlen_sz;

    status = tlsRSAparsePKCS8version(&in, &remain_sz);
    if (status < 0) {
        goto done;
    }
    // ----- only for parsing PKCS#8 -----
    // Parse privateKeyAlgorithm SEQUENCE (OID for RSA)
    // privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
    // PrivateKeyAlgorithmIdentifier ::= SEQUENCE {
    //     algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL
    // }
    tlsAlgoOID algo_oid = 0;
    obj_idlen_sz = remain_sz;
    // Use tlsASN1GetAlgoID to parse the algorithm identifier sequence
    status = tlsASN1GetAlgoID(in, &obj_idlen_sz, &algo_oid, &obj_data_sz);
    if (status < 0) {
        goto done;
    }
    if (algo_oid != TLS_ALGO_OID_RSA_KEY) { // Ensure it's an RSA key
        status = TLS_RESP_ERR_NOT_SUPPORT;
        goto done;
    }
    // obj_data_sz here is the length of the OID and its parameters (e.g., NULL for RSA)
    remain_sz -= (obj_idlen_sz + obj_data_sz);
    in += (obj_idlen_sz + obj_data_sz);

    // Parse privateKey OCTET STRING
    obj_idlen_sz = remain_sz;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, ASN_PRIMDATA_OCTET_STRING, &obj_data_sz);
    if (status < 0) {
        goto done;
    }
    remain_sz -= obj_idlen_sz;
    // `in` now points to the start of the raw RSAPrivateKey bytes
    in += obj_idlen_sz;
    // This is the length of the raw RSAPrivateKey bytes
    word16 raw_rsa_elms_len = obj_data_sz;

    // Expect the input to start with the RSAPrivateKey SEQUENCE
    obj_idlen_sz = raw_rsa_elms_len;
    status = tlsASN1GetIDlen(
        in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz
    );
    if (status < 0) {
        goto done;
    }
    remain_sz = raw_rsa_elms_len;
    in += obj_idlen_sz;

    status = tlsRSAparsePKCS8version(&in, &remain_sz);
    if (status < 0) {
        goto done;
    }
    // ----- common part for both PKCS#1 and PKCS#8 -----
    // iterate over each element of the private key
    for (idx = 0; idx < NUM_PKEY_ELMS; idx++) {
        obj_idlen_sz = remain_sz;
        status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_INTEGER), &obj_data_sz);
        if (status < 0) {
            goto done;
        }
        element_offset[idx] = &in[obj_idlen_sz];
        element_sz[idx] = obj_data_sz;
        remain_sz -= obj_idlen_sz + obj_data_sz;
        in += obj_idlen_sz + obj_data_sz;
    }
    // init RSA private key
    if (*privkey_p == NULL) {
        *privkey_p = XCALLOC(0x1, sizeof(tlsRSAkey_t));
    }
    TLS_CFG_RSA_INIT_PRIVKEY_FN(status, *privkey_p);
    if (status < 0) {
        goto done;
    }
    TLS_CFG_RSA_IMPORT_PRIVKEY_FN(
        status, *privkey_p, element_offset[0], element_sz[0], element_offset[1], element_sz[1],
        element_offset[2], element_sz[2], element_offset[3], element_sz[3], element_offset[4],
        element_sz[4], element_offset[5], element_sz[5], element_offset[6], element_sz[6],
        element_offset[7], element_sz[7]
    );
done:
    return status;
#undef NUM_PKEY_ELMS
} // end of tlsRSAgetPrivKey

void tlsRSAfreePubKey(void *pubkey_p) {
    if (pubkey_p != NULL) {
        TLS_CFG_RSA_FREE_PUBKEY_FN(pubkey_p);
        XMEMFREE(pubkey_p);
    }
} // end of tlsRSAfreePubKey

void tlsRSAfreePrivKey(void *privkey_p) {
    if (privkey_p != NULL) {
        TLS_CFG_RSA_FREE_PRIVKEY_FN(privkey_p);
        XMEMFREE((void *)privkey_p);
    }
} // end of tlsRSAfreePrivKey
