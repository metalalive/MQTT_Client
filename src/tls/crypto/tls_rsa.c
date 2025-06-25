#include "mqtt_include.h"

tlsRespStatus tlsRSAgetPubKey(const byte *in, word32 *inlen, void **pubkey_p, word32 *datalen) {
    word32        obj_idlen_sz = 0;
    word32        obj_data_sz = 0;
    word32        remain_sz = *inlen;
    const byte   *N_start = NULL;
    const byte   *e_start = NULL;
    word16        N_len = 0;
    word16        e_len = 0;
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
    word32 obj_idlen_sz = 0;
    word32 obj_data_sz = 0;
    word16 remain_sz = inlen;
    // 1. (N)  The modulus
    // 2. (e)  The public exponent
    // 3. (d)  The private exponent
    // 4. (p)  The p factor of N
    // 5. (q)  The q factor of N
    // 6. (dP) The d mod (p - 1) CRT param
    // 7. (dQ) The d mod (q - 1) CRT param
    // 8. (qP) The 1/q mod p CRT param
    const byte   *element_offset[8];
    word16        element_sz[8];
    tlsRespStatus status = TLS_RESP_OK;
    byte          idx = 0;

    obj_idlen_sz = remain_sz;
    status = tlsASN1GetIDlen(
        in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz
    );
    if (status < 0) {
        goto done;
    }
    remain_sz -= obj_idlen_sz;
    in += obj_idlen_sz;

    // Version ::= INTEGER { two-prime(0), multi(1) }
    obj_idlen_sz = remain_sz;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_INTEGER), &obj_data_sz);
    if (status < 0) {
        goto done;
    }
    remain_sz -= obj_idlen_sz - 1;
    in += obj_idlen_sz;
    if (obj_data_sz != 1 || *in++ > 0x1) {
        status = TLS_RESP_ERR_PARSE;
        goto done;
    }

    // loop through each element of the private key
    for (idx = 0; idx < 8; idx++) {
        obj_idlen_sz = remain_sz;
        status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_INTEGER), &obj_data_sz);
        if (status < 0) {
            goto done;
        }
        element_offset[idx] = &in[obj_idlen_sz];
        element_sz[idx] = obj_data_sz;
        remain_sz -= obj_idlen_sz + obj_data_sz;
        in += obj_idlen_sz + obj_data_sz;
    } // end of loop

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
