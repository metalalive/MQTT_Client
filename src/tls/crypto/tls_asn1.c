#include "mqtt_include.h"


// inlen [in/out] : specify input byte size. This function store all read bytes of OID sequence on return.
// There would be 2 bytes "0x05 0x00" (ASN.1 NULL) following the OID byte sequence, which will NOT be used
// in this implementation, skip the 2 bytes
static tlsRespStatus  tlsASN1GetOIDsum(const byte *in, word32 *inlen, tlsAlgoOID *oid)
{
    if(*inlen < (TLS_MIN_BYTES_ASN1_OBJ_ID + TLS_MIN_BYTES_ASN1_OBJ_LEN + TLS_MIN_BYTES_ASN1_OID)) {
        return TLS_RESP_ERRARGS;
    }
    word32   obj_idlen_sz = 0;
    word32   obj_data_sz  = 0;
    tlsRespStatus status = TLS_RESP_OK;

    obj_idlen_sz = *inlen;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_OID), &obj_data_sz);
    if(status < 0) { goto done; }
    else if(obj_idlen_sz < (TLS_MIN_BYTES_ASN1_OBJ_ID + TLS_MIN_BYTES_ASN1_OBJ_LEN)) {
        status = TLS_RESP_ERR_DECODE; goto done;
    }
    else if(obj_data_sz < TLS_MIN_BYTES_ASN1_OID) {
        status = TLS_RESP_ERR_DECODE; goto done;
    }
    *inlen = obj_idlen_sz + obj_data_sz;
    *oid   = 0;
    in    += obj_idlen_sz;
    while(obj_data_sz-- > 0) {
        *oid += *in++;
    }
done:
    return status;
} // end of tlsASN1GetOIDsum


static tlsRespStatus  tlsASN1validateOID(tlsAlgoOID in)
{
    tlsRespStatus status = TLS_RESP_OK;
    switch(in) {
        case TLS_ALGO_OID_RSA_KEY:
        case TLS_ALGO_OID_SHA256 :
        case TLS_ALGO_OID_SHA384 :
        case TLS_ALGO_OID_RSASSA_PSS :
        case TLS_ALGO_OID_SHA256_RSA_SIG:
        case TLS_ALGO_OID_SHA384_RSA_SIG:
            break;
        default:
            status = TLS_RESP_ERR_NOT_SUPPORT;
            break;
    }
    return status;
} // end of tlsASN1validateOID



tlsRespStatus  tlsASN1GetIDlen(const byte *in, word32 *inlen, byte expected_idtag, word32 *datalen)
{
    if(in == NULL || inlen == NULL || datalen == NULL) {
        return TLS_RESP_ERRARGS;
    }
    if(*inlen < (TLS_MIN_BYTES_ASN1_OBJ_ID + TLS_MIN_BYTES_ASN1_OBJ_LEN)) {
        return TLS_RESP_ERRARGS;
    }
    word32    remain_len = 0;
    tlsRespStatus status = TLS_RESP_OK;

    if(expected_idtag != *in++) {
        status = TLS_RESP_ERR_NOT_SUPPORT;
    } else {
        remain_len = *inlen - 1;
        TLS_CFG_ASN1_GET_LEN_FN(status, in, &remain_len, datalen);
        *inlen = 1 + remain_len;
        if(*datalen > TLS_MAX_BYTES_CERT_CHAIN) {
            status = TLS_RESP_ERR_CERT_OVFL;
        }
    }
    return status;
} // end of tlsASN1GetIDlen


tlsRespStatus  tlsASN1GetAlgoID(const byte *in, word32 *inlen, tlsAlgoOID *out, word32 *datalen)
{
    if(*inlen < (TLS_MIN_BYTES_ASN1_OBJ_ID + TLS_MIN_BYTES_ASN1_OBJ_LEN + TLS_MIN_BYTES_ASN1_OID)) {
        return TLS_RESP_ERRARGS;
    }
    word32  obj_idlen_sz = 0;
    word32  obj_data_sz  = 0;
    tlsRespStatus status = TLS_RESP_OK;
    obj_idlen_sz = *inlen;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
    if(status < 0) { goto done; }
    *inlen   = obj_idlen_sz;
    *datalen = obj_data_sz;
    in      += obj_idlen_sz;
    obj_idlen_sz = obj_data_sz;
    status = tlsASN1GetOIDsum(in, &obj_idlen_sz, out);
    if(status < 0) { goto done; }
    status = tlsASN1validateOID(*out);
    // special case for RSA-PSS , there is extra information immediately following RSA-PSS OID byte sequence
    // , don't skip these extra bytes because they provide useful information e,g, hash algorithm ID
    // or salt length
    if(*out == TLS_ALGO_OID_RSASSA_PSS) {
        *datalen = obj_idlen_sz;
    }
done:
    return status;
} // end of tlsASN1GetAlgoID


