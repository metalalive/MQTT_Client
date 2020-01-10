#include "mqtt_include.h"


static tlsRespStatus  tlsX509ChkVersion( byte *in, word32 *inlen, tlsX509versionCode expected_ver, word32 *datalen )
{
    if(*inlen < (TLS_MIN_BYTES_ASN1_OBJ_ID + TLS_MIN_BYTES_ASN1_OBJ_LEN)) {
        return TLS_RESP_ERRARGS;
    }
    word32  obj_idlen_sz = 0;
    word32  obj_data_sz  = 0;
    tlsRespStatus status = TLS_RESP_OK;
    obj_idlen_sz = *inlen;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_TAG_CONSTRUCTED | ASN_TAG_CONTEXT_SPECIFIC), &obj_data_sz);
    if(status < 0) { goto done; }
    *inlen   = obj_idlen_sz;
    *datalen = obj_data_sz;
    in      += obj_idlen_sz;
    obj_idlen_sz = obj_data_sz;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_INTEGER), &obj_data_sz);
    if(status < 0) { goto done; }
    in += obj_idlen_sz;
    XASSERT(obj_data_sz == 1);
    if(in[0] != expected_ver) {
        status = TLS_RESP_ERR_NOT_SUPPORT;
    } // report error if this is not exepcted version of x509 certificate
done:
    return status;
} // end of tlsX509ChkVersion


static tlsRespStatus  tlsX509GetDNattributes(byte *in, word32 *inlen, tlsCertProfile_t *prof, word32 *datalen)
{
    if(*inlen < ((TLS_MIN_BYTES_ASN1_OBJ_ID + TLS_MIN_BYTES_ASN1_OBJ_LEN) * 3)) {
        return TLS_RESP_ERRARGS;
    }
    const byte  oid_dn_id_at[4] = {(byte)ASN_PRIMDATA_OID, 0x3, 0x55, 0x4};
    word32  obj_idlen_sz = 0;
    word32  obj_data_sz  = 0;
    word32  remain_sz    = 0;
    tlsRespStatus status = TLS_RESP_OK;

    obj_idlen_sz = *inlen;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
    if(status < 0) { goto done; }
    *inlen     = obj_idlen_sz;
    *datalen   = obj_data_sz;
    remain_sz  = obj_data_sz;
    in        += obj_idlen_sz;
    // loop through all ASN.1 set data
    while((remain_sz > 0) && (status == TLS_RESP_OK))
    {
        obj_idlen_sz  = remain_sz;
        status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_SET | ASN_TAG_CONSTRUCTED), &obj_data_sz);
        if(status < 0) { break; }

        remain_sz    -= obj_idlen_sz;
        in           += obj_idlen_sz;
        obj_idlen_sz  = remain_sz;
        status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
        if(status < 0) { break; }

        remain_sz    -= obj_idlen_sz;
        in           += obj_idlen_sz;
        // Note this implementation ONLY extract few element from distinguished name sets :
        // common name, organization name . skip all other attributes.
        if(XSTRNCMP((const char *)&in[0], (const char *)&oid_dn_id_at[0], 4) == 0) {
            byte  **dst = NULL;
            tlsX509DNattriOID  attribute = (tlsX509DNattriOID) in[4];
            switch(attribute) {
                case X509_DN_ATTRI_CN:
                    dst = &prof->common_name;
                    break;
                case X509_DN_ATTRI_ORG:
                    dst = &prof->org_name;
                    break;
                default:
                    break;
            } // end of switch case
            if(dst != NULL) {
                remain_sz -= 5;
                in        += 5;
                obj_idlen_sz = remain_sz;
                switch(in[0]) {
                    case ASN_PRIMDATA_UTF8STRING:
                    case ASN_PRIMDATA_PRINTABLESTRING:
                        status = tlsASN1GetIDlen(in, &obj_idlen_sz, in[0], &obj_data_sz);
                        break;
                    default:
                        status = TLS_RESP_ERR_NOT_SUPPORT;
                        break;
                } // end of switch case
                if(status == TLS_RESP_OK) {
                    remain_sz -= obj_idlen_sz;
                    in        += obj_idlen_sz;
                    if(*dst == NULL) { *dst = XMALLOC(sizeof(byte) * obj_data_sz); }
                    XMEMCPY( *dst, &in[0], obj_data_sz );
                }
            } // end of dst != NULL
        } // end of XSTRNCMP()
        remain_sz -= obj_data_sz;
        in        += obj_data_sz;
    } // end of while loop
    // hash the entire distinguished name sets, it's for ease of verification at later time
    int resultcode = 0;
    remain_sz = *inlen + *datalen;
    in       -= remain_sz;
    if(prof->hashed_dn == NULL) {
        word16  hash_sz = mqttHashGetOutlenBytes(MQTT_HASH_SHA256);
        prof->hashed_dn = (byte *) XMALLOC(sizeof(byte) * hash_sz);
    }
    tlsHash_t *hashobj = (tlsHash_t *) XMALLOC(sizeof(tlsHash_t));
    resultcode |= MGTT_CFG_HASH_SHA256_FN_INIT(hashobj);
    resultcode |= MGTT_CFG_HASH_SHA256_FN_UPDATE(hashobj, in, remain_sz);
    resultcode |= MGTT_CFG_HASH_SHA256_FN_DONE(hashobj, prof->hashed_dn);
    if(resultcode != 0) { status = TLS_RESP_ERR_HASH; }
    XMEMFREE((void *)hashobj);
done:
    return status;
} // end of tlsX509GetDNattributes


static tlsRespStatus  tlsX509ChkValidTime(byte *in, word32 *inlen,  word32 *datalen)
{
    word32  obj_idlen_sz = 0;
    word32  obj_data_sz  = 0;
    tlsRespStatus status = TLS_RESP_OK;
    // time format : convert to Binary Coded Decimal, 4-bit digits as YYYYMMDDHHMM (Generalized Time), or YYMMDDHHMM (UTC time)
    // skip "seconds" part in this implementation.
    byte     notbefore[6]; // starting date after a certificate is valid
    byte     notafter[6];  // expiration data before a certificate is valid, format: byte 2: YYYY, byte 1: MM, byte 0: DD
    byte     bias  =  0;

    obj_idlen_sz = *inlen;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
    if(status < 0) { goto done; }
    *inlen   = obj_idlen_sz;
    *datalen = obj_data_sz;
    in      += obj_idlen_sz;
    obj_idlen_sz = obj_data_sz;
    // RFC 5280 suggests the certificates extended across 2050 year will use generalized time instead of UTC time.
    switch (in[0]) {
        case ASN_PRIMDATA_UTCTIME:
            notbefore[0] = 0x20; // fixed value : 20xx year
            notafter[0]  = 0x20;
            bias = 1;
        case ASN_PRIMDATA_GENERALIZEDTIME:
            status = tlsASN1GetIDlen(in, &obj_idlen_sz, in[0], &obj_data_sz);
            ////     XASSERT(obj_data_sz == 0xd);
            ////     XASSERT(obj_data_sz == 0xf);
            break;
        default:
            status = TLS_RESP_ERR_NOT_SUPPORT; goto done;
            break;
    } // end of switch case
    // now in points to starting offset of not-before time
    byte idx = 0;
    byte tmp = 0;
    in   += obj_idlen_sz;
    // note that last 3 bytes of both generalized time and UTC time are "second digits" and "z" letter,
    // which are NOT used in this implementation.
    for (idx=0; idx<(obj_data_sz - 3); idx+=2) {
        tmp = XCHAR_TO_NUM(*in++) << 0x4;
        notbefore[bias + (idx >> 1)]  = 0;
        notbefore[bias + (idx >> 1)] |= tmp;
        tmp = XCHAR_TO_NUM(*in++);
        notbefore[bias + (idx >> 1)] |= tmp;
    } // end of for loop
    in   += obj_idlen_sz + 3;
    for (idx=0; idx<(obj_data_sz - 3); idx+=2) {
        tmp = XCHAR_TO_NUM(*in++) << 0x4;
        notafter[bias + (idx >> 1)]  = 0;
        notafter[bias + (idx >> 1)] |= tmp;
        tmp = XCHAR_TO_NUM(*in++);
        notafter[bias + (idx >> 1)] |= tmp;
    } // end of for loop

    // validate current certificate at here , get current time in microcontroller.
    mqttDateTime_t  curr_datetime;
    XMEMSET(&curr_datetime, 0x00, sizeof(mqttDateTime_t));
    status = tlsRespCvtFromMqttResp( mqttSysGetDateTime(&curr_datetime) );
    if(status < 0) { goto done; }
    // this cert must be used in a period of time , specified by notbefore[...] and notafter[...]
    byte *curr_datetime_bcd = (byte *) &curr_datetime;
    for (idx=0; idx<6; idx++) {
        if(curr_datetime_bcd[idx] < notbefore[idx]) {
            status = TLS_RESP_CERT_AUTH_FAIL; break;
        } else if( curr_datetime_bcd[idx] > notbefore[idx] ) {
            break;
        }
    } // end of for-loop
    for (idx=0; idx<6; idx++) {
        if(curr_datetime_bcd[idx] > notafter[idx]) {
            status = TLS_RESP_CERT_AUTH_FAIL; break;
        } else if (curr_datetime_bcd[idx] < notafter[idx]) {
            break;
        }
    } // end of for-loop
done:
    return status;
} // end of tlsX509ChkValidTime


static tlsRespStatus  tlsX509getPublicKey(byte *in, word32 *inlen, tlsAlgoOID *pubkey_algo, void **pubkey_p, word32 *datalen)
{
    word32  obj_idlen_sz = 0;
    word32  obj_data_sz  = 0;
    word32  remain_sz    = *inlen;
    tlsRespStatus status = TLS_RESP_OK;
    // skip ASN.1 ID + length before we get public key.
    obj_idlen_sz = remain_sz;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
    if(status < 0) { goto done; }
    *inlen   = obj_idlen_sz;
    *datalen = obj_data_sz;
    remain_sz -= obj_idlen_sz;
    in      += obj_idlen_sz;
    // get public key algorithm (from OID), possible algo: RSA, EC25519, ECC
    obj_idlen_sz = remain_sz;
    status = tlsASN1GetAlgoID(in, &obj_idlen_sz, pubkey_algo, &obj_data_sz);
    if(status < 0) { goto done; }
    remain_sz -= (obj_idlen_sz + obj_data_sz);
    in        += (obj_idlen_sz + obj_data_sz);
    obj_idlen_sz = remain_sz;
    // Note currently this implementation ONLY supports RSA public key algorithm in certificate verification
    switch(*pubkey_algo) {
        case TLS_ALGO_OID_RSA_KEY:
            status = tlsRSAgetPubKey((const byte *)in, &obj_idlen_sz, pubkey_p, &obj_data_sz);
            break;
        default:
            status = TLS_RESP_ERR_NOT_SUPPORT;
            break;
    } // end of switch case
done:
    return status;
} // end of tlsX509getPublicKey


static tlsRespStatus  tlsX509getSignature(byte *in, word32 *inlen, tlsOpaque16b_t *out, word32 *datalen)
{
    word32  obj_idlen_sz = 0;
    word32  obj_data_sz  = 0;
    word32  remain_sz    = *inlen;
    tlsRespStatus status = TLS_RESP_OK;
    obj_idlen_sz = remain_sz;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_BIT_STRING), &obj_data_sz);
    if(status == TLS_RESP_OK) {
        *inlen   = obj_idlen_sz;
        *datalen = obj_data_sz;
        remain_sz -= (obj_idlen_sz + 1); // skip one NULL byte before signature byte sequence
        in        += (obj_idlen_sz + 1);
        if(out->data == NULL) {
            out->len = obj_data_sz - 1;
            out->data = (byte *) XMALLOC(sizeof(byte) * out->len);
        }
        XMEMCPY(&out->data[0], &in[0], out->len);
    }
    return status;
} // end of tlsX509getSignature


static tlsHashAlgoID  tlsX509getHashIDfromAlgoID(tlsAlgoOID algo)
{
    tlsHashAlgoID  hash_id = 0; 
    switch(algo) {
        case TLS_ALGO_OID_SHA256:
        case TLS_ALGO_OID_SHA256_RSA_SIG:
            hash_id = TLS_HASH_ALGO_SHA256;
            break;
        case TLS_ALGO_OID_SHA384:
        case TLS_ALGO_OID_SHA384_RSA_SIG:
            hash_id = TLS_HASH_ALGO_SHA384;
            break;
        default:
            break;
    }
    return hash_id;
} // end of tlsX509getHashIDfromAlgoID


static tlsRespStatus  tlsX509HashCertInfo( tlsOpaque16b_t *out, tlsHashAlgoID hash_id, byte *in, word32 inlen )
{
    if(hash_id == TLS_HASH_ALGO_UNKNOWN) {
        return TLS_RESP_ERR_NOT_SUPPORT;
    }
    tlsHash_t    *hashobj = NULL;
    tlsRespStatus status  = TLS_RESP_OK;
    int        resultcode = 0;
    if(out->data == NULL) {
        out->len  = mqttHashGetOutlenBytes((mqttHashLenType)hash_id);
        out->data = (byte *) XMALLOC(sizeof(byte) * out->len);
    }
    hashobj = (tlsHash_t *) XMALLOC(sizeof(tlsHash_t));
    switch(hash_id) {
        case TLS_HASH_ALGO_SHA256:
            resultcode |= MGTT_CFG_HASH_SHA256_FN_INIT(hashobj);
            resultcode |= MGTT_CFG_HASH_SHA256_FN_UPDATE(hashobj, in, inlen);
            resultcode |= MGTT_CFG_HASH_SHA256_FN_DONE(hashobj, out->data);
            break;
        case TLS_HASH_ALGO_SHA384:
            resultcode |= MGTT_CFG_HASH_SHA384_FN_INIT(hashobj);
            resultcode |= MGTT_CFG_HASH_SHA384_FN_UPDATE(hashobj, in, inlen);
            resultcode |= MGTT_CFG_HASH_SHA384_FN_DONE(hashobj, out->data);
            break;
        default:
            break;
    } // end of switch case statement
    if(resultcode != 0) { status = TLS_RESP_ERR_HASH; }
    XMEMFREE((void *)hashobj);
    return status;
} // end of tlsX509HashCertInfo


//  RSASSA-PSS-params = SEQUENCE {
//      hashAlgorithm      [0] HashAlgorithm
//      maskGenAlgorithm   [1] MaskGenAlgorithm
//      saltLength         [2] INTEGER
//      trailerField       [3] TrailerField
//  }
//  Note each of these is sequential, but optional.
static tlsRespStatus  tlsX509GetRSAPSSextraInfo(byte *in, word32 *inlen, tlsRSApss_t *out, word32 *datalen)
{
    word32  obj_idlen_sz = 0;
    word32  obj_data_sz  = 0;
    word32  remain_sz    = *inlen;
    tlsRespStatus status = TLS_RESP_OK;
    tlsAlgoOID  oid = 0;
    byte  idx = 0;
    byte  tmp = 0;

    obj_idlen_sz = remain_sz;
    status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
    if(status < 0) { goto done; }
    *inlen   = obj_idlen_sz;
    *datalen = obj_data_sz;
    remain_sz -= obj_idlen_sz;
    in        += obj_idlen_sz;

    for(idx=0; idx<4; idx++) {
        if((in[0] & 0xfc) == (ASN_TAG_CONTEXT_SPECIFIC | ASN_TAG_CONSTRUCTED)) {
            tmp = in[0] & 0x3;
            if(tmp == idx) {
                obj_idlen_sz = remain_sz;
                status = tlsASN1GetIDlen(in, &obj_idlen_sz, in[0], &obj_data_sz);
                if(status < 0) { goto done; }
                remain_sz -= obj_idlen_sz;
                in        += obj_idlen_sz;
                switch(tmp) {
                    case 0: // get hash algorithm OID
                        obj_idlen_sz = remain_sz;
                        status = tlsASN1GetAlgoID(in, &obj_idlen_sz, &oid , &obj_data_sz);
                        if(status < 0) { goto done; }
                        out->hash_id = tlsX509getHashIDfromAlgoID(oid);
                        remain_sz -= obj_idlen_sz;
                        in        += obj_idlen_sz;
                        break;
                    case 2: // get salt length
                        obj_idlen_sz = remain_sz;
                        status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_INTEGER), &obj_data_sz);
                        if(status < 0 || obj_data_sz != 2) { goto done; }
                        remain_sz -= obj_idlen_sz;
                        in        += obj_idlen_sz;
                        tlsDecodeWord16(&in[0], &out->salt_len);
                        break;
                    default: // skip bytes in all other cases
                        break;
                } // end of switch case
                remain_sz -= obj_data_sz;
                in        += obj_data_sz;
            } // end of if tmp == idx
        } else { break; }
    } // end of for loop

done:
    return status;
} // end of tlsX509GetRSAPSSextraInfo



// a x509 certificate byte sequence can be split into 2 parts :
// (1) Information about certificate holder, e.g. certificate algorithm, distinguished name (DN)
//      attributes,  expiration date, public key, x509v3 extensions
// (2) signature part, immediately following (1) in cert byte sequence
tlsRespStatus  tlsDecodeX509cert(tlsCert_t *cert)
{
    if(cert == NULL || cert->rawbytes.data == NULL) {
        return TLS_RESP_ERRARGS;
    }
    word32   cert_len = 0;
    tlsDecodeWord24( &cert->rawbytes.len[0] , &cert_len );
    if(cert_len == 0 || cert_len > TLS_MAX_BYTES_CERT_CHAIN) {
        return TLS_RESP_ERRARGS;
    }
    word32   decoded      = 0; // number of bytes decoded in this certificate
    word32   obj_idlen_sz = 0; // size of the "1-byte ID + length field"  of the ASN1 object
    word32   obj_data_sz  = 0; // size of the data section of the ASN1 object
    tlsRespStatus status = TLS_RESP_OK;

    word32   cert_hodler_info_len    = 0;    // total size in bytes of first part as described above
    byte    *cert_hodler_info_start  = NULL; // starting address of first part as described above
    // * get ID & length of the entire certificate.
    obj_idlen_sz = cert_len - decoded;
    status = tlsASN1GetIDlen(&cert->rawbytes.data[decoded], &obj_idlen_sz,
                          (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
    if(status < 0) { goto done; }
    decoded += obj_idlen_sz;

    // * store starting address & size of the first part of the certificate, for later hash operation
    obj_idlen_sz = cert_len - decoded;
    status = tlsASN1GetIDlen(&cert->rawbytes.data[decoded], &obj_idlen_sz,
                          (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
    if(status < 0) { goto done; }
    cert_hodler_info_start = &cert->rawbytes.data[decoded];
    cert_hodler_info_len   =  obj_idlen_sz + obj_data_sz;
    decoded += obj_idlen_sz;

    // * check certificate version, this implementation ONLY support x509v3 and don't accept negotiation on this.
    obj_idlen_sz = cert_len - decoded;
    status = tlsX509ChkVersion( &cert->rawbytes.data[decoded], &obj_idlen_sz, X509_V3, &obj_data_sz );
    if(status < 0) { goto done; }
    decoded += obj_idlen_sz + obj_data_sz;

    // * skip serial number, TODO: figure out what to do with serial number on cert verification
    obj_idlen_sz = cert_len - decoded;
    status = tlsASN1GetIDlen(&cert->rawbytes.data[decoded], &obj_idlen_sz, (ASN_PRIMDATA_INTEGER), &obj_data_sz);
    if(status < 0) { goto done; }
    decoded += obj_idlen_sz + obj_data_sz;

    // * get certificate algorithm, verify whether the algorithm is supported here
    obj_idlen_sz = cert_len - decoded;
    status = tlsASN1GetAlgoID(&cert->rawbytes.data[decoded], &obj_idlen_sz, &cert->cert_algo, &obj_data_sz);
    if(status < 0) { goto done; }
    decoded += obj_idlen_sz + obj_data_sz;

    // extract extra information in case the signature algorithm is RSA-PSS
    if(cert->cert_algo == TLS_ALGO_OID_RSASSA_PSS) {
        obj_idlen_sz = cert_len - decoded;
        status = tlsX509GetRSAPSSextraInfo(&cert->rawbytes.data[decoded], &obj_idlen_sz, &cert->rsapss, &obj_data_sz);
        if(status < 0) { goto done; }
        decoded += obj_idlen_sz + obj_data_sz;
    }

    // hash distinguished name (DN) attributes for issuer (e.g. CA, any intermediate trustee) or subject (e.g. the perr, server)
    // store few useful information, then hash entire DN section for later verification.
    obj_idlen_sz = cert_len - decoded;
    status = tlsX509GetDNattributes( &cert->rawbytes.data[decoded], &obj_idlen_sz, &cert->issuer ,&obj_data_sz );
    if(status < 0) { goto done; }
    decoded += obj_idlen_sz + obj_data_sz;

    // extract starting date and expiration date,
    // TODO: find better way to get current generalized date time, client could be on microcontroller platform
    obj_idlen_sz = cert_len - decoded;
    status = tlsX509ChkValidTime( &cert->rawbytes.data[decoded], &obj_idlen_sz, &obj_data_sz );
    if(status < 0) { goto done; }
    decoded += obj_idlen_sz + obj_data_sz;

    // * get  distinguished name (DN) attributes for subject
    obj_idlen_sz = cert_len - decoded;
    status = tlsX509GetDNattributes( &cert->rawbytes.data[decoded], &obj_idlen_sz, &cert->subject ,&obj_data_sz );
    if(status < 0) { goto done; }
    decoded += obj_idlen_sz + obj_data_sz;
    // filter out any cert that doesn't contain subject distinguished name
    if(cert->subject.common_name == NULL && cert->subject.org_name == NULL) {
        status = TLS_RESP_ERR_DECODE;  goto done;
    }

    // get public key
    obj_idlen_sz = cert_len - decoded;
    status = tlsX509getPublicKey(&cert->rawbytes.data[decoded], &obj_idlen_sz, &cert->pubkey_algo, &cert->pubkey, &obj_data_sz);
    if(status < 0) { goto done; }
    decoded += obj_idlen_sz + obj_data_sz;

    // check x509v3 extensions (optional)
    obj_idlen_sz = cert_len - decoded;
    status = tlsX509getExtensions(&cert->rawbytes.data[decoded], &obj_idlen_sz, (tlsX509v3ext_t **)&cert->cert_exts, &obj_data_sz);
    if(status < 0) { goto done; }
    decoded += obj_idlen_sz + obj_data_sz;

    // get signature algorithm
    obj_idlen_sz = cert_len - decoded;
    status = tlsASN1GetAlgoID(&cert->rawbytes.data[decoded], &obj_idlen_sz, &cert->sign_algo, &obj_data_sz);
    if(status < 0) { goto done; }
    decoded += obj_idlen_sz + obj_data_sz;
    if(cert->sign_algo != cert->cert_algo) { // must be consistent
        status = TLS_RESP_ERR_DECODE;  goto done;
    }
    // TODO: duplicate information ??
    // extract extra information in case the signature algorithm is RSA-PSS
    if(cert->sign_algo == TLS_ALGO_OID_RSASSA_PSS) {
        tlsRSApss_t   rsapss_sign = {0};
        obj_idlen_sz = cert_len - decoded;
        status = tlsX509GetRSAPSSextraInfo(&cert->rawbytes.data[decoded], &obj_idlen_sz, &rsapss_sign, &obj_data_sz);
        if(status < 0) { goto done; }
        if(XSTRNCMP((const char *)&cert->rsapss, (const char *)&rsapss_sign , sizeof(tlsRSApss_t)) != 0) {
            status = TLS_RESP_ERR_DECODE;
            goto done;
        }
        decoded += obj_idlen_sz + obj_data_sz;
    } // end of cert_algo == TLS_ALGO_OID_RSASSA_PSS

    // extract signature & algorithm ID
    obj_idlen_sz = cert_len - decoded;
    status = tlsX509getSignature(&cert->rawbytes.data[decoded], &obj_idlen_sz, &cert->signature, &obj_data_sz);
    if(status < 0) { goto done; }
    decoded += obj_idlen_sz + obj_data_sz;

    // hash certificate holder information (first part of the cert, excluding signature) for later verification
    tlsHashAlgoID hash_id = (cert->cert_algo == TLS_ALGO_OID_RSASSA_PSS) ? cert->rsapss.hash_id: tlsX509getHashIDfromAlgoID(cert->cert_algo);
    status  = tlsX509HashCertInfo( &cert->hashed_holder_info, hash_id, cert_hodler_info_start, cert_hodler_info_len );

    // final sanity check
    if(decoded != cert_len) {
        status = TLS_RESP_ERR_DECODE;
    }
done:
    return status;
} // end of tlsDecodeX509cert


