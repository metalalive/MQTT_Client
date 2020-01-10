#include "mqtt_include.h"


tlsRespStatus  tlsX509getExtensions(byte *in, word32 *inlen, tlsX509v3ext_t **ext_out, word32 *datalen)
{
    if(in==NULL || inlen==NULL || ext_out==NULL || datalen==NULL) {
        return TLS_RESP_ERRARGS;
    }
    const byte  oid_ext_prefix[4] = {(byte)ASN_PRIMDATA_OID, 0x3, 0x55, 0x1d};
    word32  obj_idlen_sz = 0;
    word32  obj_data_sz  = 0;
    word32  remain_sz    = *inlen;
    tlsRespStatus status = TLS_RESP_OK;

    *inlen   = 0;
    *datalen = 0;
    // skip implicit subject & issuer ID before we point to x509v3 extensions
    byte idx = 0;
    for(idx=1; idx<=2; idx++) {
        if (in[0] == (ASN_TAG_CONTEXT_SPECIFIC | ASN_TAG_PRIMITIVE | idx)) {
            obj_idlen_sz = remain_sz;
            status = tlsASN1GetIDlen(in, &obj_idlen_sz, in[0], &obj_data_sz);
            if(status < 0) { goto done; }
            *inlen   += obj_idlen_sz;
            *datalen += obj_data_sz;
            remain_sz -= (obj_idlen_sz + obj_data_sz);
            in        += (obj_idlen_sz + obj_data_sz);
        }
    } // end of for-loop
    // now we start parsing x509v3 extension
    if (in[0] == (ASN_TAG_CONTEXT_SPECIFIC | ASN_TAG_CONSTRUCTED | 0x3))
    {
        if(*ext_out == NULL) {
            *ext_out = (tlsX509v3ext_t *) XCALLOC(0x1, sizeof(tlsX509v3ext_t));
        }
        obj_idlen_sz = remain_sz;
        status = tlsASN1GetIDlen(in, &obj_idlen_sz, in[0], &obj_data_sz);
        if(status < 0) { goto done; }
        *inlen    += obj_idlen_sz;
        *datalen  += obj_data_sz;
        remain_sz  = obj_data_sz;
        in        += obj_idlen_sz;
        // skip useless ASN.1 ID + length
        obj_idlen_sz = remain_sz;
        status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
        if(status < 0) { goto done; }
        remain_sz -= obj_idlen_sz;
        in        += obj_idlen_sz;
        // loop through each x509v3 extension entry, tis implementation ONLY extracts  :
        // subject ID, authority ID, key usage, basic constraint
        while (remain_sz > 0) {
            // each extension entry starts with the byte sequence below :
            // * 0x30 <byte(s) for length field>
            // * 0x06 0x03 0x55 0x1d  <byte for extension type>
            // * 0x01 0x01 <byte for TRUE or FALSE> ..... optional
            // * 0x04 <byte(s) for length field>
            obj_idlen_sz = remain_sz;
            status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
            if(status < 0) { break; }
            remain_sz -= obj_idlen_sz;
            in        += obj_idlen_sz;
            // check first 4 bytes of OID sequence to decide whether to skip this part
            if(XSTRNCMP((const char *)&in[0], (const char *)&oid_ext_prefix[0], 4) == 0) {
                tlsX509extType  ext_type = (tlsX509extType) in[4];
                remain_sz -= 5;
                in        += 5;
                // ignore critical flag in this implementation
                if(in[0] == ASN_PRIMDATA_BOOLEAN) {
                    if(in[1] != 0x1) { status = TLS_RESP_ERR_DECODE; break; }
                    remain_sz -= 3;
                    in        += 3;
                }
                obj_idlen_sz = remain_sz;
                status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_OCTET_STRING), &obj_data_sz);
                if(status < 0) { break; }
                remain_sz -= obj_idlen_sz;
                in        += obj_idlen_sz;
                // check OID & extension type
                switch(ext_type) { // TODO: re-factor if we need to parse more x509 extensions in future
                    case X509_EXT_TYPE_AUTH_ID :
                        obj_idlen_sz = remain_sz;
                        status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
                        if(status < 0) { goto done; }
                        remain_sz -= obj_idlen_sz;
                        in        += obj_idlen_sz;
                        obj_idlen_sz = remain_sz;
                        status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_TAG_CONTEXT_SPECIFIC | 0x0), &obj_data_sz);
                        if(status < 0) { goto done; }
                        remain_sz -= obj_idlen_sz;
                        in        += obj_idlen_sz;
                        if((*ext_out)->authKeyID.data == NULL) {
                            (*ext_out)->authKeyID.len  = (byte) obj_data_sz;
                            (*ext_out)->authKeyID.data = (byte *) XMALLOC(sizeof(byte) * obj_data_sz);
                        }
                        XMEMCPY( &(*ext_out)->authKeyID.data[0], &in[0], (*ext_out)->authKeyID.len );
                        break;
                    case X509_EXT_TYPE_SUBJ_ID :
                        obj_idlen_sz = remain_sz;
                        status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_OCTET_STRING), &obj_data_sz);
                        if(status < 0) { goto done; }
                        remain_sz -= obj_idlen_sz;
                        in        += obj_idlen_sz;
                        if((*ext_out)->subjKeyID.data == NULL) {
                            (*ext_out)->subjKeyID.len  = (byte) obj_data_sz;
                            (*ext_out)->subjKeyID.data = (byte *) XMALLOC(sizeof(byte) * obj_data_sz);
                        }
                        XMEMCPY( &(*ext_out)->subjKeyID.data[0], &in[0], (*ext_out)->subjKeyID.len );
                        break;
                    case X509_EXT_TYPE_KEY_UASGE :
                        obj_idlen_sz = remain_sz;
                        status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_BIT_STRING), &obj_data_sz);
                        if(status < 0) { goto done; }
                        XASSERT(obj_data_sz == 2);
                        remain_sz -= obj_idlen_sz;
                        in        += obj_idlen_sz;
                        (*ext_out)->flgs.key_usage.digital_signature  = in[0] & 0x1;
                        (*ext_out)->flgs.key_usage.non_repudiation = (in[1] >> 7) & 0x1;
                        (*ext_out)->flgs.key_usage.key_encipher    = (in[1] >> 6) & 0x1;
                        (*ext_out)->flgs.key_usage.data_encipher   = (in[1] >> 5) & 0x1;
                        (*ext_out)->flgs.key_usage.key_agreement   = (in[1] >> 4) & 0x1;
                        (*ext_out)->flgs.key_usage.key_cert_sign   = (in[1] >> 3) & 0x1;
                        (*ext_out)->flgs.key_usage.crl_sign        = (in[1] >> 2) & 0x1;
                        (*ext_out)->flgs.key_usage.encipher_only   = (in[1] >> 1) & 0x1;
                        (*ext_out)->flgs.key_usage.decipher_only   = (in[1] >> 0) & 0x1;
                        break;
                    case X509_EXT_TYPE_BASIC_CONSTRAINT :
                        obj_idlen_sz = remain_sz;
                        status = tlsASN1GetIDlen(in, &obj_idlen_sz, (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
                        if(status < 0) { goto done; }
                        remain_sz -= obj_idlen_sz;
                        in        += obj_idlen_sz;
                        if(in[0] == ASN_PRIMDATA_BOOLEAN) {
                            if(in[1] != 0x1) { status = TLS_RESP_ERR_DECODE; goto done; }
                            if(in[2] != 0x0) { (*ext_out)->flgs.is_ca = 1; }
                        }
                        break;
                    default:
                        break;
                } // end of switch case
            } // end of if XSTRNCMP()
            remain_sz -= obj_data_sz;
            in        += obj_data_sz;
        } // end of while loop
    } // end of if ASN1 ID = 0xa3
done:
    return status;
} // end of tlsX509getExtensions


void tlsX509FreeCertExt(tlsX509v3ext_t *in)
{
    if(in != NULL) {
        if(in->subjKeyID.data != NULL) {
            XMEMFREE( in->subjKeyID.data );
            in->subjKeyID.data = NULL;
        }
        if(in->authKeyID.data != NULL) {
            XMEMFREE( in->authKeyID.data );
            in->authKeyID.data = NULL;
        }
    }
} // end of tlsX509FreeCertExt


