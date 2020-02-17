#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

#define  NUM_PEER_CERTS  8
#define  NUM_CA_CERTS    2
#define  NBYTES_CERT_HASHED_DISTINGUISHED_NAME  0x20
#define  MAX_RAWBYTE_BUF_SZ  0x80

static tlsSession_t *tls_session;

static byte   mock_cert_hashed_dn[NUM_PEER_CERTS + NUM_CA_CERTS][NBYTES_CERT_HASHED_DISTINGUISHED_NAME];
static byte  *mock_cert_issuer_hashed_dn[NUM_PEER_CERTS];
static byte  *mock_cert_subject_hashed_dn[NUM_PEER_CERTS];

static tlsAlgoOID  mock_cert_sig_algo; // or TLS_ALGO_OID_RSASSA_PSS or TLS_ALGO_OID_SHA384_RSA_SIG

const tlsCipherSpec_t  tls_supported_cipher_suites[] = {
    { // TLS_AES_128_GCM_SHA256, 0x1301
        TLS_CIPHERSUITE_ID_AES_128_GCM_SHA256   ,// ident
        (1 << TLS_ENCRYPT_ALGO_AES128) | (1 << TLS_ENC_CHAINMODE_GCM) | (1 << TLS_HASH_ALGO_SHA256)      ,// flags
        16   ,// tagSize
        16   ,// keySize
        12   ,// ivSize
        NULL ,// init_fn
        NULL ,// encrypt_fn
        NULL ,// decrypt_fn
        NULL ,// done_fn
    },
    { // TLS_AES_256_GCM_SHA384, 0x1302
        TLS_CIPHERSUITE_ID_AES_256_GCM_SHA384   ,// ident
        (1 << TLS_ENCRYPT_ALGO_AES256) | (1 << TLS_ENC_CHAINMODE_GCM) | (1 << TLS_HASH_ALGO_SHA384)      ,// flags
        16   ,// tagSize
        32   ,// keySize
        12   ,// ivSize
        NULL ,// init_fn
        NULL ,// encrypt_fn
        NULL ,// decrypt_fn
        NULL ,// done_fn
    },
};

word32  tlsEncodeWord24( byte *buf , word32  value )
{
    if(buf != NULL){
        buf[0] = (value >> 16) & 0xff;
        buf[1] = (value >> 8 ) & 0xff;
        buf[2] = value & 0xff;
    }
    // return number of bytes used to store the encoded value
    return  (word32)3;
} // end of tlsEncodeWord24

word32  tlsDecodeWord24( byte *buf , word32 *value )
{
    if((buf != NULL) && (value != NULL)) {
        *value  = buf[2];
        *value |= buf[1] << 8 ;
        *value |= buf[0] << 16 ;
    }
    return  (word32)3;
} // end of tlsDecodeWord24

word32 mqttEncodeWord16( byte *buf , word16 value )
{
    if(buf != NULL){
        buf[0] = value >> 8; 
        buf[1] = value &  0xff; 
    }
    // return number of bytes used to store the encoded value
    return  (word32)2; 
} // end of mqttEncodeWord16

word32 mqttDecodeWord16( byte *buf , word16 *value )
{
    if((buf != NULL) && (value != NULL)) {
        *value  =  buf[1]; 
        *value |=  buf[0] << 8 ;
    }
    return  (word32)2; 
} // end of mqttDecodeWord16

tlsRespStatus tlsAddItemToList(tlsListItem_t **list, tlsListItem_t *item, byte insert_to_front)
{
    if((list==NULL) || (item==NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if(insert_to_front != 0) {
        item->next = *list;
        *list = item; // always change head item
    }
    else {
        tlsListItem_t  *final = NULL;
        final = tlsGetFinalItemFromList(*list);
        if(final == NULL) { *list = item; }
        else { final->next = item; }
    }
    return TLS_RESP_OK;
} // tlsAddItemToList

tlsRespStatus tlsRemoveItemFromList(tlsListItem_t **list, tlsListItem_t *removing_item )
{
    if((list == NULL) && (removing_item == NULL)) { return TLS_RESP_ERRARGS; }
    tlsListItem_t  *idx  = NULL;
    tlsListItem_t  *prev = NULL;
    for(idx=*list; idx!=NULL; idx=idx->next) {
        if(removing_item == idx) {
            if(prev != NULL) {
                prev->next = removing_item->next;
            }
            else {
               *list = removing_item->next;
            }
            break;
        }
        prev = idx;
    } // end of for-loop
    return TLS_RESP_OK;
} // end of tlsRemoveItemFromList

tlsListItem_t*  tlsGetFinalItemFromList(tlsListItem_t *list)
{
    tlsListItem_t  *idx  = NULL;
    tlsListItem_t  *prev = NULL;
    for(idx=list; idx!=NULL; idx=idx->next) {
        prev = idx;
    }
    return prev;
} // end of tlsGetFinalItemFromList

tlsRespStatus  tlsFreeExtEntry(tlsExtEntry_t *in) {
    if(in == NULL) { return TLS_RESP_ERRARGS; }
    XMEMFREE((void *)in->content.data);
    in->content.data  = NULL;
    in->next = NULL;
    XMEMFREE((void *)in);
    return TLS_RESP_OK;
} // end of tlsFreeExtEntry

word16  mqttHashGetOutlenBytes(mqttHashLenType type)
{
    word16 out = 0;
    switch(type) {
        case MQTT_HASH_SHA256:
            out = 256; // unit: bit(s)
            break;
        case MQTT_HASH_SHA384:
            out = 384; // unit: bit(s)
            break;
        default:
            break;
    }
    out = out >> 3;
    return out;
} // end of mqttHashGetOutlenBits


tlsRespStatus  tlsParseExtensions(tlsSession_t *session, tlsExtEntry_t **out)
{
    if((session == NULL) || (out == NULL)) { return TLS_RESP_ERRARGS; }
    tlsExtEntry_t *curr_ext  =  NULL;
    byte    *inbuf           = &session->inbuf.data[0];
    word16   inlen_decoded   =  session->inlen_decoded;
    word16   inlen_decrypted =  session->inlen_decrypted;
    word16   entry_copied_len = session->last_ext_entry_dec_len;
    word16   rdy_cpy_len      = 0;
    const    byte insert_to_front = 1;
    tlsRespStatus  status = TLS_RESP_OK;
    // adjust decrypted length due to the authentication tag appended to the entire decrypted bytes
    if(session->flgs.hs_rx_encrypt == 1) {
        if(session->sec.flgs.ct_final_frag == 1) {
            inlen_decrypted -= (1 + session->sec.chosen_ciphersuite->tagSize);
        } // actual content type & skip authentication tag (in the final fragment)
    }
    if((entry_copied_len >> 15) == 0x1) { // get first 2-byte total size field of the extension section
        entry_copied_len &= XGET_BITMASK(15);
        switch(entry_copied_len) { // in case there is zero byte or only one byte available to parse
            case 0:
            {
                rdy_cpy_len = inlen_decrypted - inlen_decoded;
                switch(rdy_cpy_len) {
                    case 0:
                        entry_copied_len = 0x8000; // 0 + (1 << 15)
                        break;
                    case 1:
                        session->ext_dec_total_len = inbuf[inlen_decoded++] << 8;
                        entry_copied_len = 0x8001; // 1 + (1 << 15)
                        break;
                    case 2:
                    default:
                        inlen_decoded += tlsDecodeWord16( &inbuf[inlen_decoded], &session->ext_dec_total_len );
                        entry_copied_len = 0;
                        break;
                } // end of switch-case  rdy_cpy_len
                break;
            }
            case 1:
                session->ext_dec_total_len |= (inbuf[inlen_decoded++] & XGET_BITMASK(8));
                entry_copied_len = 0;
                break;
            default: // MUST NOT get here
                XASSERT(0);
                break;
        } // end of switch-case entry_copied_len
    } // end of  if entry_copied_len == 0x8000

    while (inlen_decrypted > inlen_decoded)
    { // move part of remaining received bytes to  extension entries,
        if(entry_copied_len == 0) { // MUST be in the beginning of this loop,  TODO: refactor the code
            if(session->ext_dec_total_len == 0) {
                // There may be several CertificateEntry items, each of them appended with variable-sized extension
                // between any 2 consecutive CertificateEntry items, for zero-length extension, break the loop immediately
                // for next  CertificateEntry item.
                break;
            }
            curr_ext = (tlsExtEntry_t *) XMALLOC(sizeof(tlsExtEntry_t));
            curr_ext->content.data = NULL;
            curr_ext->next = NULL;
            tlsAddItemToList((tlsListItem_t **)out, (tlsListItem_t *)curr_ext, insert_to_front);
            // see whether we can load first 4 bytes for new extension entry (from current in-flight fragment)
            rdy_cpy_len = inlen_decrypted - inlen_decoded;
            // for little-endian CPU architecture, incoming byte sequence might be written to incorrect
            // position of a 16-byte field (e.g. type, length)  in the exception entry structure, the code
            // below can handle such issue.
            switch(rdy_cpy_len) {
                case 0: break;
                case 1:
                    entry_copied_len  = 1;
                    curr_ext->type    = inbuf[inlen_decoded++] << 8;
                    break;
                case 2:
                    entry_copied_len  = 2;
                    inlen_decoded    += tlsDecodeWord16( &inbuf[inlen_decoded], &curr_ext->type );
                    break;
                case 3:
                    entry_copied_len  = 3;
                    inlen_decoded    += tlsDecodeWord16( &inbuf[inlen_decoded], &curr_ext->type );
                    curr_ext->content.len = inbuf[inlen_decoded++] << 8;
                    break;
                case 4:
                default:
                    entry_copied_len  = 4;
                    inlen_decoded    += tlsDecodeWord16( &inbuf[inlen_decoded], &curr_ext->type );
                    inlen_decoded    += tlsDecodeWord16( &inbuf[inlen_decoded], &curr_ext->content.len );
                    break;
            } // end of switch-case statement
        } // end of if entry_copied_len equal to 0
        else { // CPU arrives in here ONLY at the first iteration of the loop (means we are parsing new received fragment)
            // grab the extension entry (from head item of the exception list) we didn't complete copying bytes
            // since the last time this function is called.
            curr_ext = *out;
            if(curr_ext == NULL) {
                status = TLS_RESP_ERRMEM;
                break;
            }
            switch(entry_copied_len) {
                case 1:
                    entry_copied_len += 3;
                    curr_ext->type   |= inbuf[inlen_decoded++];
                    inlen_decoded    += tlsDecodeWord16( &inbuf[inlen_decoded], &curr_ext->content.len );
                    break;
                case 2:
                    entry_copied_len += 2;
                    inlen_decoded    += tlsDecodeWord16( &inbuf[inlen_decoded], &curr_ext->content.len );
                    break;
                case 3:
                    entry_copied_len      += 1;
                    curr_ext->content.len |= inbuf[inlen_decoded++];
                    break;
                default:
                    break;
            } // end of switch-case statement
        } // end of if entry_copied_len NOT equal to 0
        if((curr_ext->content.data == NULL) && (entry_copied_len == 4)) {
            curr_ext->content.data = XMALLOC(sizeof(byte) * curr_ext->content.len);
        } // allocate space only when first 4 bytes of an extension entry is decoded
        if(inlen_decrypted > inlen_decoded) {
            // from here on, entry_copied_len must be (greater than or equal to) 4
            rdy_cpy_len = XMIN(curr_ext->content.len - (entry_copied_len - 4), inlen_decrypted - inlen_decoded);
            XMEMCPY(&curr_ext->content.data[entry_copied_len - 4], &inbuf[inlen_decoded], rdy_cpy_len);
            entry_copied_len += rdy_cpy_len;
            inlen_decoded    += rdy_cpy_len;
            if(entry_copied_len == (4 + curr_ext->content.len)) {
                session->ext_dec_total_len -= entry_copied_len; //decrease size once raw bytes of a extensionEntry are copied.
                entry_copied_len = 0; // finish parsing current extension entry & may iterate over again
                XASSERT(inlen_decrypted >= inlen_decoded);
            }
            else {
                XASSERT(entry_copied_len < (4 + curr_ext->content.len));
                XASSERT(inlen_decrypted == inlen_decoded);
            }
        }
    } // end of while-loop
    session->inlen_decoded = inlen_decoded;
    session->last_ext_entry_dec_len = entry_copied_len;
    return  status;
} // end of tlsParseExtensions

tlsRespStatus  tlsDecodeX509cert(tlsCert_t *cert)
{
    word32  mock_size = 0;
    tlsDecodeWord24(&cert->rawbytes.len[0], &mock_size);
    mock_size = mock_size >> 2;
    if(cert->signature.data == NULL) {
        cert->signature.data = XMALLOC(mock_size);
        cert->sign_algo = mock_cert_sig_algo; // or TLS_ALGO_OID_RSASSA_PSS or TLS_ALGO_OID_SHA384_RSA_SIG
        if(cert->sign_algo == TLS_ALGO_OID_RSASSA_PSS) {
            cert->rsapss.hash_id = TLS_HASH_ALGO_SHA384;
            cert->rsapss.salt_len = mqttHashGetOutlenBytes(MQTT_HASH_SHA384);
        }
    }
    if(cert->subject.common_name == NULL) {
        cert->subject.common_name = XMALLOC(mock_size);
    }
    if(cert->issuer.common_name == NULL) {
        cert->issuer.common_name = XMALLOC(mock_size);
    }
    if(cert->subject.org_name == NULL) {
        cert->subject.org_name = XMALLOC(mock_size);
    }
    if(cert->issuer.org_name == NULL) {
        cert->issuer.org_name = XMALLOC(mock_size);
    }
    if(cert->cert_exts == NULL) {
        cert->cert_exts = XMALLOC(mock_size);
    }
    if(cert->hashed_holder_info.data == NULL) {
        cert->hashed_holder_info.data = XMALLOC(mock_size);
    }
    if(cert->pubkey == NULL) {
        cert->pubkey = XMALLOC(mock_size);
        cert->pubkey_algo = TLS_ALGO_OID_RSA_KEY;
    }
    if(cert->issuer.hashed_dn == NULL) {
        mock_size = NBYTES_CERT_HASHED_DISTINGUISHED_NAME;
        cert->issuer.hashed_dn = XMALLOC(mock_size);
    }
    if(cert->subject.hashed_dn == NULL) {
        mock_size = NBYTES_CERT_HASHED_DISTINGUISHED_NAME;
        cert->subject.hashed_dn = XMALLOC(mock_size);
    }
    return TLS_RESP_OK;
} // end of tlsDecodeX509cert

tlsHashAlgoID  TLScipherSuiteGetHashID( const tlsCipherSpec_t *cs_in )
{
    if(cs_in != NULL) {
        if((cs_in->flags & (1 << TLS_HASH_ALGO_SHA256)) != 0x0) {
            return TLS_HASH_ALGO_SHA256;
        }
        if((cs_in->flags & (1 << TLS_HASH_ALGO_SHA384)) != 0x0) {
            return TLS_HASH_ALGO_SHA384;
        }
        return TLS_HASH_ALGO_UNKNOWN; // cipher suite selected but cannot be recognized
    }
    return TLS_HASH_ALGO_NOT_NEGO;
} // end of TLScipherSuiteGetHashID

tlsRespStatus  tlsTransHashTakeSnapshot(tlsSecurityElements_t  *sec, tlsHashAlgoID hash_id, byte *out, word16 outlen)
{ return TLS_RESP_OK; }

tlsRespStatus  tlsDecodeExtCertificate(tlsCert_t *cert, word16 first_ext_unfinished)
{ return TLS_RESP_OK; }


void tlsX509FreeCertExt(tlsX509v3ext_t *in)
{
} // end of tlsX509FreeCertExt

void  tlsRSAfreePubKey(void *pubkey_p)
{
    XMEMFREE(pubkey_p);
} // end of tlsRSAfreePubKey

static tlsCert_t*  mockInitCAcerts(void)
{
    tlsCert_t *out = NULL;
    tlsCert_t *curr_cert = NULL;
    tlsCert_t *prev_cert = NULL;
    word32  mock_size = 0x25;
    word16  idx = 0;
    // assume there are 2 cert items in CA cert chain
    for(idx = 0; idx < NUM_CA_CERTS; idx++) {
        curr_cert = XMALLOC(sizeof(tlsCert_t));
        XMEMSET(curr_cert, 0x00, sizeof(tlsCert_t));
        tlsEncodeWord24(&curr_cert->rawbytes.len[0], mock_size);
        tlsDecodeX509cert(curr_cert);
        if(out == NULL) { out = curr_cert; }
        if(prev_cert == NULL) {
            prev_cert = curr_cert;
        } else {
            prev_cert->next = curr_cert;
            prev_cert       = prev_cert->next;
        }
    }
    return out;
} // end of mockInitCAcerts




// ---------------------------------------------------------------------
TEST_GROUP(tlsCopyCertRawData);
TEST_GROUP(tlsDecodeCerts);
TEST_GROUP(tlsVerifyCertChain);
TEST_GROUP(tlsCertVerifyGenDigitalSig);
TEST_GROUP(tlsSignCertSignature);

TEST_GROUP_RUNNER(tlsCopyCertRawData)
{
    RUN_TEST_CASE(tlsCopyCertRawData, multi_certs_multi_frags);
}

TEST_GROUP_RUNNER(tlsDecodeCerts)
{
    RUN_TEST_CASE(tlsDecodeCerts, decode_multi_certs);
}

TEST_GROUP_RUNNER(tlsVerifyCertChain)
{
    RUN_TEST_CASE(tlsVerifyCertChain, without_issuer_cert);
    RUN_TEST_CASE(tlsVerifyCertChain, with_issuer_cert);
    //// RUN_TEST_CASE(tlsVerifyCertChain, incorrect_issuer_order); // TODO:
}
TEST_GROUP_RUNNER(tlsCertVerifyGenDigitalSig)
{
    RUN_TEST_CASE(tlsCertVerifyGenDigitalSig, server_side);
}

TEST_GROUP_RUNNER(tlsSignCertSignature)
{
    RUN_TEST_CASE(tlsSignCertSignature, rsa_pss);
}

TEST_SETUP(tlsCopyCertRawData)
{
    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->sec.flgs.ct_final_frag = 0;
    tls_session->sec.flgs.ct_first_frag = 1;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    tls_session->last_cpy_cert_len = 0;
}

TEST_SETUP(tlsDecodeCerts)
{
    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->sec.chosen_ciphersuite = NULL;
}

TEST_SETUP(tlsVerifyCertChain)
{}

TEST_SETUP(tlsCertVerifyGenDigitalSig)
{
    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->sec.chosen_ciphersuite = NULL;
}

TEST_SETUP(tlsSignCertSignature)
{
    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->sec.chosen_ciphersuite = NULL;
}

TEST_TEAR_DOWN(tlsCopyCertRawData)
{}

TEST_TEAR_DOWN(tlsDecodeCerts)
{}

TEST_TEAR_DOWN(tlsVerifyCertChain)
{}

TEST_TEAR_DOWN(tlsCertVerifyGenDigitalSig)
{}

TEST_TEAR_DOWN(tlsSignCertSignature)
{}


TEST(tlsCopyCertRawData, multi_certs_multi_frags)
{
    word16  certs_rawbyte_sz[NUM_PEER_CERTS];
    word16  certs_ext_sz[NUM_PEER_CERTS] = {9, 6, 13, 19, 16, 10, 11, 12};
    byte   *certchain_rawbytes = NULL;
    word16  certchain_sz = 0;
    word16  nbytes_certs_copied = 0;
    word16  nbytes_certs_cpy = 0;
    byte   *buf = NULL;
    tlsCert_t  *curr_cert = NULL;
    word32  expect_value = 0;
    word32  actual_value = 0;
    word16  idx = 0;
    tlsRespStatus status = TLS_RESP_OK;

    // assume number of the decrypted bytes are always equal to input buffer size
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    // assume there's no certificate request context followed by certificate chain bytes
    tls_session->inlen_decoded = TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES + 1 + 0 + 3;

    // ---------- generate cert chain bytes for test ----------
    certs_rawbyte_sz[0] = tls_session->inbuf.len - tls_session->inlen_decoded - 3 - 2 - certs_ext_sz[0] - 1;
    // first byte of the second certificate will be received in the first flight
    certs_rawbyte_sz[1] = tls_session->inbuf.len - 3 - 2 - certs_ext_sz[1] - 1;
    // first 2 bytes of the third certificate will be received in the second flight
    certs_rawbyte_sz[2] = tls_session->inbuf.len - 3 - 2 - certs_ext_sz[2] - 1;
    // first 3 bytes of the fourth certificate will be received in the third flight
    certs_rawbyte_sz[3] = tls_session->inbuf.len - 3 - 2 - certs_ext_sz[3] - 1;
    // first 4 bytes of the fifth certificate will be received in the fourth flight
    certs_rawbyte_sz[4] = tls_session->inbuf.len - 3 - 0 + 4;
    // entire extension section of the fifth certificate will be received in the sixth flight
    certs_rawbyte_sz[5] = tls_session->inbuf.len - 3 - 2 - certs_ext_sz[4] - 1;
    // partial extension section of the sixth certificate will be received in the seventh flight
    certs_rawbyte_sz[6] = tls_session->inbuf.len - 3 - 2 - certs_ext_sz[5] - 1;
    certs_rawbyte_sz[7] = tls_session->inbuf.len - 3 - 2 - certs_ext_sz[6] - 1;
    for(idx = 0; idx < NUM_PEER_CERTS; idx++) {
        certchain_sz += 3 + certs_rawbyte_sz[idx] + 2 + certs_ext_sz[idx];
    }
    TEST_ASSERT_LESS_THAN_UINT16(TLS_MAX_BYTES_CERT_CHAIN, certchain_sz);
    certchain_rawbytes = XMALLOC(sizeof(byte) * certchain_sz);
    for(idx = 0; idx < certchain_sz; idx++) {
        certchain_rawbytes[idx] = (idx + 1) & 0xff;
    } // end of for loop
    buf = certchain_rawbytes;
    for(idx = 0; idx < NUM_PEER_CERTS; idx++) {
        buf += tlsEncodeWord24(buf, certs_rawbyte_sz[idx]);
        buf += certs_rawbyte_sz[idx];
        buf += tlsEncodeWord16(buf, certs_ext_sz[idx]);
        buf += tlsEncodeWord16(buf, TLS_EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP);
        buf += tlsEncodeWord16(buf, certs_ext_sz[idx] - 4);
        buf += certs_ext_sz[idx] - 4;
    } // end of for loop
    TEST_ASSERT_EQUAL_UINT(&certchain_rawbytes[certchain_sz] , buf);
    // ---------- generate cert chain bytes for test ----------
    tls_session->nbytes.total_certs = certchain_sz;
    // ---------- copy raw bytes from the first fragment ----------
    nbytes_certs_copied = 0;
    nbytes_certs_cpy = XMIN(certchain_sz - nbytes_certs_copied, tls_session->inbuf.len - tls_session->inlen_decoded);
    buf  = &tls_session->inbuf.data[tls_session->inlen_decoded];
    XMEMCPY(buf, &certchain_rawbytes[nbytes_certs_copied], nbytes_certs_cpy);
    nbytes_certs_copied  += nbytes_certs_cpy;
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->peer_certs);
    status = tlsCopyCertRawData(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->peer_certs);
    curr_cert = tls_session->peer_certs;
    TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->rawbytes.data);
    expect_value = certs_rawbyte_sz[0];
    tlsDecodeWord24(&curr_cert->rawbytes.len[0], (word32 *)&actual_value);
    TEST_ASSERT_EQUAL_UINT32(expect_value, actual_value);
    TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->exts);
    TEST_ASSERT_EQUAL_UINT16(TLS_EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP, curr_cert->exts->type);
    TEST_ASSERT_EQUAL_UINT16((certs_ext_sz[0] - 4), curr_cert->exts->content.len);
    TEST_ASSERT_EQUAL_UINT32(1, tls_session->last_cpy_cert_len);
    curr_cert = curr_cert->next;
    TEST_ASSERT_NOT_EQUAL(NULL, curr_cert);
    TEST_ASSERT_EQUAL_UINT(NULL, curr_cert->rawbytes.data);
    TEST_ASSERT_EQUAL_UINT(NULL, curr_cert->next);

    // ---------- copy raw bytes from the second, third, and fourth fragment ----------
    curr_cert = tls_session->peer_certs;
    for(idx = 1; idx < 4; idx++) {
        tls_session->inlen_decoded = 0;
        nbytes_certs_cpy = XMIN(certchain_sz - nbytes_certs_copied, tls_session->inbuf.len - tls_session->inlen_decoded);
        XMEMCPY(&tls_session->inbuf.data[tls_session->inlen_decoded], &certchain_rawbytes[nbytes_certs_copied], nbytes_certs_cpy);
        nbytes_certs_copied  += nbytes_certs_cpy;
        status = tlsCopyCertRawData(tls_session);
        TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
        curr_cert = curr_cert->next;
        TEST_ASSERT_NOT_EQUAL(NULL, curr_cert);
        TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->rawbytes.data);
        expect_value = certs_rawbyte_sz[idx];
        tlsDecodeWord24(&curr_cert->rawbytes.len[0], (word32 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT32(expect_value, actual_value);
        TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->exts);
        TEST_ASSERT_EQUAL_UINT16(TLS_EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP, curr_cert->exts->type);
        TEST_ASSERT_EQUAL_UINT16((certs_ext_sz[idx] - 4), curr_cert->exts->content.len);
        TEST_ASSERT_EQUAL_UINT32((idx + 1), tls_session->last_cpy_cert_len);
        TEST_ASSERT_EQUAL_UINT16(0x0 , tls_session->last_ext_entry_dec_len);
        TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->next);
        TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
    } // end of for loop idx

    // ---------- copy raw bytes of next certificate from the fifth, sixth, seventh fragment ----------
    for(idx = 4; idx < NUM_PEER_CERTS; idx++) {
        tls_session->inlen_decoded = 0;
        nbytes_certs_cpy = XMIN(certchain_sz - nbytes_certs_copied, tls_session->inbuf.len - tls_session->inlen_decoded);
        XMEMCPY(&tls_session->inbuf.data[tls_session->inlen_decoded], &certchain_rawbytes[nbytes_certs_copied], nbytes_certs_cpy);
        nbytes_certs_copied  += nbytes_certs_cpy;
        status = tlsCopyCertRawData(tls_session);
        TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
        if(idx > 4) {
            TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->exts);
            TEST_ASSERT_EQUAL_UINT16(TLS_EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP, curr_cert->exts->type);
            TEST_ASSERT_EQUAL_UINT16((certs_ext_sz[idx - 1] - 4), curr_cert->exts->content.len);
        }
        curr_cert = curr_cert->next;
        TEST_ASSERT_NOT_EQUAL(NULL, curr_cert);
        TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->rawbytes.data);
        expect_value = certs_rawbyte_sz[idx];
        tlsDecodeWord24(&curr_cert->rawbytes.len[0], (word32 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT32(expect_value, actual_value);
        TEST_ASSERT_EQUAL_UINT32((3 + certs_rawbyte_sz[idx]) , tls_session->last_cpy_cert_len);
        switch(idx) {
            case 4:  expect_value = 0x8000;  break;
            case 5:  expect_value = 0x8001;  break;
            default: expect_value = idx - 6; break;
        } // end of switch case
        TEST_ASSERT_EQUAL_UINT16(expect_value, tls_session->last_ext_entry_dec_len);
        if(idx < 7) {
            TEST_ASSERT_EQUAL_UINT(NULL, curr_cert->exts);
        }
        TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
    } // end of for loop idx

    tls_session->sec.flgs.ct_first_frag = 0;
    tls_session->sec.flgs.ct_final_frag = 1;
    tls_session->inlen_decoded = 0;
    nbytes_certs_cpy = XMIN(certchain_sz - nbytes_certs_copied, tls_session->inbuf.len - tls_session->inlen_decoded);
    XMEMCPY(&tls_session->inbuf.data[tls_session->inlen_decoded], &certchain_rawbytes[nbytes_certs_copied], nbytes_certs_cpy);
    nbytes_certs_copied  += nbytes_certs_cpy;
    TEST_ASSERT_LESS_THAN_UINT16(tls_session->inbuf.len, nbytes_certs_cpy);
    tls_session->inlen_decrypted = nbytes_certs_cpy + 1 + tls_session->sec.chosen_ciphersuite->tagSize;
    status = tlsCopyCertRawData(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->exts);
    TEST_ASSERT_EQUAL_UINT16((certs_ext_sz[7] - 4), curr_cert->exts->content.len);
    TEST_ASSERT_EQUAL_UINT16(certchain_sz, nbytes_certs_copied);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded + 1 + tls_session->sec.chosen_ciphersuite->tagSize);

    XMEMFREE(certchain_rawbytes);
} // end of TEST(tlsCopyCertRawData, multi_certs_multi_frags)


TEST(tlsDecodeCerts, decode_multi_certs)
{
    tlsCert_t  *middle_cert = NULL;
    tlsCert_t  *curr_cert   = NULL;
    word16  idx = 0;
    tlsRespStatus status = TLS_RESP_OK;
    byte final_item_rdy  = 0;

    for(idx = 0, curr_cert = tls_session->peer_certs; idx < (NUM_PEER_CERTS >> 1); idx++, middle_cert = curr_cert, curr_cert = curr_cert->next);
    TEST_ASSERT_NOT_EQUAL(NULL, middle_cert);
    TEST_ASSERT_NOT_EQUAL(tls_session->peer_certs, middle_cert);
    
    mock_cert_sig_algo = TLS_ALGO_OID_SHA384_RSA_SIG;
    final_item_rdy  = 0; // --------- assume final cert item is NOT ready yet ---------
    status = tlsDecodeCerts(middle_cert, final_item_rdy);
    tlsFreeCertChain(middle_cert, TLS_FREE_CERT_ENTRY_RAWBYTE | TLS_FREE_CERT_ENTRY_SKIP_FINAL_ITEM);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    // the cert items prior to middle_cert shouldn't be modified
    for(curr_cert = tls_session->peer_certs; curr_cert != middle_cert; curr_cert = curr_cert->next) {
        TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->rawbytes.data);
        TEST_ASSERT_EQUAL_UINT(NULL, curr_cert->signature.data);
    } // end of for loop
    for(curr_cert = middle_cert; curr_cert->next != NULL; curr_cert = curr_cert->next) {
        TEST_ASSERT_EQUAL_UINT(NULL, curr_cert->rawbytes.data);
        TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->signature.data);
        TEST_ASSERT_EQUAL_UINT16(TLS_ALGO_OID_SHA384_RSA_SIG, curr_cert->sign_algo);
    } // end of for loop
    // check the final cert item
    TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->rawbytes.data);
    TEST_ASSERT_EQUAL_UINT(NULL, curr_cert->signature.data);

    mock_cert_sig_algo = TLS_ALGO_OID_RSASSA_PSS;
    final_item_rdy  = 1; // --------- assume final cert item is NOT ready yet ---------
    status = tlsDecodeCerts(tls_session->peer_certs, final_item_rdy);
    tlsFreeCertChain(tls_session->peer_certs, TLS_FREE_CERT_ENTRY_RAWBYTE);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    for(curr_cert = tls_session->peer_certs; curr_cert != NULL; curr_cert = curr_cert->next) {
        TEST_ASSERT_EQUAL_UINT(NULL, curr_cert->rawbytes.data);
        TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->signature.data);
        if(curr_cert->sign_algo != TLS_ALGO_OID_SHA384_RSA_SIG) {
            TEST_ASSERT_EQUAL_UINT16(TLS_ALGO_OID_RSASSA_PSS, curr_cert->sign_algo);
        }
    } // end of for loop
} // end of TEST(tlsDecodeCerts, decode_multi_certs)



static void tlsVerifyCertChain_verify_single_chain(byte *cert_issuing_order)
{
    tlsCert_t  *curr_cert   = NULL;
    tlsRespStatus status = TLS_RESP_OK;
    word16  idx = 0;

    cert_issuing_order[NUM_PEER_CERTS - 1] = 0; // the final item must always be zero, that represents index of server cert
    //// printf("xxx: ");
    //// for(idx = 0; idx < NUM_PEER_CERTS; idx++) {
    ////     printf("%d, ", cert_issuing_order[idx]);
    //// } // end of for loop
    //// printf("\r\n");
    mock_cert_issuer_hashed_dn[cert_issuing_order[0]] = mock_cert_subject_hashed_dn[cert_issuing_order[0]];
    for(idx = 1; idx < NUM_PEER_CERTS; idx++) {
        mock_cert_issuer_hashed_dn[cert_issuing_order[idx]] = mock_cert_subject_hashed_dn[cert_issuing_order[idx - 1]];
    } // end of for loop
    for(idx = 0, curr_cert = tls_session->peer_certs; curr_cert != NULL; idx++, curr_cert = curr_cert->next) {
        XMEMCPY(curr_cert->issuer.hashed_dn, &mock_cert_issuer_hashed_dn[idx], NBYTES_CERT_HASHED_DISTINGUISHED_NAME);
        XMEMCPY(curr_cert->subject.hashed_dn, &mock_cert_subject_hashed_dn[idx], NBYTES_CERT_HASHED_DISTINGUISHED_NAME);
        curr_cert->flgs.auth_done = 0;
        curr_cert->flgs.auth_pass = 0;
        curr_cert->flgs.self_signed = 0;
    } // end of for loop

    status = tlsVerifyCertChain(NULL, tls_session->peer_certs);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    for(curr_cert = tls_session->peer_certs; curr_cert != NULL; curr_cert = curr_cert->next) {
        TEST_ASSERT_EQUAL_UINT8(1, curr_cert->flgs.auth_done);
        TEST_ASSERT_EQUAL_UINT8(1, curr_cert->flgs.auth_pass);
        if(curr_cert->next == NULL) {
            TEST_ASSERT_EQUAL_UINT8(1, curr_cert->flgs.self_signed);
        }
    } // end of for loop
} // end of tlsVerifyCertChain_verify_single_chain

static void tlsVerifyCertChain_verify_all_possible_chains(word16 avail_num, word16 total_num,
                 byte *combination_selected_flags, byte *cert_issuing_order)
{
    word16  idx = 0;
    if(avail_num == 0) {
        tlsVerifyCertChain_verify_single_chain(cert_issuing_order);
        return;
    }
    for(idx = 0; idx < total_num; idx++) {
        if(combination_selected_flags[idx] == 0) {
            combination_selected_flags[idx] = 1;
            cert_issuing_order[total_num - avail_num] = idx + 1;
            tlsVerifyCertChain_verify_all_possible_chains(avail_num - 1, total_num,
                   combination_selected_flags, cert_issuing_order);
            combination_selected_flags[idx] = 0;
        }
    } // end of for loop
} // end of tlsVerifyCertChain_verify_all_possible_chains
 

#define  tlsVerifyCertChain_verify_chains_wrapper(n, select_flgs, chain_order)  \
         tlsVerifyCertChain_verify_all_possible_chains((n), (n), (select_flgs), (chain_order))
TEST(tlsVerifyCertChain, without_issuer_cert)
{
    byte  combination_selected_flags[NUM_PEER_CERTS];
    byte  cert_issuing_order[NUM_PEER_CERTS];
    word16  idx = 0;

    for(idx = 0; idx < NUM_PEER_CERTS; idx++) {
        mock_cert_subject_hashed_dn[idx] = &mock_cert_hashed_dn[idx][0];
    } // end of for loop
    // this test will try all possible combinations of cert chain formation, which looks like :
    // e.g. (0) <- (2) <- (5) <- (1) <- (6) <- (4) <- (7) <- (3)
    // which means the owner of cert (2) issued cert (0), owner of cert (5) issued cert (2),
    //   .... etc. , and cert (3) is CA cert
    XMEMSET(&combination_selected_flags[0], 0x00, sizeof(byte) * NUM_PEER_CERTS);
    tlsVerifyCertChain_verify_chains_wrapper(NUM_PEER_CERTS - 1, &combination_selected_flags[0], &cert_issuing_order[0]);
} // end of TEST(tlsVerifyCertChain, without_issuer_cert)
#undef  tlsVerifyCertChain_verify_chains_wrapper



TEST(tlsVerifyCertChain, with_issuer_cert)
{
    tlsCert_t  *curr_cert   = NULL;
    byte  cert_issuing_order[NUM_PEER_CERTS];
    byte   *buf = NULL;
    word16  idx = 0;
    tlsRespStatus status = TLS_RESP_OK;

    tls_session->CA_cert = mockInitCAcerts();

    for(idx = 0; idx < NUM_CA_CERTS; idx++) {
        mock_cert_subject_hashed_dn[idx] = &mock_cert_hashed_dn[NUM_PEER_CERTS + idx][0];
    } // end of for loop
    for(idx = 1; idx < NUM_CA_CERTS; idx++) {
        mock_cert_issuer_hashed_dn[idx - 1] = mock_cert_subject_hashed_dn[idx];
    } // end of for loop
    mock_cert_issuer_hashed_dn[NUM_CA_CERTS - 1] = mock_cert_subject_hashed_dn[NUM_CA_CERTS - 1];
    for(idx = 0, curr_cert = tls_session->CA_cert; curr_cert != NULL; idx++, curr_cert = curr_cert->next) {
        XMEMCPY(curr_cert->issuer.hashed_dn, &mock_cert_issuer_hashed_dn[idx], NBYTES_CERT_HASHED_DISTINGUISHED_NAME);
        XMEMCPY(curr_cert->subject.hashed_dn, &mock_cert_subject_hashed_dn[idx], NBYTES_CERT_HASHED_DISTINGUISHED_NAME);
        curr_cert->flgs.auth_done = 0;
        curr_cert->flgs.auth_pass = 0;
        curr_cert->flgs.self_signed = 0;
    } // end of for loop
    buf = mock_cert_subject_hashed_dn[0]; // store for later use

    for(idx = 0; idx < NUM_PEER_CERTS; idx++) {
        mock_cert_subject_hashed_dn[idx] = &mock_cert_hashed_dn[idx][0];
    } // end of for loop
    cert_issuing_order[0] = 3;
    cert_issuing_order[1] = 2;
    cert_issuing_order[2] = 5;
    cert_issuing_order[3] = 4;
    cert_issuing_order[4] = 7;
    cert_issuing_order[5] = 1;
    cert_issuing_order[6] = 6;
    cert_issuing_order[7] = 0;
    mock_cert_issuer_hashed_dn[cert_issuing_order[0]] =  buf;
    for(idx = 1; idx < NUM_PEER_CERTS; idx++) {
        mock_cert_issuer_hashed_dn[cert_issuing_order[idx]] = mock_cert_subject_hashed_dn[cert_issuing_order[idx - 1]];
    } // end of for loop
    for(idx = 0, curr_cert = tls_session->peer_certs; curr_cert != NULL; idx++, curr_cert = curr_cert->next) {
        XMEMCPY(curr_cert->issuer.hashed_dn, &mock_cert_issuer_hashed_dn[idx], NBYTES_CERT_HASHED_DISTINGUISHED_NAME);
        XMEMCPY(curr_cert->subject.hashed_dn, &mock_cert_subject_hashed_dn[idx], NBYTES_CERT_HASHED_DISTINGUISHED_NAME);
        curr_cert->flgs.auth_done = 0;
        curr_cert->flgs.auth_pass = 0;
        curr_cert->flgs.self_signed = 0;
    } // end of for loop

    status = tlsVerifyCertChain(tls_session->CA_cert, tls_session->peer_certs);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    for(curr_cert = tls_session->peer_certs; curr_cert != NULL; curr_cert = curr_cert->next) {
        TEST_ASSERT_EQUAL_UINT8(1, curr_cert->flgs.auth_done);
        TEST_ASSERT_EQUAL_UINT8(1, curr_cert->flgs.auth_pass);
        TEST_ASSERT_EQUAL_UINT8(0, curr_cert->flgs.self_signed);
    } // end of for loop

    tlsFreeCertChain(tls_session->CA_cert, TLS_FREE_CERT_ENTRY_ALL);
    tls_session->CA_cert = NULL;
} // end of TEST(tlsVerifyCertChain, with_issuer_cert)


TEST(tlsCertVerifyGenDigitalSig, server_side)
{
    tlsOpaque16b_t  gened_digi_sig = {0, NULL};
    tlsRSApss_t     rsapssSig = {0 , 0};
    tlsRespStatus   status = TLS_RESP_OK;
    const byte      is_server = 1;

    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[1];
    rsapssSig.hash_id  = TLS_HASH_ALGO_SHA256;
    rsapssSig.salt_len = mqttHashGetOutlenBytes(rsapssSig.hash_id);
    status = tlsCertVerifyGenDigitalSig(&tls_session->sec, (const tlsRSApss_t *)&rsapssSig,  &gened_digi_sig, is_server);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, gened_digi_sig.data);
    TEST_ASSERT_EQUAL_UINT16(rsapssSig.salt_len, gened_digi_sig.len);
    XMEMFREE(gened_digi_sig.data);
    gened_digi_sig.data = NULL;

    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    rsapssSig.hash_id  = TLS_HASH_ALGO_SHA384;
    rsapssSig.salt_len = mqttHashGetOutlenBytes(rsapssSig.hash_id);
    status = tlsCertVerifyGenDigitalSig(&tls_session->sec, (const tlsRSApss_t *)&rsapssSig,  &gened_digi_sig, is_server);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, gened_digi_sig.data);
    TEST_ASSERT_EQUAL_UINT16(rsapssSig.salt_len, gened_digi_sig.len);
    XMEMFREE(gened_digi_sig.data);
    gened_digi_sig.data = NULL;
} // end of TEST(tlsCertVerifyGenDigitalSig, server_side)


TEST(tlsSignCertSignature, rsa_pss)
{
    tlsOpaque16b_t  digiSig   = {0 , NULL};
    tlsRSApss_t     rsapssSig = {0 , 0};
    tlsRespStatus   status = TLS_RESP_OK;

    tls_session->CA_priv_key = XCALLOC(0x1, sizeof(tlsRSAkey_t));
    tls_session->drbg        = XCALLOC(0x1, sizeof(mqttDRBG_t));
    // currently this implementation only supports rsa_pss_rsae_sha256 for signing & verifying
    // signature on Certificate & CertificateVerify, which is mandatory in RFC 8446, section 9.1
    rsapssSig.hash_id = TLS_HASH_ALGO_SHA256;
    rsapssSig.salt_len = mqttHashGetOutlenBytes(rsapssSig.hash_id);
    tls_session->client_signed_sig.len  = (rsapssSig.salt_len << 3);
    tls_session->client_signed_sig.data = XMALLOC(sizeof(byte) * tls_session->client_signed_sig.len);
    digiSig.len  = rsapssSig.salt_len;
    digiSig.data = XMALLOC(digiSig.len); // assume it's  digital signature generated by tlsCertVerifyGenDigitalSig()

    status =  tlsSignCertSignature(tls_session->CA_priv_key, tls_session->drbg, &digiSig, 
                 &tls_session->client_signed_sig, TLS_ALGO_OID_RSASSA_PSS, &rsapssSig);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);

    XMEMFREE(tls_session->CA_priv_key);
    XMEMFREE(tls_session->drbg);
    XMEMFREE(tls_session->client_signed_sig.data);
    XMEMFREE(digiSig.data);
    tls_session->CA_priv_key = NULL;
    tls_session->drbg = NULL;
    tls_session->client_signed_sig.data = NULL;
    digiSig.data = NULL;
} // end of TEST(tlsSignCertSignature, rsa_pss)




static void mockInitCertHashedDN(void) {
    word16 idx, jdx, kdx = 0;
    kdx = 0x11;
    for(idx = 0; idx < (NUM_PEER_CERTS + NUM_CA_CERTS); idx++) {
    for(jdx = 0; jdx < NBYTES_CERT_HASHED_DISTINGUISHED_NAME; jdx++) {
        mock_cert_hashed_dn[idx][jdx] = (kdx++) % 0xff;
    } // end of for loop
    } // end of for loop
} // end of mockInitCertHashedDN


static void RunAllTestGroups(void)
{
    tls_session = (tlsSession_t *) XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->inbuf.len  = MAX_RAWBYTE_BUF_SZ;
    tls_session->inbuf.data = (byte *) XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);
    mockInitCertHashedDN();

    RUN_TEST_GROUP(tlsCopyCertRawData);
    RUN_TEST_GROUP(tlsDecodeCerts);
    RUN_TEST_GROUP(tlsVerifyCertChain);
    RUN_TEST_GROUP(tlsCertVerifyGenDigitalSig);
    RUN_TEST_GROUP(tlsSignCertSignature);

    tlsFreeCertChain(tls_session->peer_certs, TLS_FREE_CERT_ENTRY_ALL);
    tls_session->peer_certs = NULL;
    XMEMFREE(tls_session->inbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups

int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


