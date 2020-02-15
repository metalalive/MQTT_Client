#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

#define  MAX_RAWBYTE_BUF_SZ  0x80

static tlsSession_t *tls_session;

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

void tlsX509FreeCertExt(tlsX509v3ext_t *in)
{
} // end of tlsX509FreeCertExt

void  tlsRSAfreePubKey(void *pubkey_p)
{
} // end of tlsRSAfreePubKey





// ---------------------------------------------------------------------
TEST_GROUP(tlsCopyCertRawData);

TEST_GROUP_RUNNER(tlsCopyCertRawData)
{
    RUN_TEST_CASE(tlsCopyCertRawData, multi_certs_multi_frags);
}

TEST_SETUP(tlsCopyCertRawData)
{
    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->sec.flgs.ct_final_frag = 0;
    tls_session->sec.flgs.ct_first_frag = 1;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    tls_session->last_cpy_cert_len = 0;
}

TEST_TEAR_DOWN(tlsCopyCertRawData)
{
    tlsFreeCertChain(tls_session->peer_certs, TLS_FREE_CERT_ENTRY_ALL);
    tls_session->peer_certs = NULL;
}


#define  NUM_CERTS  8
TEST(tlsCopyCertRawData, multi_certs_multi_frags)
{
    word16  certs_rawbyte_sz[NUM_CERTS];
    word16  certs_ext_sz[NUM_CERTS] = {9, 6, 13, 19, 16, 10, 11, 12};
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
    for(idx = 0; idx < NUM_CERTS; idx++) {
        certchain_sz += 3 + certs_rawbyte_sz[idx] + 2 + certs_ext_sz[idx];
    }
    TEST_ASSERT_LESS_THAN_UINT16(TLS_MAX_BYTES_CERT_CHAIN, certchain_sz);
    certchain_rawbytes = XMALLOC(sizeof(byte) * certchain_sz);
    for(idx = 0; idx < certchain_sz; idx++) {
        certchain_rawbytes[idx] = (idx + 1) & 0xff;
    } // end of for loop
    buf = certchain_rawbytes;
    for(idx = 0; idx < NUM_CERTS; idx++) {
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
    } // end of for loop idx

    // ---------- copy raw bytes of next certificate from the fifth, sixth, seventh fragment ----------
    for(idx = 4; idx < NUM_CERTS; idx++) {
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
    } // end of for loop idx

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

    XMEMFREE(certchain_rawbytes);
} // end of TEST(tlsCopyCertRawData, multi_certs_multi_frags)
#undef NUM_CERTS





static void RunAllTestGroups(void)
{
    tls_session = (tlsSession_t *) XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->inbuf.len  = MAX_RAWBYTE_BUF_SZ;
    tls_session->inbuf.data = (byte *) XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);

    RUN_TEST_GROUP(tlsCopyCertRawData);

    XMEMFREE(tls_session->inbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups

int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


