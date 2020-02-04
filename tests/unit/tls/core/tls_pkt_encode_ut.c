#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

#define MAX_RAWBYTE_BUF_SZ 0x100 // internal parameter for read buffer, DO NOT modify this value

static tlsSession_t *tls_session;
static word16        mock_extensions_start_idx_outbuf;

typedef struct {
    tlsExtType type;
    word16     len;
} mockExtEntryInfo_t;

static mockExtEntryInfo_t *mock_encoding_extension_entries;

static mockExtEntryInfo_t  mock_extention_entries_clienthello[] = {
    {TLS_EXT_TYPE_SERVER_NAME            , 0},
    {TLS_EXT_TYPE_SUPPORTED_VERSIONS     , 0},
    {TLS_EXT_TYPE_SUPPORTED_GROUPS       , 0},
    {TLS_EXT_TYPE_SIGNATURE_ALGORITHMS   , 0},
    {TLS_EXT_TYPE_KEY_SHARE              , 0},
    {TLS_EXT_TYPE_PSK_KEY_EXCHANGE_MODES , 0},
    {TLS_EXT_TYPE_PRE_SHARED_KEY         , 0},
    {TLS_EXT_TYPE_MAX_VALUE_RESERVED     , 0},
};



static tlsRespStatus  mock_tlsAESGCMinit (tlsSecurityElements_t *sec, byte isDecrypt)
{ return TLS_RESP_OK; }
static tlsRespStatus  mock_tlsAESGCMencrypt (tlsSecurityElements_t *sec, byte *pt, byte *ct, word32 *len)
{ return TLS_RESP_OK; }
static tlsRespStatus  mock_tlsAESGCMdecrypt (tlsSecurityElements_t *sec, byte *ct, byte *pt, word32 *len)
{ return TLS_RESP_OK; }
static tlsRespStatus  mock_tlsSymEncryptCommonDone(tlsSecurityElements_t *sec)
{ return TLS_RESP_OK; }

const tlsCipherSpec_t  tls_supported_cipher_suites[] = {
    { // TLS_AES_128_GCM_SHA256, 0x1301
        TLS_CIPHERSUITE_ID_AES_128_GCM_SHA256   ,// ident
        (1 << TLS_ENCRYPT_ALGO_AES128) | (1 << TLS_ENC_CHAINMODE_GCM) | (1 << TLS_HASH_ALGO_SHA256)      ,// flags
        16        ,// tagSize
        16        ,// keySize
        12        ,// ivSize
        mock_tlsAESGCMinit          ,// init_fn
        mock_tlsAESGCMencrypt       ,// encrypt_fn
        mock_tlsAESGCMdecrypt       ,// decrypt_fn
        mock_tlsSymEncryptCommonDone,// done_fn
    },
    { // TLS_AES_256_GCM_SHA384, 0x1302
        TLS_CIPHERSUITE_ID_AES_256_GCM_SHA384   ,// ident
        (1 << TLS_ENCRYPT_ALGO_AES256) | (1 << TLS_ENC_CHAINMODE_GCM) | (1 << TLS_HASH_ALGO_SHA384)      ,// flags
        16        ,// tagSize
        32        ,// keySize
        12        ,// ivSize
        mock_tlsAESGCMinit          ,// init_fn
        mock_tlsAESGCMencrypt       ,// encrypt_fn
        mock_tlsAESGCMdecrypt       ,// decrypt_fn
        mock_tlsSymEncryptCommonDone,// done_fn
    },
};

const tlsNamedGrp  tls_supported_named_groups[] = {
    TLS_NAMED_GRP_SECP256R1, TLS_NAMED_GRP_X25519,
    TLS_NAMED_GRP_SECP384R1, TLS_NAMED_GRP_SECP521R1,
};


byte  tlsGetSupportedCipherSuiteListSize( void )
{
    byte  out = XGETARRAYSIZE(tls_supported_cipher_suites);
    return out;
} // end of tlsGetSupportedCipherSuiteListSize

byte  tlsGetSupportedKeyExGrpSize( void )
{
    byte  out = XGETARRAYSIZE(tls_supported_named_groups);
    return out;
} // end of tlsGetSupportedKeyExGrpSize


tlsHandshakeType  tlsGetHSexpectedState(tlsSession_t *session)
{
    return (session==NULL ? TLS_HS_TYPE_HELLO_REQUEST_RESERVED: session->hs_state);
} // end of tlsGetHSexpectedState

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
} // end of mqttHashGetOutlenBytes


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


tlsRespStatus  tlsChkFragStateOutMsg(tlsSession_t *session)
{
    tlsRespStatus status = TLS_RESP_OK;
    if(session == NULL) { status = TLS_RESP_ERRARGS; }
    else {
        if(session->num_frags_out == 0) {
            status = TLS_RESP_REQ_REINIT;
        }
        else { // when num_frags_out > 0 , that means it is working & currently encoding message hasn't been sent yet
            if(session->remain_frags_out == session->num_frags_out) {
                status  = TLS_RESP_FIRST_FRAG;
            }
            if(session->remain_frags_out == 1) {
                status |= TLS_RESP_FINAL_FRAG;
            }
        }
    }
    return  status;
} // end of tlsChkFragStateOutMsg


static void mock_allocSpaceBeforeKeyEx(tlsSession_t *session)
{
    byte *buf = NULL;
    word16 len = 0;
    // initialize key-exchange structure
    session->keyex.num_grps_total = tlsGetSupportedKeyExGrpSize();
    len = (sizeof(tlsKeyExState) + sizeof(void *)) * session->keyex.num_grps_total;
    buf = XMALLOC(len);
    XMEMSET(buf, 0x00, (size_t)len);

    len = sizeof(tlsKeyExState) * session->keyex.num_grps_total;
    session->keyex.grp_nego_state = (tlsKeyExState *) &buf[0];
    // create a list of pointers, pointed to different key structures (e.g. ECC, X25519, DH)
    session->keyex.keylist = (void **) &buf[len];
    // chosen_grp_idx  should NOT be greater than num_grps_total, here we set num_grps_total as default value
    // which means we haven't found appropriate named groups / key exchange algorithm
    session->keyex.chosen_grp_idx = session->keyex.num_grps_total;
    // allocate space for early hankshake phase.
    buf = XMALLOC(sizeof(byte) * ((TLS_HS_RANDOM_BYTES << 1) + TLS_MAX_BYTES_SESSION_ID));
    session->sec.client_rand = &buf[0];
    session->sec.server_rand = &buf[TLS_HS_RANDOM_BYTES];
    session->tmpbuf.session_id.len  = TLS_MAX_BYTES_SESSION_ID;
    session->tmpbuf.session_id.data = &buf[TLS_HS_RANDOM_BYTES << 1];
} // end of mock_allocSpaceBeforeKeyEx


static void mock_cleanSpaceAfterKeyEx(tlsSession_t *session)
{
    // deallocate generated but unused key(s) after key-exchange algorithm is negotiated
    tlsFreeEphemeralKeyPairs(&session->keyex);
    if( session->keyex.grp_nego_state != NULL ){
        XMEMFREE((void *)session->keyex.grp_nego_state);
        session->keyex.grp_nego_state = NULL;
        session->keyex.keylist = NULL;
    }
    if(session->sec.client_rand != NULL) {
        XMEMFREE((void *)session->sec.client_rand);
        session->sec.client_rand = NULL;
        session->sec.server_rand = NULL;
        session->tmpbuf.session_id.data = NULL;
    }
} // end of mock_cleanSpaceAfterKeyEx


void tlsCleanSpaceOnClientCertSent(tlsSession_t *session)
{
    if(session->flgs.omit_client_cert_chk == 0) {
        if(session->tmpbuf.cert_req_ctx.data != NULL) {
            session->tmpbuf.cert_req_ctx.data = NULL;
        }
    }
} // end of tlsCleanSpaceOnClientCertSent


word16  tlsGetExtListSize( tlsExtEntry_t *ext_head )
{
    tlsExtEntry_t  *curr = ext_head;
    word16        out_sz = 0;
    while (curr != NULL) {
        out_sz += (2 + 2 + curr->content.len);
        curr = curr->next;
    } // end of while-loop
    return out_sz;
} // end of tlsGetExtListSize


tlsRespStatus  tlsFreeExtEntry(tlsExtEntry_t *in) {
    if(in == NULL) { return TLS_RESP_ERRARGS; }
    in->content.data  = NULL;
    in->next = NULL;
    XMEMFREE((void *)in);
    return TLS_RESP_OK;
} // end of tlsFreeExtEntry


tlsExtEntry_t*  tlsGenExtensions( tlsSession_t *session )
{
    tlsExtEntry_t  *out  = NULL;
    tlsExtEntry_t  *curr = NULL;
    tlsExtEntry_t  *prev = NULL;
    byte           *buf  = NULL;
    word16 len = 0;
    byte idx = 0;
    // generate a list of extension entries for this unit test
    for(idx=0; (mock_encoding_extension_entries != NULL) && (mock_encoding_extension_entries[idx].type != TLS_EXT_TYPE_MAX_VALUE_RESERVED); idx++) {
        len = mock_encoding_extension_entries[idx].len;
        if(len == 0) { continue; }
        buf = XMALLOC(sizeof(tlsExtEntry_t) + len);
        curr = (tlsExtEntry_t *) &buf[0];
        curr->next = NULL;
        curr->type = mock_encoding_extension_entries[idx].type;
        curr->content.len  = len;
        curr->content.data = &buf[sizeof(tlsExtEntry_t)];
        if(prev != NULL) { prev->next = curr; }
        else{ out = curr; }
        prev = curr;
    } // end of for-loop
    return out;
} // end of tlsGenExtensions


tlsRespStatus  tlsEncodeExtensions(tlsSession_t *session)
{
    tlsRespStatus  status     =  TLS_RESP_OK;
    word16     outlen_encoded =  session->outlen_encoded;
    byte      *outbuf         = &session->outbuf.data[0];
    tlsExtEntry_t *curr_ext   =  session->exts;
    word16     entry_copied_len = session->last_ext_entry_enc_len;
    word16     rdy_cpy_len   =  0;

    if((entry_copied_len >> 15) == 0x1) {
        // encode total length field of extension section byte-by-byte at here
        // (must be implemented in production code)
        mock_extensions_start_idx_outbuf = outlen_encoded;
        outlen_encoded += tlsEncodeWord16( &outbuf[outlen_encoded], session->ext_enc_total_len );
        entry_copied_len = 0;
    }

    while ((session->outbuf.len > outlen_encoded) && (curr_ext != NULL))
    {
        if(entry_copied_len == 0) { // TODO: refactor the code
            entry_copied_len  = 4;
            outlen_encoded += tlsEncodeWord16( &outbuf[outlen_encoded], (word16)curr_ext->type );
            outlen_encoded += tlsEncodeWord16( &outbuf[outlen_encoded], (word16)curr_ext->content.len );
        } // end of if entry_copied_len equal to 0
        if(session->outbuf.len > outlen_encoded) {
            rdy_cpy_len = XMIN(curr_ext->content.len - (entry_copied_len - 4), session->outbuf.len - outlen_encoded);
            XMEMCPY( &outbuf[outlen_encoded], &curr_ext->content.data[entry_copied_len - 4], rdy_cpy_len );
            outlen_encoded   += rdy_cpy_len;
            entry_copied_len += rdy_cpy_len;
            if(entry_copied_len == (4 + curr_ext->content.len)) { // if entire entry is copied to outbuf
                entry_copied_len = 0; // finish parsing current extension entry & may iterate over again
                tlsExtEntry_t  *prev_ext = curr_ext;
                tlsRemoveItemFromList((tlsListItem_t **)&curr_ext, (tlsListItem_t *)curr_ext);
                tlsFreeExtEntry(prev_ext);
                session->exts = curr_ext;
                XASSERT(session->outbuf.len >= outlen_encoded);
            }
            else {
                XASSERT(entry_copied_len < (4 + curr_ext->content.len));
                XASSERT(session->outbuf.len == outlen_encoded);
            }
        } // end of  if session->outbuf.len > outlen_encoded
    } // end of while-loop

    session->outlen_encoded         = outlen_encoded;
    session->last_ext_entry_enc_len = entry_copied_len;
    // more buffer space is required for current handshake message
    if (session->outbuf.len >= outlen_encoded) {
        status = (session->exts != NULL) ? TLS_RESP_REQ_MOREDATA : TLS_RESP_OK ;
    } else { XASSERT(NULL); }
    return status;
} // end of tlsEncodeExtensions

tlsRespStatus  tlsCertVerifyGenDigitalSig(tlsSecurityElements_t *sec, const tlsRSApss_t *rsapss_attri, tlsOpaque16b_t *out, const byte is_server)
{
    const byte clientlabel[] = "TLS 1.3, client CertificateVerify";
    word16         hash_len = 0;
    tlsHashAlgoID  hash_algo_id = TLS_HASH_ALGO_UNKNOWN;

    hash_algo_id = TLScipherSuiteGetHashID(sec->chosen_ciphersuite);
    hash_len     = mqttHashGetOutlenBytes(hash_algo_id);
    out->len  = 64 + sizeof(clientlabel) - 1 + 1 + hash_len;
    out->data = XMALLOC(sizeof(byte) * out->len);
    return TLS_RESP_OK;
} // end of tlsCertVerifyGenDigitalSig


mqttRespStatus  mqttUtilRandByteSeq(mqttDRBG_t *drbg, byte *out, word16 outlen)
{ return MQTT_RESP_OK; }

tlsRespStatus tlsSignCertSignature(void *privkey,  mqttDRBG_t *drbg, tlsOpaque16b_t *in, tlsOpaque16b_t *out,
                                    tlsAlgoOID sign_algo, tlsRSApss_t *rsapssextra)
{ return TLS_RESP_OK; }

tlsRespStatus  tlsHKDFexpandLabel(tlsHashAlgoID hash_id, tlsOpaque8b_t *in_secret, tlsOpaque8b_t *label, 
                                 tlsOpaque8b_t *context, tlsOpaque8b_t *out_secret)
{ return TLS_RESP_OK; }

tlsRespStatus  tlsTransHashTakeSnapshot(tlsSecurityElements_t  *sec, tlsHashAlgoID hash_id, byte *out, word16 outlen)
{ return TLS_RESP_OK; }

void  tlsFreeEphemeralKeyPairs(tlsKeyEx_t *keyexp)
{ return; }


// -----------------------------------------------------------------------------------

TEST_GROUP(tlsEncodeRecordLayer);


TEST_GROUP_RUNNER(tlsEncodeRecordLayer)
{
    RUN_TEST_CASE(tlsEncodeRecordLayer, clienthello);
    RUN_TEST_CASE(tlsEncodeRecordLayer, clienthello_fragments);
    RUN_TEST_CASE(tlsEncodeRecordLayer, certificate_fragments);
    RUN_TEST_CASE(tlsEncodeRecordLayer, cert_verify_fragments);
    RUN_TEST_CASE(tlsEncodeRecordLayer, finished_fragments);
    RUN_TEST_CASE(tlsEncodeRecordLayer, app_data_fragments);
    RUN_TEST_CASE(tlsEncodeRecordLayer, change_cipher_spec);
    //// RUN_TEST_CASE(tlsEncodeRecordLayer, err_chk);
}

TEST_SETUP(tlsEncodeRecordLayer)
{
    XMEMSET(tls_session->outbuf.data , 0x00, sizeof(byte) * MAX_RAWBYTE_BUF_SZ);
    tls_session->num_frags_out = 0;
    tls_session->remain_frags_out = 0;
    tls_session->record_type = TLS_CONTENT_TYPE_HANDSHAKE;
}


TEST_TEAR_DOWN(tlsEncodeRecordLayer)
{
    mock_cleanSpaceAfterKeyEx(tls_session);
}


TEST(tlsEncodeRecordLayer, clienthello)
{
    tlsRespStatus status = TLS_RESP_OK;
    word16 encoded_idx = 0;
    word16 expect_value = 0;
    word16 actual_value = 0;
    const byte num_extensions = 7;
    byte idx = 0;

    tls_session->outlen_encoded = 0;
    tls_session->flgs.hs_tx_encrypt = 0;
    tls_session->hs_state = TLS_HS_TYPE_CLIENT_HELLO;

    mock_extention_entries_clienthello[0].len = 30;
    mock_extention_entries_clienthello[1].len = 4;
    mock_extention_entries_clienthello[2].len = tlsGetSupportedKeyExGrpSize() << 1;
    mock_extention_entries_clienthello[3].len = 6;
    mock_extention_entries_clienthello[4].len = 51;
    mock_extention_entries_clienthello[5].len = 0;
    mock_extention_entries_clienthello[6].len = 0;
    mock_encoding_extension_entries = &mock_extention_entries_clienthello[0];
    mock_allocSpaceBeforeKeyEx(tls_session);
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    // check structure of the encoded packet
    encoded_idx = (tls_session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES);
    TEST_ASSERT_GREATER_THAN_UINT16(encoded_idx, mock_extensions_start_idx_outbuf);
    // skip 32-byte random value, legacy session ID, check ID code of each supported cipher suite
    encoded_idx += 2 + TLS_HS_RANDOM_BYTES + 1 + TLS_MAX_BYTES_SESSION_ID + 2;
    for(idx=0; idx<tlsGetSupportedCipherSuiteListSize(); idx++) {
        expect_value = (word16) tls_supported_cipher_suites[idx].ident;
        encoded_idx += mqttDecodeWord16(&tls_session->outbuf.data[encoded_idx] , &actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    }
    // total length field of extension
    expect_value = 0;
    for(idx=0; idx<num_extensions; idx++) {
        if(mock_extention_entries_clienthello[idx].len == 0) { continue; }
        expect_value += (2 + 2 + mock_extention_entries_clienthello[idx].len);
    }
    encoded_idx  = mock_extensions_start_idx_outbuf;
    encoded_idx += mqttDecodeWord16(&tls_session->outbuf.data[encoded_idx] , &actual_value);
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    // loop through each encoded entension in order
    for(idx=0; idx<num_extensions; idx++) {
        if(mock_extention_entries_clienthello[idx].len == 0) { continue; }
        expect_value = (word16) mock_extention_entries_clienthello[idx].type;
        encoded_idx += mqttDecodeWord16(&tls_session->outbuf.data[encoded_idx] , &actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = (word16) mock_extention_entries_clienthello[idx].len;
        encoded_idx += mqttDecodeWord16(&tls_session->outbuf.data[encoded_idx] , &actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_idx  = (encoded_idx + expect_value) % tls_session->outbuf.len;
    } // end of for-loop
} // end of TEST(tlsEncodeRecordLayer, clienthello)


TEST(tlsEncodeRecordLayer, clienthello_fragments)
{
    tlsRespStatus status = TLS_RESP_OK;
    word16 encoded_idx = 0;
    word16 expect_value = 0;
    word16 actual_value = 0;
    const byte num_extensions = 7;
    const byte num_extensions_first_frag  = 5;
    const byte num_extensions_second_frag = 2;
    byte idx = 0;

    tls_session->outlen_encoded = 0;
    tls_session->flgs.hs_tx_encrypt = 0;
    tls_session->hs_state = TLS_HS_TYPE_CLIENT_HELLO;

    mock_extention_entries_clienthello[0].len = 0;
    mock_extention_entries_clienthello[1].len = 2;
    mock_extention_entries_clienthello[2].len = tlsGetSupportedKeyExGrpSize() << 1;
    mock_extention_entries_clienthello[3].len = 0;
    mock_extention_entries_clienthello[4].len = tls_session->outbuf.len;
    mock_extention_entries_clienthello[5].len = 13;
    mock_extention_entries_clienthello[6].len = 19;
    mock_encoding_extension_entries = &mock_extention_entries_clienthello[0];
    // start encoding first fragment of ClientHello
    mock_allocSpaceBeforeKeyEx(tls_session);
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts);
    TEST_ASSERT_EQUAL_UINT8(mock_extention_entries_clienthello[4].type, tls_session->exts->type);
    TEST_ASSERT_LESS_THAN_UINT16(mock_extention_entries_clienthello[4].len, tls_session->last_ext_entry_enc_len);
    // total length field of extension
    expect_value = 0;
    for(idx=0; idx<num_extensions; idx++) {
        if(mock_extention_entries_clienthello[idx].len == 0) { continue; }
        expect_value += (2 + 2 + mock_extention_entries_clienthello[idx].len);
    }
    encoded_idx  = mock_extensions_start_idx_outbuf;
    encoded_idx += mqttDecodeWord16(&tls_session->outbuf.data[encoded_idx] , &actual_value);
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    // loop through each encoded entension in first fragment in order
    for(idx=0; idx<num_extensions_first_frag; idx++) {
        if(mock_extention_entries_clienthello[idx].len == 0) { continue; }
        expect_value = (word16) mock_extention_entries_clienthello[idx].type;
        encoded_idx += mqttDecodeWord16(&tls_session->outbuf.data[encoded_idx] , &actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = (word16) mock_extention_entries_clienthello[idx].len;
        encoded_idx += mqttDecodeWord16(&tls_session->outbuf.data[encoded_idx] , &actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_idx  = (encoded_idx + expect_value) % tls_session->outbuf.len;
    } // end of for-loop
    TEST_ASSERT_EQUAL_UINT16(mock_extention_entries_clienthello[4].len, (encoded_idx + tls_session->last_ext_entry_enc_len - 4));
    // assume first fragment of ClientHello is sent successfully to the peer.
    // Time to copy rest of extension bytes to the second fragment.
    tls_session->outlen_encoded = 0;
    tls_session->remain_frags_out = 1;
    tls_session->num_frags_out    = 1;
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    // loop through each encoded entension in second fragment in order
    for(idx=num_extensions_first_frag; idx<num_extensions_second_frag; idx++) {
        if(mock_extention_entries_clienthello[idx].len == 0) { continue; }
        expect_value = (word16) mock_extention_entries_clienthello[idx].type;
        encoded_idx += mqttDecodeWord16(&tls_session->outbuf.data[encoded_idx] , &actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = (word16) mock_extention_entries_clienthello[idx].len;
        encoded_idx += mqttDecodeWord16(&tls_session->outbuf.data[encoded_idx] , &actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_idx  = (encoded_idx + expect_value) % tls_session->outbuf.len;
    } // end of for-loop
} // end of TEST(tlsEncodeRecordLayer, clienthello_fragments)


TEST(tlsEncodeRecordLayer, certificate_fragments)
{
    tlsRespStatus status = TLS_RESP_OK;
    byte   *buf = NULL;
    word32  cert_sz     = 0;
    byte    cert_req_sz = 0;
    word16  encoded_idx = 0;
    word32  expect_value = 0;
    word32  actual_value = 0;

    tls_session->outlen_encoded = 0;
    tls_session->flgs.hs_tx_encrypt = 1;
    tls_session->flgs.omit_client_cert_chk = 0;
    tls_session->flgs.omit_server_cert_chk = 0;
    tls_session->hs_state = TLS_HS_TYPE_CERTIFICATE;

    cert_req_sz = 32;
    cert_sz     = tls_session->outbuf.len << 1;
    buf = XMALLOC(sizeof(byte) * (cert_sz + cert_req_sz));
    tls_session->CA_cert = XMALLOC(sizeof(tlsCert_t));
    tls_session->CA_cert->rawbytes.data   = &buf[0];
    tls_session->tmpbuf.cert_req_ctx.data = &buf[cert_sz];
    tls_session->tmpbuf.cert_req_ctx.len  =  cert_req_sz;
    tlsEncodeWord24(&tls_session->CA_cert->rawbytes.len[0], cert_sz);
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[1];
    // start encoding first fragment of Certificate
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_GREATER_THAN_UINT32(tls_session->outbuf.len, tls_session->nbytes.remaining_to_send);
    encoded_idx  = (tls_session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES);
    expect_value = cert_req_sz;
    actual_value = tls_session->outbuf.data[encoded_idx];
    TEST_ASSERT_EQUAL_UINT8(expect_value, actual_value);
    encoded_idx += 1 + cert_req_sz;
    expect_value = cert_sz + 3 + 2;
    encoded_idx += tlsDecodeWord24(&tls_session->outbuf.data[encoded_idx], &actual_value);
    TEST_ASSERT_EQUAL_UINT32(expect_value, actual_value);
    expect_value = cert_sz;
    encoded_idx += tlsDecodeWord24(&tls_session->outbuf.data[encoded_idx], &actual_value);
    TEST_ASSERT_EQUAL_UINT32(expect_value, actual_value);
    // encoding first fragment of Certificate
    tls_session->outlen_encoded = 0;
    tls_session->remain_frags_out = 2;
    tls_session->num_frags_out    = 2;
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_LESS_THAN_UINT32(tls_session->outbuf.len, tls_session->nbytes.remaining_to_send);
    encoded_idx = tls_session->nbytes.remaining_to_send;
    // encoding third fragment of Certificate
    tls_session->outlen_encoded = 0;
    tls_session->remain_frags_out = 1;
    tls_session->num_frags_out    = 2;
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0, tls_session->nbytes.remaining_to_send);
    expect_value = 0; // no extension is appended to Certificate message in current implementation
    encoded_idx += tlsDecodeWord16(&tls_session->outbuf.data[encoded_idx], (word16 *)&actual_value);
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    encoded_idx += 1 + tls_session->sec.chosen_ciphersuite->tagSize;
    TEST_ASSERT_EQUAL_UINT16(encoded_idx, tls_session->outlen_encoded);

    XMEMFREE(tls_session->CA_cert->rawbytes.data);
    tls_session->CA_cert->rawbytes.data = NULL;
    tls_session->tmpbuf.cert_req_ctx.data = NULL;
    XMEMFREE(tls_session->CA_cert);
    tls_session->CA_cert = NULL;
} // end of TEST(tlsEncodeRecordLayer, certificate_fragments)


TEST(tlsEncodeRecordLayer, cert_verify_fragments)
{
    tlsRespStatus status = TLS_RESP_OK;
    word16  gened_sig_sz = 0;
    word16  encoded_idx  = 0;
    word16  expect_value = 0;
    word16  actual_value = 0;

    gened_sig_sz = mqttHashGetOutlenBytes(MQTT_HASH_SHA256) << 3;
    tls_session->flgs.hs_tx_encrypt = 1;
    tls_session->flgs.omit_client_cert_chk = 0;
    tls_session->flgs.omit_server_cert_chk = 0;
    tls_session->hs_state = TLS_HS_TYPE_CERTIFICATE_VERIFY;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    tls_session->client_signed_sig.data = NULL;

    // encoding first fragment of CertificateVerify
    tls_session->outlen_encoded = tls_session->outbuf.len - (gened_sig_sz >> 1);
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_NOT_EQUAL(0, tls_session->nbytes.remaining_to_send);
    TEST_ASSERT_LESS_THAN_UINT32(tls_session->outbuf.len, tls_session->nbytes.remaining_to_send);

    encoded_idx  = (tls_session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES);
    expect_value = (word16) TLS_SIGNATURE_RSA_PSS_RSAE_SHA256;
    encoded_idx += tlsDecodeWord16(&tls_session->outbuf.data[encoded_idx], (word16 *)&actual_value);
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    expect_value = gened_sig_sz;
    encoded_idx += tlsDecodeWord16(&tls_session->outbuf.data[encoded_idx], (word16 *)&actual_value);
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    // encoding second fragment of CertificateVerify
    encoded_idx = tls_session->nbytes.remaining_to_send + 1 + tls_session->sec.chosen_ciphersuite->tagSize;
    tls_session->outlen_encoded = 0;
    tls_session->remain_frags_out = 1;
    tls_session->num_frags_out    = 1;
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    expect_value = encoded_idx;
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
} // end of TEST(tlsEncodeRecordLayer, cert_verify_fragments)


TEST(tlsEncodeRecordLayer, finished_fragments)
{
    tlsRespStatus status = TLS_RESP_OK;
    tlsHashAlgoID  hash_id  = TLS_HASH_ALGO_UNKNOWN;
    word16  finish_verify_data_sz = 0;
    word16  encoded_idx  = 0;
    word16  expect_value = 0;
    word16  actual_value = 0;

    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    hash_id = TLScipherSuiteGetHashID(tls_session->sec.chosen_ciphersuite);
    finish_verify_data_sz = mqttHashGetOutlenBytes(hash_id);
    tls_session->sec.secret.hs.client.len  = finish_verify_data_sz;
    tls_session->sec.secret.hs.client.data = XMALLOC(sizeof(byte) * finish_verify_data_sz);

    tls_session->flgs.hs_tx_encrypt = 1;
    tls_session->hs_state = TLS_HS_TYPE_FINISHED;
    // encoding first fragment of Finished
    tls_session->outlen_encoded = tls_session->outbuf.len - (finish_verify_data_sz >> 1);
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_NOT_EQUAL(0, tls_session->nbytes.remaining_to_send);
    TEST_ASSERT_LESS_THAN_UINT32(tls_session->outbuf.len, tls_session->nbytes.remaining_to_send);
    // encoding second fragment of Finished
    encoded_idx = tls_session->nbytes.remaining_to_send + 1 + tls_session->sec.chosen_ciphersuite->tagSize;
    tls_session->outlen_encoded = 0;
    tls_session->remain_frags_out = 1;
    tls_session->num_frags_out    = 1;
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    expect_value = encoded_idx;
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    XMEMFREE(tls_session->sec.secret.hs.client.data);
    tls_session->sec.secret.hs.client.data = NULL;
} // end of TEST(tlsEncodeRecordLayer, finished_fragments)


TEST(tlsEncodeRecordLayer, app_data_fragments)
{
    tlsRespStatus status = TLS_RESP_OK;
    word16  encoded_idx  = 0;
    word16  idx  = 0;
    word16  expect_value = 0;
    word16  actual_value = 0;

    tls_session->app_pt.len  = tls_session->outbuf.len;
    tls_session->app_pt.data = XMALLOC(sizeof(byte) * tls_session->app_pt.len);
    for(idx=0; idx<tls_session->app_pt.len; idx++) {
        tls_session->app_pt.data[idx] = idx % 0xff;
    } // end of for loop

    tls_session->flgs.hs_tx_encrypt = 1;
    tls_session->hs_state = TLS_HS_TYPE_FINISHED;
    tls_session->record_type = TLS_CONTENT_TYPE_APP_DATA;
    // encoding first fragment of application data
    tls_session->outlen_encoded = tls_session->outbuf.len >> 3;
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_NOT_EQUAL(0, tls_session->nbytes.remaining_to_send);
    TEST_ASSERT_LESS_THAN_UINT32(tls_session->app_pt.len, tls_session->nbytes.remaining_to_send);
    encoded_idx  = tls_session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES;
    for(idx=0; idx<(tls_session->app_pt.len - tls_session->nbytes.remaining_to_send); idx++) {
        expect_value = tls_session->app_pt.data[idx];
        actual_value = tls_session->outbuf.data[encoded_idx + idx];
        TEST_ASSERT_EQUAL_UINT8(expect_value, actual_value);
    } // end of for loop
    // encoding second fragment of application data
    tls_session->outlen_encoded = 0;
    tls_session->remain_frags_out = 1;
    tls_session->num_frags_out    = 1;
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    encoded_idx  = tls_session->app_pt.len - idx; // remaining bytes not copied yet
    for(idx=0; idx<encoded_idx; idx++) {
        expect_value = tls_session->app_pt.data[tls_session->app_pt.len - encoded_idx + idx];
        actual_value = tls_session->outbuf.data[idx];
        TEST_ASSERT_EQUAL_UINT8(expect_value, actual_value);
    } // end of for loop
    encoded_idx += 1 + tls_session->sec.chosen_ciphersuite->tagSize;
    expect_value = encoded_idx;
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    XMEMFREE(tls_session->app_pt.data);
    tls_session->app_pt.data = NULL;
} // end of TEST(tlsEncodeRecordLayer, app_data_fragments)


TEST(tlsEncodeRecordLayer, change_cipher_spec)
{
    tlsRespStatus status = TLS_RESP_OK;
    tls_session->record_type = TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC;
    tls_session->outlen_encoded = 0;
    tls_session->flgs.hs_tx_encrypt = 0;
    status = tlsEncodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0x6, tls_session->outlen_encoded);
} // end of TEST(tlsEncodeRecordLayer, change_cipher_spec)





static void RunAllTestGroups(void)
{
    tls_session = (tlsSession_t *) XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->outbuf.len  = MAX_RAWBYTE_BUF_SZ;
    tls_session->outbuf.data = (byte *) XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);

    RUN_TEST_GROUP(tlsEncodeRecordLayer);

    XMEMFREE(tls_session->outbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


