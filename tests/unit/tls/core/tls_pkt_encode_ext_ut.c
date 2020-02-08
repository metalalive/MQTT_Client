#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

#define MAX_RAWBYTE_BUF_SZ 0x100 // internal parameter for read buffer, DO NOT modify this value

static tlsSession_t *tls_session;
static word32 mock_sys_get_time_ms;
static byte   mock_keyshare_public_bytes[TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO][0x80];
static tlsRespStatus  mock_keyshare_export_pubval_return_val;

const tlsVersionCode  tls_supported_versions[] = {
    TLS_VERSION_ENCODE_1_0, // only for testing purpose, this implemetation doesn't support previous version of TLS
    TLS_VERSION_ENCODE_1_2, // only for testing purpose, this implemetation doesn't support previous version of TLS
    TLS_VERSION_ENCODE_1_3,
};

const tlsNamedGrp  tls_supported_named_groups[] = {
    TLS_NAMED_GRP_SECP256R1, TLS_NAMED_GRP_X25519,
    TLS_NAMED_GRP_SECP384R1, TLS_NAMED_GRP_SECP521R1,
};

const tlsSignScheme  tls_supported_sign_scheme[] = {
    TLS_SIGNATURE_RSA_PKCS1_SHA256 ,
    TLS_SIGNATURE_RSA_PKCS1_SHA384 ,
    TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    TLS_SIGNATURE_RSA_PSS_RSAE_SHA384,

    TLS_SIGNATURE_ED25519,
    TLS_SIGNATURE_ED448  ,
    TLS_SIGNATURE_RSA_PSS_PSS_SHA256,
    TLS_SIGNATURE_RSA_PSS_PSS_SHA384,
    TLS_SIGNATURE_RSA_PSS_PSS_SHA512,
};

tlsHandshakeType  tlsGetHSexpectedState(tlsSession_t *session)
{
    return (session==NULL ? TLS_HS_TYPE_HELLO_REQUEST_RESERVED: session->hs_state);
} // end of tlsGetHSexpectedState

byte  tlsGetSupportedVersionListSize( void )
{
    return XGETARRAYSIZE(tls_supported_versions);
} // end of tlsGetSupportedVersionListSize

byte  tlsGetSupportedKeyExGrpSize( void )
{
    byte  out = XGETARRAYSIZE(tls_supported_named_groups);
    return out;
} // end of tlsGetSupportedKeyExGrpSize

byte  tlsGetSupportedSignSchemeListSize( void )
{
    return XGETARRAYSIZE(tls_supported_sign_scheme);
} // end of tlsGetSupportedSignSchemeListSize

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

word32 mqttEncodeWord32( byte *buf , word32  value )
{
    if(buf != NULL){
        buf[0] =  value >> 24; 
        buf[1] = (value >> 16) & 0xff; 
        buf[2] = (value >> 8 ) & 0xff; 
        buf[3] =  value &  0xff; 
    }
    // return number of bytes used to store the encoded value
    return  (word32)4;
} // end of mqttEncodeWord32

word32 mqttDecodeWord32( byte *buf , word32 *value )
{
    if((buf != NULL) && (value != NULL)) {
        *value  = buf[3]; 
        *value |= buf[2] << 8  ;
        *value |= buf[1] << 16 ;
        *value |= buf[0] << 24 ;
    }
    return  (word32)4; 
} // end of mqttDecodeWord32

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


void  tlsEncodeHandshakeHeader(tlsSession_t *session)
{
    tlsHandshakeMsg_t  *hs_header = NULL;
    word32       hs_msg_total_len = 0;
    // if the handshake message is split to multiple fragments(packets) to send,
    // then we only add handshake header to the first fragment.
    hs_header = (tlsHandshakeMsg_t *)&session->outbuf.data[session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES];
    hs_header->type  = tlsGetHSexpectedState(session);
    hs_msg_total_len = session->curr_outmsg_len - TLS_HANDSHAKE_HEADER_NBYTES - TLS_RECORD_LAYER_HEADER_NBYTES;
    tlsEncodeWord24((byte *)&hs_header->fragment.len[0], (word32)hs_msg_total_len);
} // end of tlsEncodeHandshakeHeader


word16 tlsKeyExGetKeySize( tlsNamedGrp grp_id )
{
    word16  keysize = 0;
    switch(grp_id)
    {
        case TLS_NAMED_GRP_SECP256R1:
            keysize = 32;
            break;
        case TLS_NAMED_GRP_SECP384R1:
            keysize = 48;
            break;
        case TLS_NAMED_GRP_SECP521R1:
            keysize = 65;
            break;
        case TLS_NAMED_GRP_X25519:
            keysize = 32;
            break;
        default:
            break;
    } // end of switch-case statement
    return keysize;
} // end of tlsKeyExGetKeySize


word16 tlsKeyExGetExportKeySize( tlsNamedGrp grp_id )
{
    word16  export_size = tlsKeyExGetKeySize(grp_id);
    switch(grp_id)
    {
        case TLS_NAMED_GRP_SECP256R1:
        case TLS_NAMED_GRP_SECP384R1:
        case TLS_NAMED_GRP_SECP521R1:
            export_size = (export_size << 1) + 1;
            break;
        default:
            break;
    } // end of switch-case statement
    return export_size;
} // end of tlsKeyExGetExportKeySize


static void mock_tlsAllocSpaceBeforeKeyEx(tlsKeyEx_t *keyexp)
{
    byte *buf = NULL;
    word16 len = 0;
    // initialize key-exchange structure
    keyexp->num_grps_total = tlsGetSupportedKeyExGrpSize();
    len = (sizeof(tlsKeyExState) + sizeof(void *)) * keyexp->num_grps_total;
    buf = XMALLOC(len);
    XMEMSET(buf, 0x00, (size_t)len);

    len = sizeof(tlsKeyExState) * keyexp->num_grps_total;
    keyexp->grp_nego_state = (tlsKeyExState *) &buf[0];
    // create a list of pointers, pointed to different key structures (e.g. ECC, X25519, DH)
    keyexp->keylist = (void **) &buf[len];
    // chosen_grp_idx  should NOT be greater than num_grps_total, here we set num_grps_total as default value
    // which means we haven't found appropriate named groups / key exchange algorithm
    keyexp->chosen_grp_idx = keyexp->num_grps_total;
} // end of mock_tlsAllocSpaceBeforeKeyEx


static void mock_tlsCleanSpaceAfterKeyEx(tlsKeyEx_t *keyexp)
{
    // deallocate generated but unused key(s) after key-exchange algorithm is negotiated
    if( keyexp->grp_nego_state != NULL ){
        XMEMFREE((void *)keyexp->grp_nego_state);
        keyexp->grp_nego_state = NULL;
        keyexp->keylist = NULL;
    }
} // end of mock_tlsCleanSpaceAfterKeyEx

static tlsPSK_t* mock_createEmptyPSKitem(word16 id_len, byte key_len, word32 timestamp_ms)
{
    tlsPSK_t *out = NULL;
    byte     *buf = NULL;
    if(id_len > 0 && key_len > 0) {
        out = (tlsPSK_t *) XMALLOC(sizeof(tlsPSK_t));
        buf = XMALLOC(id_len + key_len);
        out->key.data = buf;
        buf += key_len;
        out->id.data = buf;
        out->key.len = key_len;
        out->id.len  = id_len;
        out->next    = NULL;
        out->flgs.is_resumption = 1;
        out->time_param.ticket_lifetime = 0x500;
        out->time_param.timestamp_ms = timestamp_ms;
    }
    return out;
} // end of mock_createEmptyPSKitem


static tlsExtEntry_t*  mock_createEmptyExtensionItem(tlsExtType type, word16 len)
{
    tlsExtEntry_t *out = NULL;
    if(len > 0) {
        out = XMALLOC(sizeof(tlsExtEntry_t));
        out->type = type;
        out->next = NULL;
        out->content.len  = len;
        out->content.data = XMALLOC(len);
        XMEMSET(out->content.data, 0x00, len);
    }
    return out;
} // end of mock_createEmptyExtensionItem


tlsRespStatus  tlsGenEphemeralKeyPairs(mqttDRBG_t *drbg, tlsKeyEx_t *keyexp)
{
    tlsRespStatus status = TLS_RESP_OK;
    byte   ngrps_chosen = 0;
    byte   ngrps_max    = keyexp->num_grps_total;
    byte   idx          = keyexp->chosen_grp_idx;

    if(idx == ngrps_max) { // if not specifying any algorithm, we choose first two available algorithms to generate keys
        for(idx = 0; (idx < ngrps_max) && (ngrps_chosen < TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO); idx++) {
            if(keyexp->grp_nego_state[idx] == TLS_KEYEX_STATE_NOT_NEGO_YET) {
                keyexp->keylist[idx] = (void *) &mock_keyshare_public_bytes[ngrps_chosen]; 
                keyexp->grp_nego_state[idx] = TLS_KEYEX_STATE_NEGOTIATING;
                ngrps_chosen++;
            }
        } // end of for-loop
        if((idx == ngrps_max) && (ngrps_chosen == 0)) {
            // return error because the client already negotiated with all available key-exchange
            // methods (using all the supported named groups) without success
            status = TLS_RESP_ERR_NO_KEYEX_MTHD_AVAIL;
        }
    } else {
        status = TLS_RESP_ERR; XASSERT(0);
    }
    keyexp->num_grps_chosen = ngrps_chosen;
    return status;
} // end of tlsGenEphemeralKeyPairs

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

tlsHashAlgoID    tlsGetHashAlgoIDBySize(word16 in)
{
    tlsHashAlgoID  out = TLS_HASH_ALGO_UNKNOWN;
    // this implementation currently only supports SHA256, SHA384, the input must be equal
    // to the hash output of either  SHA256 or SHA384
    word16  hash_sz = 0;
    hash_sz = mqttHashGetOutlenBytes((mqttHashLenType)TLS_HASH_ALGO_SHA256);
    if(hash_sz == in) { out = TLS_HASH_ALGO_SHA256; }
    hash_sz = mqttHashGetOutlenBytes((mqttHashLenType)TLS_HASH_ALGO_SHA384);
    if(hash_sz == in) { out = TLS_HASH_ALGO_SHA384; }
    return  out;
} // end of tlsGetHashAlgoIDBySize

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

tlsRespStatus  tlsFreePSKentry(tlsPSK_t *in) {
    if(in == NULL) { return TLS_RESP_ERRARGS; }
    if(in->key.data != NULL) {
        XMEMFREE((void *)in->key.data);
        in->key.data = NULL;
        in->id.data  = NULL;
    }
    in->next     = NULL;
    XMEMFREE((void *)in);
    return TLS_RESP_OK;
} // end of tlsFreePSKentry

tlsRespStatus  tlsFreeExtEntry(tlsExtEntry_t *in) {
    if(in == NULL) { return TLS_RESP_ERRARGS; }
    XMEMFREE((void *)in->content.data);
    in->content.data  = NULL;
    in->next = NULL;
    XMEMFREE((void *)in);
    return TLS_RESP_OK;
} // end of tlsFreeExtEntry

word32  mqttGetInterval(word32 now, word32 then)
{
    return (now - then);
} // end of mqttGetInterval

tlsRespStatus  tlsExportPubValKeyShare( byte *out, tlsNamedGrp grp_id, void *chosen_key, word16 chosen_key_sz )
{
    XMEMCPY(out, (byte *)chosen_key, chosen_key_sz);
    return  mock_keyshare_export_pubval_return_val;
} // end of tlsExportPubValKeyShare


void  tlsFreeEphemeralKeyPairs(tlsKeyEx_t *keyexp)
{
    byte   ngrps_max    = keyexp->num_grps_total;
    byte   idx          = 0;
    for(idx = 0; idx < ngrps_max; idx++) {
        if(keyexp->keylist[idx] != NULL) {
            keyexp->keylist[idx] = NULL;
        }
    } // end of for-loop 
}

word32  mqttSysGetTimeMs(void)
{ return mock_sys_get_time_ms; }

tlsRespStatus  tlsDerivePSKbinderKey( tlsPSK_t *pskin, tlsOpaque8b_t *out )
{ return TLS_RESP_OK; }


// ------------------------------------------------------------------------
TEST_GROUP(tlsGenExtensions);
TEST_GROUP(tlsEncodeExtensions);

TEST_GROUP_RUNNER(tlsGenExtensions)
{
    RUN_TEST_CASE(tlsGenExtensions, clienthello_ext_ok);
    RUN_TEST_CASE(tlsGenExtensions, clienthello_gen_keyshare_fail);
}

TEST_GROUP_RUNNER(tlsEncodeExtensions)
{
    RUN_TEST_CASE(tlsEncodeExtensions, fit_into_one_fragment);
    //// RUN_TEST_CASE(tlsEncodeExtensions, split_two_fragments_case1);
    //// RUN_TEST_CASE(tlsEncodeExtensions, split_two_fragments_case2);
    //// RUN_TEST_CASE(tlsEncodeExtensions, split_two_fragments_case3);
    //// RUN_TEST_CASE(tlsEncodeExtensions, split_two_fragments_case4);
    //// RUN_TEST_CASE(tlsEncodeExtensions, with_psk_binder_one_frag);
    //// RUN_TEST_CASE(tlsEncodeExtensions, with_psk_binder_two_frags);
}

TEST_SETUP(tlsGenExtensions)
{}

TEST_SETUP(tlsEncodeExtensions)
{
    tls_session->remain_frags_out = 0;
    tls_session->num_frags_out = 0;
    tls_session->last_ext_entry_enc_len = 0x1 << 15; // reset this value every time before we encode a new extension lists
}

TEST_TEAR_DOWN(tlsGenExtensions)
{}

TEST_TEAR_DOWN(tlsEncodeExtensions)
{}


TEST(tlsGenExtensions, clienthello_ext_ok)
{
    mqttStr_t mock_server_name = {17, (byte *)&("www.yourbroker.io")};
    tlsExtEntry_t *actual_ext_list = NULL;
    tlsExtEntry_t *extitem = NULL;
    tlsPSK_t      *mock_psk_list = NULL;
    tlsPSK_t      *pskitem = NULL;
    byte          *buf = NULL;
    word32  expect_value = 0;
    word32  actual_value = 0;
    word16      idx, jdx = 0;

    tls_session->flgs.hello_retry = 0;
    tls_session->hs_state = TLS_HS_TYPE_CLIENT_HELLO;
    tls_session->server_name = &mock_server_name;
    tls_session->sec.psk_list = &mock_psk_list;
    // create several PSK items, assume one of them expires
    pskitem = mock_createEmptyPSKitem(0x37, 0x21, 3); // will be filtered out due to expiration, for testing purpose
    mock_psk_list = pskitem;
    pskitem = mock_createEmptyPSKitem(0x41, 0x30, 4);
    mock_psk_list->next = pskitem;
    pskitem = mock_createEmptyPSKitem(0x6a, 0x20, 2); // will be filtered out due to expiration, for testing purpose
    mock_psk_list->next->next = pskitem;
    pskitem = mock_createEmptyPSKitem(0x82, 0x30, 5);
    mock_psk_list->next->next->next = pskitem;
    pskitem = mock_createEmptyPSKitem(0x82, 0x30, 1);
    mock_psk_list->next->next->next->next = pskitem;
    mock_sys_get_time_ms  = mock_psk_list->time_param.timestamp_ms + mock_psk_list->time_param.ticket_lifetime * 1000;
    // set up test data for key exchange group
    mock_tlsAllocSpaceBeforeKeyEx(&tls_session->keyex);
    mock_keyshare_export_pubval_return_val = TLS_RESP_OK;
    for(idx = 0; idx < TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO; idx++) {
    for(jdx = 0; jdx < 0x80; jdx++) {
        mock_keyshare_public_bytes[idx][jdx] = ((idx + 1) * (jdx + 1)) % 0xff;
    }}

    actual_ext_list = tlsGenExtensions(tls_session);
    TEST_ASSERT_NOT_EQUAL(NULL, mock_psk_list);
    TEST_ASSERT_NOT_EQUAL(NULL, mock_psk_list->next);
    TEST_ASSERT_EQUAL_UINT(NULL, mock_psk_list->next->next);
    TEST_ASSERT_EQUAL_UINT32(4, mock_psk_list->time_param.timestamp_ms);
    TEST_ASSERT_EQUAL_UINT32(5, mock_psk_list->next->time_param.timestamp_ms);

    TEST_ASSERT_NOT_EQUAL(NULL, actual_ext_list);
    for(extitem = actual_ext_list; extitem != NULL; extitem = extitem->next) {
        buf = &extitem->content.data[0];
        switch(extitem->type) {
            case TLS_EXT_TYPE_SERVER_NAME:
                TEST_ASSERT_EQUAL_STRING_LEN(&mock_server_name.data[0], &buf[2+1+2], mock_server_name.len);
                break;
            case TLS_EXT_TYPE_SUPPORTED_VERSIONS:
                buf++; // skip duplicate length field
                for(idx=0; idx < tlsGetSupportedVersionListSize(); idx++) {
                    expect_value = tls_supported_versions[idx];
                    buf += tlsDecodeWord16(buf, (word16 *)&actual_value);
                    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
                }
                break;
            case TLS_EXT_TYPE_SUPPORTED_GROUPS:
                buf += 2; // skip duplicate length field
                for(idx=0; idx < tlsGetSupportedKeyExGrpSize(); idx++) {
                    expect_value = tls_supported_named_groups[idx];
                    buf += tlsDecodeWord16(buf, (word16 *)&actual_value);
                    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
                }
                break;
            case TLS_EXT_TYPE_SIGNATURE_ALGORITHMS:
                buf += 2; // skip duplicate length field
                for(idx=0; idx < tlsGetSupportedSignSchemeListSize() ; idx++) {
                    expect_value = tls_supported_sign_scheme[idx];
                    buf += tlsDecodeWord16(buf, (word16 *)&actual_value);
                    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
                }
                break;
            case TLS_EXT_TYPE_KEY_SHARE:
                jdx = 0;
                buf += 2; // skip duplicate length field
                for(idx = 0; (idx < tls_session->keyex.num_grps_total) && (jdx < TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO); idx++) {
                    if(tls_session->keyex.grp_nego_state[idx] == TLS_KEYEX_STATE_NEGOTIATING) {
                        expect_value = tls_supported_named_groups[idx]; // 2 bytes for named group ID
                        buf += tlsDecodeWord16(buf, (word16 *)&actual_value);
                        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
                        expect_value = tlsKeyExGetExportKeySize(expect_value); // 2 bytes for size of public value
                        buf += tlsDecodeWord16(buf, (word16 *)&actual_value);
                        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
                        TEST_ASSERT_EQUAL_STRING_LEN(&mock_keyshare_public_bytes[jdx][0], buf, expect_value); // compare the entire public value
                        buf += expect_value;
                        jdx++;
                    }
                } // end of for-loop
                break;
            case TLS_EXT_TYPE_PSK_KEY_EXCHANGE_MODES:
                break;
            case TLS_EXT_TYPE_PRE_SHARED_KEY:
                TEST_ASSERT_EQUAL_UINT(NULL, extitem->next); // must be in the end of extension list
                buf += 2; // skip length field of ID section
                for(pskitem = mock_psk_list; pskitem != NULL; pskitem = pskitem->next) {
                    expect_value = pskitem->id.len;
                    buf += tlsDecodeWord16(buf, (word16 *)&actual_value);
                    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
                    buf += expect_value; // TODO: test PSK ID content ?
                    expect_value  = mqttGetInterval(mqttSysGetTimeMs(), pskitem->time_param.timestamp_ms);
                    expect_value += pskitem->time_param.ticket_age_add;
                    buf += tlsDecodeWord32(buf, (word32 *)&actual_value);
                    TEST_ASSERT_EQUAL_UINT32(expect_value, actual_value);
                } // end of for loop
                buf += 2; // skip length field of binder section
                for(pskitem = mock_psk_list; pskitem != NULL; pskitem = pskitem->next) {
                    expect_value = pskitem->key.len;
                    actual_value = *buf++;
                    TEST_ASSERT_EQUAL_UINT8(expect_value, actual_value);
                    buf += expect_value;
                } // end of for loop
                break;
            default:
                TEST_ASSERT(0);
                break;
        } // end of switch case statement
    } // end of for loop

    mock_tlsCleanSpaceAfterKeyEx(&tls_session->keyex);
    tlsDeleteAllExtensions(actual_ext_list);
    tlsFreePSKentry(mock_psk_list->next);
    tlsFreePSKentry(mock_psk_list);
    actual_ext_list = NULL;
    tls_session->sec.psk_list = NULL;
} // end of TEST(tlsGenExtensions, clienthello_ext_ok)



TEST(tlsGenExtensions, clienthello_gen_keyshare_fail)
{
    mqttStr_t mock_server_name = {16, (byte *)&("www.hisbroker.io")};
    tlsExtEntry_t *actual_ext_list = NULL;

    tls_session->flgs.hello_retry = 0;
    tls_session->hs_state = TLS_HS_TYPE_CLIENT_HELLO;
    tls_session->server_name = &mock_server_name;
    // set up test data for key exchange group
    mock_tlsAllocSpaceBeforeKeyEx(&tls_session->keyex);
    mock_keyshare_export_pubval_return_val = TLS_RESP_ERR_KEYGEN;
    tls_session->keyex.grp_nego_state[1] = TLS_KEYEX_STATE_NOT_APPLY;

    actual_ext_list = tlsGenExtensions(tls_session);
    TEST_ASSERT_EQUAL_UINT(NULL, actual_ext_list);

    mock_tlsCleanSpaceAfterKeyEx(&tls_session->keyex);
    tlsDeleteAllExtensions(actual_ext_list);
    actual_ext_list = NULL;
} // end of TEST(tlsGenExtensions, clienthello_gen_keyshare_fail)


#define  NUM_EXTENSION_ITEMS   0x3
TEST(tlsEncodeExtensions, fit_into_one_fragment)
{
    const tlsExtType  ext_type_list[NUM_EXTENSION_ITEMS]   = {
                         TLS_EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP,
                         TLS_EXT_TYPE_SERVER_CERTIFICATE_TYPE,
                         TLS_EXT_TYPE_SIGNATURE_ALGORITHMS_CERT };
    const word16      ext_content_len[NUM_EXTENSION_ITEMS] = {0x13, 0x3f, 0x10};
    tlsExtEntry_t  *extitem  = NULL;
    byte *encoded_ext_start  = NULL;
    word32  expect_value = 0;
    word32  actual_value = 0;
    tlsRespStatus  status = TLS_RESP_OK;
    byte idx = 0;

    tls_session->exts = mock_createEmptyExtensionItem(ext_type_list[0], ext_content_len[0]);
    extitem = tls_session->exts;
    for(idx = 1; idx < NUM_EXTENSION_ITEMS; idx++) {
        extitem->next = mock_createEmptyExtensionItem(ext_type_list[idx], ext_content_len[idx]);
        extitem = extitem->next;
    } // end of for loop

    tls_session->ext_enc_total_len = tlsGetExtListSize(tls_session->exts);
    tls_session->outlen_encoded  = tls_session->outbuf.len - 2 - tls_session->ext_enc_total_len;
    tls_session->curr_outmsg_start = 0x1a;
    tls_session->curr_outmsg_len  = tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    tls_session->curr_outmsg_len += 2 + tls_session->ext_enc_total_len;
    encoded_ext_start = &tls_session->outbuf.data[tls_session->outlen_encoded];

    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(tls_session->outbuf.len, tls_session->outlen_encoded);

    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    expect_value = 0;
    for(idx = 0; idx < NUM_EXTENSION_ITEMS; idx++) {
        expect_value += 2 + 2 + ext_content_len[idx];
    } // end of for loop
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    for(idx = 0; idx < NUM_EXTENSION_ITEMS; idx++) {
        expect_value = ext_type_list[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = ext_content_len[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_ext_start += ext_content_len[idx];
    } // end of for loop

    if(tls_session->exts != NULL) {
        tlsDeleteAllExtensions(tls_session->exts);
        tls_session->exts = NULL;
        TEST_ASSERT(0);
    }
} // end of TEST(tlsEncodeExtensions, fit_into_one_fragment)
#undef   NUM_EXTENSION_ITEMS






static void RunAllTestGroups(void)
{
    tls_session = (tlsSession_t *) XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->outbuf.len  = MAX_RAWBYTE_BUF_SZ;
    tls_session->outbuf.data = (byte *) XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);

    RUN_TEST_GROUP(tlsGenExtensions);
    RUN_TEST_GROUP(tlsEncodeExtensions);

    XMEMFREE(tls_session->outbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


