#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

#define MAX_RAWBYTE_BUF_SZ 0x100 // internal parameter for read buffer, DO NOT modify this value

static tlsSession_t *tls_session;
static word32 mock_sys_get_time_ms;

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


tlsRespStatus  tlsGenEphemeralKeyPairs(mqttDRBG_t *drbg, tlsKeyEx_t *keyexp)
{
    tlsRespStatus status = TLS_RESP_OK;
    byte   ngrps_chosen = 0;
    byte   ngrps_max    = keyexp->num_grps_total;
    byte   idx          = keyexp->chosen_grp_idx;

    if(idx == ngrps_max) { // if not specifying any algorithm, we choose first two available algorithms to generate keys
        for(idx = 0; (idx < ngrps_max) && (ngrps_chosen < TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO); idx++) {
            if(keyexp->grp_nego_state[idx] == TLS_KEYEX_STATE_NOT_NEGO_YET) {
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
    tlsRespStatus status = TLS_RESP_OK;
    XMEMSET(out, 0x00, chosen_key_sz);
    return status;
} // end of tlsExportPubValKeyShare


void  tlsFreeEphemeralKeyPairs(tlsKeyEx_t *keyexp)
{ return; }

word32  mqttSysGetTimeMs(void)
{ return mock_sys_get_time_ms; }




// ------------------------------------------------------------------------
TEST_GROUP(tlsGenExtensions);

TEST_GROUP_RUNNER(tlsGenExtensions)
{
    RUN_TEST_CASE(tlsGenExtensions, clienthello_ext_ok);
    //// RUN_TEST_CASE(tlsGenExtensions, clienthello_gen_keyshare_fail);
}

TEST_SETUP(tlsGenExtensions)
{}

TEST_TEAR_DOWN(tlsGenExtensions)
{}


TEST(tlsGenExtensions, clienthello_ext_ok)
{
    mqttStr_t mock_server_name = {17, "www.yourbroker.io"};
    tlsExtEntry_t *actual_ext_list = NULL;
    tlsExtEntry_t *extitem = NULL;
    tlsPSK_t      *mock_psk_list = NULL;
    tlsPSK_t      *pskitem = NULL;
    byte          *buf = NULL;
    word32  expect_value = 0;
    word32  actual_value = 0;
    word16         idx = 0;

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
    // key exchange group
    mock_tlsAllocSpaceBeforeKeyEx(&tls_session->keyex);

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
} // end of TEST(tlsGenExtensions, clienthello_ext_ok)





static void RunAllTestGroups(void)
{
    tls_session = (tlsSession_t *) XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->outbuf.len  = MAX_RAWBYTE_BUF_SZ;
    tls_session->outbuf.data = (byte *) XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);

    RUN_TEST_GROUP(tlsGenExtensions);

    XMEMFREE(tls_session->outbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


