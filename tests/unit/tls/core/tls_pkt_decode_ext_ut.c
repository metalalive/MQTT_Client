#include "mqtt_include.h"

// internal parameter for read buffer, DO NOT modify these values
#define  MAX_RAWBYTE_BUF_SZ         0x200
#define  TEST_NUM_EXTENSION_ITEMS   0x4

static tlsSession_t *tls_session;

static tlsExtType  mock_extension_types[TEST_NUM_EXTENSION_ITEMS]   = {
     TLS_EXT_TYPE_MAX_FRAGMENT_LENGTH,
     TLS_EXT_TYPE_ALPN,
     TLS_EXT_TYPE_SERVER_CERTIFICATE_TYPE,
     TLS_EXT_TYPE_OID_FILTERS,
};

static word16  mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS] = {0x33, 0x4f, 0x61, 0x29};

static tlsExtEntry_t  *mock_ext_list;
static tlsPSK_t       *mock_psk_list;

const tlsVersionCode  tls_supported_versions[] = {
    TLS_VERSION_ENCODE_1_0,
    TLS_VERSION_ENCODE_1_3,
};

const tlsNamedGrp  tls_supported_named_groups[] = {
    TLS_NAMED_GRP_SECP256R1, TLS_NAMED_GRP_X25519,
    TLS_NAMED_GRP_SECP384R1, TLS_NAMED_GRP_SECP521R1,
    TLS_NAMED_GRP_X448     ,
    TLS_NAMED_GRP_FFDHE2048,
    TLS_NAMED_GRP_FFDHE3072,
    TLS_NAMED_GRP_FFDHE4096,
    TLS_NAMED_GRP_FFDHE6144,
    TLS_NAMED_GRP_FFDHE8192,
};


static void util_reverse_linked_list(tlsListItem_t **listhead)
{
    tlsListItem_t *curr_item = NULL;
    tlsListItem_t *prev_item = NULL;
    tlsListItem_t *next_item = NULL;

    for(curr_item = *listhead; curr_item != NULL; curr_item = next_item) {
        next_item = curr_item->next; // preserve pointer of next item
        curr_item->next = prev_item; // change pointer of current item, to its predecessor
        prev_item = curr_item; // curr_item and  prev_item ,move forward to next item
    }
    *listhead = prev_item;
} // end of util_reverse_linked_list

byte  tlsGetSupportedVersionListSize( void )
{
    return XGETARRAYSIZE(tls_supported_versions);
} // end of tlsGetSupportedVersionListSize

byte  tlsGetSupportedKeyExGrpSize( void )
{
    byte  out = XGETARRAYSIZE(tls_supported_named_groups);
    return out;
} // end of tlsGetSupportedKeyExGrpSize

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

tlsListItem_t*  tlsGetFinalItemFromList(tlsListItem_t *list)
{
    tlsListItem_t  *idx  = NULL;
    tlsListItem_t  *prev = NULL;
    for(idx=list; idx!=NULL; idx=idx->next) {
        prev = idx;
    }
    return prev;
} // end of tlsGetFinalItemFromList

// user application can call this function to add on specific PSK
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
    XMEMFREE((void *)in->content.data);
    in->content.data  = NULL;
    in->next = NULL;
    XMEMFREE((void *)in);
    return TLS_RESP_OK;
} // end of tlsFreeExtEntry

void  tlsDeleteAllExtensions( tlsExtEntry_t *ext_head )
{
    tlsExtEntry_t  *curr = ext_head;
    tlsExtEntry_t  *prev = NULL;
    while (curr != NULL) {
        XMEMFREE((void *)curr->content.data);
        curr->content.data = NULL;
        prev = curr;
        tlsRemoveItemFromList((tlsListItem_t **)&curr, (tlsListItem_t *)curr);
        tlsFreeExtEntry(prev);
    } // end of while-loop
} // end of tlsDeleteExtensions

static tlsExtEntry_t*  mock_createEmptyExtensionItem(tlsExtType type, word16 len)
{
    tlsExtEntry_t *out = NULL;
    word16  idx = 0;
    if(len > 0) {
        out = XMALLOC(sizeof(tlsExtEntry_t));
        out->type = type;
        out->next = NULL;
        out->content.len  = len;
        out->content.data = XMALLOC(len);
        for(idx=0; idx< len; idx++) {
            out->content.data[idx] = (len + idx) % 0xff;
        }
    }
    return out;
} // end of mock_createEmptyExtensionItem

// this function generates received bytes of extension section to session->inbuf,
// the bytes in this unit tests may be split between 2 fragments, but the total number of
// received bytes will NOT exceed the size of session->inbuf for ease of test.
static void  mock_generate_recv_extension_bytes(tlsSession_t *session, tlsExtEntry_t *extlist, word16 nbytes_in_frag)
{
    tlsExtEntry_t  *extitem = NULL;
    byte *buf    = NULL;
    byte *rd_ptr = NULL;
    tlsExtEntry_t *extlist_rev = NULL;
    word16  ext_total_sz = 0;
    word16  idx = 0;

    extlist_rev = extlist;
    util_reverse_linked_list((tlsListItem_t **)&extlist_rev);
    ext_total_sz = tlsGetExtListSize(extlist_rev);
    session->inlen_decoded = session->inlen_decrypted - nbytes_in_frag;

    buf = XMALLOC(2 + ext_total_sz);
    rd_ptr = buf;
    rd_ptr += tlsEncodeWord16(rd_ptr, ext_total_sz);
    for(extitem = extlist_rev; extitem != NULL; extitem = extitem->next) {
        rd_ptr += tlsEncodeWord16(rd_ptr, extitem->type);
        rd_ptr += tlsEncodeWord16(rd_ptr, extitem->content.len);
        XMEMCPY(rd_ptr, extitem->content.data, extitem->content.len);
        rd_ptr += extitem->content.len;
    } // end of for loop
    for(idx = 0; idx < (2 + ext_total_sz); idx++) {
        session->inbuf.data[(session->inlen_decoded + idx) % session->inlen_decrypted] = buf[idx];
    } // end of for loop
    XMEMFREE(buf);
    util_reverse_linked_list((tlsListItem_t **)&extlist_rev); // reverse back to original order
} // end of mock_generate_recv_extension_bytes


static void  test_assert_equal_extension_list(tlsExtEntry_t *extitem0, tlsExtEntry_t *extitem1)
{
    while(extitem0 != NULL && extitem1 != NULL) {
        TEST_ASSERT_EQUAL_UINT16(extitem0->type, extitem1->type);
        TEST_ASSERT_EQUAL_UINT16(extitem0->content.len, extitem1->content.len);
        TEST_ASSERT_EQUAL_STRING_LEN(extitem0->content.data, extitem1->content.data, extitem1->content.len);
        extitem0 = extitem0->next;
        extitem1 = extitem1->next;
    } // end of while loop
    TEST_ASSERT_EQUAL_UINT(extitem0, extitem1);
    TEST_ASSERT_EQUAL_UINT(NULL, extitem1);
} // end of test_assert_equal_extension_list

tlsRespStatus  tlsImportPubValKeyShare( byte *in, word16 inlen, tlsNamedGrp grp_id, void **chosen_key)
{
    *chosen_key = XMALLOC(sizeof(byte) * inlen);
    XMEMCPY(*chosen_key, in, inlen);
    return TLS_RESP_OK;
}


// ------------------------------------------------------------------------------

TEST_GROUP(tlsParseExtensions);
TEST_GROUP(tlsDecodeExtServerHello);
TEST_GROUP(tlsDecodeExtEncryptExt);
TEST_GROUP(tlsDecodeExtCertReq);
TEST_GROUP(tlsDecodeExtCertificate);

TEST_GROUP_RUNNER(tlsParseExtensions)
{
    RUN_TEST_CASE(tlsParseExtensions, fit_into_one_fragment);
    RUN_TEST_CASE(tlsParseExtensions, split_total_length_case1);
    RUN_TEST_CASE(tlsParseExtensions, split_total_length_case2);
    RUN_TEST_CASE(tlsParseExtensions, split_1st_ext_item_case1);
    RUN_TEST_CASE(tlsParseExtensions, split_1st_ext_item_case2);
    RUN_TEST_CASE(tlsParseExtensions, split_1st_ext_item_case3);
    RUN_TEST_CASE(tlsParseExtensions, split_1st_ext_item_case4);
    RUN_TEST_CASE(tlsParseExtensions, split_1st_ext_item_content);
    RUN_TEST_CASE(tlsParseExtensions, split_2nd_ext_item_case1);
    RUN_TEST_CASE(tlsParseExtensions, split_2nd_ext_item_case2);
    RUN_TEST_CASE(tlsParseExtensions, split_2nd_ext_item_case3);
    RUN_TEST_CASE(tlsParseExtensions, split_2nd_ext_item_encrypt);
}

TEST_GROUP_RUNNER(tlsDecodeExtServerHello)
{
    RUN_TEST_CASE(tlsDecodeExtServerHello, chk_ok);
    RUN_TEST_CASE(tlsDecodeExtServerHello, version_error);
    RUN_TEST_CASE(tlsDecodeExtServerHello, keyshare_error);
    RUN_TEST_CASE(tlsDecodeExtServerHello, psk_not_found);
}

TEST_GROUP_RUNNER(tlsDecodeExtEncryptExt)
{
    RUN_TEST_CASE(tlsDecodeExtEncryptExt, chk_ok);
}

TEST_GROUP_RUNNER(tlsDecodeExtCertReq)
{
    RUN_TEST_CASE(tlsDecodeExtCertReq, chk_ok);
}

TEST_GROUP_RUNNER(tlsDecodeExtCertificate)
{
    RUN_TEST_CASE(tlsDecodeExtCertificate, chk_ok);
}

TEST_SETUP(tlsParseExtensions)
{
    tlsExtEntry_t  *extitem  = NULL;
    byte idx = 0;

    XMEMSET(tls_session->inbuf.data , 0x00, sizeof(byte) * MAX_RAWBYTE_BUF_SZ);
    tls_session->flgs.hs_rx_encrypt = 0;
    tls_session->sec.chosen_ciphersuite = NULL;
    tls_session->num_frags_in = 1;
    tls_session->remain_frags_in = 1;
    tls_session->sec.flgs.ct_first_frag = 1;
    tls_session->sec.flgs.ct_final_frag = 1;
    tls_session->last_ext_entry_dec_len = 0x1 << 15; // reset this value every time before we encode a new extension lists
    // create mock extension list that is supposed to receive (e.g. from peer)
    mock_ext_list = mock_createEmptyExtensionItem(mock_extension_types[0], mock_extension_content_len[0]);
    extitem = mock_ext_list;
    for(idx = 1; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        extitem->next = mock_createEmptyExtensionItem(mock_extension_types[idx], mock_extension_content_len[idx]);
        extitem = extitem->next;
    } // end of for loop
}

TEST_SETUP(tlsDecodeExtServerHello)
{
    tlsExtEntry_t  *extitem  = NULL;
    tlsKeyEx_t   *keyexp = NULL;
    byte *buf = NULL;
    word16 len = 0;
    byte idx = 0;

    mock_extension_types[0] = TLS_EXT_TYPE_COOKIE;
    mock_extension_types[1] = TLS_EXT_TYPE_SUPPORTED_VERSIONS;
    mock_extension_types[2] = TLS_EXT_TYPE_KEY_SHARE;
    mock_extension_types[3] = TLS_EXT_TYPE_PRE_SHARED_KEY;
    mock_extension_content_len[0] = 16;
    mock_extension_content_len[1] = 2;
    mock_extension_content_len[2] = 2 + 2 + 32; // named group ID field + key length field + key field
    mock_extension_content_len[3] = 2; // chosen PSK index
    tls_session->exts = mock_createEmptyExtensionItem(mock_extension_types[0], mock_extension_content_len[0]);
    extitem = tls_session->exts;
    for(idx = 1; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        extitem->next = mock_createEmptyExtensionItem(mock_extension_types[idx], mock_extension_content_len[idx]);
        extitem = extitem->next;
    } // end of for loop
    // initialize key-exchange structure
    keyexp = &tls_session->keyex;
    keyexp->num_grps_total = tlsGetSupportedKeyExGrpSize();
    len = (sizeof(tlsKeyExState) + sizeof(void *)) * keyexp->num_grps_total;
    buf = XMALLOC(len);
    XMEMSET(buf, 0x00, (size_t)len);
    len = sizeof(tlsKeyExState) * keyexp->num_grps_total;
    keyexp->grp_nego_state = (tlsKeyExState *) &buf[0];
    keyexp->keylist = (void **) &buf[len];
    for (idx = 0; idx < keyexp->num_grps_total; idx++) {
        keyexp->keylist[idx] = (void *) XMALLOC(32);
        XMEMSET(keyexp->keylist[idx], 0x00, (size_t)32);
    } // end of for loop
    // chosen_grp_idx  should NOT be greater than num_grps_total, here we set num_grps_total as default value
    // which means we haven't found appropriate named groups / key exchange algorithm
    keyexp->chosen_grp_idx = keyexp->num_grps_total;
    tls_session->chosen_tls_ver = 0;
    tls_session->last_ext_entry_dec_len = 0;
} // end of TEST_SETUP(tlsDecodeExtServerHello)


TEST_SETUP(tlsDecodeExtEncryptExt)
{
    tlsExtEntry_t  *extitem  = NULL;
    byte idx = 0;
    mock_extension_types[0] = TLS_EXT_TYPE_MAX_FRAGMENT_LENGTH;
    mock_extension_types[1] = TLS_EXT_TYPE_SERVER_NAME;
    mock_extension_types[2] = TLS_EXT_TYPE_ALPN;
    mock_extension_types[3] = TLS_EXT_TYPE_SUPPORTED_GROUPS;
    mock_extension_content_len[0] = 4;
    mock_extension_content_len[1] = 30;
    mock_extension_content_len[2] = 25;
    mock_extension_content_len[3] = 20;
    tls_session->exts = mock_createEmptyExtensionItem(mock_extension_types[0], mock_extension_content_len[0]);
    extitem = tls_session->exts;
    for(idx = 1; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        extitem->next = mock_createEmptyExtensionItem(mock_extension_types[idx], mock_extension_content_len[idx]);
        extitem = extitem->next;
    } // end of for loop
} // end of TEST_SETUP(tlsDecodeExtEncryptExt)


TEST_SETUP(tlsDecodeExtCertReq)
{
    tlsExtEntry_t  *extitem  = NULL;
    byte idx = 0;
    mock_extension_types[0] = TLS_EXT_TYPE_STATUS_REQUEST;
    mock_extension_types[1] = TLS_EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP;
    mock_extension_types[2] = TLS_EXT_TYPE_CERTIFICATE_AUTHORITIES;
    mock_extension_types[3] = TLS_EXT_TYPE_OID_FILTERS;
    tls_session->exts = mock_createEmptyExtensionItem(mock_extension_types[0], mock_extension_content_len[0]);
    extitem = tls_session->exts;
    for(idx = 1; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        extitem->next = mock_createEmptyExtensionItem(mock_extension_types[idx], mock_extension_content_len[idx]);
        extitem = extitem->next;
    } // end of for loop
} // end of TEST_SETUP(tlsDecodeExtCertReq)


TEST_SETUP(tlsDecodeExtCertificate)
{
    mock_extension_types[0] = TLS_EXT_TYPE_STATUS_REQUEST;
    mock_extension_types[1] = TLS_EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP;
    tls_session->peer_certs = XMALLOC(sizeof(tlsCert_t));
    tls_session->peer_certs->next = NULL;
    tls_session->peer_certs->exts       = mock_createEmptyExtensionItem(mock_extension_types[0], mock_extension_content_len[0]);
    tls_session->peer_certs->exts->next = mock_createEmptyExtensionItem(mock_extension_types[1], mock_extension_content_len[1]);
} // end of TEST_SETUP(tlsDecodeExtCertificate)


TEST_TEAR_DOWN(tlsParseExtensions)
{
    if(mock_ext_list != NULL) {
        tlsDeleteAllExtensions(mock_ext_list);
        mock_ext_list = NULL;
    }
    if(tls_session->exts != NULL) {
        tlsDeleteAllExtensions(tls_session->exts);
        tls_session->exts = NULL;
    }
}

TEST_TEAR_DOWN(tlsDecodeExtServerHello)
{
    tlsKeyEx_t   *keyexp = NULL;
    byte idx = 0;
    if(tls_session->exts != NULL) {
        tlsDeleteAllExtensions(tls_session->exts);
        tls_session->exts = NULL;
    }
    keyexp = &tls_session->keyex;
    if(keyexp->grp_nego_state != NULL){
        for (idx = 0; idx < keyexp->num_grps_total; idx++) {
            XMEMFREE((void *)keyexp->keylist[idx]);
        }
        XMEMFREE((void *)keyexp->grp_nego_state);
        keyexp->grp_nego_state = NULL;
        keyexp->keylist = NULL;
    }
    if(tls_session->sec.ephemeralkeylocal != NULL) {
        XMEMFREE((void *)tls_session->sec.ephemeralkeylocal);
        tls_session->sec.ephemeralkeylocal = NULL;
    }
    if(tls_session->sec.ephemeralkeyremote != NULL) {
        XMEMFREE((void *)tls_session->sec.ephemeralkeyremote);
        tls_session->sec.ephemeralkeyremote = NULL;
    }
} // end of TEST_TEAR_DOWN(tlsDecodeExtServerHello)

TEST_TEAR_DOWN(tlsDecodeExtEncryptExt)
{
    if(tls_session->exts != NULL) {
        tlsDeleteAllExtensions(tls_session->exts);
        tls_session->exts = NULL;
    }
}

TEST_TEAR_DOWN(tlsDecodeExtCertReq)
{
    if(tls_session->exts != NULL) {
        tlsDeleteAllExtensions(tls_session->exts);
        tls_session->exts = NULL;
    }
}

TEST_TEAR_DOWN(tlsDecodeExtCertificate)
{
    if(tls_session->peer_certs->exts != NULL) {
        tlsDeleteAllExtensions(tls_session->peer_certs->exts);
        tls_session->peer_certs->exts = NULL;
    }
    XMEMFREE(tls_session->peer_certs);
    tls_session->peer_certs = NULL;
}




TEST(tlsParseExtensions, fit_into_one_fragment)
{
    tlsRespStatus  status = TLS_RESP_OK;
    word16  nbytes_in_first_frag = 2 + tlsGetExtListSize(mock_ext_list);

    // write raw bytes to inbuf as received extension section of a TLS record message
    tls_session->inlen_decrypted = tls_session->inbuf.len - 17;
    mock_generate_recv_extension_bytes(tls_session, mock_ext_list, nbytes_in_first_frag);

    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    // supposed to be decreased to zero when all extension bytes are decoded.
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->ext_dec_total_len);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts);
    test_assert_equal_extension_list(mock_ext_list , tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
} // end of TEST(tlsParseExtensions, fit_into_one_fragment)


TEST(tlsParseExtensions, split_total_length_case1)
{
    tlsRespStatus  status = TLS_RESP_OK;
    word16  nbytes_in_first_frag = 1;

    // write raw bytes to inbuf as received extension section of a TLS record message
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    mock_generate_recv_extension_bytes(tls_session, mock_ext_list, nbytes_in_first_frag);
    // assume to read 1st fragment
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0x8001, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);

    // assume to read 2nd fragment
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = 1 + tlsGetExtListSize(mock_ext_list);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->ext_dec_total_len);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts);
    test_assert_equal_extension_list(mock_ext_list , tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
} // end of TEST(tlsParseExtensions, split_total_length_case1)


TEST(tlsParseExtensions, split_total_length_case2)
{
    tlsRespStatus  status = TLS_RESP_OK;
    word16  nbytes_in_first_frag = 2;
    // write raw bytes to inbuf as received extension section of a TLS record message
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    mock_generate_recv_extension_bytes(tls_session, mock_ext_list, nbytes_in_first_frag);
    // assume to read 1st fragment
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(tlsGetExtListSize(mock_ext_list), tls_session->ext_dec_total_len);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);

    // assume to read 2nd fragment
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = tlsGetExtListSize(mock_ext_list);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->ext_dec_total_len);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts);
    test_assert_equal_extension_list(mock_ext_list , tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
} // end of TEST(tlsParseExtensions, split_total_length_case2)


TEST(tlsParseExtensions, split_1st_ext_item_case1)
{
    tlsRespStatus  status = TLS_RESP_OK;
    word16  nbytes_in_first_frag = 2 + 1;
    // write raw bytes to inbuf as received extension section of a TLS record message
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    mock_generate_recv_extension_bytes(tls_session, mock_ext_list, nbytes_in_first_frag);
    // assume to read 1st fragment
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(1, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(tlsGetExtListSize(mock_ext_list), tls_session->ext_dec_total_len);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);

    // assume to read 2nd fragment
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = tlsGetExtListSize(mock_ext_list) - 1;
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->ext_dec_total_len);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts);
    test_assert_equal_extension_list(mock_ext_list , tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
} // end of TEST(tlsParseExtensions, split_1st_ext_item_case1)


TEST(tlsParseExtensions, split_1st_ext_item_case2)
{
    tlsRespStatus  status = TLS_RESP_OK;
    word16  nbytes_in_first_frag = 2 + 2;
    // write raw bytes to inbuf as received extension section of a TLS record message
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    mock_generate_recv_extension_bytes(tls_session, mock_ext_list, nbytes_in_first_frag);
    // assume to read 1st fragment
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[TEST_NUM_EXTENSION_ITEMS - 1], tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT16(2, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);

    // assume to read 2nd fragment
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = tlsGetExtListSize(mock_ext_list) - 2;
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts);
    test_assert_equal_extension_list(mock_ext_list , tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
} // end of TEST(tlsParseExtensions, split_1st_ext_item_case2)


TEST(tlsParseExtensions, split_1st_ext_item_case3)
{
    tlsRespStatus  status = TLS_RESP_OK;
    word16  nbytes_in_first_frag = 2 + 3;
    // write raw bytes to inbuf as received extension section of a TLS record message
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    mock_generate_recv_extension_bytes(tls_session, mock_ext_list, nbytes_in_first_frag);
    // assume to read 1st fragment
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[TEST_NUM_EXTENSION_ITEMS - 1], tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT16(3, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);

    // assume to read 2nd fragment
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = tlsGetExtListSize(mock_ext_list) - 3;
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    test_assert_equal_extension_list(mock_ext_list , tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
} // end of TEST(tlsParseExtensions, split_1st_ext_item_case3)


TEST(tlsParseExtensions, split_1st_ext_item_case4)
{
    tlsRespStatus  status = TLS_RESP_OK;
    word16  nbytes_in_first_frag = 2 + 4;
    // write raw bytes to inbuf as received extension section of a TLS record message
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    mock_generate_recv_extension_bytes(tls_session, mock_ext_list, nbytes_in_first_frag);
    // assume to read 1st fragment
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[TEST_NUM_EXTENSION_ITEMS - 1], tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT16(mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS - 1], tls_session->exts->content.len);
    TEST_ASSERT_EQUAL_UINT16(4, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);

    // assume to read 2nd fragment
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = tlsGetExtListSize(mock_ext_list) - 4;
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    test_assert_equal_extension_list(mock_ext_list , tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
} // end of TEST(tlsParseExtensions, split_1st_ext_item_case4)


TEST(tlsParseExtensions, split_1st_ext_item_content)
{
    tlsRespStatus  status = TLS_RESP_OK;
    word16  nbytes_in_first_frag = 2 + 5;
    // write raw bytes to inbuf as received extension section of a TLS record message
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    mock_generate_recv_extension_bytes(tls_session, mock_ext_list, nbytes_in_first_frag);
    // assume to read 1st fragment
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(5, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);

    // assume to read 2nd fragment
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = tlsGetExtListSize(mock_ext_list) - 5;
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    test_assert_equal_extension_list(mock_ext_list , tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
} // end of TEST(tlsParseExtensions, split_1st_ext_item_content)


TEST(tlsParseExtensions, split_2nd_ext_item_case1)
{
    tlsRespStatus  status = TLS_RESP_OK;
    word16  nbytes_in_first_frag = 2 + 4 + mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS - 1] + 1;
    // write raw bytes to inbuf as received extension section of a TLS record message
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    mock_generate_recv_extension_bytes(tls_session, mock_ext_list, nbytes_in_first_frag);
    // assume to read 1st fragment
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts->next);
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[TEST_NUM_EXTENSION_ITEMS - 1], tls_session->exts->next->type);
    TEST_ASSERT_EQUAL_UINT16(1, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);

    // assume to read 2nd fragment
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = tlsGetExtListSize(mock_ext_list) - 4 - mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS - 1] - 1;
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    test_assert_equal_extension_list(mock_ext_list , tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
} // end of TEST(tlsParseExtensions, split_2nd_ext_item_case1)


TEST(tlsParseExtensions, split_2nd_ext_item_case2)
{
    tlsRespStatus  status = TLS_RESP_OK;
    word16  nbytes_in_first_frag = 2 + 4 + mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS - 1] + 2;
    // write raw bytes to inbuf as received extension section of a TLS record message
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    mock_generate_recv_extension_bytes(tls_session, mock_ext_list, nbytes_in_first_frag);
    // assume to read 1st fragment
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[TEST_NUM_EXTENSION_ITEMS - 2], tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[TEST_NUM_EXTENSION_ITEMS - 1], tls_session->exts->next->type);
    TEST_ASSERT_EQUAL_UINT16(2, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);

    // assume to read 2nd fragment
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = tlsGetExtListSize(mock_ext_list) - 4 - mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS - 1] - 2;
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    test_assert_equal_extension_list(mock_ext_list , tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
} // end of TEST(tlsParseExtensions, split_2nd_ext_item_case2)


TEST(tlsParseExtensions, split_2nd_ext_item_case3)
{
    tlsRespStatus  status = TLS_RESP_OK;
    word16  nbytes_in_first_frag = 2 + 4 + mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS - 1] + 4;
    // write raw bytes to inbuf as received extension section of a TLS record message
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    mock_generate_recv_extension_bytes(tls_session, mock_ext_list, nbytes_in_first_frag);
    // assume to read 1st fragment
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[TEST_NUM_EXTENSION_ITEMS - 2], tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[TEST_NUM_EXTENSION_ITEMS - 1], tls_session->exts->next->type);
    TEST_ASSERT_EQUAL_UINT16(mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS - 2], tls_session->exts->content.len);
    TEST_ASSERT_EQUAL_UINT16(mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS - 1], tls_session->exts->next->content.len);
    TEST_ASSERT_EQUAL_UINT16(4, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);

    // assume to read 2nd fragment
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = tlsGetExtListSize(mock_ext_list) - 4 - mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS - 1] - 4;
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    test_assert_equal_extension_list(mock_ext_list , tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
} // end of TEST(tlsParseExtensions, split_2nd_ext_item_case3)


TEST(tlsParseExtensions, split_2nd_ext_item_encrypt)
{
    const tlsCipherSpec_t  mock_tls_cipher_suites[] = {
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
    tlsRespStatus  status = TLS_RESP_OK;
    word16  nbytes_in_first_frag = 2 + 4 + mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS - 1] + 5;
    // write raw bytes to inbuf as received extension section of a TLS record message
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    mock_generate_recv_extension_bytes(tls_session, mock_ext_list, nbytes_in_first_frag);
    // assume to read 1st fragment
    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->sec.chosen_ciphersuite = &mock_tls_cipher_suites[0];
    tls_session->num_frags_in = 2;
    tls_session->remain_frags_in = 2;
    tls_session->sec.flgs.ct_first_frag = 1;
    tls_session->sec.flgs.ct_final_frag = 0;
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(5, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);

    // assume to read 2nd fragment
    tls_session->num_frags_in = 2;
    tls_session->remain_frags_in = 1;
    tls_session->sec.flgs.ct_first_frag = 0;
    tls_session->sec.flgs.ct_final_frag = 1;
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted  = tlsGetExtListSize(mock_ext_list) - 4 - mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS - 1] - 5;
    tls_session->inlen_decrypted += 1 + tls_session->sec.chosen_ciphersuite->tagSize;
    status = tlsParseExtensions(tls_session, &tls_session->exts);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    test_assert_equal_extension_list(mock_ext_list , tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, (tls_session->inlen_decoded + 1 + tls_session->sec.chosen_ciphersuite->tagSize));
} // end of TEST(tlsParseExtensions, split_2nd_ext_item_encrypt)


TEST(tlsDecodeExtServerHello, chk_ok)
{
    tlsExtEntry_t  *extitem = NULL;
    tlsKeyEx_t   *keyexp = NULL;
    tlsRespStatus status = TLS_RESP_OK;

    keyexp = &tls_session->keyex;
    keyexp->grp_nego_state[0] = TLS_KEYEX_STATE_NEGOTIATING;
    keyexp->grp_nego_state[1] = TLS_KEYEX_STATE_NEGOTIATING;
    keyexp->grp_nego_state[2] = TLS_KEYEX_STATE_NEGOTIATING;
    keyexp->grp_nego_state[3] = TLS_KEYEX_STATE_NOT_APPLY;
    keyexp->grp_nego_state[4] = TLS_KEYEX_STATE_NEGOTIATING;
    keyexp->grp_nego_state[5] = TLS_KEYEX_STATE_NOT_APPLY;
    tls_session->flgs.hello_retry = 0;
    for(extitem = tls_session->exts; extitem != NULL; extitem = extitem->next) {
        switch(extitem->type) {
            case TLS_EXT_TYPE_SUPPORTED_VERSIONS:
                mqttEncodeWord16(&extitem->content.data[0], TLS_VERSION_ENCODE_1_3);
                break;
            case TLS_EXT_TYPE_KEY_SHARE:
                mqttEncodeWord16(&extitem->content.data[0], TLS_NAMED_GRP_X25519);
                mqttEncodeWord16(&extitem->content.data[2], 32);
                break;
            case TLS_EXT_TYPE_PRE_SHARED_KEY:
                mqttEncodeWord16(&extitem->content.data[0], 0x1); // assume there were 2 psk items sent in previous ClientHello
                break;
            default:
                break;
        } // end of switch case
    } // end of for loop
    
    status = tlsDecodeExtServerHello(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(mock_psk_list->next, tls_session->sec.chosen_psk);
    TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_NOT_APPLY, keyexp->grp_nego_state[0]);
    TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_APPLIED  , keyexp->grp_nego_state[1]);
    TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_NOT_APPLY, keyexp->grp_nego_state[2]);
    TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_NOT_APPLY, keyexp->grp_nego_state[3]);
    TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_NOT_APPLY, keyexp->grp_nego_state[4]);
    TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_NOT_APPLY, keyexp->grp_nego_state[5]);
    TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_NOT_NEGO_YET, keyexp->grp_nego_state[6]);
    TEST_ASSERT_EQUAL_UINT8(1, keyexp->chosen_grp_idx);
    TEST_ASSERT_EQUAL_UINT(NULL, keyexp->keylist[1]);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->sec.ephemeralkeylocal);
    TEST_ASSERT_EQUAL_UINT16(TLS_VERSION_ENCODE_1_3, tls_session->chosen_tls_ver);
} // end of TEST(tlsDecodeExtServerHello, chk_ok)


TEST(tlsDecodeExtServerHello, version_error)
{
    tlsExtEntry_t  *extitem = NULL;
    tlsKeyEx_t   *keyexp = NULL;
    tlsRespStatus status = TLS_RESP_OK;

    keyexp = &tls_session->keyex;
    keyexp->grp_nego_state[5] = TLS_KEYEX_STATE_NEGOTIATING;
    tls_session->chosen_tls_ver = TLS_VERSION_ENCODE_1_3;
    tls_session->flgs.hello_retry = 0;
    for(extitem = tls_session->exts; extitem != NULL; extitem = extitem->next) {
        switch(extitem->type) {
            case TLS_EXT_TYPE_SUPPORTED_VERSIONS:
                mqttEncodeWord16(&extitem->content.data[0], TLS_VERSION_ENCODE_1_1);
                break;
            case TLS_EXT_TYPE_KEY_SHARE:
                mqttEncodeWord16(&extitem->content.data[0], TLS_NAMED_GRP_FFDHE2048);
                mqttEncodeWord16(&extitem->content.data[2], 32);
                break;
            case TLS_EXT_TYPE_PRE_SHARED_KEY:
                mqttEncodeWord16(&extitem->content.data[0], 0x0);
                break;
            default:
                break;
        } // end of switch case
    } // end of for loop
    
    status = tlsDecodeExtServerHello(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_ALERT, status);
} // end of TEST(tlsDecodeExtServerHello, version_error)


TEST(tlsDecodeExtServerHello, keyshare_error)
{
    tlsExtEntry_t  *extitem = NULL;
    tlsKeyEx_t   *keyexp = NULL;
    tlsRespStatus status = TLS_RESP_OK;
    const byte origin_chosen_named_grp_id = 5;
    // assume the client got HelloRetryRequest which specified TLS_NAMED_GRP_FFDHE2048 as key
    // exchange method, but the later received handshake message (ServerHello) specifies another
    // key exchange method, which must result in protocol error.
    keyexp = &tls_session->keyex;
    keyexp->grp_nego_state[3] = TLS_KEYEX_STATE_NEGOTIATING;
    keyexp->grp_nego_state[6] = TLS_KEYEX_STATE_NEGOTIATING;
    keyexp->grp_nego_state[origin_chosen_named_grp_id] = TLS_KEYEX_STATE_RENEGO_HRR;
    keyexp->chosen_grp_idx = origin_chosen_named_grp_id;
    tls_session->flgs.hello_retry = 0;
    for(extitem = tls_session->exts; extitem != NULL; extitem = extitem->next) {
        switch(extitem->type) {
            case TLS_EXT_TYPE_SUPPORTED_VERSIONS:
                mqttEncodeWord16(&extitem->content.data[0], TLS_VERSION_ENCODE_1_3);
                break;
            case TLS_EXT_TYPE_KEY_SHARE:
                mqttEncodeWord16(&extitem->content.data[0], TLS_NAMED_GRP_FFDHE6144);
                mqttEncodeWord16(&extitem->content.data[2], 32);
                break;
            case TLS_EXT_TYPE_PRE_SHARED_KEY:
                mqttEncodeWord16(&extitem->content.data[0], 0x1);
                break;
            default:
                break;
        } // end of switch case
    } // end of for loop

    status = tlsDecodeExtServerHello(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_ALERT, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_NOT_APPLY, keyexp->grp_nego_state[3]);
    TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_NOT_APPLY, keyexp->grp_nego_state[6]);
    TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_NOT_APPLY, keyexp->grp_nego_state[origin_chosen_named_grp_id]);
    TEST_ASSERT_EQUAL_UINT8(XGET_BITMASK(8), keyexp->chosen_grp_idx);
    TEST_ASSERT_NOT_EQUAL( NULL, keyexp->keylist[origin_chosen_named_grp_id]);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->sec.ephemeralkeylocal);
} // end of TEST(tlsDecodeExtServerHello, keyshare_error)


TEST(tlsDecodeExtServerHello, psk_not_found)
{
    tlsExtEntry_t  *extitem = NULL;
    tlsKeyEx_t   *keyexp = NULL;
    tlsRespStatus status = TLS_RESP_OK;

    keyexp = &tls_session->keyex;
    keyexp->grp_nego_state[0] = TLS_KEYEX_STATE_NEGOTIATING;
    keyexp->grp_nego_state[1] = TLS_KEYEX_STATE_NEGOTIATING;
    tls_session->flgs.hello_retry = 0;
    for(extitem = tls_session->exts; extitem != NULL; extitem = extitem->next) {
        switch(extitem->type) {
            case TLS_EXT_TYPE_SUPPORTED_VERSIONS:
                mqttEncodeWord16(&extitem->content.data[0], TLS_VERSION_ENCODE_1_3);
                break;
            case TLS_EXT_TYPE_KEY_SHARE:
                mqttEncodeWord16(&extitem->content.data[0], TLS_NAMED_GRP_X25519);
                mqttEncodeWord16(&extitem->content.data[2], 32);
                break;
            case TLS_EXT_TYPE_PRE_SHARED_KEY:
                mqttEncodeWord16(&extitem->content.data[0], 0xf8); // give incorrect PSK item index
                break;
            default:
                break;
        } // end of switch case
    } // end of for loop
    
    status = tlsDecodeExtServerHello(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ILLEGAL_PARAMS, status);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->sec.chosen_psk);
} // end of TEST(tlsDecodeExtServerHello, psk_not_found)


TEST(tlsDecodeExtEncryptExt, chk_ok)
{
    tlsRespStatus status = TLS_RESP_OK;
    status = tlsDecodeExtEncryptExt(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsDecodeExtEncryptExt, chk_ok)


TEST(tlsDecodeExtCertReq, chk_ok)
{
    tlsRespStatus status = TLS_RESP_OK;
    status = tlsDecodeExtCertReq(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsDecodeExtCertReq, chk_ok)


TEST(tlsDecodeExtCertificate, chk_ok)
{
    tlsRespStatus status = TLS_RESP_OK;
    status = tlsDecodeExtCertificate(tls_session->peer_certs, 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->peer_certs->exts);
} // end of TEST(tlsDecodeExtCertificate, chk_ok)





static void RunAllTestGroups(void)
{
    tls_session = (tlsSession_t *) XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->inbuf.len  = MAX_RAWBYTE_BUF_SZ;
    tls_session->inbuf.data = (byte *) XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);
    tls_session->sec.chosen_ciphersuite = NULL;
    tls_session->sec.psk_list = &mock_psk_list; // set up pre-shared key list
    mock_psk_list       = XMALLOC(sizeof(tlsPSK_t));
    mock_psk_list->next = XMALLOC(sizeof(tlsPSK_t));
    mock_psk_list->next->next = NULL;

    RUN_TEST_GROUP(tlsParseExtensions);
    RUN_TEST_GROUP(tlsDecodeExtServerHello);
    RUN_TEST_GROUP(tlsDecodeExtEncryptExt);
    RUN_TEST_GROUP(tlsDecodeExtCertReq);
    RUN_TEST_GROUP(tlsDecodeExtCertificate);

    XMEMFREE(tls_session->inbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
    XMEMFREE(mock_psk_list->next);
    XMEMFREE(mock_psk_list);
    mock_psk_list = NULL;
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


