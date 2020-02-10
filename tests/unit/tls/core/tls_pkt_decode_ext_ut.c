#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

// internal parameter for read buffer, DO NOT modify these values
#define  MAX_RAWBYTE_BUF_SZ         0x200
#define  TEST_NUM_EXTENSION_ITEMS   0x4

static tlsSession_t *tls_session;

static const tlsExtType  mock_extension_types[TEST_NUM_EXTENSION_ITEMS]   = {
     TLS_EXT_TYPE_MAX_FRAGMENT_LENGTH,
     TLS_EXT_TYPE_ALPN,
     TLS_EXT_TYPE_SERVER_CERTIFICATE_TYPE,
     TLS_EXT_TYPE_OID_FILTERS,
};

static const word16  mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS] = {0x33, 0x4f, 0x61, 0x29};

static tlsExtEntry_t  *mock_ext_list;



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


// ------------------------------------------------------------------------------

TEST_GROUP(tlsParseExtensions);

TEST_GROUP_RUNNER(tlsParseExtensions)
{
    RUN_TEST_CASE(tlsParseExtensions, fit_into_one_fragment);
    RUN_TEST_CASE(tlsParseExtensions, split_total_length_case1);
    RUN_TEST_CASE(tlsParseExtensions, split_total_length_case2);
    RUN_TEST_CASE(tlsParseExtensions, split_1st_ext_item_case1);
    //// RUN_TEST_CASE(tlsParseExtensions, split_1st_ext_item_case2);
    //// RUN_TEST_CASE(tlsParseExtensions, split_1st_ext_item_case3);
    //// RUN_TEST_CASE(tlsParseExtensions, split_1st_ext_item_case4);
    //// RUN_TEST_CASE(tlsParseExtensions, split_1st_ext_item_content);
    //// RUN_TEST_CASE(tlsParseExtensions, split_2nd_ext_item_case1);
    //// RUN_TEST_CASE(tlsParseExtensions, split_2nd_ext_item_case2);
    //// RUN_TEST_CASE(tlsParseExtensions, split_2nd_ext_item_case3);
}


TEST_SETUP(tlsParseExtensions)
{
    tlsExtEntry_t  *extitem  = NULL;
    byte idx = 0;

    XMEMSET(tls_session->inbuf.data , 0x00, sizeof(byte) * MAX_RAWBYTE_BUF_SZ);
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
    word16  nbytes_in_first_frag = 3;
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







static void RunAllTestGroups(void)
{
    tls_session = (tlsSession_t *) XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->inbuf.len  = MAX_RAWBYTE_BUF_SZ;
    tls_session->inbuf.data = (byte *) XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);
    tls_session->sec.chosen_ciphersuite = NULL;

    RUN_TEST_GROUP(tlsParseExtensions);

    XMEMFREE(tls_session->inbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


