#include "mqtt_include.h"

static tlsSession_t *tls_session;

const tlsNamedGrp  tls_supported_named_groups[] = {
    TLS_NAMED_GRP_SECP256R1, TLS_NAMED_GRP_X25519,
    TLS_NAMED_GRP_SECP384R1, TLS_NAMED_GRP_SECP521R1,
};

static void tlsAllocSpaceBeforeKeyEx(tlsKeyEx_t *keyexp)
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
    // which means we haven't found appropriate named groups (key exchange algorithm)
    keyexp->chosen_grp_idx = keyexp->num_grps_total;
} // end of tlsAllocSpaceBeforeKeyEx

static void tlsCleanSpaceAfterKeyEx(tlsKeyEx_t *keyexp)
{
    // deallocate generated but unused key(s) after key-exchange algorithm is negotiated
    tlsFreeEphemeralKeyPairs(keyexp);
    if(keyexp->grp_nego_state != NULL) {
        XMEMFREE((void *)keyexp->grp_nego_state);
        keyexp->grp_nego_state = NULL;
        keyexp->keylist = NULL;
    }
} // end of tlsCleanSpaceAfterKeyEx

byte  tlsGetSupportedKeyExGrpSize( void )
{
    byte  out = XGETARRAYSIZE(tls_supported_named_groups);
    return out;
} // end of tlsGetSupportedKeyExGrpSize



// -------------------------------------------------------------------------
TEST_GROUP(tlsKeyExchange);

TEST_GROUP_RUNNER(tlsKeyExchange)
{
    RUN_TEST_CASE(tlsKeyExchange, tlsGenEphemeralKeyPairs);
    RUN_TEST_CASE(tlsKeyExchange, tlsExportPubValKeyShare);
    RUN_TEST_CASE(tlsKeyExchange, tlsImportPubValKeyShare);
    RUN_TEST_CASE(tlsKeyExchange, tlsECDHEgenSharedSecret);
}

TEST_SETUP(tlsKeyExchange)
{}

TEST_TEAR_DOWN(tlsKeyExchange)
{}

TEST(tlsKeyExchange, tlsGenEphemeralKeyPairs)
{
    tlsKeyEx_t   *keyexp = NULL;
    tlsRespStatus status = TLS_RESP_OK;
    word16    idx = 0;

    keyexp = &tls_session->keyex;
    // assumption #1 : generate ephemeral keys using the chosen key-exchange algorithms for the 1st ClientHello
    for(idx = 0; idx < keyexp->num_grps_total; idx++) {
        TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_NOT_NEGO_YET, keyexp->grp_nego_state[idx]);
    }
    TEST_ASSERT_EQUAL_UINT8(keyexp->num_grps_total, keyexp->chosen_grp_idx);
    status =  tlsGenEphemeralKeyPairs(tls_session->drbg, keyexp);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO, keyexp->num_grps_chosen);
    for(idx = 0; idx < keyexp->num_grps_total; idx++) {
        if(keyexp->grp_nego_state[idx] != TLS_KEYEX_STATE_NOT_NEGO_YET) {
            TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_NEGOTIATING, keyexp->grp_nego_state[idx]);
            TEST_ASSERT_NOT_EQUAL(NULL, &keyexp->keylist[idx]);
        }
    } // end of for loop

    // assumption #2 : received HelloRetryRequest, generate ephemeral keys using key-exchange algorithm specified
    //  by the HelloRetryRequest, for the 2nd ClientHello
    keyexp->chosen_grp_idx = keyexp->num_grps_total - 1;
    status =  tlsGenEphemeralKeyPairs(tls_session->drbg, keyexp);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_ENCODE, status);
    keyexp->grp_nego_state[keyexp->chosen_grp_idx] = TLS_KEYEX_STATE_RENEGO_HRR;
    status =  tlsGenEphemeralKeyPairs(tls_session->drbg, keyexp);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(1, keyexp->num_grps_chosen);
    TEST_ASSERT_EQUAL_UINT8(TLS_KEYEX_STATE_RENEGO_HRR, keyexp->grp_nego_state[keyexp->chosen_grp_idx]);
    TEST_ASSERT_NOT_EQUAL(NULL, &keyexp->keylist[keyexp->chosen_grp_idx]);
} // end of TEST(tlsKeyExchange, tlsGenEphemeralKeyPairs)


TEST(tlsKeyExchange, tlsExportPubValKeyShare)
{
    byte          expect_key_data[5] = {0x2e, 0x2f, 0x30, 0x31, 0x0};
    tlsKeyEx_t   *keyexp = NULL;
    byte         *buf    = NULL;
    tlsRespStatus status = TLS_RESP_OK;
    tlsNamedGrp  grp_id = 0;
    word16  chosen_key_sz = 0;
    word16  idx = 0;

    keyexp = &tls_session->keyex;

    for(idx = 0; idx < TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO; idx++) {
        if(&keyexp->keylist[idx] == NULL) { continue; }
        expect_key_data[4] = idx + 1;
        XMEMCPY(keyexp->keylist[idx], &expect_key_data[0], 5);
        grp_id = tls_supported_named_groups[idx];
        chosen_key_sz = tlsKeyExGetExportKeySize(grp_id);
        buf = XMALLOC(chosen_key_sz);
        status = tlsExportPubValKeyShare(buf, grp_id, keyexp->keylist[idx], chosen_key_sz);
        TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
        TEST_ASSERT_EQUAL_STRING_LEN(&expect_key_data[0], buf, 5);
        XMEMFREE(buf);
    } // end of for loop
} // end of TEST(tlsKeyExchange, tlsExportPubValKeyShare)


TEST(tlsKeyExchange, tlsImportPubValKeyShare)
{
    const byte expect_import_data[5] = {0x33, 0x34, 0x35, 0x36, 0x37};
    void  *key  = NULL;
    byte  *buf  = NULL;
    tlsRespStatus status = TLS_RESP_OK;
    tlsNamedGrp  grp_id = 0;
    word16  inlen = 0;

    grp_id = TLS_NAMED_GRP_SECP256R1;
    inlen  = tlsKeyExGetExportKeySize(grp_id);
    buf    = XCALLOC(sizeof(byte), inlen);
    XMEMCPY(buf, &expect_import_data[0], 5);
    status = tlsImportPubValKeyShare(buf, inlen, grp_id, &key);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, key);
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_import_data[0], key, 5);
    XMEMFREE(key);
    key  = NULL;
    XMEMFREE(buf);
    buf  = NULL;

    grp_id = TLS_NAMED_GRP_X25519;
    inlen  = tlsKeyExGetExportKeySize(grp_id);
    buf    = XCALLOC(sizeof(byte), inlen);
    XMEMCPY(buf, &expect_import_data[0], 5);
    status = tlsImportPubValKeyShare(buf, inlen, grp_id, &key);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, key);
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_import_data[0], key, 5);
    XMEMFREE(key);
    key  = NULL;
    XMEMFREE(buf);
    buf  = NULL;
} // end of TEST(tlsKeyExchange, tlsImportPubValKeyShare)


TEST(tlsKeyExchange, tlsECDHEgenSharedSecret)
{
    tlsKeyEx_t   *keyexp = NULL;
    tlsOpaque8b_t  mock_secret = {0, NULL};
    tlsRespStatus  status = TLS_RESP_OK;
    tlsNamedGrp  grp_id = 0;
    word16  inlen = 0;

    keyexp = &tls_session->keyex;

    TEST_ASSERT_LESS_THAN_UINT8(keyexp->num_grps_total, keyexp->chosen_grp_idx);
    TEST_ASSERT_GREATER_THAN_UINT8(0, keyexp->chosen_grp_idx);
    TEST_ASSERT_NOT_EQUAL(NULL, keyexp->keylist[keyexp->chosen_grp_idx]);

    keyexp->grp_nego_state[keyexp->chosen_grp_idx] = TLS_KEYEX_STATE_APPLIED;
    tls_session->sec.agreed_keyex_named_grp = tls_supported_named_groups[keyexp->chosen_grp_idx];
    tls_session->sec.ephemeralkeyremote = XMALLOC(inlen);
    tls_session->sec.ephemeralkeylocal  = keyexp->keylist[keyexp->chosen_grp_idx];

    status =  tlsECDHEgenSharedSecret(tls_session, &mock_secret);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, mock_secret.data);

    XMEMFREE(mock_secret.data);
    mock_secret.data = NULL;
    XMEMFREE(tls_session->sec.ephemeralkeyremote);
    tls_session->sec.ephemeralkeyremote = NULL;

} // end of TEST(tlsKeyExchange, tlsECDHEgenSharedSecret)




static void RunAllTestGroups(void)
{
    tls_session = (tlsSession_t *) XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->drbg = XMALLOC(sizeof(mqttDRBG_t));
    tlsAllocSpaceBeforeKeyEx(&tls_session->keyex);

    RUN_TEST_GROUP(tlsKeyExchange);

    tlsCleanSpaceAfterKeyEx(&tls_session->keyex);
    XMEMFREE(tls_session->drbg);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


