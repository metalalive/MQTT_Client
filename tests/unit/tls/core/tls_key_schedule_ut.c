#include "mqtt_include.h"

static tlsSession_t *tls_session;
static byte         *mock_hkdf_extract_copydata;
static word16        mock_hkdf_expandlabel_idx;

static tlsRespStatus mock_tlsAESGCMinit(tlsSecurityElements_t *sec, byte isDecrypt) {
    return TLS_RESP_OK;
}
static tlsRespStatus
mock_tlsAESGCMencrypt(tlsSecurityElements_t *sec, byte *pt, byte *ct, word32 *len) {
    return TLS_RESP_OK;
}
static tlsRespStatus
mock_tlsAESGCMdecrypt(tlsSecurityElements_t *sec, byte *ct, byte *pt, word32 *len) {
    return TLS_RESP_OK;
}
static tlsRespStatus mock_tlsSymEncryptCommonDone(tlsSecurityElements_t *sec) {
    return TLS_RESP_OK;
}

static const tlsCipherSpec_t tls_supported_cipher_suites[] = {
    {
        // TLS_AES_128_GCM_SHA256, 0x1301
        TLS_CIPHERSUITE_ID_AES_128_GCM_SHA256, // ident
        (1 << TLS_ENCRYPT_ALGO_AES128) | (1 << TLS_ENC_CHAINMODE_GCM) |
            (1 << TLS_HASH_ALGO_SHA256), // flags
        16,                              // tagSize
        16,                              // keySize
        12,                              // ivSize
        mock_tlsAESGCMinit,              // init_fn
        mock_tlsAESGCMencrypt,           // encrypt_fn
        mock_tlsAESGCMdecrypt,           // decrypt_fn
        mock_tlsSymEncryptCommonDone,    // done_fn
    },
    {
        // TLS_AES_256_GCM_SHA384, 0x1302
        TLS_CIPHERSUITE_ID_AES_256_GCM_SHA384, // ident
        (1 << TLS_ENCRYPT_ALGO_AES256) | (1 << TLS_ENC_CHAINMODE_GCM) |
            (1 << TLS_HASH_ALGO_SHA384), // flags
        16,                              // tagSize
        32,                              // keySize
        12,                              // ivSize
        mock_tlsAESGCMinit,              // init_fn
        mock_tlsAESGCMencrypt,           // encrypt_fn
        mock_tlsAESGCMdecrypt,           // decrypt_fn
        mock_tlsSymEncryptCommonDone,    // done_fn
    },
}; // end of tls_supported_cipher_suites

static const byte SHA256hashedEmptyInputString[0x20] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

static const byte SHA384hashedEmptyInputString[0x30] = {
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
};

tlsHashAlgoID TLScipherSuiteGetHashID(const tlsCipherSpec_t *cs_in) {
    if (cs_in != NULL) {
        if ((cs_in->flags & (1 << TLS_HASH_ALGO_SHA256)) != 0x0) {
            return TLS_HASH_ALGO_SHA256;
        }
        if ((cs_in->flags & (1 << TLS_HASH_ALGO_SHA384)) != 0x0) {
            return TLS_HASH_ALGO_SHA384;
        }
        return TLS_HASH_ALGO_UNKNOWN; // cipher suite selected but cannot be recognized
    }
    return TLS_HASH_ALGO_NOT_NEGO;
} // end of TLScipherSuiteGetHashID

byte tlsGetSupportedCipherSuiteListSize(void) {
    byte out = XGETARRAYSIZE(tls_supported_cipher_suites);
    return out;
}

const tlsCipherSpec_t *tlsGetCipherSuiteByID(word16 idcode) {
    const tlsCipherSpec_t *out = NULL;
    word16                 len = tlsGetSupportedCipherSuiteListSize();
    word16                 idx = 0;
    for (idx = 0; idx < len; idx++) {
        if (idcode == tls_supported_cipher_suites[idx].ident) {
            out = &tls_supported_cipher_suites[idx];
            break;
        }
    }
    return out;
} // end of tlsGetCipherSuite

tlsRespStatus tlsHKDFextract(
    tlsHashAlgoID hash_id, word16 hash_sz, tlsOpaque8b_t *out, tlsOpaque8b_t *ikm,
    tlsOpaque8b_t *salt
) {
    if (mock_hkdf_extract_copydata != NULL) {
        XMEMCPY(out->data, mock_hkdf_extract_copydata, out->len);
    }
    return TLS_RESP_OK;
}

tlsRespStatus tlsHKDFexpandLabel(
    tlsHashAlgoID hash_id, tlsOpaque8b_t *in_secret, tlsOpaque8b_t *label, tlsOpaque8b_t *context,
    tlsOpaque8b_t *out_secret
) {
    byte idx = 0;
    for (idx = 0; idx < label->len; idx++) {
        out_secret->data[mock_hkdf_expandlabel_idx] = label->data[idx];
        mock_hkdf_expandlabel_idx = (mock_hkdf_expandlabel_idx + 1) % out_secret->len;
    } // end of for loop
    return TLS_RESP_OK;
}

tlsRespStatus tlsCpyHashEmptyInput(tlsHashAlgoID hash_id, tlsOpaque8b_t *out) {
    if ((out == NULL) || (out->data != NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    out->len = mqttHashGetOutlenBytes(hash_id);
    switch (hash_id) {
    case TLS_HASH_ALGO_SHA256:
        out->data = (byte *)&SHA256hashedEmptyInputString[0];
        break;
    case TLS_HASH_ALGO_SHA384:
        out->data = (byte *)&SHA384hashedEmptyInputString[0];
        break;
    default:
        status = TLS_RESP_ERRARGS;
        break;
    } // end of switch-case statement
    return status;
} // end of tlsCpyHashEmptyInput

tlsRespStatus tlsECDHEgenSharedSecret(tlsSession_t *session, tlsOpaque8b_t *out) {
    return TLS_RESP_OK;
}

tlsRespStatus tlsTransHashTakeSnapshot(
    tlsSecurityElements_t *sec, tlsHashAlgoID hash_id, byte *out, word16 outlen
) {
    return TLS_RESP_OK;
}

// ------------------------------------------------------------------------------
TEST_GROUP(tlsGenEarlySecret);
TEST_GROUP(tlsDerivePSKbinderKey);
TEST_GROUP(tlsDeriveTrafficSecret);
TEST_GROUP(tlsDeriveTraffickey);
TEST_GROUP(tlsKeyScheduleMisc);

TEST_GROUP_RUNNER(tlsGenEarlySecret) {
    RUN_TEST_CASE(tlsGenEarlySecret, without_psk);
    RUN_TEST_CASE(tlsGenEarlySecret, with_psk);
}

TEST_GROUP_RUNNER(tlsDerivePSKbinderKey) {
    RUN_TEST_CASE(tlsDerivePSKbinderKey, resumption_psk_binder);
}

TEST_GROUP_RUNNER(tlsDeriveTrafficSecret) {
    RUN_TEST_CASE(tlsDeriveTrafficSecret, tlsDeriveHStrafficSecret);
    RUN_TEST_CASE(tlsDeriveTrafficSecret, tlsDeriveAPPtrafficSecret);
}

TEST_GROUP_RUNNER(tlsDeriveTraffickey) { RUN_TEST_CASE(tlsDeriveTraffickey, chk_ok); }

TEST_GROUP_RUNNER(tlsKeyScheduleMisc) {
    RUN_TEST_CASE(tlsKeyScheduleMisc, tlsActivateReadKey);
    RUN_TEST_CASE(tlsKeyScheduleMisc, tlsActivateWriteKey);
}

TEST_SETUP(tlsGenEarlySecret) {}

TEST_SETUP(tlsDerivePSKbinderKey) { mock_hkdf_expandlabel_idx = 0; }

TEST_SETUP(tlsDeriveTrafficSecret) {}

TEST_SETUP(tlsDeriveTraffickey) {}

TEST_SETUP(tlsKeyScheduleMisc) {}

TEST_TEAR_DOWN(tlsGenEarlySecret) { mock_hkdf_extract_copydata = NULL; }

TEST_TEAR_DOWN(tlsDerivePSKbinderKey) {}

TEST_TEAR_DOWN(tlsDeriveTrafficSecret) {}

TEST_TEAR_DOWN(tlsDeriveTraffickey) {}

TEST_TEAR_DOWN(tlsKeyScheduleMisc) {}

TEST(tlsGenEarlySecret, without_psk) {
    tlsOpaque8b_t          actual_earlysecret = {0, NULL};
    tlsSecurityElements_t *sec = NULL;
    byte                  *expect_earlysecret = NULL;
    tlsRespStatus          status = TLS_RESP_OK;
    byte                   idx = 0;

    sec = &tls_session->sec;
    sec->chosen_ciphersuite = NULL;
    status = tlsGenEarlySecret(sec->chosen_ciphersuite, sec->chosen_psk, &actual_earlysecret);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERRARGS, status);
    // assume a cipher suite was selected by ServerHello
    sec->chosen_ciphersuite = &tls_supported_cipher_suites[1];
    actual_earlysecret.len =
        mqttHashGetOutlenBytes(TLScipherSuiteGetHashID(sec->chosen_ciphersuite));
    actual_earlysecret.data = XMALLOC(sizeof(byte) * actual_earlysecret.len);
    expect_earlysecret = XMALLOC(sizeof(byte) * actual_earlysecret.len);
    for (idx = 0; idx < actual_earlysecret.len; idx++) {
        expect_earlysecret[idx] = (idx + 1) % 0xff;
    }
    mock_hkdf_extract_copydata = &expect_earlysecret[0];
    status = tlsGenEarlySecret(sec->chosen_ciphersuite, sec->chosen_psk, &actual_earlysecret);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_STRING_LEN(
        expect_earlysecret, actual_earlysecret.data, actual_earlysecret.len
    );

    XMEMFREE(actual_earlysecret.data);
    XMEMFREE(expect_earlysecret);
    sec->chosen_ciphersuite = NULL;
} // end of TEST(tlsGenEarlySecret, without_psk)

TEST(tlsGenEarlySecret, with_psk) {
    tlsOpaque8b_t          actual_earlysecret = {0, NULL};
    tlsSecurityElements_t *sec = NULL;
    byte                  *expect_earlysecret = NULL;
    tlsRespStatus          status = TLS_RESP_OK;
    byte                   idx = 0;

    sec = &tls_session->sec;
    sec->chosen_psk = XMALLOC(sizeof(tlsPSK_t));
    sec->chosen_psk->key.len = mqttHashGetOutlenBytes(MQTT_HASH_SHA256);
    actual_earlysecret.len = sec->chosen_psk->key.len;
    actual_earlysecret.data = XMALLOC(sizeof(byte) * actual_earlysecret.len);
    expect_earlysecret = XMALLOC(sizeof(byte) * actual_earlysecret.len);
    for (idx = 0; idx < actual_earlysecret.len; idx++) {
        expect_earlysecret[idx] = (idx + 0xf0) % 0xff;
    }
    mock_hkdf_extract_copydata = &expect_earlysecret[0];
    status = tlsGenEarlySecret(sec->chosen_ciphersuite, sec->chosen_psk, &actual_earlysecret);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_STRING_LEN(
        expect_earlysecret, actual_earlysecret.data, actual_earlysecret.len
    );

    XMEMFREE(actual_earlysecret.data);
    XMEMFREE(expect_earlysecret);
    XMEMFREE(sec->chosen_psk);
    sec->chosen_psk = NULL;
} // end of TEST(tlsGenEarlySecret, with_psk)

TEST(tlsDerivePSKbinderKey, resumption_psk_binder) {
    tlsOpaque8b_t          actual_psk_binder_key = {0, NULL};
    byte                  *expect_psk_binder_key = NULL;
    tlsSecurityElements_t *sec = NULL;
    tlsRespStatus          status = TLS_RESP_OK;

    sec = &tls_session->sec;
    status = tlsDerivePSKbinderKey(sec->chosen_psk, &actual_psk_binder_key);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERRARGS, status);
    sec->chosen_psk = XMALLOC(sizeof(tlsPSK_t));
    sec->chosen_psk->flgs.is_resumption = 1;
    sec->chosen_psk->key.len = mqttHashGetOutlenBytes(MQTT_HASH_SHA256);
    sec->chosen_psk->id.len = 97;
    sec->chosen_psk->key.data = XMALLOC(sec->chosen_psk->key.len);
    sec->chosen_psk->id.data = XMALLOC(sec->chosen_psk->id.len);

    actual_psk_binder_key.len = sec->chosen_psk->key.len;
    actual_psk_binder_key.data = XMALLOC(sizeof(byte) * actual_psk_binder_key.len);
    expect_psk_binder_key = XMALLOC(sizeof(byte) * actual_psk_binder_key.len);
    XMEMCPY(&expect_psk_binder_key[0], "finished", 8);
    status = tlsDerivePSKbinderKey(sec->chosen_psk, &actual_psk_binder_key);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_psk_binder_key[0], &actual_psk_binder_key.data[10], 8);

    XMEMFREE(expect_psk_binder_key);
    XMEMFREE(actual_psk_binder_key.data);
    XMEMFREE(sec->chosen_psk->key.data);
    XMEMFREE(sec->chosen_psk->id.data);
    XMEMFREE(sec->chosen_psk);
    sec->chosen_psk = NULL;
} // end of TEST(tlsDerivePSKbinderKey, resumption_psk_binder)

TEST(tlsDeriveTrafficSecret, tlsDeriveHStrafficSecret) {
    tlsRespStatus status = TLS_RESP_OK;
    tlsOpaque8b_t earlysecret = {0, NULL};

    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->sec.secret.hs.hs.data);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->sec.secret.hs.client.data);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->sec.secret.hs.server.data);
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    earlysecret.len =
        mqttHashGetOutlenBytes(TLScipherSuiteGetHashID(tls_session->sec.chosen_ciphersuite));
    earlysecret.data = XMALLOC(earlysecret.len);
    status = tlsDeriveHStrafficSecret(tls_session, &earlysecret);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, earlysecret.data);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->sec.secret.hs.hs.data);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->sec.secret.hs.client.data);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->sec.secret.hs.server.data);
} // end of TEST(tlsDeriveTrafficSecret, tlsDeriveHStrafficSecret)

TEST(tlsDeriveTrafficSecret, tlsDeriveAPPtrafficSecret) {
    tlsSecurityElements_t *sec = NULL;
    word16                 hash_len = 0;
    tlsRespStatus          status = TLS_RESP_OK;

    sec = &tls_session->sec;
    hash_len = mqttHashGetOutlenBytes(TLScipherSuiteGetHashID(sec->chosen_ciphersuite));
    sec->hashed_hs_msg.snapshot_server_finished = XMALLOC(hash_len);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->secret.hs.hs.data);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->secret.hs.client.data);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->secret.hs.server.data);
    TEST_ASSERT_EQUAL_UINT(NULL, sec->secret.app.resumption.data);
    TEST_ASSERT_EQUAL_UINT(&tls_supported_cipher_suites[0], sec->chosen_ciphersuite);

    status = tlsDeriveAPPtrafficSecret(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->secret.app.resumption.data);

    XMEMFREE(sec->hashed_hs_msg.snapshot_server_finished);
    sec->hashed_hs_msg.snapshot_server_finished = NULL;
} // end of TEST(tlsDeriveTrafficSecret, tlsDeriveAPPtrafficSecret)

TEST(tlsDeriveTraffickey, chk_ok) {
    tlsSecurityElements_t *sec = NULL;
    tlsRespStatus          status = TLS_RESP_OK;

    sec = &tls_session->sec;
    status = tlsDeriveTraffickey(sec, &sec->secret.hs.server, &sec->secret.hs.client);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);

    XMEMFREE(sec->secret.hs.hs.data);
    sec->secret.hs.hs.data = NULL;
    sec->secret.hs.client.data = NULL;
    sec->secret.hs.server.data = NULL;
    sec->secret.app.resumption.data = NULL;
} // end of TEST(tlsDeriveTraffickey, chk_ok)

TEST(tlsKeyScheduleMisc, tlsActivateReadKey) {
    tlsSecurityElements_t *sec = NULL;
    tlsRespStatus          status = TLS_RESP_OK;

    sec = &tls_session->sec;
    TEST_ASSERT_EQUAL_UINT(&tls_supported_cipher_suites[0], sec->chosen_ciphersuite);
    status = tlsActivateReadKey(sec);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
} // end of TEST(tlsKeyScheduleMisc, tlsActivateReadKey)

TEST(tlsKeyScheduleMisc, tlsActivateWriteKey) {
    tlsSecurityElements_t *sec = NULL;
    tlsRespStatus          status = TLS_RESP_OK;

    sec = &tls_session->sec;
    TEST_ASSERT_EQUAL_UINT(&tls_supported_cipher_suites[0], sec->chosen_ciphersuite);
    status = tlsActivateWriteKey(sec);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
} // end of TEST(tlsKeyScheduleMisc, tlsActivateWriteKey)

static void RunAllTestGroups(void) {
    tls_session = (tlsSession_t *)XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));

    RUN_TEST_GROUP(tlsGenEarlySecret);
    RUN_TEST_GROUP(tlsDerivePSKbinderKey);
    RUN_TEST_GROUP(tlsDeriveTrafficSecret);
    RUN_TEST_GROUP(tlsDeriveTraffickey);
    RUN_TEST_GROUP(tlsKeyScheduleMisc);

    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups

int main(int argc, const char *argv[]) {
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main
