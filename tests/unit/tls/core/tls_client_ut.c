#include "mqtt_include.h"

#define MAX_RAWBYTE_READ_BUF_SZ \
    0x100 // internal parameter for read buffer, DO NOT modify this value
#define TEST_CMD_TIMEOUT_MS  1000
#define NET_SYS_EXT_OBJ1_REF 0x2
#define NET_SYS_EXT_OBJ2_REF 0x3

static const byte mock_mqtt_auth_ca_priv_key_rawbyte[] = {
    0x30, 0x82, 0x04, 0xa5, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
};

static unsigned int mock_mqtt_auth_ca_priv_key_rawbyte_len = 12;

static const byte mock_mqtt_auth_ca_cert_rawbyte[] = {
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0x02, 0x01, 0xa0, 0x03, 0x02, 0x01,
};

static unsigned int mock_mqtt_auth_ca_cert_rawbyte_len = 0x100;

static mqttCtx_t     *unittest_mctx;
static mqttRespStatus mock_auth_getprivkey_return_val;
static mqttRespStatus mock_auth_getcacert_return_val;
static mqttRespStatus mock_sys_net_start_return_val;
static tlsRespStatus  mock_rsa_extract_privkey_return_val;
static tlsRespStatus  mock_decode_cert_return_val;
static tlsRespStatus  mock_verify_certchain_return_val;
static tlsRespStatus  mock_client_handshake_return_val;

static tlsRSAkey_t mock_rsa_privkey;
void              *tls_CA_priv_key;   // only for unit test
tlsCert_t         *tls_CA_cert;       // only for unit test
tlsPSK_t          *tls_PSKs_rdy_list; // only for unit test

static mqttStr_t mock_mqtt_broker_host = {12, (const byte *)&("mock_broker")};

mqttRespStatus mqttUtilRandByteSeq(mqttDRBG_t *drbg, byte *out, word16 outlen) {
    return MQTT_RESP_OK;
}

mqttRespStatus mqttAuthGetCAprivKeyRawBytes(const byte **out, word16 *len) {
    if (mock_auth_getprivkey_return_val == MQTT_RESP_OK) {
        *out = (const byte *)&mock_mqtt_auth_ca_priv_key_rawbyte[0];
        *len = (word16)mock_mqtt_auth_ca_priv_key_rawbyte_len;
    }
    return mock_auth_getprivkey_return_val;
} // end of mqttAuthGetCAprivKeyRawBytes

mqttRespStatus mqttAuthGetCertRawBytes(byte **out, word16 *len) {
    if (mock_auth_getcacert_return_val == MQTT_RESP_OK) {
        *out = (const byte *)&mock_mqtt_auth_ca_cert_rawbyte[0];
        *len = (word16)mock_mqtt_auth_ca_cert_rawbyte_len;
    }
    return mock_auth_getcacert_return_val;
} // end of mqttAuthGetCertRawBytes

tlsRespStatus tlsRemoveItemFromList(tlsListItem_t **list, tlsListItem_t *removing_item) {
    if ((list == NULL) && (removing_item == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsListItem_t *idx = NULL;
    tlsListItem_t *prev = NULL;
    for (idx = *list; idx != NULL; idx = idx->next) {
        if (removing_item == idx) {
            if (prev != NULL) {
                prev->next = removing_item->next;
            } else {
                *list = removing_item->next;
            }
            break;
        }
        prev = idx;
    } // end of for-loop
    return TLS_RESP_OK;
} // end of tlsRemoveItemFromList

mqttRespStatus tlsRespCvtToMqttResp(tlsRespStatus in) {
    mqttRespStatus out;
    switch (in) {
    case TLS_RESP_OK:
    case TLS_RESP_REQ_MOREDATA:
        out = MQTT_RESP_OK;
        break;
    case TLS_RESP_ERRARGS:
        out = MQTT_RESP_ERRARGS;
        break;
    case TLS_RESP_ERRMEM:
        out = MQTT_RESP_ERRMEM;
        break;
    case TLS_RESP_TIMEOUT:
        out = MQTT_RESP_TIMEOUT;
        break;
    case TLS_RESP_MALFORMED_PKT:
        out = MQTT_RESP_MALFORMED_DATA;
        break;
    case TLS_RESP_ILLEGAL_PARAMS:
    case TLS_RESP_ERR_ENCODE:
    case TLS_RESP_ERR_DECODE:
    case TLS_RESP_ERR_KEYGEN:
    case TLS_RESP_CERT_AUTH_FAIL:
    case TLS_RESP_HS_AUTH_FAIL:
    case TLS_RESP_PEER_CONN_FAIL:
        out = MQTT_RESP_ERR_SECURE_CONN;
        break;
    case TLS_RESP_ERR_SYS_SEND_PKT:
    case TLS_RESP_ERR_SYS_RECV_PKT:
        out = MQTT_RESP_ERR_TRANSMIT;
        break;
    case TLS_RESP_ERR:
    default:
        out = MQTT_RESP_ERR;
        break;
    } // end of switch-case statement
    return out;
} // end of tlsRespCvtToMqttResp

tlsRespStatus tlsFreePSKentry(tlsPSK_t *in) {
    if (in == NULL) {
        return TLS_RESP_ERRARGS;
    }
    in->next = NULL;
    XMEMFREE((void *)in);
    return TLS_RESP_OK;
} // end of tlsFreePSKentry

word32 tlsEncodeWord24(byte *buf, word32 value) {
    if (buf != NULL) {
        buf[0] = (value >> 16) & 0xff;
        buf[1] = (value >> 8) & 0xff;
        buf[2] = value & 0xff;
    }
    // return number of bytes used to store the encoded value
    return (word32)3;
} // end of tlsEncodeWord24

tlsRespStatus tlsRSAgetPrivKey(const byte *in, word16 inlen, void **privkey_p) {
    if (mock_rsa_extract_privkey_return_val == TLS_RESP_OK) {
        *privkey_p = (void *)&mock_rsa_privkey;
    }
    return mock_rsa_extract_privkey_return_val;
}

tlsRespStatus tlsDecodeCerts(tlsCert_t *cert, byte final_item_rdy) {
    return mock_decode_cert_return_val;
}

tlsRespStatus tlsVerifyCertChain(tlsCert_t *issuer_cert, tlsCert_t *subject_cert) {
    return mock_verify_certchain_return_val;
}

void tlsFreeCertChain(tlsCert_t *in, tlsFreeCertEntryFlag ctrl_flg) {
    tlsCert_t *curr_cert = in;
    if (curr_cert != NULL) {
        if (ctrl_flg == TLS_FREE_CERT_ENTRY_ALL) {
            XMEMFREE(curr_cert);
        }
    }
}

mqttRespStatus mqttDRBGinit(mqttDRBG_t **drbg) {
    if (drbg != NULL) {
        *drbg = (mqttDRBG_t *)XMALLOC(sizeof(mqttDRBG_t));
    }
    return MQTT_RESP_OK;
}

mqttRespStatus mqttDRBGdeinit(mqttDRBG_t *drbg) {
    if (drbg != NULL) {
        XMEMFREE(drbg);
    }
    return MQTT_RESP_OK;
}

void tlsRSAfreePrivKey(void *privkey_p) { return; }

mqttRespStatus mqttSysNetconnStart(mqttCtx_t *mctx) {
    // system object for handling network session
    if (mock_sys_net_start_return_val == MQTT_RESP_OK) {
        mctx->ext_sysobjs[0] = (void *)NET_SYS_EXT_OBJ1_REF;
        mctx->ext_sysobjs[1] = (void *)NET_SYS_EXT_OBJ2_REF;
    }
    return mock_sys_net_start_return_val;
}

mqttRespStatus mqttSysNetconnStop(mqttCtx_t *mctx) {
    mctx->ext_sysobjs[0] = NULL;
    mctx->ext_sysobjs[1] = NULL;
    return MQTT_RESP_OK;
}

tlsRespStatus tlsClientStartHandshake(tlsSession_t *session) {
    return mock_client_handshake_return_val;
}

tlsRespStatus tlsChkHSfinished(tlsSession_t *session) { return TLS_RESP_OK; }
word16        tlsGetUndecodedNumBytes(tlsSession_t *session) { return 0; }
tlsRespStatus tlsEncodeRecordLayer(tlsSession_t *session) { return TLS_RESP_OK; }
tlsRespStatus tlsDecodeRecordLayer(tlsSession_t *session) {
    session->app_pt.len = 0;
    return TLS_RESP_OK;
}
tlsRespStatus tlsEncryptRecordMsg(tlsSession_t *session) { return TLS_RESP_OK; }
tlsRespStatus tlsDecryptRecordMsg(tlsSession_t *session) { return TLS_RESP_OK; }
tlsRespStatus tlsPktSendToPeer(tlsSession_t *session, byte flush_flg) { return TLS_RESP_OK; }
tlsRespStatus tlsPktRecvFromPeer(tlsSession_t *session) { return TLS_RESP_OK; }
tlsRespStatus tlsChkFragStateOutMsg(tlsSession_t *session) { return TLS_RESP_REQ_REINIT; }
void          tlsDecrementFragNumInMsg(tlsSession_t *session) { return; }

// --------------------------------------------------------------------------------------
TEST_GROUP(tlsClientInit);
TEST_GROUP(tlsClientDeInit);
TEST_GROUP(mqttSecureNetconn);

TEST_GROUP_RUNNER(tlsClientInit) {
    RUN_TEST_CASE(tlsClientInit, init_err);
    RUN_TEST_CASE(tlsClientInit, init_ok);
}

TEST_GROUP_RUNNER(tlsClientDeInit) { RUN_TEST_CASE(tlsClientDeInit, deinit_ok); }

TEST_GROUP_RUNNER(mqttSecureNetconn) {
    RUN_TEST_CASE(mqttSecureNetconn, start_err);
    RUN_TEST_CASE(mqttSecureNetconn, start_ok);
    RUN_TEST_CASE(mqttSecureNetconn, send_ok);
    RUN_TEST_CASE(mqttSecureNetconn, recv_ok);
    RUN_TEST_CASE(mqttSecureNetconn, stop_ok);
}

TEST_SETUP(tlsClientInit) {}

TEST_SETUP(tlsClientDeInit) {}

TEST_SETUP(mqttSecureNetconn) {}

TEST_TEAR_DOWN(tlsClientInit) {}

TEST_TEAR_DOWN(tlsClientDeInit) {}

TEST_TEAR_DOWN(mqttSecureNetconn) {}

TEST(tlsClientInit, init_err) {
    tlsRespStatus status = TLS_RESP_OK;
    mock_auth_getprivkey_return_val = MQTT_RESP_ERRMEM;
    status = tlsClientInit(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERRMEM, status);

    mock_auth_getprivkey_return_val = MQTT_RESP_OK;
    mock_rsa_extract_privkey_return_val = TLS_RESP_ERR_KEYGEN;
    status = tlsClientInit(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_KEYGEN, status);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_CA_priv_key);

    mock_rsa_extract_privkey_return_val = TLS_RESP_OK;
    mock_decode_cert_return_val = TLS_RESP_ERR_CERT_OVFL;
    status = tlsClientInit(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_CERT_OVFL, status);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_CA_priv_key);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_CA_cert);

    mock_decode_cert_return_val = TLS_RESP_ERR_NOT_SUPPORT;
    status = tlsClientInit(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_NOT_SUPPORT, status);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_CA_priv_key);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_CA_cert);

    mock_decode_cert_return_val = TLS_RESP_OK;
    mock_verify_certchain_return_val = TLS_RESP_CERT_AUTH_FAIL;
    status = tlsClientInit(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_CERT_AUTH_FAIL, status);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_CA_priv_key);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_CA_cert);
} // end of TEST(tlsClientInit, init_err)

TEST(tlsClientInit, init_ok) {
    tlsRespStatus status = TLS_RESP_OK;

    mock_auth_getprivkey_return_val = MQTT_RESP_OK;
    mock_rsa_extract_privkey_return_val = TLS_RESP_OK;
    mock_decode_cert_return_val = TLS_RESP_OK;
    mock_verify_certchain_return_val = TLS_RESP_OK;
    status = tlsClientInit(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(&mock_rsa_privkey, tls_CA_priv_key);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_CA_cert);
    TEST_ASSERT_EQUAL_UINT(&mock_mqtt_auth_ca_cert_rawbyte[0], tls_CA_cert->rawbytes.data);
} // end of TEST(tlsClientInit, init_ok)

TEST(tlsClientDeInit, deinit_ok) {
    TEST_ASSERT_EQUAL_UINT(NULL, tls_PSKs_rdy_list);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->drbg);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_CA_cert);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_CA_priv_key);

    tls_PSKs_rdy_list = XMALLOC(sizeof(tlsPSK_t));
    tls_PSKs_rdy_list->next = XMALLOC(sizeof(tlsPSK_t));
    tls_PSKs_rdy_list->next->next = NULL;
    unittest_mctx->drbg = XMALLOC(sizeof(mqttDRBG_t));

    tlsClientDeInit(unittest_mctx);

    TEST_ASSERT_EQUAL_UINT(NULL, tls_PSKs_rdy_list);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->drbg);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_CA_cert);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_CA_priv_key);
} // end of TEST(tlsClientDeInit, deinit_ok)

TEST(mqttSecureNetconn, start_err) {
    mqttRespStatus status = MQTT_RESP_OK;

    mock_sys_net_start_return_val = MQTT_RESP_TIMEOUT;
    status = mqttSecureNetconnStart(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_TIMEOUT, status);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->ext_sysobjs[0]);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->ext_sysobjs[1]);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->secure_session);

    mock_sys_net_start_return_val = MQTT_RESP_OK;
    mock_client_handshake_return_val = TLS_RESP_ERR_SYS_SEND_PKT;
    status = mqttSecureNetconnStart(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_TRANSMIT, status);
    TEST_ASSERT_EQUAL_UINT(NET_SYS_EXT_OBJ1_REF, unittest_mctx->ext_sysobjs[0]);
    TEST_ASSERT_EQUAL_UINT(NET_SYS_EXT_OBJ2_REF, unittest_mctx->ext_sysobjs[1]);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->secure_session);

    unittest_mctx->ext_sysobjs[0] = NULL;
    unittest_mctx->ext_sysobjs[1] = NULL;
} // end of TEST(mqttSecureNetconn, start_err)

TEST(mqttSecureNetconn, start_ok) {
    tlsSession_t  *session = NULL;
    mqttRespStatus status = MQTT_RESP_OK;

    mock_sys_net_start_return_val = MQTT_RESP_OK;
    mock_client_handshake_return_val = MQTT_RESP_OK;
    status = mqttSecureNetconnStart(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NET_SYS_EXT_OBJ1_REF, unittest_mctx->ext_sysobjs[0]);
    TEST_ASSERT_EQUAL_UINT(NET_SYS_EXT_OBJ2_REF, unittest_mctx->ext_sysobjs[1]);
    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx->secure_session);

    session = (tlsSession_t *)unittest_mctx->secure_session;
    TEST_ASSERT_EQUAL_UINT(unittest_mctx->ext_sysobjs[0], session->ext_sysobjs[0]);
    TEST_ASSERT_EQUAL_UINT(unittest_mctx->ext_sysobjs[1], session->ext_sysobjs[1]);
    TEST_ASSERT_EQUAL_INT(TEST_CMD_TIMEOUT_MS, session->cmd_timeout_ms);
    TEST_ASSERT_EQUAL_UINT(&mock_mqtt_broker_host, session->server_name);
} // end of TEST(mqttSecureNetconn, start_ok)

TEST(mqttSecureNetconn, stop_ok) {
    mqttRespStatus         status = MQTT_RESP_OK;
    tlsSession_t          *session = (tlsSession_t *)unittest_mctx->secure_session;
    tlsSecurityElements_t *sec = &session->sec;

    sec->secret.app.mst.data = XMALLOC(sizeof(byte) * 0x30); // only for improving test coverage
    sec->secret.app.client.data = &sec->secret.app.mst.data[0x10];
    sec->secret.app.server.data = &sec->secret.app.mst.data[0x20];
    sec->secret.app.client.len = 0x10;
    sec->secret.app.server.len = 0x10;

    status = mqttSecureNetconnStop(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->ext_sysobjs[0]);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->ext_sysobjs[1]);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->secure_session);
} // end of TEST(mqttSecureNetconn, stop_ok)

TEST(mqttSecureNetconn, send_ok) {
    byte           sendbuf[0x10];
    mqttRespStatus status = MQTT_RESP_OK;
    const byte     buflen = 0x10;

    status = (mqttRespStatus)mqttSecurePktSend(unittest_mctx, &sendbuf[0], (word32)buflen);
    TEST_ASSERT_EQUAL_INT(buflen, status);
} // end of TEST(mqttSecureNetconn, send_ok)

TEST(mqttSecureNetconn, recv_ok) {
    byte           recvbuf[0x10];
    mqttRespStatus status = MQTT_RESP_OK;
    byte           buflen = 0;

    status = mqttSecurePktRecv(unittest_mctx, NULL, (word32)buflen);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERRARGS, status);
    buflen = 0x0;
    status = mqttSecurePktRecv(unittest_mctx, &recvbuf[0], (word32)buflen);
    TEST_ASSERT_EQUAL_INT(buflen, status);
    buflen = 0x10;
    status = mqttSecurePktRecv(unittest_mctx, &recvbuf[0], (word32)buflen);
    TEST_ASSERT_EQUAL_INT(buflen, status);
} // end of TEST(mqttSecureNetconn, recv_ok)

static void RunAllTestGroups(void) {
    tls_CA_priv_key = NULL;
    tls_CA_cert = NULL;
    tls_PSKs_rdy_list = NULL;
    unittest_mctx = XMALLOC(sizeof(mqttCtx_t));
    XMEMSET(unittest_mctx, 0x00, sizeof(mqttCtx_t));
    // be aware of encoding / decoding message may require more buffer space
    unittest_mctx->tx_buf = XMALLOC(sizeof(byte) * MAX_RAWBYTE_READ_BUF_SZ);
    unittest_mctx->tx_buf_len = MAX_RAWBYTE_READ_BUF_SZ;
    unittest_mctx->rx_buf = XMALLOC(sizeof(byte) * MAX_RAWBYTE_READ_BUF_SZ);
    unittest_mctx->rx_buf_len = MAX_RAWBYTE_READ_BUF_SZ;
    unittest_mctx->cmd_timeout_ms = TEST_CMD_TIMEOUT_MS;
    unittest_mctx->broker_host = &mock_mqtt_broker_host;

    RUN_TEST_GROUP(tlsClientInit);
    RUN_TEST_GROUP(tlsClientDeInit);
    {
        mock_auth_getprivkey_return_val = MQTT_RESP_OK;
        mock_rsa_extract_privkey_return_val = TLS_RESP_OK;
        mock_decode_cert_return_val = TLS_RESP_OK;
        mock_verify_certchain_return_val = TLS_RESP_OK;
        tlsClientInit(unittest_mctx);
    }
    RUN_TEST_GROUP(mqttSecureNetconn);
    { tlsClientDeInit(unittest_mctx); }
    XMEMFREE(unittest_mctx->tx_buf);
    XMEMFREE(unittest_mctx->rx_buf);
    XMEMFREE(unittest_mctx);
    unittest_mctx = NULL;
} // end of RunAllTestGroups

int main(int argc, const char *argv[]) {
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main
