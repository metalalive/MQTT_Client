#include "mqtt_include.h"

#define MAX_RAWBYTE_READ_BUF_SZ \
    0x100 // internal parameter for read buffer, DO NOT modify this value
#define TEST_CMD_TIMEOUT_MS  1000
#define NET_SYS_EXT_OBJ1_REF 0x2
#define NET_SYS_EXT_OBJ2_REF 0x3

static const byte mock_client_cert_raw[] = {
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
    0x30, 0x82, 0xa4, 0xe1, 0x79, 0x01, 0x00, 0x02, 0x82, 0xa1, 0x1e, 0x1b, 0x90, 0x89, 0xd8, 0x9e,
};

static unsigned int mock_client_cert_nbytes = 0x110;

static const byte mock_client_privkey_raw[] = {
    0x30, 0x82, 0x04, 0xa5, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
};

static unsigned int mock_client_privkey_nbytes = 12;

static const byte mock_cacert_broker_raw[] = {
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
    0x30, 0x82, 0x04, 0x2d, 0x30, 0x82, 0x03, 0x15, 0xa0, 0x03, 0xa0, 0xb5, 0x6c, 0x71, 0x56, 0xc8,
};

static unsigned int mock_cacert_broker_nbytes = 0x110;

static mqttCtx_t     *unittest_mctx;
static mqttRespStatus mock_auth_getprivkey_return_val;
static mqttRespStatus mock_auth_getcacert_return_val;
static mqttRespStatus mock_sys_net_start_return_val;
static tlsRespStatus  mock_rsa_extract_privkey_return_val;
static tlsRespStatus  mock_decode_cert_return_val;
static tlsRespStatus  mock_verify_certchain_return_val;
static tlsRespStatus  mock_client_handshake_return_val;

static tlsRSAkey_t mock_rsa_privkey;

static mqttHost_t mock_mqtt_broker_host = {
    .domain_name = {.len = 12, .data = (byte *)&("mock_broker")},
    .ip_address = {.len = 0, .data = NULL},
};

mqttRespStatus mqttDRBGgen(mqttDRBG_t *drbg, mqttStr_t *out, mqttStr_t *extra_in) {
    (void)drbg;
    (void)extra_in;
    XASSERT(out->data);
    out->data[0] = 't';
    out->data[1] = 'w';
    out->len = 2;
    return MQTT_RESP_OK;
}

mqttRespStatus mqttAuthClientPrivKeyRaw(const byte **out, word16 *len) {
    if (mock_auth_getprivkey_return_val == MQTT_RESP_OK) {
        *out = (byte *)&mock_client_privkey_raw[0];
        *len = (word16)mock_client_privkey_nbytes;
    }
    return mock_auth_getprivkey_return_val;
}

mqttRespStatus mqttAuthCACertBrokerRaw(byte **out, word16 *len) {
    if (mock_auth_getcacert_return_val == MQTT_RESP_OK) {
        *out = (byte *)&mock_cacert_broker_raw[0];
        *len = (word16)mock_cacert_broker_nbytes;
    }
    return mock_auth_getcacert_return_val;
}

mqttRespStatus mqttAuthClientCertRaw(byte **out, word16 *len) {
    if (mock_auth_getcacert_return_val == MQTT_RESP_OK) {
        *out = (byte *)&mock_client_cert_raw[0];
        *len = (word16)mock_client_cert_nbytes;
    }
    return mock_auth_getcacert_return_val;
}

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

    mock_rsa_extract_privkey_return_val = TLS_RESP_OK;
    mock_decode_cert_return_val = TLS_RESP_ERR_CERT_OVFL;
    status = tlsClientInit(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_CERT_OVFL, status);

    mock_decode_cert_return_val = TLS_RESP_ERR_NOT_SUPPORT;
    status = tlsClientInit(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_NOT_SUPPORT, status);

    mock_decode_cert_return_val = TLS_RESP_OK;
    mock_verify_certchain_return_val = TLS_RESP_CERT_AUTH_FAIL;
    status = tlsClientInit(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_CERT_AUTH_FAIL, status);
} // end of TEST(tlsClientInit, init_err)

TEST(tlsClientInit, init_ok) {
    tlsRespStatus status = TLS_RESP_OK;

    mock_auth_getprivkey_return_val = MQTT_RESP_OK;
    mock_rsa_extract_privkey_return_val = TLS_RESP_OK;
    mock_decode_cert_return_val = TLS_RESP_OK;
    mock_verify_certchain_return_val = TLS_RESP_OK;
    status = tlsClientInit(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(&mock_rsa_privkey, NULL);
}

TEST(tlsClientDeInit, deinit_ok) {
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->drbg);
    unittest_mctx->drbg = XMALLOC(sizeof(mqttDRBG_t));
    tlsClientDeInit(unittest_mctx);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->drbg);
}

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
