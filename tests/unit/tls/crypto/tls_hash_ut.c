#include "mqtt_include.h"

#define MAX_RAWBYTE_BUF_SZ 0x80

extern const unsigned char *mock_hash_curr_state[2];
extern const unsigned char *mock_hash_curr_outbytes[2];
extern unsigned char       *mock_last_hash_in_data[2];
extern unsigned int         mock_last_hash_in_len[2];
static tlsSession_t        *tls_session;

const tlsCipherSpec_t tls_supported_cipher_suites[] = {
    {
        // TLS_AES_128_GCM_SHA256, 0x1301
        TLS_CIPHERSUITE_ID_AES_128_GCM_SHA256, // ident
        (1 << TLS_ENCRYPT_ALGO_AES128) | (1 << TLS_ENC_CHAINMODE_GCM) |
            (1 << TLS_HASH_ALGO_SHA256), // flags
        16,                              // tagSize
        16,                              // keySize
        12,                              // ivSize
        NULL,                            // init_fn
        NULL,                            // encrypt_fn
        NULL,                            // decrypt_fn
        NULL,                            // done_fn
    },
    {
        // TLS_AES_256_GCM_SHA384, 0x1302
        TLS_CIPHERSUITE_ID_AES_256_GCM_SHA384, // ident
        (1 << TLS_ENCRYPT_ALGO_AES256) | (1 << TLS_ENC_CHAINMODE_GCM) |
            (1 << TLS_HASH_ALGO_SHA384), // flags
        16,                              // tagSize
        32,                              // keySize
        12,                              // ivSize
        NULL,                            // init_fn
        NULL,                            // encrypt_fn
        NULL,                            // decrypt_fn
        NULL,                            // done_fn
    },
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

word16 mqttHashGetOutlenBytes(mqttHashLenType type) {
    word16 out = 0;
    switch (type) {
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

tlsRespStatus tlsChkFragStateOutMsg(tlsSession_t *session) {
    tlsRespStatus status = TLS_RESP_OK;
    if (session == NULL) {
        status = TLS_RESP_ERRARGS;
    } else {
        if (session->num_frags_out == 0) {
            status = TLS_RESP_REQ_REINIT;
        } else { // when num_frags_out > 0 , that means it is working & currently encoding message
                 // hasn't been sent yet
            if (session->remain_frags_out == session->num_frags_out) {
                status = TLS_RESP_FIRST_FRAG;
            }
            if (session->remain_frags_out == 1) {
                status |= TLS_RESP_FINAL_FRAG;
            }
        }
    }
    return status;
} // end of tlsChkFragStateOutMsg

tlsRespStatus tlsChkFragStateInMsg(tlsSession_t *session) {
    tlsRespStatus status = TLS_RESP_OK;
    if (session == NULL) {
        status = TLS_RESP_ERRARGS;
    } else {
        if (session->num_frags_in == 0) {
            status = TLS_RESP_REQ_REINIT;
        } else { // when num_frags_in > 0 , that means this client received bytes & should be
                 // decoding them
            if (session->remain_frags_in == session->num_frags_in) {
                status = TLS_RESP_FIRST_FRAG;
            }
            if (session->remain_frags_in == 1) {
                status |= TLS_RESP_FINAL_FRAG;
            } // ignore those fragments which are not first one and last one
        }
    }
    return status;
} // end of tlsChkFragStateInMsg

tlsHandshakeType tlsGetHSexpectedState(tlsSession_t *session) {
    return (session == NULL ? TLS_HS_TYPE_HELLO_REQUEST_RESERVED : session->hs_state);
} // end of tlsGetHSexpectedState

// ------------------------------------------------------
TEST_GROUP(tlsHandshakeHash);
TEST_GROUP(tlsTranscrptHashHSmsgUpdate);

TEST_SETUP(tlsHandshakeHash) {}

TEST_SETUP(tlsTranscrptHashHSmsgUpdate) {}

TEST_TEAR_DOWN(tlsHandshakeHash) {}

TEST_TEAR_DOWN(tlsTranscrptHashHSmsgUpdate) {}

TEST_GROUP_RUNNER(tlsHandshakeHash) {
    RUN_TEST_CASE(tlsHandshakeHash, tlsTranscrptHashInit);
    RUN_TEST_CASE(tlsHandshakeHash, tlsTransHashTakeSnapshot);
    RUN_TEST_CASE(tlsHandshakeHash, tlsTranscrptHashDeInit);
    RUN_TEST_CASE(tlsHandshakeHash, tlsTranscrptHashReInit);
    RUN_TEST_CASE(tlsHandshakeHash, tlsTransHashCleanUnsuedHashHandler);
    RUN_TEST_CASE(tlsHandshakeHash, tlsCpyHashEmptyInput);
}

TEST_GROUP_RUNNER(tlsTranscrptHashHSmsgUpdate) {
    tlsRespStatus status = TLS_RESP_OK;
    tls_session->sec.chosen_ciphersuite = NULL;
    status = tlsTranscrptHashInit(&tls_session->sec);
    XASSERT(TLS_RESP_OK == status);
    tls_session->record_type = TLS_CONTENT_TYPE_HANDSHAKE;

    RUN_TEST_CASE(tlsTranscrptHashHSmsgUpdate, outbuf_one_frag_multi_msgs);
    RUN_TEST_CASE(tlsTranscrptHashHSmsgUpdate, inbuf_multi_frags_one_msg);
    RUN_TEST_CASE(tlsTranscrptHashHSmsgUpdate, hs_after_server_finished);

    status = tlsTranscrptHashDeInit(&tls_session->sec);
    XASSERT(TLS_RESP_OK == status);
}

TEST(tlsHandshakeHash, tlsTranscrptHashInit) {
    tlsRespStatus status = TLS_RESP_OK;

    tls_session->sec.chosen_ciphersuite = NULL;
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->sec.hashed_hs_msg.objsha256);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->sec.hashed_hs_msg.objsha384);
    status = tlsTranscrptHashInit(&tls_session->sec);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->sec.hashed_hs_msg.objsha256);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->sec.hashed_hs_msg.objsha384);
} // end of TEST(tlsHandshakeHash, tlsTranscrptHashInit)

TEST(tlsHandshakeHash, tlsTransHashTakeSnapshot) {
    const byte *expect_hash_state[2] = {
        (const byte *)&("\x01\x02\x03\x04\x05"),
        (const byte *)&("\x10\x20\x30\x40\x50"),
    };
    tlsSecurityElements_t *sec = NULL;
    byte                  *buf = NULL;
    word16                 buflen = 0;
    tlsRespStatus          status = TLS_RESP_OK;
    const byte             sha256_idx = 0;
    const byte             sha384_idx = 1;

    sec = &tls_session->sec;
    buflen = mqttHashGetOutlenBytes(MQTT_HASH_SHA384);
    buf = XMALLOC(buflen);
    XMEMCPY(sec->hashed_hs_msg.objsha384, expect_hash_state[sha384_idx], 5);
    XMEMCPY(sec->hashed_hs_msg.objsha256, expect_hash_state[sha256_idx], 5);

    status = tlsTransHashTakeSnapshot(sec, TLS_HASH_ALGO_NOT_NEGO, buf, buflen);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERRARGS, status);

    mock_hash_curr_state[sha384_idx] = (const byte *)&("\x06\x07\x08\x09\x0a");
    mock_hash_curr_outbytes[sha384_idx] =
        (const byte *)&("It is supposed to be the hash output, 48 bytes in total (SHA384)");
    status = tlsTransHashTakeSnapshot(sec, TLS_HASH_ALGO_SHA384, buf, buflen);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_STRING_LEN(mock_hash_curr_outbytes[sha384_idx], buf, buflen);
    TEST_ASSERT_EQUAL_STRING_LEN(expect_hash_state[sha384_idx], sec->hashed_hs_msg.objsha384, 5);

    buflen = mqttHashGetOutlenBytes(MQTT_HASH_SHA256);
    mock_hash_curr_state[sha256_idx] = (const byte *)&("\x0b\x0c\x0d\x0e\x0f");
    mock_hash_curr_outbytes[sha256_idx] =
        (const byte *)&("Bytes that are supposed to load, 32 bytes in total (SHA256)");
    status = tlsTransHashTakeSnapshot(sec, TLS_HASH_ALGO_SHA256, buf, buflen);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_STRING_LEN(mock_hash_curr_outbytes[sha256_idx], buf, buflen);
    TEST_ASSERT_EQUAL_STRING_LEN(
        expect_hash_state[sha256_idx], sec->hashed_hs_msg.objsha256, 5
    ); // hash state must not be changed after snapshot

    XMEMFREE(buf);
    mock_hash_curr_state[sha384_idx] = NULL;
    mock_hash_curr_outbytes[sha384_idx] = NULL;
    mock_hash_curr_state[sha256_idx] = NULL;
    mock_hash_curr_outbytes[sha256_idx] = NULL;
} // end of TEST(tlsHandshakeHash, tlsTransHashTakeSnapshot)

TEST(tlsHandshakeHash, tlsTranscrptHashDeInit) {
    tlsSecurityElements_t *sec = NULL;
    tlsRespStatus          status = TLS_RESP_OK;

    sec = &tls_session->sec;
    TEST_ASSERT_NOT_EQUAL(NULL, sec->hashed_hs_msg.objsha256);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->hashed_hs_msg.objsha384);
    status = tlsTranscrptHashDeInit(sec);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, sec->hashed_hs_msg.objsha256);
    TEST_ASSERT_EQUAL_UINT(NULL, sec->hashed_hs_msg.objsha384);
} // end of TEST(tlsHandshakeHash, tlsTranscrptHashDeInit)

TEST(tlsHandshakeHash, tlsTranscrptHashReInit) {
    tlsSecurityElements_t *sec = NULL;
    tlsRespStatus          status = TLS_RESP_OK;
    const byte             sha256_idx = 0;

    sec = &tls_session->sec;
    sec->chosen_ciphersuite = NULL;
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->sec.hashed_hs_msg.objsha256);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->sec.hashed_hs_msg.objsha384);
    status = tlsTranscrptHashInit(&tls_session->sec);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);

    sec->chosen_ciphersuite = &tls_supported_cipher_suites[0]; // SHA256 is chosen
    TEST_ASSERT_NOT_EQUAL(NULL, sec->hashed_hs_msg.objsha256);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->hashed_hs_msg.objsha384);
    mock_hash_curr_state[sha256_idx] = (const byte *)&("\x0b\x0c\x0d\x0e\x0f");
    status = tlsTranscrptHashReInit(sec);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->hashed_hs_msg.objsha256);
    TEST_ASSERT_EQUAL_UINT(NULL, sec->hashed_hs_msg.objsha384);
    TEST_ASSERT_EQUAL_STRING_LEN(mock_hash_curr_state[sha256_idx], sec->hashed_hs_msg.objsha256, 5);

    status = tlsTranscrptHashDeInit(sec);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, sec->hashed_hs_msg.objsha256);
    TEST_ASSERT_EQUAL_UINT(NULL, sec->hashed_hs_msg.objsha384);
    mock_hash_curr_state[sha256_idx] = NULL;
} // end of TEST(tlsHandshakeHash, tlsTranscrptHashReInit)

TEST(tlsHandshakeHash, tlsTransHashCleanUnsuedHashHandler) {
    tlsSecurityElements_t *sec = NULL;
    tlsRespStatus          status = TLS_RESP_OK;

    sec = &tls_session->sec;
    sec->chosen_ciphersuite = NULL;
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->sec.hashed_hs_msg.objsha256);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->sec.hashed_hs_msg.objsha384);
    status = tlsTranscrptHashInit(&tls_session->sec);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->hashed_hs_msg.objsha256);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->hashed_hs_msg.objsha384);

    sec->chosen_ciphersuite = &tls_supported_cipher_suites[0]; // SHA256 is chosen
    status = tlsTransHashCleanUnsuedHashHandler(sec);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->hashed_hs_msg.objsha256);
    TEST_ASSERT_EQUAL_UINT(NULL, sec->hashed_hs_msg.objsha384);

    sec->chosen_ciphersuite = &tls_supported_cipher_suites[1]; // SHA2384 is chosen
    status = tlsTransHashCleanUnsuedHashHandler(sec);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, sec->hashed_hs_msg.objsha256);
    TEST_ASSERT_EQUAL_UINT(NULL, sec->hashed_hs_msg.objsha384);
} // end of TEST(tlsHandshakeHash, tlsTransHashCleanUnsuedHashHandler)

TEST(tlsHandshakeHash, tlsCpyHashEmptyInput) {
    tlsOpaque8b_t actual_out = {0, NULL};
    tlsRespStatus status = TLS_RESP_OK;

    actual_out.data = NULL;
    status = tlsCpyHashEmptyInput(TLS_HASH_ALGO_SHA384, &actual_out);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(mqttHashGetOutlenBytes(MQTT_HASH_SHA384), actual_out.len);

    actual_out.data = NULL;
    status = tlsCpyHashEmptyInput(TLS_HASH_ALGO_SHA256, &actual_out);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(mqttHashGetOutlenBytes(MQTT_HASH_SHA256), actual_out.len);
} // end of TEST(tlsHandshakeHash, tlsCpyHashEmptyInput)

TEST(tlsTranscrptHashHSmsgUpdate, outbuf_one_frag_multi_msgs) {
    tlsSecurityElements_t *sec = NULL;
    byte                  *buf = NULL;
    tlsRespStatus          status = TLS_RESP_OK;
    const byte             sha384_idx = 1;

    sec = &tls_session->sec;
    sec->chosen_ciphersuite = &tls_supported_cipher_suites[1]; // SHA384 is chosen
    tls_session->flgs.hs_tx_encrypt = 1;

    // the first hasdshake message
    tls_session->remain_frags_out = 0;
    tls_session->num_frags_out = 0;
    tls_session->curr_outmsg_start = tls_session->outbuf.len >> 1;
    tls_session->curr_outmsg_len =
        tls_session->outbuf.len - TLS_RECORD_LAYER_HEADER_NBYTES - TLS_HANDSHAKE_HEADER_NBYTES;
    tls_session->curr_outmsg_len -= (2 + sec->chosen_ciphersuite->tagSize);
    tls_session->outlen_encoded = tls_session->curr_outmsg_start + tls_session->curr_outmsg_len;
    tls_session->log.last_encode_result = TLS_RESP_OK;
    mock_hash_curr_state[sha384_idx] = (const byte *)&("\x11\x12\x13\x14\x15");
    status = tlsTranscrptHashHSmsgUpdate(tls_session, &tls_session->outbuf);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_STRING_LEN(mock_hash_curr_state[sha384_idx], sec->hashed_hs_msg.objsha384, 5);
    // .... check the region of outbuf that is fed to hash function
    buf =
        tls_session->outbuf.data + tls_session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES;
    TEST_ASSERT_EQUAL_UINT(buf, mock_last_hash_in_data[sha384_idx]);
    buf += tls_session->curr_outmsg_len -
           (TLS_RECORD_LAYER_HEADER_NBYTES + 1 + tls_session->sec.chosen_ciphersuite->tagSize);
    TEST_ASSERT_EQUAL_UINT(
        buf, (mock_last_hash_in_data[sha384_idx] + mock_last_hash_in_len[sha384_idx])
    );

    // the second hasdshake message, 4-byte handshake field & 3-byte data field are encoded, the
    // auth tag is not encoded due to insufficient space in outbuf, but the handshake field and data
    // field are not hashed, not encrypted, also not sent.
    mock_last_hash_in_data[sha384_idx] = NULL;
    mock_last_hash_in_len[sha384_idx] = 0;
    tls_session->curr_outmsg_start = tls_session->outlen_encoded;
    tls_session->curr_outmsg_len = TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES;
    tls_session->curr_outmsg_len += 3 + 1 + sec->chosen_ciphersuite->tagSize;
    tls_session->outlen_encoded += TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES + 3;
    tls_session->log.last_encode_result = TLS_RESP_REQ_MOREDATA;
    status = tlsTranscrptHashHSmsgUpdate(
        tls_session, &tls_session->outbuf
    ); // not update transcript hash state
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, mock_last_hash_in_data[sha384_idx]);
    TEST_ASSERT_EQUAL_UINT32(0, mock_last_hash_in_len[sha384_idx]);

    // the second hasdshake message, previously encoded handshake field and data field are hashed in
    // this fragment.
    tls_session->remain_frags_out = 1;
    tls_session->num_frags_out = 2;
    tls_session->curr_outmsg_start = 0;
    tls_session->outlen_encoded =
        TLS_HANDSHAKE_HEADER_NBYTES + 3 + 1 + sec->chosen_ciphersuite->tagSize;
    tls_session->log.last_encode_result = TLS_RESP_OK;
    mock_hash_curr_state[sha384_idx] = (const byte *)&("\x17\x18\x19\x1a\x1b");
    status = tlsTranscrptHashHSmsgUpdate(tls_session, &tls_session->outbuf);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_STRING_LEN(mock_hash_curr_state[sha384_idx], sec->hashed_hs_msg.objsha384, 5);
    // .... check the region of outbuf that is fed to hash function
    buf = tls_session->outbuf.data + tls_session->curr_outmsg_start;
    TEST_ASSERT_EQUAL_UINT(buf, mock_last_hash_in_data[sha384_idx]);
    buf += TLS_HANDSHAKE_HEADER_NBYTES + 3;
    TEST_ASSERT_EQUAL_UINT(
        buf, (mock_last_hash_in_data[sha384_idx] + mock_last_hash_in_len[sha384_idx])
    );

    // skip the third message, now assume that it's the fourth hasdshake message. Partial data bytes
    // encoded are hashed in current fragment, while rest of data bytes encoded will be hashed in
    // next fragment.
    tls_session->remain_frags_out = 0;
    tls_session->num_frags_out = 0;
    tls_session->outlen_encoded =
        tls_session->outbuf.len - TLS_RECORD_LAYER_HEADER_NBYTES - TLS_HANDSHAKE_HEADER_NBYTES;
    tls_session->outlen_encoded -= (sec->chosen_ciphersuite->tagSize << 1);
    tls_session->curr_outmsg_start = tls_session->outlen_encoded;
    tls_session->curr_outmsg_len = TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES;
    tls_session->curr_outmsg_len +=
        (sec->chosen_ciphersuite->tagSize << 1) + 1 + sec->chosen_ciphersuite->tagSize;
    tls_session->outlen_encoded += TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES;
    tls_session->outlen_encoded += (sec->chosen_ciphersuite->tagSize << 1);
    TEST_ASSERT_EQUAL_UINT16(tls_session->outbuf.len, tls_session->outlen_encoded);
    tls_session->log.last_encode_result = TLS_RESP_REQ_MOREDATA;
    mock_hash_curr_state[sha384_idx] = (const byte *)&("\x1c\x1d\x1e\x1f\x20");
    status = tlsTranscrptHashHSmsgUpdate(tls_session, &tls_session->outbuf);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_STRING_LEN(mock_hash_curr_state[sha384_idx], sec->hashed_hs_msg.objsha384, 5);
    // .... check the region of outbuf that is fed to hash function
    buf =
        tls_session->outbuf.data + tls_session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES;
    TEST_ASSERT_EQUAL_UINT(buf, mock_last_hash_in_data[sha384_idx]);
    buf += (sec->chosen_ciphersuite->tagSize << 1);
    TEST_ASSERT_EQUAL_UINT(
        buf, (mock_last_hash_in_data[sha384_idx] + mock_last_hash_in_len[sha384_idx])
    );

    // rest of data bytes encoded are hashed in first fragment.
    tls_session->remain_frags_out = 1;
    tls_session->num_frags_out = 2;
    tls_session->curr_outmsg_start = 0;
    tls_session->outlen_encoded =
        TLS_HANDSHAKE_HEADER_NBYTES + 1 + sec->chosen_ciphersuite->tagSize;
    tls_session->log.last_encode_result = TLS_RESP_OK;
    mock_hash_curr_state[sha384_idx] = (const byte *)&("\x22\x24\x26\x28\x2a");
    status = tlsTranscrptHashHSmsgUpdate(tls_session, &tls_session->outbuf);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_STRING_LEN(mock_hash_curr_state[sha384_idx], sec->hashed_hs_msg.objsha384, 5);
    // .... check the region of outbuf that is fed to hash function
    buf = tls_session->outbuf.data + tls_session->curr_outmsg_start;
    TEST_ASSERT_EQUAL_UINT(buf, mock_last_hash_in_data[sha384_idx]);
    buf += TLS_HANDSHAKE_HEADER_NBYTES;
    TEST_ASSERT_EQUAL_UINT(
        buf, (mock_last_hash_in_data[sha384_idx] + mock_last_hash_in_len[sha384_idx])
    );

    mock_hash_curr_state[sha384_idx] = NULL;
} // end of TEST(tlsTranscrptHashHSmsgUpdate, outbuf_one_frag_multi_msgs)

TEST(tlsTranscrptHashHSmsgUpdate, inbuf_multi_frags_one_msg) {
    tlsSecurityElements_t *sec = NULL;
    byte                  *buf = NULL;
    tlsRespStatus          status = TLS_RESP_OK;
    const byte             sha256_idx = 0;

    sec = &tls_session->sec;
    sec->chosen_ciphersuite = &tls_supported_cipher_suites[0]; // SHA256 is chosen
    tls_session->flgs.hs_rx_encrypt = 1;

    // the first fragment
    tls_session->remain_frags_in = 2;
    tls_session->num_frags_in = 2;
    tls_session->sec.flgs.ct_first_frag = 1;
    tls_session->sec.flgs.ct_final_frag = 0;
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = tls_session->inbuf.len - 7;
    mock_hash_curr_state[sha256_idx] = (const byte *)&("\x23\x25\x27\x29\x2b");
    status = tlsTranscrptHashHSmsgUpdate(tls_session, &tls_session->inbuf);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_STRING_LEN(mock_hash_curr_state[sha256_idx], sec->hashed_hs_msg.objsha256, 5);
    buf = tls_session->inbuf.data + TLS_RECORD_LAYER_HEADER_NBYTES;
    TEST_ASSERT_EQUAL_UINT(buf, mock_last_hash_in_data[sha256_idx]);
    buf = tls_session->inbuf.data + tls_session->inlen_decrypted;
    TEST_ASSERT_EQUAL_UINT(
        buf, (mock_last_hash_in_data[sha256_idx] + mock_last_hash_in_len[sha256_idx])
    );

    // the second fragment
    tls_session->remain_frags_in = 1;
    tls_session->num_frags_in = 2;
    tls_session->sec.flgs.ct_first_frag = 0;
    tls_session->sec.flgs.ct_final_frag = 1;
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = sec->chosen_ciphersuite->tagSize;
    mock_last_hash_in_data[sha256_idx] = NULL;
    mock_last_hash_in_len[sha256_idx] = 0;
    status = tlsTranscrptHashHSmsgUpdate(tls_session, &tls_session->inbuf);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, mock_last_hash_in_data[sha256_idx]);
    TEST_ASSERT_EQUAL_UINT32(0, mock_last_hash_in_len[sha256_idx]);

    mock_hash_curr_state[sha256_idx] = NULL;
} // end of TEST(tlsTranscrptHashHSmsgUpdate, inbuf_multi_frags_one_msg)

TEST(tlsTranscrptHashHSmsgUpdate, hs_after_server_finished) {
    tlsSecurityElements_t *sec = NULL;
    tlsRespStatus          status = TLS_RESP_OK;
    const byte             sha256_idx = 0;

    sec = &tls_session->sec;
    sec->chosen_ciphersuite = &tls_supported_cipher_suites[0]; // SHA256 is chosen
    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->flgs.hs_server_finish = 0;
    tls_session->hs_state = TLS_HS_TYPE_FINISHED;

    tls_session->remain_frags_in = 1;
    tls_session->num_frags_in = 1;
    tls_session->sec.flgs.ct_first_frag = 1;
    tls_session->sec.flgs.ct_final_frag = 1;
    tls_session->inlen_decoded = 0;
    tls_session->inlen_decrypted = tls_session->inbuf.len >> 1;
    mock_hash_curr_state[sha256_idx] = (const byte *)&("\x28\x29\x2a\x2b\x2c");
    mock_hash_curr_outbytes[sha256_idx] = (const byte *)&("server Finished trHash");

    TEST_ASSERT_EQUAL_UINT(NULL, sec->hashed_hs_msg.snapshot_server_finished);
    status = tlsTranscrptHashHSmsgUpdate(tls_session, &tls_session->inbuf);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_STRING_LEN(mock_hash_curr_state[sha256_idx], sec->hashed_hs_msg.objsha256, 5);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->hashed_hs_msg.snapshot_server_finished);
    TEST_ASSERT_EQUAL_STRING_LEN(
        mock_hash_curr_outbytes[sha256_idx], sec->hashed_hs_msg.snapshot_server_finished, 22
    );

    mock_hash_curr_state[sha256_idx] = NULL;
    mock_hash_curr_outbytes[sha256_idx] = NULL;
} // end of TEST(tlsTranscrptHashHSmsgUpdate, hs_after_server_finished)

static void RunAllTestGroups(void) {
    tls_session = (tlsSession_t *)XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->inbuf.len = MAX_RAWBYTE_BUF_SZ;
    tls_session->inbuf.data = (byte *)XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);
    tls_session->outbuf.len = MAX_RAWBYTE_BUF_SZ;
    tls_session->outbuf.data = (byte *)XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);

    RUN_TEST_GROUP(tlsHandshakeHash);
    RUN_TEST_GROUP(tlsTranscrptHashHSmsgUpdate);

    XMEMFREE(tls_session->inbuf.data);
    XMEMFREE(tls_session->outbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups

int main(int argc, const char *argv[]) {
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main
