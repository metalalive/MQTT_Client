#include "mqtt_include.h"

#define MAX_RAWBYTE_BUF_SZ 0x100

static tlsSession_t  *tls_session;
static byte           mock_sys_pkt_write_content[MAX_RAWBYTE_BUF_SZ];
static byte           mock_sys_pkt_read_content[MAX_RAWBYTE_BUF_SZ];
static word16         mock_sys_pkt_read_ptr;
static mqttRespStatus mock_sys_pkt_write_return_val;
static mqttRespStatus mock_sys_pkt_read_return_val;

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
}; // end of tls_supported_cipher_suites

tlsRespStatus tlsVerifyDecodeRecordType(tlsContentType rec_type) {
    tlsRespStatus status = TLS_RESP_OK;
    switch (rec_type) {
    case TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
    case TLS_CONTENT_TYPE_ALERT:
    case TLS_CONTENT_TYPE_HANDSHAKE:
    case TLS_CONTENT_TYPE_APP_DATA:
        break;
    case TLS_CONTENT_TYPE_INVALID:
    case TLS_CONTENT_TYPE_HEARTBEAT: // heartbeat is NOT support in this implementation
    default:
        status = TLS_RESP_MALFORMED_PKT;
        break;
    } // end of switch-case statement
    return status;
} // end of tlsVerifyDecodeRecordType

tlsRespStatus tlsVerifyDecodeVersionCode(const byte *ver_in
) { // TODO: consider future version checks
    if (ver_in == NULL) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    if (ver_in[0] != (TLS_VERSION_ENCODE_1_2 >> 8)) {
        status = TLS_RESP_MALFORMED_PKT;
    } else if (ver_in[1] != (TLS_VERSION_ENCODE_1_2 & 0xff)) {
        status = TLS_RESP_MALFORMED_PKT;
    }
    return status;
} // end of tlsVerifyDecodeVersionCode

int mqttSysPktWrite(void **extsysobjs, byte *buf, word32 buf_len) {
    mqttRespStatus status = mock_sys_pkt_write_return_val;
    if (status == MQTT_RESP_OK) {
        if (buf_len <= MAX_RAWBYTE_BUF_SZ) {
            XMEMCPY(&mock_sys_pkt_write_content[0], buf, buf_len);
            status = buf_len;
        } else {
            status = MQTT_RESP_ERR_TRANSMIT;
        }
    }
    return status;
} // end of mqttSysPktWrite

int mqttSysPktRead(void **extsysobjs, byte *buf, word32 buf_len, int timeout_ms) {
    mqttRespStatus status = mock_sys_pkt_read_return_val;
    if (status == MQTT_RESP_OK) {
        if ((buf_len + mock_sys_pkt_read_ptr) <= MAX_RAWBYTE_BUF_SZ) {
            XMEMCPY(buf, &mock_sys_pkt_read_content[mock_sys_pkt_read_ptr], buf_len);
            mock_sys_pkt_read_ptr += buf_len;
            status = buf_len;
        } else {
            status = MQTT_RESP_ERR_TRANSMIT;
        }
    }
    return status;
} // end of mqttSysPktRead

// ---------------------------------------------------------------------------------
TEST_GROUP(tlsPktSendToPeer);
TEST_GROUP(tlsPktRecvFromPeer);

TEST_GROUP_RUNNER(tlsPktSendToPeer) {
    RUN_TEST_CASE(tlsPktSendToPeer, one_msg_one_fragment);
    RUN_TEST_CASE(tlsPktSendToPeer, one_msg_multi_fragments);
    RUN_TEST_CASE(tlsPktSendToPeer, multi_msgs_one_fragment);
}

TEST_GROUP_RUNNER(tlsPktRecvFromPeer) {
    RUN_TEST_CASE(tlsPktRecvFromPeer, err_chk);
    RUN_TEST_CASE(tlsPktRecvFromPeer, one_msg_one_fragment);
    RUN_TEST_CASE(tlsPktRecvFromPeer, one_msg_multi_fragments);
}

TEST_SETUP(tlsPktSendToPeer) {
    tls_session->remain_frags_out = 0;
    tls_session->num_frags_out = 0;
    tls_session->sec.chosen_ciphersuite = NULL;
    XMEMSET(&mock_sys_pkt_write_content[0], 0x00, MAX_RAWBYTE_BUF_SZ);
}

TEST_SETUP(tlsPktRecvFromPeer) {
    tls_session->remain_frags_in = 0;
    tls_session->num_frags_in = 0;
    tls_session->sec.chosen_ciphersuite = NULL;
    XMEMSET(&mock_sys_pkt_read_content[0], 0x00, MAX_RAWBYTE_BUF_SZ);
}

TEST_TEAR_DOWN(tlsPktSendToPeer) {}

TEST_TEAR_DOWN(tlsPktRecvFromPeer) {}

TEST(tlsPktSendToPeer, one_msg_one_fragment) {
    byte expect_content[2][TLS_RECORD_LAYER_HEADER_NBYTES] = {
        {0x16, 0x3, 0x3, 0x0, 0x0},
        {0xe, 0x1, 0xf, 0x5a, 0xa5},
    };
    tlsRespStatus status = TLS_RESP_OK;
    byte         *buf = NULL;
    byte          flush_flg = 1;

    tls_session->flgs.hs_tx_encrypt = 0;
    tls_session->log.last_encode_result = TLS_RESP_OK;
    tls_session->curr_outmsg_start = 0x0;
    tls_session->outlen_encoded = tls_session->outbuf.len + 1; // error check #1
    status = tlsPktSendToPeer(tls_session, flush_flg);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERRMEM, status);

    tls_session->outlen_encoded = tls_session->outbuf.len;
    tls_session->curr_outmsg_len = TLS_MAX_BYTES_RECORD_LAYER_PKT + 1; // error check #2
    status = tlsPktSendToPeer(tls_session, flush_flg);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_EXCEED_MAX_REC_SZ, status);

    mock_sys_pkt_write_return_val = MQTT_RESP_ERR_TRANSMIT; // error check #3
    tls_session->curr_outmsg_len = TLS_MAX_BYTES_RECORD_LAYER_PKT;
    tls_session->log.last_encode_result = TLS_RESP_REQ_MOREDATA;
    status = tlsPktSendToPeer(tls_session, flush_flg);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_SYS_SEND_PKT, status);
    while (tlsChkFragStateOutMsg(tls_session) != TLS_RESP_REQ_REINIT) {
        tlsDecrementFragNumOutMsg(tls_session);
    }

    mock_sys_pkt_write_return_val = MQTT_RESP_OK;
    tls_session->log.last_encode_result = TLS_RESP_OK;
    tls_session->outlen_encoded = tls_session->outbuf.len;
    tls_session->curr_outmsg_len = tls_session->outbuf.len;
    tlsEncodeWord16(
        &expect_content[0][3], (tls_session->curr_outmsg_len - TLS_RECORD_LAYER_HEADER_NBYTES)
    );
    buf = &tls_session->outbuf.data[tls_session->curr_outmsg_start];
    XMEMCPY(buf, &expect_content[0][0], TLS_RECORD_LAYER_HEADER_NBYTES);
    buf += tls_session->outlen_encoded - TLS_RECORD_LAYER_HEADER_NBYTES;
    XMEMCPY(buf, &expect_content[1][0], TLS_RECORD_LAYER_HEADER_NBYTES);
    status = tlsPktSendToPeer(tls_session, flush_flg);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->outlen_encoded);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->outlen_encrypted);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_REINIT, tlsChkFragStateOutMsg(tls_session));
    buf = &mock_sys_pkt_write_content[0];
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_content[0][0], buf, TLS_RECORD_LAYER_HEADER_NBYTES);
    buf += tls_session->curr_outmsg_len - TLS_RECORD_LAYER_HEADER_NBYTES;
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_content[1][0], buf, TLS_RECORD_LAYER_HEADER_NBYTES);
} // end of TEST(tlsPktSendToPeer, one_msg_one_fragment)

TEST(tlsPktSendToPeer, one_msg_multi_fragments) {
    byte expect_content[4][2][TLS_RECORD_LAYER_HEADER_NBYTES] = {
        {{TLS_CONTENT_TYPE_APP_DATA, 0x3, 0x3, 0x0, 0x0}, {0x12, 0x13, 0x14, 0x15, 0xe6}},
        {{0xe7, 0x18, 0x19, 0x1a, 0x1b}, {0x1c, 0x1d, 0x1e, 0x1f, 0x20}},
        {{0x21, 0x22, 0x23, 0x24, 0x25}, {0x26, 0x27, 0x28, 0x29, 0x2a}},
        {{0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, {0x33, 0x34, 0x35, 0x36, 0x37}},
    }; // assume the record message is split into 4 fragments
    byte         *buf = NULL;
    word16        nbytes_encoded_not_encrypted = 0;
    word16        nbytes_sent = 0;
    word16        tmp = 0;
    tlsRespStatus status = TLS_RESP_OK;
    byte          flush_flg = 1;

    tls_session->flgs.hs_tx_encrypt = 1;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    // --------- send first fragment of a record message ---------
    tls_session->log.last_encode_result = TLS_RESP_REQ_MOREDATA;
    tls_session->curr_outmsg_start = TLS_RECORD_LAYER_HEADER_NBYTES + 1;
    tls_session->curr_outmsg_len = tls_session->outbuf.len * 3;
    tls_session->outlen_encoded = tls_session->outbuf.len;
    nbytes_encoded_not_encrypted = (tls_session->outlen_encoded - tls_session->curr_outmsg_start) %
                                   tls_session->sec.chosen_ciphersuite->tagSize;
    tls_session->outlen_encrypted = tls_session->outlen_encoded - nbytes_encoded_not_encrypted;
    tlsEncodeWord16(
        &expect_content[0][0][3], (tls_session->curr_outmsg_len - TLS_RECORD_LAYER_HEADER_NBYTES)
    );
    buf = tls_session->outbuf.data + tls_session->curr_outmsg_start;
    XMEMCPY(buf, &expect_content[0][0][0], TLS_RECORD_LAYER_HEADER_NBYTES);
    buf = tls_session->outbuf.data + tls_session->outlen_encrypted - TLS_RECORD_LAYER_HEADER_NBYTES;
    XMEMCPY(buf, &expect_content[0][1][0], TLS_RECORD_LAYER_HEADER_NBYTES);
    buf = tls_session->outbuf.data + tls_session->outlen_encrypted;
    XMEMCPY(buf, &expect_content[1][0][0], TLS_RECORD_LAYER_HEADER_NBYTES);
    nbytes_sent += tls_session->outlen_encrypted;
    status = tlsPktSendToPeer(tls_session, flush_flg);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(nbytes_encoded_not_encrypted, tls_session->outlen_encoded);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->outlen_encrypted);
    TEST_ASSERT_EQUAL_UINT8(2, tls_session->num_frags_out);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_FINAL_FRAG, tlsChkFragStateOutMsg(tls_session));
    buf = &mock_sys_pkt_write_content[0] + tls_session->curr_outmsg_start;
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_content[0][0][0], buf, TLS_RECORD_LAYER_HEADER_NBYTES);
    buf = &mock_sys_pkt_write_content[0] + tls_session->outbuf.len - nbytes_encoded_not_encrypted -
          TLS_RECORD_LAYER_HEADER_NBYTES;
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_content[0][1][0], buf, TLS_RECORD_LAYER_HEADER_NBYTES);
    buf = tls_session->outbuf.data;
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_content[1][0][0], buf, TLS_RECORD_LAYER_HEADER_NBYTES);

    // --------- send second fragment of a record message ---------
    tls_session->log.last_encode_result = TLS_RESP_REQ_MOREDATA;
    tls_session->curr_outmsg_start = 0;
    tls_session->outlen_encoded = tls_session->outbuf.len;
    nbytes_encoded_not_encrypted = (tls_session->outlen_encoded - tls_session->curr_outmsg_start) %
                                   tls_session->sec.chosen_ciphersuite->tagSize;
    tls_session->outlen_encrypted = tls_session->outlen_encoded - nbytes_encoded_not_encrypted;
    buf = tls_session->outbuf.data + tls_session->outlen_encrypted - TLS_RECORD_LAYER_HEADER_NBYTES;
    XMEMCPY(buf, &expect_content[1][1][0], TLS_RECORD_LAYER_HEADER_NBYTES);
    nbytes_sent += tls_session->outlen_encrypted;
    status = tlsPktSendToPeer(tls_session, flush_flg);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, nbytes_encoded_not_encrypted);
    TEST_ASSERT_EQUAL_UINT16(nbytes_encoded_not_encrypted, tls_session->outlen_encoded);
    TEST_ASSERT_EQUAL_UINT8(3, tls_session->num_frags_out);
    buf = &mock_sys_pkt_write_content[0] + tls_session->curr_outmsg_start;
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_content[1][0][0], buf, TLS_RECORD_LAYER_HEADER_NBYTES);
    buf = &mock_sys_pkt_write_content[0] + tls_session->outbuf.len - nbytes_encoded_not_encrypted -
          TLS_RECORD_LAYER_HEADER_NBYTES;
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_content[1][1][0], buf, TLS_RECORD_LAYER_HEADER_NBYTES);

    // --------- send third fragment of a record message ---------
    tls_session->log.last_encode_result = TLS_RESP_REQ_MOREDATA;
    tls_session->curr_outmsg_start = 0;
    // All of data (excluding 1-byte content type and variable size of authentication tag in the end
    // of record message) should be fit into current fragment, BUT cannot copy the entire
    // authentication tag to current fragment. (which means auth tag cnanot be sent in current
    // flight)
    tmp = tls_session->curr_outmsg_len - nbytes_sent;
    TEST_ASSERT_GREATER_THAN_UINT16(tls_session->outbuf.len, tmp);
    tmp -= (1 + tls_session->sec.chosen_ciphersuite->tagSize);
    TEST_ASSERT_LESS_THAN_UINT16(tls_session->outbuf.len, tmp);
    tls_session->outlen_encoded = tmp;
    nbytes_encoded_not_encrypted = (tls_session->outlen_encoded - tls_session->curr_outmsg_start) %
                                   tls_session->sec.chosen_ciphersuite->tagSize;
    tls_session->outlen_encrypted = tls_session->outlen_encoded - nbytes_encoded_not_encrypted;
    buf = tls_session->outbuf.data + tls_session->curr_outmsg_start;
    XMEMCPY(buf, &expect_content[2][0][0], TLS_RECORD_LAYER_HEADER_NBYTES);
    buf = tls_session->outbuf.data + tls_session->outlen_encrypted - TLS_RECORD_LAYER_HEADER_NBYTES;
    XMEMCPY(buf, &expect_content[2][1][0], TLS_RECORD_LAYER_HEADER_NBYTES);
    buf += TLS_RECORD_LAYER_HEADER_NBYTES;
    tmp = XMIN(
        TLS_RECORD_LAYER_HEADER_NBYTES, (tls_session->outbuf.len - tls_session->outlen_encoded)
    );
    XMEMCPY(buf, &expect_content[3][0][0], tmp);

    nbytes_sent += tls_session->outlen_encrypted;
    tmp = tls_session->outlen_encrypted; // for later check
    status = tlsPktSendToPeer(tls_session, flush_flg);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_GREATER_THAN_UINT16(0, nbytes_encoded_not_encrypted);
    TEST_ASSERT_EQUAL_UINT16(nbytes_encoded_not_encrypted, tls_session->outlen_encoded);
    TEST_ASSERT_EQUAL_UINT8(4, tls_session->num_frags_out);
    buf = &mock_sys_pkt_write_content[0] + tls_session->curr_outmsg_start;
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_content[2][0][0], buf, TLS_RECORD_LAYER_HEADER_NBYTES);
    buf = &mock_sys_pkt_write_content[0] + tmp - TLS_RECORD_LAYER_HEADER_NBYTES;
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_content[2][1][0], buf, TLS_RECORD_LAYER_HEADER_NBYTES);
    buf = tls_session->outbuf.data;
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_content[3][0][0], buf, TLS_RECORD_LAYER_HEADER_NBYTES);

    // --------- send fourth fragment of a record message ---------
    tls_session->log.last_encode_result = TLS_RESP_OK;
    tls_session->curr_outmsg_start = 0;
    tmp = tls_session->curr_outmsg_len - nbytes_sent;
    TEST_ASSERT_EQUAL_UINT16(
        (nbytes_encoded_not_encrypted + 1 + tls_session->sec.chosen_ciphersuite->tagSize), tmp
    );
    tls_session->outlen_encoded = tmp;
    nbytes_encoded_not_encrypted = 0;
    tls_session->outlen_encrypted = tmp;
    buf = tls_session->outbuf.data + tls_session->outlen_encrypted - TLS_RECORD_LAYER_HEADER_NBYTES;
    XMEMCPY(buf, &expect_content[3][1][0], TLS_RECORD_LAYER_HEADER_NBYTES);
    nbytes_sent += tls_session->outlen_encrypted;
    tmp = tls_session->outlen_encrypted; // for later check
    status = tlsPktSendToPeer(tls_session, flush_flg);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->outlen_encoded);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->num_frags_out);
    buf = &mock_sys_pkt_write_content[0] + tls_session->curr_outmsg_start;
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_content[3][0][0], buf, TLS_RECORD_LAYER_HEADER_NBYTES);
    buf = &mock_sys_pkt_write_content[0] + tmp - TLS_RECORD_LAYER_HEADER_NBYTES;
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_content[3][1][0], buf, TLS_RECORD_LAYER_HEADER_NBYTES);
    // #bytes sent out must be equal to total #bytes of the record message
    TEST_ASSERT_EQUAL_UINT16(tls_session->curr_outmsg_len, nbytes_sent);
} // end of TEST(tlsPktSendToPeer, one_msg_multi_fragments)

TEST(tlsPktSendToPeer, multi_msgs_one_fragment) {
    byte record_header[TLS_RECORD_LAYER_HEADER_NBYTES] = {
        TLS_CONTENT_TYPE_APP_DATA, 0x3, 0x3, 0x0, 0x0,
    };
    byte expect_lastbyte_msgs[0x20] = {
        0,
    };
    byte actual_lastbyte_msgs[0x20] = {
        0,
    };
    byte         *buf = NULL;
    word16        nbytes_encoded_not_encrypted = 0;
    word16        nbytes_per_record_msg = 0;
    word16        nbytes_msg_body = 0;
    word16        nbytes_sent_in_splitting_msg = 0;
    word16        expect_num_msgs = 0;
    word16        actual_num_msgs = 0;
    word16        idx = 0, jdx = 0;
    int           tmp = 0;
    tlsRespStatus status = TLS_RESP_OK;
    byte          flush_flg = 0;

    tls_session->flgs.hs_tx_encrypt = 1;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    // try testing with different length of message content
    for (nbytes_msg_body = 2; nbytes_msg_body < (tls_session->sec.chosen_ciphersuite->tagSize << 1);
         nbytes_msg_body++) { // start of loop nbytes_msg_body
        nbytes_per_record_msg = nbytes_msg_body + 1 + tls_session->sec.chosen_ciphersuite->tagSize;
        tlsEncodeWord16(&record_header[3], nbytes_per_record_msg);
        nbytes_per_record_msg += TLS_RECORD_LAYER_HEADER_NBYTES;
        tls_session->outlen_encoded = 0;
        tls_session->outlen_encrypted = 0;
        expect_num_msgs = 0;
        actual_num_msgs = 0;
        XMEMSET(&mock_sys_pkt_write_content[0], 0x00, MAX_RAWBYTE_BUF_SZ);

        do { // cramming as many record messages as it could in the outbuf
            tls_session->curr_outmsg_start = tls_session->outlen_encoded;
            tls_session->curr_outmsg_len = nbytes_per_record_msg;
            // copy new record message to outbuf
            buf = tls_session->outbuf.data + tls_session->curr_outmsg_start;
            XMEMCPY(buf, &record_header[0], TLS_RECORD_LAYER_HEADER_NBYTES);
            buf += TLS_RECORD_LAYER_HEADER_NBYTES;
            tls_session->outlen_encoded += TLS_RECORD_LAYER_HEADER_NBYTES;
            expect_num_msgs++;
            for (idx = 0;
                 idx < nbytes_msg_body && tls_session->outlen_encoded < tls_session->outbuf.len;
                 idx++) {
                *buf++ = jdx++ & 0xff;
                tls_session->outlen_encoded++;
            } // end of for loop
            tmp = tls_session->outbuf.len - tls_session->outlen_encoded - 1 -
                  tls_session->sec.chosen_ciphersuite->tagSize;
            if (tmp >= 0) {
                for (idx = 0; idx < (1 + tls_session->sec.chosen_ciphersuite->tagSize); idx++) {
                    *buf++ = jdx++ & 0xff;
                } // end of for loop
                expect_lastbyte_msgs[expect_num_msgs - 1] = buf[-1];
                tls_session->outlen_encoded += 1 + tls_session->sec.chosen_ciphersuite->tagSize;
                tls_session->log.last_encode_result = TLS_RESP_OK;
                nbytes_encoded_not_encrypted = 0;
            } else {
                tls_session->log.last_encode_result = TLS_RESP_REQ_MOREDATA;
                nbytes_sent_in_splitting_msg =
                    tls_session->outlen_encoded - tls_session->curr_outmsg_start;
                nbytes_encoded_not_encrypted =
                    (nbytes_sent_in_splitting_msg + TLS_RECORD_LAYER_HEADER_NBYTES) %
                    tls_session->sec.chosen_ciphersuite->tagSize;
            }
            tls_session->outlen_encrypted =
                tls_session->outlen_encoded - nbytes_encoded_not_encrypted;
            status = tlsPktSendToPeer(tls_session, flush_flg);
        } while (status == TLS_RESP_REQ_MOREDATA);
        // start checking the first sent fragment
        TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
        if (tls_session->num_frags_out > 0) {
            TEST_ASSERT_EQUAL_UINT8(2, tls_session->num_frags_out);
        }
        TEST_ASSERT_EQUAL_UINT16(nbytes_encoded_not_encrypted, tls_session->outlen_encoded);
        if (nbytes_encoded_not_encrypted > 0) {
            TEST_ASSERT_EQUAL_UINT8(
                ((jdx - 1) % 0xff), tls_session->outbuf.data[nbytes_encoded_not_encrypted - 1]
            );
        }
        buf = &mock_sys_pkt_write_content[0];
        for (idx = 0; idx < MAX_RAWBYTE_BUF_SZ; idx += nbytes_per_record_msg) {
            if (XSTRNCMP(
                    (const char *)&record_header[0], (const char *)buf,
                    TLS_RECORD_LAYER_HEADER_NBYTES
                ) == 0) {
                buf += nbytes_per_record_msg;
                actual_lastbyte_msgs[actual_num_msgs++] = buf[-1];
            } else {
                break;
            }
        } // end of for loop
        TEST_ASSERT_EQUAL_UINT16(expect_num_msgs, actual_num_msgs);
        TEST_ASSERT_EQUAL_STRING_LEN(
            &expect_lastbyte_msgs[0], &actual_lastbyte_msgs[0], (expect_num_msgs - 1)
        );

        // send rest of bytes of the splitting record message
        buf = &tls_session->outbuf.data[nbytes_encoded_not_encrypted];
        for (idx = nbytes_encoded_not_encrypted;
             idx < (nbytes_per_record_msg - nbytes_sent_in_splitting_msg); idx++) {
            *buf++ = jdx++ & 0xff;
            tls_session->outlen_encoded++;
        } // end of for loop
        expect_lastbyte_msgs[expect_num_msgs - 1] = buf[-1];
        tls_session->log.last_encode_result = TLS_RESP_OK;
        tls_session->outlen_encrypted = tls_session->outlen_encoded;
        flush_flg = 1;
        status = tlsPktSendToPeer(tls_session, flush_flg);
        TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
        TEST_ASSERT_EQUAL_UINT8(0, tls_session->num_frags_out);
        TEST_ASSERT_EQUAL_UINT16(0, tls_session->outlen_encoded);

        buf = &mock_sys_pkt_write_content[0];
        buf += nbytes_per_record_msg - nbytes_sent_in_splitting_msg;
        actual_lastbyte_msgs[actual_num_msgs - 1] = buf[-1];
        TEST_ASSERT_EQUAL_UINT16(expect_num_msgs, actual_num_msgs);
        TEST_ASSERT_EQUAL_STRING_LEN(
            &expect_lastbyte_msgs[0], &actual_lastbyte_msgs[0], expect_num_msgs
        );
    } // end of loop nbytes_msg_body
} // end of TEST(tlsPktSendToPeer, multi_msgs_one_fragment)

TEST(tlsPktRecvFromPeer, err_chk) {
    byte record_header[TLS_RECORD_LAYER_HEADER_NBYTES] = {
        TLS_CONTENT_TYPE_APP_DATA, 0x3, 0x3, 0x0, 0x0,
    };
    word16        nbytes_per_record_msg = 0;
    tlsRespStatus status = TLS_RESP_OK;

    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];

    mock_sys_pkt_read_return_val = MQTT_RESP_TIMEOUT;
    status = tlsPktRecvFromPeer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_TIMEOUT, status);

    mock_sys_pkt_read_return_val = TLS_RECORD_LAYER_HEADER_NBYTES + 1;
    status = tlsPktRecvFromPeer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_MALFORMED_PKT, status);

    mock_sys_pkt_read_return_val = MQTT_RESP_OK;
    record_header[0] = TLS_CONTENT_TYPE_INVALID; // give invalid record type
    XMEMCPY(&mock_sys_pkt_read_content[0], &record_header[0], TLS_RECORD_LAYER_HEADER_NBYTES);
    mock_sys_pkt_read_ptr = 0;
    status = tlsPktRecvFromPeer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_MALFORMED_PKT, status);

    mock_sys_pkt_read_return_val = MQTT_RESP_OK;
    record_header[0] = TLS_CONTENT_TYPE_APP_DATA;
    nbytes_per_record_msg = TLS_RECORD_LAYER_HEADER_NBYTES + TLS_MAX_BYTES_RECORD_LAYER_PKT +
                            1; // message size that exceeds limit
    tlsEncodeWord16(&record_header[3], (nbytes_per_record_msg - TLS_RECORD_LAYER_HEADER_NBYTES));
    XMEMCPY(&mock_sys_pkt_read_content[0], &record_header[0], TLS_RECORD_LAYER_HEADER_NBYTES);
    mock_sys_pkt_read_ptr = 0;
    status = tlsPktRecvFromPeer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_EXCEED_MAX_REC_SZ, status);
} // end of TEST(tlsPktRecvFromPeer, err_chk)

TEST(tlsPktRecvFromPeer, one_msg_one_fragment) {
    byte record_header[TLS_RECORD_LAYER_HEADER_NBYTES] = {
        TLS_CONTENT_TYPE_APP_DATA, 0x3, 0x3, 0x0, 0x0,
    };
    byte expect_lastbyte_msgs[5] = {
        0,
    };
    byte actual_lastbyte_msgs[5] = {
        0,
    };
    word16        nbytes_per_record_msg = 0;
    word16        idx = 0, jdx = 1;
    tlsRespStatus status = TLS_RESP_OK;

    tls_session->flgs.hs_rx_encrypt = 0;

    mock_sys_pkt_read_return_val = MQTT_RESP_OK;
    nbytes_per_record_msg = tls_session->inbuf.len;
    tlsEncodeWord16(&record_header[3], (nbytes_per_record_msg - TLS_RECORD_LAYER_HEADER_NBYTES));
    XMEMCPY(&mock_sys_pkt_read_content[0], &record_header[0], TLS_RECORD_LAYER_HEADER_NBYTES);
    for (idx = TLS_RECORD_LAYER_HEADER_NBYTES; idx < MAX_RAWBYTE_BUF_SZ; idx++) {
        mock_sys_pkt_read_content[idx] = jdx++;
    }
    mock_sys_pkt_read_ptr = 0;
    XMEMCPY(&expect_lastbyte_msgs[0], &mock_sys_pkt_read_content[MAX_RAWBYTE_BUF_SZ - 5], 5);
    status = tlsPktRecvFromPeer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->num_frags_in);
    TEST_ASSERT_EQUAL_UINT8(tls_session->num_frags_in, tls_session->remain_frags_in);
    status = tlsChkFragStateInMsg(tls_session);
    TEST_ASSERT_EQUAL_INT((TLS_RESP_FIRST_FRAG | TLS_RESP_FINAL_FRAG), status);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->inlen_total);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->inlen_unprocessed);
    TEST_ASSERT_EQUAL_UINT16(nbytes_per_record_msg, tls_session->inlen_decrypted);
    XMEMCPY(&actual_lastbyte_msgs[0], &tls_session->inbuf.data[MAX_RAWBYTE_BUF_SZ - 5], 5);
    TEST_ASSERT_EQUAL_STRING_LEN(&expect_lastbyte_msgs[0], &actual_lastbyte_msgs[0], 5);

    tlsDecrementFragNumInMsg(tls_session);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->num_frags_in);
} // end of TEST(tlsPktRecvFromPeer, one_msg_one_fragment)

TEST(tlsPktRecvFromPeer, one_msg_multi_fragments) {
    byte         *record_msg = NULL;
    byte         *buf = NULL;
    word16        nbytes_per_record_msg = 0;
    word16        nbytes_cpy = 0;
    word16        nbytes_recved = 0;
    word16        nbytes_recv_not_decrypted = 0;
    word16        idx = 0;
    tlsRespStatus status = TLS_RESP_OK;

    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    // the record message at here is supposed to split into 4 fragments
    nbytes_per_record_msg =
        tls_session->inbuf.len * 3 - (tls_session->sec.chosen_ciphersuite->tagSize) - 1;
    record_msg = XMALLOC(nbytes_per_record_msg);
    buf = record_msg;
    *buf++ = TLS_CONTENT_TYPE_APP_DATA;
    buf += tlsEncodeWord16(buf, TLS_VERSION_ENCODE_1_2);
    buf += tlsEncodeWord16(buf, nbytes_per_record_msg - TLS_RECORD_LAYER_HEADER_NBYTES);
    for (idx = TLS_RECORD_LAYER_HEADER_NBYTES; idx < nbytes_per_record_msg; idx++) {
        *buf++ = (idx + 3) % 0xff;
    }
    tls_session->inlen_unprocessed = TLS_RECORD_LAYER_HEADER_NBYTES;
    nbytes_recved = 0;
    idx = 1; // used to represent expected number of fragments
    do { // -------------- receive / check all the fragments of the record message --------------
        if ((tls_session->inlen_total > 0) &&
            (tls_session->inlen_total < tls_session->sec.chosen_ciphersuite->tagSize)) {
            // part of auth tag is already copied in current fragment, but there's still part of it
            // in the final fragment which will be loaded later
            nbytes_recv_not_decrypted =
                tls_session->sec.chosen_ciphersuite->tagSize - tls_session->inlen_total;
        } else {
            nbytes_recv_not_decrypted =
                (tls_session->inlen_unprocessed - TLS_RECORD_LAYER_HEADER_NBYTES) %
                tls_session->sec.chosen_ciphersuite->tagSize;
            idx++;
        }
        tls_session->inlen_decrypted = tls_session->inlen_unprocessed - nbytes_recv_not_decrypted;
        tls_session->inlen_unprocessed = nbytes_recv_not_decrypted;

        nbytes_cpy = XMIN(
            tls_session->inbuf.len - nbytes_recv_not_decrypted,
            nbytes_per_record_msg - nbytes_recved
        );
        XMEMCPY(&mock_sys_pkt_read_content[0], &record_msg[nbytes_recved], nbytes_cpy);
        nbytes_recved += nbytes_cpy;
        mock_sys_pkt_read_ptr = 0;
        status = tlsPktRecvFromPeer(tls_session);
        TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
        TEST_ASSERT_EQUAL_UINT8(idx, tls_session->num_frags_in);
        TEST_ASSERT_EQUAL_UINT16(nbytes_per_record_msg - nbytes_recved, tls_session->inlen_total);
        if (tls_session->inlen_total > 0) {
            TEST_ASSERT_EQUAL_UINT16(tls_session->inbuf.len, tls_session->inlen_unprocessed);
        } else {
            TEST_ASSERT_EQUAL_UINT16(
                tls_session->sec.chosen_ciphersuite->tagSize, tls_session->inlen_unprocessed
            );
        }
        TEST_ASSERT_EQUAL_STRING_LEN(
            &mock_sys_pkt_read_content[0], &tls_session->inbuf.data[nbytes_recv_not_decrypted],
            nbytes_cpy
        );
        if (nbytes_recv_not_decrypted > 0) {
            buf = &tls_session->inbuf.data[nbytes_recv_not_decrypted];
            TEST_ASSERT_EQUAL_UINT8(buf[0], (buf[-1] + 1));
        }
        tlsDecrementFragNumInMsg(tls_session);
    } while (tlsChkFragStateInMsg(tls_session) != TLS_RESP_REQ_REINIT);

    TEST_ASSERT_EQUAL_UINT16(nbytes_per_record_msg, nbytes_recved);
    XMEMFREE(record_msg);
} // end of TEST(tlsPktRecvFromPeer, one_msg_multi_fragments)

static void RunAllTestGroups(void) {
    tls_session = (tlsSession_t *)XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->inbuf.len = MAX_RAWBYTE_BUF_SZ;
    tls_session->inbuf.data = (byte *)XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);
    tls_session->outbuf.len = MAX_RAWBYTE_BUF_SZ;
    tls_session->outbuf.data = (byte *)XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);

    RUN_TEST_GROUP(tlsPktSendToPeer);
    RUN_TEST_GROUP(tlsPktRecvFromPeer);

    XMEMFREE(tls_session->inbuf.data);
    XMEMFREE(tls_session->outbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups

int main(int argc, const char *argv[]) {
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main
