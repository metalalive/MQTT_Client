#include "mqtt_include.h"

static tlsSession_t *tls_session;
static word32        mock_tls_encode_clienthello_total_sz;
static word32        mock_tls_encode_cert_total_sz;
static word32        mock_tls_encode_cert_verify_total_sz;
static word32        mock_tls_encode_finished_total_sz;

static tlsRespStatus mock_pkt_send_return_val;
static tlsRespStatus mock_pkt_recv_return_val;

static word16        mock_tls_recv_serverhello_total_sz;
static word16        mock_tls_recv_encrypt_extension_total_sz;
static word16        mock_tls_recv_cert_chain_total_sz;
static word16        mock_tls_recv_cert_req_total_sz;
static word16        mock_tls_recv_cert_verify_total_sz;
static word16        mock_tls_recv_finished_total_sz;
static word16        mock_tls_recv_new_session_ticket_total_sz;
static tlsRespStatus mock_decode_serverhello_return_val;
static tlsRespStatus mock_decode_encrypt_extension_return_val;
static tlsRespStatus mock_decode_cert_req_return_val;
static tlsRespStatus mock_decode_cert_chain_return_val;
static tlsRespStatus mock_decode_cert_verify_return_val;
static tlsRespStatus mock_decode_finished_return_val;
static tlsRespStatus mock_decode_new_session_ticket_return_val;

static byte mock_enable_client_cert_verify;
static byte mock_enable_server_cert_verify;

static const tlsNamedGrp mock_tls_supported_named_groups[] = {
    TLS_NAMED_GRP_SECP256R1,
    TLS_NAMED_GRP_X25519,
};

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

static const tlsCipherSpec_t mock_tls_supported_cipher_suites[] = {
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
};

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

void tlsInitFragNumOutMsg(tlsSession_t *session) {
    if (session != NULL) {
        session->num_frags_out = 1;
        session->remain_frags_out = 1;
    }
} // end of tlsInitFragNumOutMsg

void tlsIncrementFragNumOutMsg(tlsSession_t *session) {
    if (session != NULL) {
        session->num_frags_out += 1;
        session->remain_frags_out += 1;
    }
} // end of tlsIncrementFragNumOutMsg

void tlsDecrementFragNumOutMsg(tlsSession_t *session) {
    if ((session != NULL) && (session->remain_frags_out > 0)) {
        session->remain_frags_out -= 1;
        if (session->remain_frags_out == 0) {
            session->num_frags_out = 0;
        }
    }
} // end of tlsDecrementFragNumOutMsg

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

void tlsInitFragNumInMsg(tlsSession_t *session) {
    if (session != NULL) {
        session->num_frags_in = 1;
        session->remain_frags_in = 1;
    }
} // end of tlsInitFragNumInMsg

void tlsIncrementFragNumInMsg(tlsSession_t *session) {
    if (session != NULL) {
        session->num_frags_in += 1;
        session->remain_frags_in += 1;
    }
} // end of tlsIncrementFragNumInMsg

void tlsDecrementFragNumInMsg(tlsSession_t *session) {
    if ((session != NULL) && (session->remain_frags_in > 0)) {
        session->remain_frags_in -= 1;
        if (session->remain_frags_in == 0) {
            session->num_frags_in = 0;
        }
    }
} // end of tlsDecrementFragNumInMsg

byte tlsGetSupportedKeyExGrpSize(void) {
    byte out = XGETARRAYSIZE(mock_tls_supported_named_groups);
    return out;
} // end of tlsGetSupportedKeyExGrpSize

tlsRespStatus tlsEncodeRecordLayer(tlsSession_t *session) {
    tlsRespStatus status = TLS_RESP_OK;
    tlsRespStatus frag_status = tlsChkFragStateOutMsg(session);
    if (frag_status == TLS_RESP_REQ_REINIT) { // runs only for the first fragment
        switch (tlsGetHSexpectedState(session)) {
        case TLS_HS_TYPE_CLIENT_HELLO:
            session->nbytes.remaining_to_send = mock_tls_encode_clienthello_total_sz;
            break;
        case TLS_HS_TYPE_CERTIFICATE:
            session->nbytes.remaining_to_send = mock_tls_encode_cert_total_sz;
            break;
        case TLS_HS_TYPE_CERTIFICATE_VERIFY:
            session->nbytes.remaining_to_send = mock_tls_encode_cert_verify_total_sz;
            break;
        case TLS_HS_TYPE_FINISHED:
            session->nbytes.remaining_to_send = mock_tls_encode_finished_total_sz;
            break;
        case TLS_HS_TYPE_END_OF_EARLY_DATA:
        default:
            session->nbytes.remaining_to_send = 0;
            status = TLS_RESP_ERR_NOT_SUPPORT;
            break;
        } // end of switch-case statement
    }
    if (session->nbytes.remaining_to_send > 0) {
        word16 rdy_cpy_sz = XMIN(session->outbuf.len, session->nbytes.remaining_to_send);
        session->nbytes.remaining_to_send -= rdy_cpy_sz;
        if (session->nbytes.remaining_to_send > 0) {
            status = TLS_RESP_REQ_MOREDATA;
        } else { // for last fragment
            status = TLS_RESP_OK;
        }
    }
    session->log.last_encode_result = status;
    return status;
} // end of tlsEncodeRecordLayer

tlsRespStatus tlsPktSendToPeer(tlsSession_t *session, byte flush_flg) {
    if (tlsChkFragStateOutMsg(session) == TLS_RESP_REQ_REINIT) {
        tlsInitFragNumOutMsg(session);
    }
    if (session->log.last_encode_result == TLS_RESP_REQ_MOREDATA) {
        tlsIncrementFragNumOutMsg(session);
    } // implicit meaning : not the final fragment
    // assume packet transmission at low-level system works well
    tlsDecrementFragNumOutMsg(session);
    return mock_pkt_send_return_val;
}

tlsRespStatus tlsPktRecvFromPeer(tlsSession_t *session) {
    tlsRespStatus status = mock_pkt_recv_return_val;
    if (tlsChkFragStateInMsg(session) == TLS_RESP_REQ_REINIT) {
        switch (tlsGetHSexpectedState(session)) {
        case TLS_HS_TYPE_SERVER_HELLO:
            session->inlen_total = mock_tls_recv_serverhello_total_sz;
            break;
        case TLS_HS_TYPE_ENCRYPTED_EXTENSIONS:
            session->inlen_total = mock_tls_recv_encrypt_extension_total_sz;
            break;
        case TLS_HS_TYPE_CERTIFICATE_REQUEST:
            session->inlen_total = mock_tls_recv_cert_req_total_sz;
            break;
        case TLS_HS_TYPE_CERTIFICATE:
            session->inlen_total = mock_tls_recv_cert_chain_total_sz;
            break;
        case TLS_HS_TYPE_CERTIFICATE_VERIFY:
            session->inlen_total = mock_tls_recv_cert_verify_total_sz;
            break;
        case TLS_HS_TYPE_FINISHED:
            session->inlen_total = mock_tls_recv_finished_total_sz;
            break;
        case TLS_HS_TYPE_NEW_SESSION_TICKET:
            session->inlen_total = mock_tls_recv_new_session_ticket_total_sz;
            break;
        case TLS_HS_TYPE_KEY_UPDATE:
        default:
            session->inlen_total = 0;
            status = TLS_RESP_REQ_ALERT;
            break;
        } // end of switch case statement
        tlsInitFragNumInMsg(session);
    }
    if (session->inlen_total > session->inbuf.len) {
        tlsIncrementFragNumInMsg(session);
        session->inlen_total -= session->inbuf.len;
    } else {
        session->inlen_total = 0;
    }
    return status;
} // end of tlsPktRecvFromPeer

tlsRespStatus tlsDecodeRecordLayer(tlsSession_t *session) {
    tlsRespStatus status = tlsChkFragStateInMsg(session);
    if ((status & TLS_RESP_FIRST_FRAG) == TLS_RESP_FIRST_FRAG) {
        if (tlsGetHSexpectedState(session) == TLS_HS_TYPE_CERTIFICATE_REQUEST) {
            if (mock_enable_client_cert_verify == 0) {
                session->flgs.omit_client_cert_chk = 1;
                if (mock_enable_server_cert_verify == 0) {
                    session->flgs.omit_server_cert_chk = 1;
                }
                tlsHSstateTransition(session);
            }
        }
        switch (tlsGetHSexpectedState(session)) {
        case TLS_HS_TYPE_SERVER_HELLO:
            session->flgs.hello_retry = 0;
            session->sec.chosen_ciphersuite = &mock_tls_supported_cipher_suites[0];
            status = mock_decode_serverhello_return_val;
            if (status == TLS_RESP_OK) {
                session->flgs.hs_rx_encrypt = 1;
            }
            break;
        case TLS_HS_TYPE_ENCRYPTED_EXTENSIONS:
            status = mock_decode_encrypt_extension_return_val;
            break;
        case TLS_HS_TYPE_CERTIFICATE_REQUEST:
            session->tmpbuf.cert_req_ctx.data = XMALLOC(sizeof(byte) * 0x30);
            status = mock_decode_cert_req_return_val;
            break;
        case TLS_HS_TYPE_CERTIFICATE:
            status = mock_decode_cert_chain_return_val;
            break;
        case TLS_HS_TYPE_CERTIFICATE_VERIFY:
            status = mock_decode_cert_verify_return_val;
            break;
        case TLS_HS_TYPE_FINISHED:
            status = mock_decode_finished_return_val;
            break;
        case TLS_HS_TYPE_NEW_SESSION_TICKET:
            status = mock_decode_new_session_ticket_return_val;
            break;
        case TLS_HS_TYPE_KEY_UPDATE:
        default:
            status = TLS_RESP_REQ_ALERT;
            break;
        } // end of switch case statement
    }
    return status;
} // end of tlsDecodeRecordLayer

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

tlsRespStatus tlsTranscrptHashInit(tlsSecurityElements_t *sec) { return TLS_RESP_OK; }

tlsRespStatus tlsTranscrptHashReInit(tlsSecurityElements_t *sec) { return TLS_RESP_OK; }

tlsRespStatus tlsTranscrptHashHSmsgUpdate(tlsSession_t *session, tlsOpaque16b_t *buf) {
    return TLS_RESP_OK;
}

tlsRespStatus tlsTranscrptHashDeInit(tlsSecurityElements_t *sec) { return TLS_RESP_OK; }

tlsRespStatus tlsTransHashCleanUnsuedHashHandler(tlsSecurityElements_t *sec) { return TLS_RESP_OK; }

tlsRespStatus tlsActivateReadKey(tlsSecurityElements_t *sec) { return TLS_RESP_OK; }

tlsRespStatus tlsActivateWriteKey(tlsSecurityElements_t *sec) { return TLS_RESP_OK; }

void tlsFreeEphemeralKeyPairs(tlsKeyEx_t *keyexp) { return; }

tlsRespStatus tlsFreeEphemeralKeyPairByGrp(void *keyout, tlsNamedGrp grp_id) { return TLS_RESP_OK; }

tlsRespStatus tlsGenEarlySecret(const tlsCipherSpec_t *cs, tlsPSK_t *pskin, tlsOpaque8b_t *out) {
    return TLS_RESP_OK;
}

tlsRespStatus tlsDeriveHStrafficSecret(tlsSession_t *session, tlsOpaque8b_t *earlysecret_in) {
    return TLS_RESP_OK;
}

tlsRespStatus tlsDeriveAPPtrafficSecret(tlsSession_t *session) { return TLS_RESP_OK; }

tlsRespStatus tlsDeriveTraffickey(
    tlsSecurityElements_t *sec, tlsOpaque8b_t *in_rd_secret, tlsOpaque8b_t *in_wr_secret
) {
    return TLS_RESP_OK;
}

void tlsFreeCertChain(tlsCert_t *in, tlsFreeCertEntryFlag ctrl_flg) { return; }

tlsRespStatus tlsDecryptRecordMsg(tlsSession_t *session) { return TLS_RESP_OK; }

tlsRespStatus tlsEncryptRecordMsg(tlsSession_t *session) { return TLS_RESP_OK; }

// -----------------------------------------------------------------------------------

TEST_GROUP(tlsHSstateTransition);
TEST_GROUP(tlsClientStartHandshake);

TEST_GROUP_RUNNER(tlsHSstateTransition) {
    RUN_TEST_CASE(tlsHSstateTransition, init_clienthello);
    RUN_TEST_CASE(tlsHSstateTransition, hello_entry_req);
    RUN_TEST_CASE(tlsHSstateTransition, serverhello);
    RUN_TEST_CASE(tlsHSstateTransition, skip_server_cert_chk);
    RUN_TEST_CASE(tlsHSstateTransition, no_client_cert_req_verify_server_cert);
    RUN_TEST_CASE(tlsHSstateTransition, client_cert_req);
    RUN_TEST_CASE(tlsHSstateTransition, server_finish_send_client_cert);
    RUN_TEST_CASE(tlsHSstateTransition, server_finish_client_finish);
    RUN_TEST_CASE(tlsHSstateTransition, client_finish_key_update);
    RUN_TEST_CASE(tlsHSstateTransition, client_finish_new_session_ticket);
}

TEST_GROUP_RUNNER(tlsClientStartHandshake) {
    RUN_TEST_CASE(tlsClientStartHandshake, hello_err);
    RUN_TEST_CASE(tlsClientStartHandshake, encrypt_extension_err);
    RUN_TEST_CASE(tlsClientStartHandshake, cert_req__server_cert_auth_fail);
    RUN_TEST_CASE(tlsClientStartHandshake, cert_req__client_finish);
    RUN_TEST_CASE(tlsClientStartHandshake, server_cert__client_finish);
    RUN_TEST_CASE(tlsClientStartHandshake, skip_cert_verify_client_finish);
}

TEST_SETUP(tlsHSstateTransition) {}

TEST_SETUP(tlsClientStartHandshake) {
    tls_session->hs_state = 0;
    tls_session->flgs.hs_rx_encrypt = 0;
    tls_session->flgs.hs_tx_encrypt = 0;
    tls_session->flgs.omit_client_cert_chk = 0;
    tls_session->flgs.omit_server_cert_chk = 0;
    tls_session->flgs.hs_server_finish = 0;
    tls_session->flgs.hs_client_finish = 0;
    tls_session->sec.chosen_ciphersuite = NULL;
}

TEST_TEAR_DOWN(tlsHSstateTransition) {}

TEST_TEAR_DOWN(tlsClientStartHandshake) {}

TEST(tlsHSstateTransition, init_clienthello) {
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->hs_state);
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CLIENT_HELLO, tls_session->hs_state);
} // end of TEST(tlsHSstateTransition, init_clienthello)

TEST(tlsHSstateTransition, hello_entry_req) {
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CLIENT_HELLO, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->flgs.hello_retry);

    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_SERVER_HELLO, tls_session->hs_state);

    tls_session->flgs.hello_retry += 1;
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CLIENT_HELLO, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hello_retry);
} // end of TEST(tlsHSstateTransition, hello_entry_req)

TEST(tlsHSstateTransition, serverhello) {
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CLIENT_HELLO, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hello_retry);

    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_SERVER_HELLO, tls_session->hs_state);

    tls_session->flgs.hello_retry = 0;
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_ENCRYPTED_EXTENSIONS, tls_session->hs_state);
} // end of TEST(tlsHSstateTransition, serverhello)

TEST(
    tlsHSstateTransition, skip_server_cert_chk
) { // to skip verifying certification from server, this means client choose authentication via
    // pre-shared key and server can find out the corresponding pre-shared key.
    tls_session->hs_state = TLS_HS_TYPE_ENCRYPTED_EXTENSIONS;
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CERTIFICATE_REQUEST, tls_session->hs_state);
    tls_session->flgs.omit_client_cert_chk = 1;
    tls_session->flgs.omit_server_cert_chk = 1;
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_FINISHED, tls_session->hs_state);
} // end of TEST(tlsHSstateTransition, skip_server_cert_chk)

TEST(tlsHSstateTransition, no_client_cert_req_verify_server_cert) {
    tls_session->hs_state = TLS_HS_TYPE_ENCRYPTED_EXTENSIONS;
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CERTIFICATE_REQUEST, tls_session->hs_state);
    tls_session->flgs.omit_client_cert_chk = 1;
    tls_session->flgs.omit_server_cert_chk = 0;
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CERTIFICATE, tls_session->hs_state);
}

TEST(tlsHSstateTransition, client_cert_req) {
    tls_session->hs_state = TLS_HS_TYPE_ENCRYPTED_EXTENSIONS;
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CERTIFICATE_REQUEST, tls_session->hs_state);
    tls_session->flgs.omit_client_cert_chk = 0;
    tls_session->flgs.omit_server_cert_chk = 0;
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CERTIFICATE, tls_session->hs_state);
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CERTIFICATE_VERIFY, tls_session->hs_state);
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_FINISHED, tls_session->hs_state);
}

TEST(tlsHSstateTransition, server_finish_send_client_cert) {
    tls_session->hs_state = TLS_HS_TYPE_FINISHED;
    tls_session->flgs.hs_server_finish = 0;
    tls_session->flgs.hs_client_finish = 0;
    tls_session->flgs.omit_client_cert_chk = 0;
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CERTIFICATE, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hs_server_finish);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->flgs.hs_client_finish);
}

TEST(tlsHSstateTransition, server_finish_client_finish) {
    tls_session->hs_state = TLS_HS_TYPE_FINISHED;
    tls_session->flgs.hs_server_finish = 0;
    tls_session->flgs.hs_client_finish = 0;
    tls_session->flgs.omit_client_cert_chk = 1;
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_FINISHED, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hs_server_finish);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->flgs.hs_client_finish);

    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_FINISHED, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hs_server_finish);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hs_client_finish);

    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_FINISHED, tls_session->hs_state);
}

TEST(tlsHSstateTransition, client_finish_key_update) {
    tls_session->hs_state = TLS_HS_TYPE_FINISHED;
    tls_session->flgs.hs_server_finish = 1;
    tls_session->flgs.hs_client_finish = 1;
    tls_session->flgs.key_update = 1;

    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_KEY_UPDATE, tls_session->hs_state);
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_KEY_UPDATE, tls_session->hs_state);

    tls_session->flgs.key_update = 0;
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_KEY_UPDATE, tls_session->hs_state);
}

TEST(tlsHSstateTransition, client_finish_new_session_ticket) {
    tls_session->hs_state = TLS_HS_TYPE_FINISHED;
    tls_session->flgs.hs_server_finish = 1;
    tls_session->flgs.hs_client_finish = 1;
    tls_session->flgs.new_session_tkt = 1;

    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_FINISHED, tls_session->hs_state);
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_NEW_SESSION_TICKET, tls_session->hs_state);
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_NEW_SESSION_TICKET, tls_session->hs_state);

    tls_session->flgs.new_session_tkt = 0;
    tlsHSstateTransition(tls_session);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_NEW_SESSION_TICKET, tls_session->hs_state);
}

TEST(tlsClientStartHandshake, hello_err) {
    tlsRespStatus status = TLS_RESP_OK;

    mock_tls_encode_clienthello_total_sz = 2580;
    mock_pkt_send_return_val = TLS_RESP_ERR_SYS_SEND_PKT;
    status = tlsClientStartHandshake(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_SYS_SEND_PKT, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CLIENT_HELLO, tls_session->hs_state);

    mock_pkt_send_return_val = TLS_RESP_OK;
    mock_pkt_recv_return_val = TLS_RESP_TIMEOUT;
    tls_session->hs_state = 0;
    status = tlsClientStartHandshake(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_TIMEOUT, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_SERVER_HELLO, tls_session->hs_state);

    mock_pkt_send_return_val = TLS_RESP_OK;
    mock_pkt_recv_return_val = TLS_RESP_OK;
    mock_tls_recv_serverhello_total_sz = 102;
    mock_decode_serverhello_return_val = TLS_RESP_ERR_NO_KEYEX_MTHD_AVAIL;
    tls_session->hs_state = 0;
    status = tlsClientStartHandshake(tls_session);
    TEST_ASSERT_EQUAL_INT(mock_decode_serverhello_return_val, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_SERVER_HELLO, tls_session->hs_state);
}

TEST(tlsClientStartHandshake, encrypt_extension_err) {
    tlsRespStatus status = TLS_RESP_OK;

    mock_pkt_send_return_val = TLS_RESP_OK;
    mock_pkt_recv_return_val = TLS_RESP_OK;
    mock_tls_encode_clienthello_total_sz = 2570;
    mock_tls_recv_serverhello_total_sz = 88;
    mock_tls_recv_encrypt_extension_total_sz = 41;
    mock_decode_serverhello_return_val = TLS_RESP_OK;
    mock_decode_encrypt_extension_return_val = TLS_RESP_ERR_DECODE;
    status = tlsClientStartHandshake(tls_session);
    TEST_ASSERT_EQUAL_INT(mock_decode_encrypt_extension_return_val, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_ENCRYPTED_EXTENSIONS, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hs_rx_encrypt);

    mock_enable_client_cert_verify = 1;
    mock_enable_server_cert_verify = 1;
    mock_decode_encrypt_extension_return_val = TLS_RESP_OK;
    mock_tls_recv_cert_req_total_sz = 49;
    mock_decode_cert_req_return_val = TLS_RESP_MALFORMED_PKT;

    tls_session->flgs.hs_rx_encrypt = 0;
    tls_session->hs_state = 0;
    status = tlsClientStartHandshake(tls_session);
    TEST_ASSERT_EQUAL_INT(mock_decode_cert_req_return_val, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CERTIFICATE_REQUEST, tls_session->hs_state);
} // end of TEST(tlsClientStartHandshake, encrypt_extension_err)

TEST(tlsClientStartHandshake, cert_req__server_cert_auth_fail) {
    tlsRespStatus status = TLS_RESP_OK;

    mock_enable_client_cert_verify = 1;
    mock_enable_server_cert_verify = 1;
    mock_pkt_send_return_val = TLS_RESP_OK;
    mock_pkt_recv_return_val = TLS_RESP_OK;
    mock_tls_encode_clienthello_total_sz = 2570;
    mock_tls_recv_serverhello_total_sz = 128;
    mock_tls_recv_encrypt_extension_total_sz = 83;
    mock_tls_recv_cert_req_total_sz = 53;
    mock_tls_recv_cert_chain_total_sz = 2167;
    mock_decode_serverhello_return_val = TLS_RESP_OK;
    mock_decode_encrypt_extension_return_val = TLS_RESP_OK;
    mock_decode_cert_req_return_val = TLS_RESP_OK;
    mock_decode_cert_chain_return_val = TLS_RESP_CERT_AUTH_FAIL;

    status = tlsClientStartHandshake(tls_session);
    TEST_ASSERT_EQUAL_INT(mock_decode_cert_chain_return_val, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CERTIFICATE, tls_session->hs_state);
} // end of TEST(tlsClientStartHandshake, cert_req__server_cert_auth_fail)

TEST(tlsClientStartHandshake, cert_req__client_finish) {
    tlsRespStatus status = TLS_RESP_OK;

    mock_enable_client_cert_verify = 1;
    mock_enable_server_cert_verify = 1;

    mock_pkt_send_return_val = TLS_RESP_OK;
    mock_pkt_recv_return_val = TLS_RESP_OK;
    mock_tls_encode_clienthello_total_sz = 2570;
    mock_tls_recv_serverhello_total_sz = 128;
    mock_tls_recv_encrypt_extension_total_sz = 83;
    mock_tls_recv_cert_req_total_sz = 53;
    mock_tls_recv_cert_chain_total_sz = 2167;
    mock_tls_recv_cert_verify_total_sz = 292;
    mock_tls_recv_finished_total_sz = 65;
    mock_decode_serverhello_return_val = TLS_RESP_OK;
    mock_decode_encrypt_extension_return_val = TLS_RESP_OK;
    mock_decode_cert_req_return_val = TLS_RESP_OK;
    mock_decode_cert_chain_return_val = TLS_RESP_OK;
    mock_decode_cert_verify_return_val = TLS_RESP_OK;
    mock_decode_finished_return_val = TLS_RESP_OK;
    mock_tls_encode_cert_total_sz = 1803;
    mock_tls_encode_cert_verify_total_sz = 283;
    mock_tls_encode_finished_total_sz = 65;

    status = tlsClientStartHandshake(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_FINISHED, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->flgs.omit_client_cert_chk);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->flgs.omit_server_cert_chk);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hs_server_finish);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hs_client_finish);
} // end of TEST(tlsClientStartHandshake, cert_req__client_finish)

TEST(tlsClientStartHandshake, server_cert__client_finish) {
    tlsRespStatus status = TLS_RESP_OK;

    mock_enable_client_cert_verify = 0;
    mock_enable_server_cert_verify = 1;

    mock_pkt_send_return_val = TLS_RESP_OK;
    mock_pkt_recv_return_val = TLS_RESP_OK;
    mock_tls_encode_clienthello_total_sz = 2570;
    mock_tls_recv_serverhello_total_sz = 128;
    mock_tls_recv_encrypt_extension_total_sz = 83;
    mock_tls_recv_cert_req_total_sz = 0;
    mock_tls_recv_cert_chain_total_sz = 2167;
    mock_tls_recv_cert_verify_total_sz = 292;
    mock_tls_recv_finished_total_sz = 65;
    mock_decode_serverhello_return_val = TLS_RESP_OK;
    mock_decode_encrypt_extension_return_val = TLS_RESP_OK;
    mock_decode_cert_req_return_val = TLS_RESP_ERR;
    mock_decode_cert_chain_return_val = TLS_RESP_OK;
    mock_decode_cert_verify_return_val = TLS_RESP_OK;
    mock_decode_finished_return_val = TLS_RESP_OK;
    mock_tls_encode_cert_total_sz = 0;
    mock_tls_encode_cert_verify_total_sz = 0;
    mock_tls_encode_finished_total_sz = 65;

    status = tlsClientStartHandshake(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_FINISHED, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.omit_client_cert_chk);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->flgs.omit_server_cert_chk);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hs_server_finish);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hs_client_finish);
} // end of TEST(tlsClientStartHandshake, server_cert__client_finish)

TEST(tlsClientStartHandshake, skip_cert_verify_client_finish) {
    tlsRespStatus status = TLS_RESP_OK;

    mock_enable_client_cert_verify = 0;
    mock_enable_server_cert_verify = 0;

    mock_pkt_send_return_val = TLS_RESP_OK;
    mock_pkt_recv_return_val = TLS_RESP_OK;
    mock_tls_encode_clienthello_total_sz = 2570;
    mock_tls_recv_serverhello_total_sz = 128;
    mock_tls_recv_encrypt_extension_total_sz = 83;
    mock_tls_recv_cert_req_total_sz = 0;
    mock_tls_recv_cert_chain_total_sz = 2167;
    mock_tls_recv_cert_verify_total_sz = 292;
    mock_tls_recv_finished_total_sz = 65;
    mock_decode_serverhello_return_val = TLS_RESP_OK;
    mock_decode_encrypt_extension_return_val = TLS_RESP_OK;
    mock_decode_cert_req_return_val = TLS_RESP_ERR; // should skip these handshake states
    mock_decode_cert_chain_return_val = TLS_RESP_ERR;
    mock_decode_cert_verify_return_val = TLS_RESP_ERR;
    mock_decode_finished_return_val = TLS_RESP_OK;
    mock_tls_encode_cert_total_sz = 0;
    mock_tls_encode_cert_verify_total_sz = 0;
    mock_tls_encode_finished_total_sz = 65;

    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR, tlsChkHSfinished(tls_session));
    status = tlsClientStartHandshake(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, tlsChkHSfinished(tls_session));

    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_FINISHED, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.omit_client_cert_chk);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.omit_server_cert_chk);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hs_server_finish);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.hs_client_finish);
} // end of TEST(tlsClientStartHandshake, skip_cert_verify_client_finish)

static void RunAllTestGroups(void) {
    tls_session = (tlsSession_t *)XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));

    RUN_TEST_GROUP(tlsHSstateTransition);
    RUN_TEST_GROUP(tlsClientStartHandshake);

    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups

int main(int argc, const char *argv[]) {
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main
