#include "mqtt_include.h"

#define MAX_RAWBYTE_BUF_SZ 0x100 // internal parameter for read buffer, DO NOT modify this value

static tlsSession_t *tls_session;
static byte          mock_finish_verify_data[8];
static word32        mock_sys_get_time_ms;
static mqttHost_t    mock_server_addr = {
       .domain_name = {.len = 10, .data = (byte *)&"tokio.hot.curve.alpaca"},
       .ip_address = {.len = 0, .data = NULL},
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

const tlsCipherSpec_t tls_supported_cipher_suites[] = {
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
};

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

word32 mqttEncodeWord16(byte *buf, word16 value) {
    if (buf != NULL) {
        buf[0] = value >> 8;
        buf[1] = value & 0xff;
    }
    // return number of bytes used to store the encoded value
    return (word32)2;
} // end of mqttEncodeWord16

word32 mqttDecodeWord16(byte *buf, word16 *value) {
    if ((buf != NULL) && (value != NULL)) {
        *value = buf[1];
        *value |= buf[0] << 8;
    }
    return (word32)2;
} // end of mqttDecodeWord16

word32 tlsDecodeWord24(byte *buf, word32 *value) {
    if ((buf != NULL) && (value != NULL)) {
        *value = buf[2];
        *value |= buf[1] << 8;
        *value |= buf[0] << 16;
    }
    return (word32)3;
} // end of tlsDecodeWord24

word32 tlsEncodeWord24(byte *buf, word32 value) {
    if (buf != NULL) {
        buf[0] = (value >> 16) & 0xff;
        buf[1] = (value >> 8) & 0xff;
        buf[2] = value & 0xff;
    }
    // return number of bytes used to store the encoded value
    return (word32)3;
} // end of tlsEncodeWord24

word32 mqttDecodeWord32(byte *buf, word32 *value) {
    if ((buf != NULL) && (value != NULL)) {
        *value = buf[3];
        *value |= buf[2] << 8;
        *value |= buf[1] << 16;
        *value |= buf[0] << 24;
    }
    return (word32)4;
} // end of mqttDecodeWord32

word32 mqttEncodeWord32(byte *buf, word32 value) {
    if (buf != NULL) {
        buf[0] = value >> 24;
        buf[1] = (value >> 16) & 0xff;
        buf[2] = (value >> 8) & 0xff;
        buf[3] = value & 0xff;
    }
    // return number of bytes used to store the encoded value
    return (word32)4;
} // end of mqttEncodeWord32

tlsListItem_t *tlsGetFinalItemFromList(tlsListItem_t *list) {
    tlsListItem_t *idx = NULL;
    tlsListItem_t *prev = NULL;
    for (idx = list; idx != NULL; idx = idx->next) {
        prev = idx;
    }
    return prev;
} // end of tlsGetFinalItemFromList

tlsRespStatus tlsAddItemToList(tlsListItem_t **list, tlsListItem_t *item, byte insert_to_front) {
    if ((list == NULL) || (item == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if (insert_to_front != 0) {
        item->next = *list;
        *list = item; // always change head item
    } else {
        tlsListItem_t *final = NULL;
        final = tlsGetFinalItemFromList(*list);
        if (final == NULL) {
            *list = item;
        } else {
            final->next = item;
        }
    }
    return TLS_RESP_OK;
} // tlsAddItemToList

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

tlsRespStatus tlsFreeExtEntry(tlsExtEntry_t *in) {
    if (in == NULL) {
        return TLS_RESP_ERRARGS;
    }
    XMEMFREE((void *)in->content.data);
    in->content.data = NULL;
    in->next = NULL;
    XMEMFREE((void *)in);
    return TLS_RESP_OK;
} // end of tlsFreeExtEntry

tlsRespStatus tlsFreePSKentry(tlsPSK_t *in) {
    if (in == NULL) {
        return TLS_RESP_ERRARGS;
    }
    if (in->key.data != NULL) {
        XMEMFREE((void *)in->key.data);
        in->key.data = NULL;
        in->id.data = NULL;
    }
    in->next = NULL;
    XMEMFREE((void *)in);
    return TLS_RESP_OK;
} // end of tlsFreePSKentry

word32 tlsGetListItemSz(tlsListItem_t *list) {
    tlsListItem_t *idx = NULL;
    word32         out = 0;
    for (idx = list; idx != NULL; idx = idx->next) {
        out++;
    }
    return out;
} // end of tlsGetListItemSz

tlsHandshakeType tlsGetHSexpectedState(tlsSession_t *session) {
    return (session == NULL ? TLS_HS_TYPE_HELLO_REQUEST_RESERVED : session->hs_state);
} // end of tlsGetHSexpectedState

byte tlsGetSupportedCipherSuiteListSize(void) {
    byte out = XGETARRAYSIZE(tls_supported_cipher_suites);
    return out;
} // end of tlsGetSupportedCipherSuiteListSize

tlsRespStatus tlsAlertTypeCvtToTlsResp(tlsAlertType in) {
    tlsRespStatus out = TLS_RESP_OK;
    switch (in) {
    case TLS_ALERT_TYPE_CLOSE_NOTIFY:
    case TLS_ALERT_TYPE_USER_CANCELED:
        out = TLS_RESP_PEER_CONN_FAIL;
        break;
    case TLS_ALERT_TYPE_UNEXPECTED_MESSAGE:
        out = TLS_RESP_MALFORMED_PKT;
        break;
    case TLS_ALERT_TYPE_RECORD_OVERFLOW:
        out = TLS_RESP_ERR_EXCEED_MAX_REC_SZ;
        break;
    case TLS_ALERT_TYPE_ILLEGAL_PARAMETER:
        out = TLS_RESP_ILLEGAL_PARAMS;
        break;
    case TLS_ALERT_TYPE_DECODE_ERROR:
    case TLS_ALERT_TYPE_MISSING_EXTENSION:
        out = TLS_RESP_ERR_DECODE;
        break;
    default:
        out = TLS_RESP_ERR;
        break;
    } // end of switch-case statement
    return out;
} // end of tlsAlertTypeCvtToTlsResp

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

tlsRespStatus tlsParseExtensions(tlsSession_t *session, tlsExtEntry_t **out) {
    byte         *inbuf = &session->inbuf.data[0];
    word16        inlen_decoded = session->inlen_decoded;
    word16        inlen_decrypted = session->inlen_decrypted;
    word16        entry_copied_len = session->last_ext_entry_dec_len;
    tlsRespStatus status = TLS_RESP_OK;

    // adjust decrypted length due to the authentication tag appended to the entire decrypted bytes
    if (session->flgs.hs_rx_encrypt == 1) {
        if (session->sec.flgs.ct_final_frag == 1) {
            inlen_decrypted -= (1 + session->sec.chosen_ciphersuite->tagSize);
        } // actual content type & skip authentication tag (in the final fragment)
    }
    // get first 2-byte total size field of the extension section
    if ((entry_copied_len >> 15) == 0x1) {
        entry_copied_len &= XGET_BITMASK(15);
        inlen_decoded += tlsDecodeWord16(&inbuf[inlen_decoded], &session->ext_dec_total_len);
        XASSERT(session->ext_dec_total_len == 0);
        entry_copied_len = 0;
    }
    session->inlen_decoded = inlen_decoded;
    session->last_ext_entry_dec_len = entry_copied_len;
    return status;
} // end of tlsParseExtensions

tlsRespStatus tlsCopyCertRawData(tlsSession_t *session) {
    tlsCert_t    *curr_cert = NULL;
    word32        cert_len = 0;
    word32        cert_copied_len = session->last_cpy_cert_len;
    byte         *inbuf = &session->inbuf.data[0];
    word16        inlen_decoded = session->inlen_decoded;
    word16        inlen_decrypted = session->inlen_decrypted;
    tlsRespStatus status = TLS_RESP_OK;
    word16        rdy_cpy_len = 0;

    // adjust decrypted length due to the authentication tag appended to the entire decrypted bytes
    if (session->flgs.hs_rx_encrypt == 1 && session->sec.flgs.ct_final_frag == 1) {
        inlen_decrypted -= (1 + session->sec.chosen_ciphersuite->tagSize);
    } // actual content type & skip authentication tag (in the final fragment)
    while (inlen_decrypted > inlen_decoded
    ) { // move part of remaining received bytes to certificate entries,
        switch (cert_copied_len) {
        case 0:
            curr_cert = (tlsCert_t *)XMALLOC(sizeof(tlsCert_t));
            XMEMSET(curr_cert, 0x0, sizeof(tlsCert_t));
            // insert the cert item to the end of list
            tlsAddItemToList(
                (tlsListItem_t **)&session->peer_certs, (tlsListItem_t *)curr_cert, 0x0
            );
            rdy_cpy_len = XMIN(0x3, inlen_decrypted - inlen_decoded);
            break;
        default:
            rdy_cpy_len = 0;
            curr_cert = (tlsCert_t *)tlsGetFinalItemFromList((tlsListItem_t *)session->peer_certs);
            // copy operation hasn't been finished on the final cert item
            break;
        } // end of switch case
        if (rdy_cpy_len > 0) {
            XMEMCPY(&curr_cert->rawbytes.len[cert_copied_len], &inbuf[inlen_decoded], rdy_cpy_len);
            inlen_decoded += rdy_cpy_len;
            cert_copied_len += rdy_cpy_len;
        }
        if ((curr_cert->rawbytes.data == NULL) && (cert_copied_len == 3)) {
            tlsDecodeWord24(&curr_cert->rawbytes.len[0], &cert_len);
            curr_cert->rawbytes.data = XMALLOC(sizeof(byte) * cert_len);
        } // allocate space only when first 4 bytes of an extension entry is decoded
        if (inlen_decrypted > inlen_decoded) {
            tlsDecodeWord24(&curr_cert->rawbytes.len[0], &cert_len);
            if (cert_copied_len < (3 + cert_len)) {
                rdy_cpy_len =
                    XMIN(cert_len - (cert_copied_len - 3), inlen_decrypted - inlen_decoded);
                XMEMCPY(
                    &curr_cert->rawbytes.data[cert_copied_len - 3], &inbuf[inlen_decoded],
                    rdy_cpy_len
                );
                cert_copied_len += rdy_cpy_len;
                inlen_decoded += rdy_cpy_len;
                // finish copying current certificate, start check extensions attached with this
                // certificate
                if ((cert_len + 3) == cert_copied_len) {
                    session->last_ext_entry_dec_len = 0x1 << 15;
                }
            }
        } // end of  inlen_decrypted > inlen_decoded
        session->inlen_decoded = inlen_decoded;
        if (inlen_decrypted > inlen_decoded) {
            status = tlsParseExtensions(session, &curr_cert->exts);
            inlen_decoded = session->inlen_decoded;
            if (status >= 0) {
                if (session->ext_dec_total_len == 0) {
                    cert_copied_len = 0;
                } // will be set to zero in the end of loop
            }
        } // end of inlen_decrypted > inlen_decoded
    } // end of while (inlen_decrypted > inlen_decoded)
    session->last_cpy_cert_len = cert_copied_len;
    return status;
} // end of tlsCopyCertRawData

void tlsFreeCertChain(tlsCert_t *in, tlsFreeCertEntryFlag ctrl_flg) {
    tlsCert_t *curr_cert = in;
    while (curr_cert != NULL
    ) { // raw byte array of CA cert CANNOT be deallocated since it's declared as const array
        if ((ctrl_flg & TLS_FREE_CERT_ENTRY_SKIP_FINAL_ITEM) ==
            TLS_FREE_CERT_ENTRY_SKIP_FINAL_ITEM) {
            if (curr_cert->next == NULL) {
                break;
            }
        }
        if ((ctrl_flg & TLS_FREE_CERT_ENTRY_RAWBYTE) == TLS_FREE_CERT_ENTRY_RAWBYTE) {
            if (curr_cert->rawbytes.data != NULL) {
                XMEMFREE((void *)curr_cert->rawbytes.data);
                curr_cert->rawbytes.data = NULL;
            }
        }
        if ((ctrl_flg & TLS_FREE_CERT_ENTRY_SIGNATURE) == TLS_FREE_CERT_ENTRY_SIGNATURE) {
        } // end of if flag TLS_FREE_CERT_ENTRY_SIGNATURE is set
        if (ctrl_flg == TLS_FREE_CERT_ENTRY_ALL) {
            tlsCert_t *prev_cert = NULL;
            prev_cert = curr_cert;
            tlsRemoveItemFromList((tlsListItem_t **)&curr_cert, (tlsListItem_t *)curr_cert);
            if (prev_cert->hashed_holder_info.data != NULL) {
                XMEMFREE((void *)prev_cert->hashed_holder_info.data);
                prev_cert->hashed_holder_info.data = NULL;
            }
            // deallocate entire extension list
            tlsExtEntry_t *prev_ext = NULL;
            tlsExtEntry_t *curr_ext = prev_cert->exts;
            while (curr_ext != NULL) {
                prev_ext = curr_ext;
                tlsRemoveItemFromList((tlsListItem_t **)&curr_ext, (tlsListItem_t *)curr_ext);
                tlsFreeExtEntry(prev_ext);
            }
            prev_cert->next = NULL;
            XMEMFREE((void *)prev_cert);
        } else {
            curr_cert = curr_cert->next;
        } // end of if flag TLS_FREE_CERT_ENTRY_ALL is set
    } // end of while loop
} // end of tlsFreeCertChain

tlsRespStatus tlsDecodeExtServerHello(tlsSession_t *session) { return TLS_RESP_OK; }

tlsRespStatus tlsDecodeExtEncryptExt(tlsSession_t *session) { return TLS_RESP_OK; }

tlsRespStatus tlsDecodeExtCertReq(tlsSession_t *session) { return TLS_RESP_OK; }

tlsRespStatus tlsDecodeCerts(tlsCert_t *cert, byte final_item_rdy) {
    word32        cert_sz = 0;
    tlsRespStatus status = TLS_RESP_OK;
    while (cert != NULL) {
        if (final_item_rdy == 0x0 && cert->next == NULL) {
            break; // final cert item is NOT ready, simply return OK
        }
        if (cert->rawbytes.data != NULL) { // record something for later check
            tlsDecodeWord24(&cert->rawbytes.len[0], &cert_sz);
            cert->hashed_holder_info.data = XMALLOC(0x8); // only for testing purpose
            XMEMCPY(&cert->hashed_holder_info.data[0], &cert->rawbytes.data[0], 0x4);
            XMEMCPY(&cert->hashed_holder_info.data[4], &cert->rawbytes.data[cert_sz - 4], 0x4);
            cert->subject.common_name = mock_server_addr.domain_name.data;
        }
        cert = cert->next;
    } // end of while-loop
    return status;
}

tlsRespStatus tlsCertVerifyGenDigitalSig(
    tlsSecurityElements_t *sec, const tlsRSApss_t *rsapss_attri, tlsOpaque16b_t *out,
    const byte is_server
) {
    if (out != NULL && out->data == NULL) {
        out->len = rsapss_attri->salt_len;
        out->data = XMALLOC(out->len);
    }
    return TLS_RESP_OK;
}

tlsRespStatus
tlsGenFinishedVerifyData(tlsSecurityElements_t *sec, tlsOpaque8b_t *base_key, tlsOpaque8b_t *out) {
    if (out != NULL && out->data != NULL) {
        XMEMSET(out->data, 0x00, out->len);
        XMEMCPY(&out->data[0], &mock_finish_verify_data[0], 4);
        XMEMCPY(&out->data[out->len - 4], &mock_finish_verify_data[4], 4);
    }
    return TLS_RESP_OK;
}

void tlsHSstateTransition(tlsSession_t *session) {
    switch (session->hs_state) {
    case TLS_HS_TYPE_CERTIFICATE_REQUEST:
        if ((session->flgs.omit_client_cert_chk == 1) &&
            (session->flgs.omit_server_cert_chk == 1)) {
            session->hs_state = TLS_HS_TYPE_FINISHED;
        } else {
            session->hs_state = TLS_HS_TYPE_CERTIFICATE;
        }
        break;
    case TLS_HS_TYPE_FINISHED:
        if (session->flgs.new_session_tkt != 0) {
            session->hs_state = TLS_HS_TYPE_NEW_SESSION_TICKET;
        }
        break;
    case TLS_HS_TYPE_NEW_SESSION_TICKET:
        break;
    default:
        break;
    } // end of switch-case statement
} // end of tlsHSstateTransition

tlsRespStatus tlsVerifyCertSignature(
    void *pubkey, tlsOpaque16b_t *sig, tlsAlgoOID sign_algo, tlsOpaque16b_t *ref,
    tlsRSApss_t *rsapssextra
) {
    return TLS_RESP_OK;
}

tlsRespStatus tlsVerifyCertChain(tlsCert_t *issuer_cert, tlsCert_t *subject_cert) {
    return TLS_RESP_OK;
}

tlsRespStatus tlsHKDFexpandLabel(
    tlsHashAlgoID hash_id, tlsOpaque8b_t *in_secret, tlsOpaque8b_t *label, tlsOpaque8b_t *context,
    tlsOpaque8b_t *out_secret
) {
    return TLS_RESP_OK;
}

word32 mqttSysGetTimeMs(void) { return mock_sys_get_time_ms; }

// Mock function for tlsX509FindSubjAltName
tlsX509SANEntry_t *tlsX509FindSubjAltName(tlsX509v3ext_t *ext, mqttHost_t *keyword) {
    // This is a mock implementation for unit testing purposes.
    // By default, it returns NULL, simulating that no matching Subject Alternative Name was found.
    // If a test needs to simulate a successful find, it would typically set up a static
    // variable in this file to be returned by this mock.
    (void)ext;     // Suppress unused parameter warning
    (void)keyword; // Suppress unused parameter warning
    return NULL;
}

// -----------------------------------------------------------------------------------
TEST_GROUP(tlsPktDecodeMisc);
TEST_GROUP(tlsDecodeRecordLayer);

TEST_GROUP_RUNNER(tlsPktDecodeMisc) {
    RUN_TEST_CASE(tlsPktDecodeMisc, tlsVerifyDecodeRecordType);
    RUN_TEST_CASE(tlsPktDecodeMisc, tlsVerifyDecodeVersionCode);
    RUN_TEST_CASE(tlsPktDecodeMisc, tlsGetUndecodedNumBytes);
}

TEST_GROUP_RUNNER(tlsDecodeRecordLayer) {
    RUN_TEST_CASE(tlsDecodeRecordLayer, serverhello);
    RUN_TEST_CASE(tlsDecodeRecordLayer, encryptedextensions);
    RUN_TEST_CASE(tlsDecodeRecordLayer, certrequest);
    RUN_TEST_CASE(tlsDecodeRecordLayer, certchain);
    RUN_TEST_CASE(tlsDecodeRecordLayer, certchain_fragments);
    RUN_TEST_CASE(tlsDecodeRecordLayer, certchain_overflow);
    RUN_TEST_CASE(tlsDecodeRecordLayer, certverify);
    RUN_TEST_CASE(tlsDecodeRecordLayer, finished);
    RUN_TEST_CASE(tlsDecodeRecordLayer, new_session_ticket_fragments);
    RUN_TEST_CASE(tlsDecodeRecordLayer, new_session_ticket_list_limit);
    RUN_TEST_CASE(tlsDecodeRecordLayer, app_data_fragments);
    RUN_TEST_CASE(tlsDecodeRecordLayer, change_cipher_spec);
    RUN_TEST_CASE(tlsDecodeRecordLayer, alert);
}

TEST_SETUP(tlsPktDecodeMisc) {}

TEST_SETUP(tlsDecodeRecordLayer) {
    XMEMSET(tls_session->inbuf.data, 0x00, sizeof(byte) * MAX_RAWBYTE_BUF_SZ);
    tls_session->num_frags_in = 1;
    tls_session->remain_frags_in = 1;
    tls_session->sec.flgs.ct_first_frag = 1;
    tls_session->sec.flgs.ct_final_frag = 1;
    tls_session->flgs.omit_client_cert_chk = 0;
    tls_session->flgs.omit_server_cert_chk = 0;
    tls_session->flgs.hs_server_finish = 0;
    tls_session->flgs.hs_client_finish = 0;
    tls_session->flgs.new_session_tkt = 0;
}

TEST_TEAR_DOWN(tlsPktDecodeMisc) {}

TEST_TEAR_DOWN(tlsDecodeRecordLayer) {}

TEST(tlsPktDecodeMisc, tlsVerifyDecodeRecordType) {
    TEST_ASSERT_EQUAL_INT(
        TLS_RESP_OK, tlsVerifyDecodeRecordType(TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC)
    );
    TEST_ASSERT_EQUAL_INT(
        TLS_RESP_MALFORMED_PKT, tlsVerifyDecodeRecordType(TLS_CONTENT_TYPE_INVALID)
    );
    TEST_ASSERT_EQUAL_INT(
        TLS_RESP_MALFORMED_PKT, tlsVerifyDecodeRecordType(TLS_CONTENT_TYPE_HEARTBEAT)
    );
    TEST_ASSERT_EQUAL_INT(
        TLS_RESP_MALFORMED_PKT, tlsVerifyDecodeRecordType(TLS_CONTENT_TYPE_HEARTBEAT + 1)
    );
} // end of TEST(tlsPktDecodeMisc, tlsVerifyDecodeRecordType)

TEST(tlsPktDecodeMisc, tlsVerifyDecodeVersionCode) {
    byte version_code[2];
    version_code[0] = 0;
    version_code[1] = 0;
    TEST_ASSERT_EQUAL_INT(
        TLS_RESP_MALFORMED_PKT, tlsVerifyDecodeVersionCode((const byte *)&version_code[0])
    );
    version_code[0] = TLS_VERSION_ENCODE_1_2 >> 8;
    TEST_ASSERT_EQUAL_INT(
        TLS_RESP_MALFORMED_PKT, tlsVerifyDecodeVersionCode((const byte *)&version_code[0])
    );
    version_code[1] = TLS_VERSION_ENCODE_1_2 & 0xff;
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, tlsVerifyDecodeVersionCode((const byte *)&version_code[0]));
} // end of TEST(tlsPktDecodeMisc, tlsVerifyDecodeVersionCode)

TEST(tlsPktDecodeMisc, tlsGetUndecodedNumBytes) {
    word16 actual_value = 0;
    word16 expect_value = 0;

    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[1];
    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->num_frags_in = 0;
    tls_session->remain_frags_in = 0;
    expect_value = 0;
    actual_value = tlsGetUndecodedNumBytes(tls_session);
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    tls_session->inlen_decrypted = 50;
    tls_session->inlen_decoded = 7;
    tls_session->num_frags_in = 2;
    tls_session->remain_frags_in = 2;
    expect_value = tls_session->inlen_decrypted - tls_session->inlen_decoded;
    actual_value = tlsGetUndecodedNumBytes(tls_session);
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    tls_session->remain_frags_in = 1;
    expect_value = tls_session->inlen_decrypted - tls_session->inlen_decoded - 1 -
                   tls_session->sec.chosen_ciphersuite->tagSize;
    actual_value = tlsGetUndecodedNumBytes(tls_session);
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
} // end of TEST(tlsPktDecodeMisc, tlsGetUndecodedNumBytes)

TEST(tlsDecodeRecordLayer, serverhello) {
    byte         *buf = NULL;
    tlsRespStatus status = TLS_RESP_OK;

    tls_session->sec.server_rand = XMALLOC(TLS_HS_RANDOM_BYTES);
    tls_session->tmpbuf.session_id.data = XMALLOC(TLS_MAX_BYTES_SESSION_ID);
    tls_session->tmpbuf.session_id.len = TLS_MAX_BYTES_SESSION_ID;
    XMEMSET(tls_session->tmpbuf.session_id.data, 0x00, tls_session->tmpbuf.session_id.len);
    // assume ServerHello is received successfully
    buf = &tls_session->inbuf.data[0];
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tlsEncodeWord16(&buf[0], TLS_VERSION_ENCODE_1_2);
    buf += 2; // modify length field later
    *buf++ = TLS_HS_TYPE_SERVER_HELLO;
    buf += 3; // modify length field later
    buf += tlsEncodeWord16(&buf[0], TLS_VERSION_ENCODE_1_2);
    buf += TLS_HS_RANDOM_BYTES; // 32-byte random
    *buf++ = tls_session->tmpbuf.session_id.len;
    XMEMCPY(buf, tls_session->tmpbuf.session_id.data, tls_session->tmpbuf.session_id.len);
    buf += tls_session->tmpbuf.session_id.len;
    buf += tlsEncodeWord16(&buf[0], TLS_CIPHERSUITE_ID_AES_256_GCM_SHA384);
    *buf++ = 0x2; // legacy compression method must be NULL, delibrately set to non-zero then the
                  // production function should report error
    // empty extension section, it's OK to do so only in unit test, in practice there must be
    // extension entries like "server name", "supported version", or "key share" in ServerHello
    buf += tlsEncodeWord16(&buf[0], 0x00);

    tls_session->inlen_decrypted = (word16)(buf - &tls_session->inbuf.data[0]);
    tlsEncodeWord16(
        &tls_session->inbuf.data[3], (tls_session->inlen_decrypted - TLS_RECORD_LAYER_HEADER_NBYTES)
    );
    tlsEncodeWord24(
        &tls_session->inbuf.data[6], (tls_session->inlen_decrypted -
                                      TLS_RECORD_LAYER_HEADER_NBYTES - TLS_HANDSHAKE_HEADER_NBYTES)
    );
    tls_session->hs_state = TLS_HS_TYPE_SERVER_HELLO;
    tls_session->flgs.hs_rx_encrypt = 0;

    tls_session->flgs.hello_retry = 1;
    tls_session->inlen_decoded = 0;
    tls_session->sec.chosen_ciphersuite = NULL;
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_ALERT, status);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->flgs.hello_retry);
    TEST_ASSERT_EQUAL_UINT(&tls_supported_cipher_suites[1], tls_session->sec.chosen_ciphersuite);

    tls_session->flgs.hello_retry = 1;
    tls_session->inlen_decoded = 0;
    tls_session->sec.chosen_ciphersuite = NULL;
    buf[-3] = 0x0; // legacy compression method must be NULL
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->flgs.hello_retry);
    TEST_ASSERT_EQUAL_UINT(&tls_supported_cipher_suites[1], tls_session->sec.chosen_ciphersuite);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->ext_dec_total_len);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);

    XMEMFREE(tls_session->sec.server_rand);
    XMEMFREE(tls_session->tmpbuf.session_id.data);
    tls_session->sec.server_rand = NULL;
    tls_session->tmpbuf.session_id.data = NULL;
} // end of TEST(tlsDecodeRecordLayer, serverhello)

TEST(tlsDecodeRecordLayer, encryptedextensions) {
    byte         *buf = NULL;
    tlsRespStatus status = TLS_RESP_OK;

    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    // assume EncryptedExtension is received successfully
    buf = &tls_session->inbuf.data[0];
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tlsEncodeWord16(&buf[0], TLS_VERSION_ENCODE_1_2);
    buf += 2; // modify length field later
    *buf++ = TLS_HS_TYPE_ENCRYPTED_EXTENSIONS;
    buf += 3; // modify length field later
    // empty extension section, it's OK to do so only in unit test, in practice there should be
    // extension entries like "supported groups", "max fragment length", "ALPN", or "server name" in
    // EncryptedExtension
    buf += tlsEncodeWord16(&buf[0], 0x00);
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;                 // TLSInnerPlainText.contentType
    buf += tls_session->sec.chosen_ciphersuite->tagSize; // preserve space for authentication tag

    tls_session->inlen_decrypted = (word16)(buf - &tls_session->inbuf.data[0]);
    tlsEncodeWord16(
        &tls_session->inbuf.data[3], (tls_session->inlen_decrypted - TLS_RECORD_LAYER_HEADER_NBYTES)
    );
    tlsEncodeWord24(
        &tls_session->inbuf.data[6], (tls_session->inlen_decrypted -
                                      TLS_RECORD_LAYER_HEADER_NBYTES - TLS_HANDSHAKE_HEADER_NBYTES)
    );
    tls_session->hs_state = TLS_HS_TYPE_ENCRYPTED_EXTENSIONS;
    tls_session->inlen_decoded = 0;

    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->ext_dec_total_len);
    TEST_ASSERT_EQUAL_UINT16(
        tls_session->inlen_decrypted,
        (tls_session->inlen_decoded + 1 + tls_session->sec.chosen_ciphersuite->tagSize)
    );
} // end of TEST(tlsDecodeRecordLayer, encryptedextensions)

TEST(tlsDecodeRecordLayer, certrequest) {
    byte         *buf = NULL;
    tlsRespStatus status = TLS_RESP_OK;
    byte          expect_cert_req[37] = {0};
    const byte    cert_req_ctx_sz = 37;

    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    // assume EncryptedExtension is received successfully
    buf = &tls_session->inbuf.data[0];
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tlsEncodeWord16(&buf[0], TLS_VERSION_ENCODE_1_2);
    buf += 2; // modify length field later
    *buf++ = TLS_HS_TYPE_CERTIFICATE_REQUEST;
    buf += 3; // modify length field later
    *buf++ = cert_req_ctx_sz;
    XMEMCPY(buf, &expect_cert_req[0], cert_req_ctx_sz);
    buf += cert_req_ctx_sz;
    buf += tlsEncodeWord16(&buf[0], 0x00);               // assume no extension entry at here
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;                 // TLSInnerPlainText.contentType
    buf += tls_session->sec.chosen_ciphersuite->tagSize; // preserve space for authentication tag

    tls_session->inlen_decrypted = (word16)(buf - &tls_session->inbuf.data[0]);
    tlsEncodeWord16(
        &tls_session->inbuf.data[3], (tls_session->inlen_decrypted - TLS_RECORD_LAYER_HEADER_NBYTES)
    );
    tlsEncodeWord24(
        &tls_session->inbuf.data[6], (tls_session->inlen_decrypted -
                                      TLS_RECORD_LAYER_HEADER_NBYTES - TLS_HANDSHAKE_HEADER_NBYTES)
    );
    tls_session->hs_state = TLS_HS_TYPE_CERTIFICATE_REQUEST;
    tls_session->inlen_decoded = 0;
    tls_session->tmpbuf.cert_req_ctx.data = NULL;
    tls_session->tmpbuf.cert_req_ctx.len = 0;

    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_dec_len);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->ext_dec_total_len);
    TEST_ASSERT_EQUAL_UINT16(
        tls_session->inlen_decrypted,
        (tls_session->inlen_decoded + 1 + tls_session->sec.chosen_ciphersuite->tagSize)
    );
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->tmpbuf.cert_req_ctx.data);
    TEST_ASSERT_EQUAL_UINT8(cert_req_ctx_sz, tls_session->tmpbuf.cert_req_ctx.len);
    TEST_ASSERT_EQUAL_STRING_LEN(
        &expect_cert_req[0], tls_session->tmpbuf.cert_req_ctx.data, cert_req_ctx_sz
    );

    XMEMFREE(tls_session->tmpbuf.cert_req_ctx.data);
    tls_session->tmpbuf.cert_req_ctx.data = NULL;
} // end of TEST(tlsDecodeRecordLayer, certrequest)

TEST(tlsDecodeRecordLayer, certchain) {
    const byte expect_cert_bytes[2][8] = {
        {
            0x1,
            0x2,
            0x3,
            0x4,
            0x5,
            0x6,
            0x7,
            0x8,
        },
        {
            0x1a,
            0x1b,
            0x1c,
            0x1d,
            0x1e,
            0x1f,
            0x20,
            0x21,
        }
    };
    byte         *buf = NULL;
    tlsCert_t    *curr_cert = NULL;
    mqttStr_t     cert[2] = {{0x15, NULL}, {0x28, NULL}};
    tlsRespStatus status = TLS_RESP_OK;
    byte          idx = 0;
    word32        total_sz_cert_entry = (3 + 2) * 2 + cert[0].len + cert[1].len;

    for (idx = 0; idx < 2; idx++) {
        cert[idx].data = XMALLOC(sizeof(byte) * cert[idx].len);
        XMEMSET(cert[idx].data, 0x00, cert[idx].len);
        XMEMCPY(&cert[idx].data[0], &expect_cert_bytes[idx][0], 4);
        XMEMCPY(&cert[idx].data[cert[idx].len - 4], &expect_cert_bytes[idx][4], 4);
    } // end of for loop

    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[1];
    // assume Certificate is received successfully
    buf = &tls_session->inbuf.data[0];
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tlsEncodeWord16(&buf[0], TLS_VERSION_ENCODE_1_2);
    buf += 2; // modify length field later
    *buf++ = TLS_HS_TYPE_CERTIFICATE;
    buf += 3;   // modify length field later
    *buf++ = 0; // certificate_request_context from server's Certificate is usually empty.
    buf += tlsEncodeWord24(&buf[0], total_sz_cert_entry);
    for (idx = 0; idx < 2; idx++) {
        buf += tlsEncodeWord24(&buf[0], cert[idx].len);
        XMEMCPY(buf, &cert[idx].data[0], cert[idx].len);
        buf += cert[idx].len;
        buf += tlsEncodeWord16(&buf[0], 0x00);
        XMEMFREE(cert[idx].data);
    } // end of for loop
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;                 // TLSInnerPlainText.contentType
    buf += tls_session->sec.chosen_ciphersuite->tagSize; // preserve space for authentication tag

    tls_session->inlen_decrypted = (word16)(buf - &tls_session->inbuf.data[0]);
    tlsEncodeWord16(
        &tls_session->inbuf.data[3], (tls_session->inlen_decrypted - TLS_RECORD_LAYER_HEADER_NBYTES)
    );
    tlsEncodeWord24(
        &tls_session->inbuf.data[6], (tls_session->inlen_decrypted -
                                      TLS_RECORD_LAYER_HEADER_NBYTES - TLS_HANDSHAKE_HEADER_NBYTES)
    );
    // test weather decode function can adjust handshake state properly
    tls_session->hs_state = TLS_HS_TYPE_CERTIFICATE_REQUEST;
    tls_session->inlen_decoded = 0;
    tls_session->peer_certs = NULL;

    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->peer_certs);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CERTIFICATE, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.omit_client_cert_chk);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->flgs.omit_server_cert_chk);
    idx = 0;
    for (curr_cert = tls_session->peer_certs; curr_cert != NULL; curr_cert = curr_cert->next) {
        TEST_ASSERT_EQUAL_UINT(NULL, curr_cert->exts);
        TEST_ASSERT_EQUAL_UINT(NULL, curr_cert->rawbytes.data);
        TEST_ASSERT_NOT_EQUAL(NULL, curr_cert->hashed_holder_info.data);
        TEST_ASSERT_EQUAL_STRING_LEN(
            &expect_cert_bytes[idx], curr_cert->hashed_holder_info.data,
            curr_cert->hashed_holder_info.len
        );
        idx++;
    }
    TEST_ASSERT_EQUAL_UINT8(2, idx);
    tlsFreeCertChain(tls_session->peer_certs, TLS_FREE_CERT_ENTRY_ALL);
    tls_session->peer_certs = NULL;
} // end of TEST(tlsDecodeRecordLayer, certchain)

#define TEST_NUM_OF_PEER_CERTS 0x5
TEST(tlsDecodeRecordLayer, certchain_fragments) {
    const byte expect_cert_bytes[TEST_NUM_OF_PEER_CERTS][8] = {
        {
            0x10,
            0x12,
            0x13,
            0x14,
            0x15,
            0x16,
            0x17,
            0x18,
        },
        {
            0x19,
            0x1a,
            0x1c,
            0x1d,
            0x1e,
            0x1f,
            0x21,
            0x23,
        },
        {
            0x24,
            0x25,
            0x26,
            0x27,
            0x28,
            0x29,
            0x2a,
            0x2b,
        },
        {
            0x2c,
            0x2d,
            0x2e,
            0x2f,
            0x31,
            0x32,
            0x33,
            0x34,
        },
        {
            0x35,
            0x36,
            0x37,
            0x38,
            0x39,
            0x40,
            0x41,
            0x42,
        },
    };
    word16        cert_sz[TEST_NUM_OF_PEER_CERTS] = {0x83, 0x5b, 0xe7, 0xa1, 0x3d};
    byte         *buf = NULL;
    mqttStr_t     entire_handshake_msg = {0, NULL};
    tlsCert_t    *curr_cert = NULL;
    word32        total_sz_cert_entry = 0;
    word16        nbytes_cert_copied = 0;
    tlsRespStatus status = TLS_RESP_OK;
    byte          idx = 0;

    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[1];
    for (idx = 0; idx < TEST_NUM_OF_PEER_CERTS; idx++) {
        total_sz_cert_entry += 3 + cert_sz[idx] + 2;
    }
    entire_handshake_msg.len = TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES;
    entire_handshake_msg.len += 1 + 3 + total_sz_cert_entry;
    entire_handshake_msg.len += 1 + tls_session->sec.chosen_ciphersuite->tagSize;
    entire_handshake_msg.data = XMALLOC(entire_handshake_msg.len);
    XMEMSET(entire_handshake_msg.data, 0x00, entire_handshake_msg.len);
    buf = &entire_handshake_msg.data[0];
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tlsEncodeWord16(&buf[0], TLS_VERSION_ENCODE_1_2);
    buf += tlsEncodeWord16(buf, (entire_handshake_msg.len - TLS_RECORD_LAYER_HEADER_NBYTES));
    *buf++ = TLS_HS_TYPE_CERTIFICATE;
    buf += tlsEncodeWord24(buf, (1 + 3 + total_sz_cert_entry));
    *buf++ = 0; // certificate_request_context from server's Certificate is usually empty.
    buf += tlsEncodeWord24(&buf[0], total_sz_cert_entry);
    for (idx = 0; idx < TEST_NUM_OF_PEER_CERTS; idx++) {
        buf += tlsEncodeWord24(buf, cert_sz[idx]);
        XMEMCPY(buf, &expect_cert_bytes[idx][0], 0x4);
        buf += cert_sz[idx] - 4;
        XMEMCPY(buf, &expect_cert_bytes[idx][4], 0x4);
        buf += 4;
        buf += tlsEncodeWord16(&buf[0], 0x00);
    } // end of for loop
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;                 // TLSInnerPlainText.contentType
    buf += tls_session->sec.chosen_ciphersuite->tagSize; // preserve space for authentication tag
    TEST_ASSERT_EQUAL_UINT(&entire_handshake_msg.data[entire_handshake_msg.len], buf);

    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->hs_state = TLS_HS_TYPE_CERTIFICATE;
    tls_session->peer_certs = NULL;
    // ------------- decode the first fragment of Certificate message -------------
    tls_session->inlen_decrypted =
        XMIN(tls_session->inbuf.len, (entire_handshake_msg.len - nbytes_cert_copied));
    XMEMCPY(
        &tls_session->inbuf.data[0], &entire_handshake_msg.data[nbytes_cert_copied],
        tls_session->inlen_decrypted
    );
    nbytes_cert_copied += tls_session->inlen_decrypted;
    tls_session->inlen_decoded = 0;
    tls_session->num_frags_in = 2;
    tls_session->remain_frags_in = 2;
    tls_session->sec.flgs.ct_first_frag = 1;
    tls_session->sec.flgs.ct_final_frag = 0;
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->peer_certs);
    idx = 0;
    for (curr_cert = tls_session->peer_certs;
         (curr_cert != NULL) && (curr_cert->hashed_holder_info.data != NULL);
         curr_cert = curr_cert->next) {
        TEST_ASSERT_EQUAL_UINT(NULL, curr_cert->exts);
        TEST_ASSERT_EQUAL_STRING_LEN(
            &expect_cert_bytes[idx], curr_cert->hashed_holder_info.data,
            curr_cert->hashed_holder_info.len
        );
        idx++;
    }
    TEST_ASSERT_EQUAL_UINT8(2, idx);
    TEST_ASSERT_GREATER_THAN_UINT32(0, tls_session->last_cpy_cert_len);
    TEST_ASSERT_LESS_THAN_UINT32((3 + cert_sz[2]), tls_session->last_cpy_cert_len);

    // ------------- decode the second fragment of Certificate message -------------
    tls_session->inlen_decrypted =
        XMIN(tls_session->inbuf.len, (entire_handshake_msg.len - nbytes_cert_copied));
    XMEMCPY(
        &tls_session->inbuf.data[0], &entire_handshake_msg.data[nbytes_cert_copied],
        tls_session->inlen_decrypted
    );
    nbytes_cert_copied += tls_session->inlen_decrypted;
    tls_session->inlen_decoded = 0;
    tls_session->num_frags_in = 3;
    tls_session->remain_frags_in = 2;
    tls_session->sec.flgs.ct_first_frag = 0;
    tls_session->sec.flgs.ct_final_frag = 0;
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    idx = 0;
    for (curr_cert = tls_session->peer_certs;
         (curr_cert != NULL) && (curr_cert->hashed_holder_info.data != NULL);
         curr_cert = curr_cert->next) {
        TEST_ASSERT_EQUAL_UINT(NULL, curr_cert->exts);
        TEST_ASSERT_EQUAL_STRING_LEN(
            &expect_cert_bytes[idx], curr_cert->hashed_holder_info.data,
            curr_cert->hashed_holder_info.len
        );
        idx++;
    }
    TEST_ASSERT_EQUAL_UINT8(3, idx);
    TEST_ASSERT_GREATER_THAN_UINT32(0, tls_session->last_cpy_cert_len);
    TEST_ASSERT_LESS_THAN_UINT32((3 + cert_sz[3]), tls_session->last_cpy_cert_len);

    // ------------- decode the third  fragment of Certificate message -------------
    tls_session->inlen_decrypted =
        XMIN(tls_session->inbuf.len, (entire_handshake_msg.len - nbytes_cert_copied));
    XMEMCPY(
        &tls_session->inbuf.data[0], &entire_handshake_msg.data[nbytes_cert_copied],
        tls_session->inlen_decrypted
    );
    nbytes_cert_copied += tls_session->inlen_decrypted;
    tls_session->inlen_decoded = 0;
    tls_session->num_frags_in = 3;
    tls_session->remain_frags_in = 1;
    tls_session->sec.flgs.ct_first_frag = 0;
    tls_session->sec.flgs.ct_final_frag = 1;
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    idx = 0;
    for (curr_cert = tls_session->peer_certs;
         (curr_cert != NULL) && (curr_cert->hashed_holder_info.data != NULL);
         curr_cert = curr_cert->next) {
        TEST_ASSERT_EQUAL_UINT(NULL, curr_cert->exts);
        TEST_ASSERT_EQUAL_STRING_LEN(
            &expect_cert_bytes[idx], curr_cert->hashed_holder_info.data,
            curr_cert->hashed_holder_info.len
        );
        idx++;
    }
    TEST_ASSERT_EQUAL_UINT8(TEST_NUM_OF_PEER_CERTS, idx);
    TEST_ASSERT_EQUAL_UINT32(0, tls_session->last_cpy_cert_len);
    TEST_ASSERT_EQUAL_UINT16(
        tls_session->inlen_decrypted,
        (tls_session->inlen_decoded + 1 + tls_session->sec.chosen_ciphersuite->tagSize)
    );

    tlsFreeCertChain(tls_session->peer_certs, TLS_FREE_CERT_ENTRY_ALL);
    tls_session->peer_certs = NULL;
    XMEMFREE(entire_handshake_msg.data);
} // end of TEST(tlsDecodeRecordLayer, certchain_fragments)
#undef TEST_NUM_OF_PEER_CERTS

TEST(tlsDecodeRecordLayer, certchain_overflow) {
    byte         *buf = NULL;
    tlsRespStatus status = TLS_RESP_OK;

    buf = &tls_session->inbuf.data[0];
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tlsEncodeWord16(buf, TLS_VERSION_ENCODE_1_2);
    buf +=
        tlsEncodeWord16(buf, (TLS_DEFAULT_BYTES_RECORD_LAYER_PKT - TLS_RECORD_LAYER_HEADER_NBYTES));
    *buf++ = TLS_HS_TYPE_CERTIFICATE;
    buf += tlsEncodeWord24(buf, (TLS_MAX_BYTES_HANDSHAKE_MSG - TLS_HANDSHAKE_HEADER_NBYTES));
    *buf++ = 0; // certificate_request_context from server's Certificate is usually empty.
    buf += tlsEncodeWord24(buf, (TLS_MAX_BYTES_CERT_CHAIN + 1));
    buf += tlsEncodeWord24(buf, (TLS_MAX_BYTES_CERT_CHAIN + 1 - 3 - 2));

    tls_session->inlen_decrypted = tls_session->inbuf.len - 7;
    tls_session->num_frags_in = 2;
    tls_session->remain_frags_in = 2;
    tls_session->sec.flgs.ct_first_frag = 1;
    tls_session->sec.flgs.ct_final_frag = 0;
    tls_session->peer_certs = NULL;

    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->inlen_decoded = 0;
    tls_session->hs_state = TLS_HS_TYPE_CERTIFICATE_REQUEST;
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_CERT_OVFL, status);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->peer_certs);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CERTIFICATE, tls_session->hs_state);

    tlsEncodeWord24(&buf[-6], TLS_MAX_BYTES_CERT_CHAIN);
    tlsEncodeWord24(&buf[-3], (TLS_MAX_BYTES_CERT_CHAIN - 3 - 2));
    tls_session->inlen_decoded = 0;
    tls_session->hs_state = TLS_HS_TYPE_CERTIFICATE_REQUEST;
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->peer_certs);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->peer_certs->rawbytes.data);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->peer_certs->hashed_holder_info.data);
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->peer_certs->next);
    TEST_ASSERT_GREATER_THAN_UINT32(0, tls_session->last_cpy_cert_len);
    TEST_ASSERT_LESS_THAN_UINT32(
        (3 + TLS_MAX_BYTES_CERT_CHAIN - 3 - 2), tls_session->last_cpy_cert_len
    );
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_CERTIFICATE, tls_session->hs_state);

    tlsFreeCertChain(tls_session->peer_certs, TLS_FREE_CERT_ENTRY_ALL);
    tls_session->peer_certs = NULL;
} // end of TEST(tlsDecodeRecordLayer, certchain_overflow)

TEST(tlsDecodeRecordLayer, certverify) {
    byte         *buf = NULL;
    word16        expect_verify_data_sz = 0;
    tlsRespStatus status = TLS_RESP_OK;

    tls_session->peer_certs = XMALLOC(sizeof(tlsCert_t));
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[1];
    expect_verify_data_sz = tls_session->inbuf.len;
    expect_verify_data_sz -= (TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES);
    expect_verify_data_sz -= (4 + 1 + tls_session->sec.chosen_ciphersuite->tagSize);

    buf = &tls_session->inbuf.data[0];
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tlsEncodeWord16(buf, TLS_VERSION_ENCODE_1_2);
    buf += tlsEncodeWord16(buf, (tls_session->inbuf.len - TLS_RECORD_LAYER_HEADER_NBYTES));
    *buf++ = TLS_HS_TYPE_CERTIFICATE_VERIFY;
    buf += tlsEncodeWord24(buf, (2 + 2 + expect_verify_data_sz));
    // give unsupported signature algorithm ID, the decode function should report error
    buf += tlsEncodeWord16(buf, TLS_SIGNATURE_ED448);
    buf += tlsEncodeWord16(buf, expect_verify_data_sz);
    buf += expect_verify_data_sz;
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tls_session->sec.chosen_ciphersuite->tagSize; // preserve space for authentication tag
    TEST_ASSERT_EQUAL_UINT(&tls_session->inbuf.data[tls_session->inbuf.len], buf);

    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->hs_state = TLS_HS_TYPE_CERTIFICATE_VERIFY;
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    tls_session->inlen_decoded = 0;
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_NOT_SUPPORT, status);

    tlsEncodeWord16(
        &tls_session->inbuf.data[TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES],
        TLS_SIGNATURE_RSA_PSS_PSS_SHA256
    );
    tls_session->inlen_decoded = 0;
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(
        tls_session->inlen_decrypted,
        (tls_session->inlen_decoded + 1 + tls_session->sec.chosen_ciphersuite->tagSize)
    );

    tlsEncodeWord16(
        &tls_session->inbuf.data[TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES],
        TLS_SIGNATURE_RSA_PSS_PSS_SHA384
    );
    tls_session->inlen_decoded = 0;
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(
        tls_session->inlen_decrypted,
        (tls_session->inlen_decoded + 1 + tls_session->sec.chosen_ciphersuite->tagSize)
    );

    XMEMFREE(tls_session->peer_certs);
    tls_session->peer_certs = NULL;
} // end of TEST(tlsDecodeRecordLayer, certverify)

TEST(tlsDecodeRecordLayer, finished) {
    byte      *buf = NULL;
    const byte expect_verify_bytes[8] = {
        0x1d, 0x1e, 0x1f, 0x2a, 0x21, 0x22, 0x23, 0x24,
    };
    word16        expect_verify_data_sz = 0;
    tlsRespStatus status = TLS_RESP_OK;

    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    expect_verify_data_sz =
        mqttHashGetOutlenBytes(TLScipherSuiteGetHashID(tls_session->sec.chosen_ciphersuite));

    buf = &tls_session->inbuf.data[0];
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tlsEncodeWord16(buf, TLS_VERSION_ENCODE_1_2);
    buf += tlsEncodeWord16(
        buf, (expect_verify_data_sz + TLS_HANDSHAKE_HEADER_NBYTES + 1 +
              tls_session->sec.chosen_ciphersuite->tagSize)
    );
    *buf++ = TLS_HS_TYPE_FINISHED;
    buf += tlsEncodeWord24(buf, expect_verify_data_sz);
    XMEMCPY(buf, &expect_verify_bytes[0], 0x4);
    buf += (expect_verify_data_sz - 4);
    XMEMCPY(buf, &expect_verify_bytes[4], 0x4);
    buf += 4;
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tls_session->sec.chosen_ciphersuite->tagSize; // preserve space for authentication tag

    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->hs_state =
        TLS_HS_TYPE_CERTIFICATE_REQUEST; // test transition from CertificateRequest to Finished
    tls_session->inlen_decrypted = (word16)(buf - &tls_session->inbuf.data[0]);

    tls_session->inlen_decoded = 0;
    XMEMSET(&mock_finish_verify_data[0], 0x00, 8);
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_HS_AUTH_FAIL, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_FINISHED, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.omit_client_cert_chk);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.omit_server_cert_chk);

    tls_session->inlen_decoded = 0;
    XMEMCPY(&mock_finish_verify_data[0], &expect_verify_bytes[0], 8);
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(
        tls_session->inlen_decrypted,
        (tls_session->inlen_decoded + 1 + tls_session->sec.chosen_ciphersuite->tagSize)
    );
} // end of TEST(tlsDecodeRecordLayer, finished)

#define TEST_NBYTES_NST_NONCE 9
TEST(tlsDecodeRecordLayer, new_session_ticket_fragments) {
    const word32  expect_lifetime = 0x11c02;
    const word32  expect_age_add = 0x505bee8d;
    const byte    expect_nonce[TEST_NBYTES_NST_NONCE] = {0x20, 2, 3, 4, 5, 6, 7, 0xe8, 0xf1};
    const byte    expect_ticket_boundbytes[8] = {0xfd, 0xfb, 0xfa, 0xf9, 0xf6, 0xf5, 0xf4, 0xf3};
    mqttStr_t     entire_handshake_msg = {0, NULL};
    tlsPSK_t     *mock_psk_list = NULL;
    byte         *buf = NULL;
    word16        total_nst_hs_msg_sz = 0;
    word16        ticket_id_sz = 0;
    word16        nbytes_hs_msg_copied = 0;
    tlsRespStatus status = TLS_RESP_OK;

    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->flgs.hs_server_finish = 1;
    tls_session->flgs.hs_client_finish = 1;
    tls_session->sec.psk_list = &mock_psk_list;

    ticket_id_sz = tls_session->inbuf.len + 7;
    total_nst_hs_msg_sz = 4 + 4 + 1 + TEST_NBYTES_NST_NONCE + 2 + ticket_id_sz + 2;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];

    entire_handshake_msg.len = TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES;
    entire_handshake_msg.len +=
        total_nst_hs_msg_sz + 1 + tls_session->sec.chosen_ciphersuite->tagSize;
    entire_handshake_msg.data = XMALLOC(entire_handshake_msg.len);
    XMEMSET(entire_handshake_msg.data, 0x00, entire_handshake_msg.len);

    buf = &entire_handshake_msg.data[0];
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tlsEncodeWord16(buf, TLS_VERSION_ENCODE_1_2);
    buf += tlsEncodeWord16(buf, (entire_handshake_msg.len - TLS_RECORD_LAYER_HEADER_NBYTES));
    *buf++ = TLS_HS_TYPE_NEW_SESSION_TICKET;
    buf += tlsEncodeWord24(buf, (word32)total_nst_hs_msg_sz);
    buf += tlsEncodeWord32(buf, expect_lifetime);
    buf += tlsEncodeWord32(buf, expect_age_add);
    *buf++ = TEST_NBYTES_NST_NONCE;
    XMEMCPY(buf, &expect_nonce[0], TEST_NBYTES_NST_NONCE);
    buf += TEST_NBYTES_NST_NONCE;
    buf += tlsEncodeWord16(buf, ticket_id_sz);
    XMEMCPY(buf, &expect_ticket_boundbytes[0], 4);
    buf += (ticket_id_sz - 4);
    XMEMCPY(buf, &expect_ticket_boundbytes[4], 4);
    buf += 4;
    buf += tlsEncodeWord16(buf, 0); // no extension entry at here
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tls_session->sec.chosen_ciphersuite->tagSize; // preserve space for authentication tag
    TEST_ASSERT_EQUAL_UINT(&entire_handshake_msg.data[entire_handshake_msg.len], buf);
    TEST_ASSERT_EQUAL_UINT(NULL, *tls_session->sec.psk_list);

    mock_sys_get_time_ms = 0x123;
    tls_session->hs_state = TLS_HS_TYPE_FINISHED;
    // decode the first fragment of NewSessionTicket
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    tls_session->inlen_decoded = 0;
    XMEMCPY(
        &tls_session->inbuf.data[0], &entire_handshake_msg.data[nbytes_hs_msg_copied],
        tls_session->inlen_decrypted
    );
    nbytes_hs_msg_copied += tls_session->inlen_decrypted;
    tls_session->num_frags_in = 2;
    tls_session->remain_frags_in = 2;
    tls_session->sec.flgs.ct_first_frag = 1;
    tls_session->sec.flgs.ct_final_frag = 0;
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_NEW_SESSION_TICKET, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->flgs.new_session_tkt);
    TEST_ASSERT_NOT_EQUAL(NULL, *tls_session->sec.psk_list);
    TEST_ASSERT_EQUAL_UINT(expect_lifetime, mock_psk_list->time_param.ticket_lifetime);
    TEST_ASSERT_EQUAL_UINT(expect_age_add, mock_psk_list->time_param.ticket_age_add);
    TEST_ASSERT_EQUAL_UINT(mock_sys_get_time_ms, mock_psk_list->time_param.timestamp_ms);
    TEST_ASSERT_EQUAL_UINT16(ticket_id_sz, mock_psk_list->id.len);
    TEST_ASSERT_GREATER_THAN_UINT32(0, tls_session->nbytes.remaining_to_recv);
    TEST_ASSERT_LESS_THAN_UINT32(ticket_id_sz, tls_session->nbytes.remaining_to_recv);
    // decode the second fragment of NewSessionTicket
    tls_session->inlen_decrypted = entire_handshake_msg.len - nbytes_hs_msg_copied;
    tls_session->inlen_decoded = 0;
    XMEMCPY(
        &tls_session->inbuf.data[0], &entire_handshake_msg.data[nbytes_hs_msg_copied],
        tls_session->inlen_decrypted
    );
    nbytes_hs_msg_copied += tls_session->inlen_decrypted;
    tls_session->num_frags_in = 2;
    tls_session->remain_frags_in = 1;
    tls_session->sec.flgs.ct_first_frag = 0;
    tls_session->sec.flgs.ct_final_frag = 1;
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_NEW_SESSION_TICKET, tls_session->hs_state);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->flgs.new_session_tkt);
    TEST_ASSERT_EQUAL_UINT32(0, tls_session->nbytes.remaining_to_recv);
    TEST_ASSERT_NOT_EQUAL(NULL, *tls_session->sec.psk_list);
    TEST_ASSERT_EQUAL_UINT16(ticket_id_sz, mock_psk_list->id.len);
    TEST_ASSERT_EQUAL_STRING_LEN(&mock_psk_list->id.data[0], &expect_ticket_boundbytes[0], 4);
    TEST_ASSERT_EQUAL_STRING_LEN(
        &mock_psk_list->id.data[ticket_id_sz - 4], &expect_ticket_boundbytes[4], 4
    );
    TEST_ASSERT_EQUAL_UINT32(entire_handshake_msg.len, nbytes_hs_msg_copied);
    TEST_ASSERT_EQUAL_UINT16(
        tls_session->inlen_decrypted,
        (tls_session->inlen_decoded + 1 + tls_session->sec.chosen_ciphersuite->tagSize)
    );

    tlsFreePSKentry(*tls_session->sec.psk_list);
    *tls_session->sec.psk_list = NULL;
    tls_session->sec.psk_list = NULL;
    XMEMFREE(entire_handshake_msg.data);
} // end of TEST(tlsDecodeRecordLayer, new_session_ticket_fragments)

TEST(tlsDecodeRecordLayer, new_session_ticket_list_limit) {
    const word32  expect_lifetime = 0x5435;
    const word32  expect_age_add = 0xe5a013d5;
    const byte    expect_nonce[TEST_NBYTES_NST_NONCE] = {0x7a, 0xc2, 3, 4, 5, 6, 7, 0xe8, 0x1};
    word32       *expect_sys_get_time_ms = NULL;
    tlsPSK_t     *mock_psk_list = NULL;
    tlsPSK_t     *tmp_psk = NULL;
    byte         *buf = NULL;
    word16        total_nst_rec_msg_sz = 0;
    word16        total_nst_hs_msg_sz = 0;
    word16        ticket_id_sz = 0x10;
    tlsRespStatus status = TLS_RESP_OK;
    word16        idx, jdx = 0;

    expect_sys_get_time_ms = XMALLOC(sizeof(word32) * (TLS_MAX_NUM_PSK_LISTITEM + 5));
    for (idx = 0; idx < (TLS_MAX_NUM_PSK_LISTITEM + 5); idx++) {
        expect_sys_get_time_ms[idx] = 0x1ff + idx;
    }
    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->flgs.hs_server_finish = 1;
    tls_session->flgs.hs_client_finish = 1;
    tls_session->sec.psk_list = &mock_psk_list;
    tls_session->hs_state = TLS_HS_TYPE_NEW_SESSION_TICKET;

    total_nst_hs_msg_sz = 4 + 4 + 1 + TEST_NBYTES_NST_NONCE + 2 + ticket_id_sz + 2;
    total_nst_rec_msg_sz = total_nst_hs_msg_sz + TLS_HANDSHAKE_HEADER_NBYTES + 1 +
                           tls_session->sec.chosen_ciphersuite->tagSize;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];

    buf = &tls_session->inbuf.data[0];
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tlsEncodeWord16(buf, TLS_VERSION_ENCODE_1_2);
    buf += tlsEncodeWord16(buf, total_nst_rec_msg_sz);
    *buf++ = TLS_HS_TYPE_NEW_SESSION_TICKET;
    buf += tlsEncodeWord24(buf, (word32)total_nst_hs_msg_sz);
    buf += tlsEncodeWord32(buf, expect_lifetime);
    buf += tlsEncodeWord32(buf, expect_age_add);
    *buf++ = TEST_NBYTES_NST_NONCE;
    XMEMCPY(buf, &expect_nonce[0], TEST_NBYTES_NST_NONCE);
    buf += TEST_NBYTES_NST_NONCE;
    buf += tlsEncodeWord16(buf, ticket_id_sz);
    buf += ticket_id_sz;
    buf += tlsEncodeWord16(buf, 0); // no extension entry at here
    *buf++ = TLS_CONTENT_TYPE_HANDSHAKE;
    buf += tls_session->sec.chosen_ciphersuite->tagSize; // preserve space for authentication tag

    tls_session->inlen_decrypted = (word16)(buf - &tls_session->inbuf.data[0]);

    // decode the first NewSessionTicket
    for (idx = 0; idx < (TLS_MAX_NUM_PSK_LISTITEM + 5); idx++) {
        mock_sys_get_time_ms = expect_sys_get_time_ms[idx];
        tls_session->inlen_decoded = 0;
        status = tlsDecodeRecordLayer(tls_session);
        TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
        TEST_ASSERT_EQUAL_UINT8(TLS_HS_TYPE_NEW_SESSION_TICKET, tls_session->hs_state);
        TEST_ASSERT_EQUAL_UINT8(0, tls_session->flgs.new_session_tkt);
        TEST_ASSERT_EQUAL_UINT16(
            tls_session->inlen_decrypted,
            (tls_session->inlen_decoded + 1 + tls_session->sec.chosen_ciphersuite->tagSize)
        );
        TEST_ASSERT_NOT_EQUAL(NULL, *tls_session->sec.psk_list);
        tmp_psk = *tls_session->sec.psk_list;
        for (jdx = 0; tmp_psk != NULL; jdx++) {
            TEST_ASSERT_EQUAL_UINT(expect_lifetime, tmp_psk->time_param.ticket_lifetime);
            TEST_ASSERT_EQUAL_UINT(expect_age_add, tmp_psk->time_param.ticket_age_add);
            TEST_ASSERT_EQUAL_UINT(
                expect_sys_get_time_ms[idx - jdx], tmp_psk->time_param.timestamp_ms
            );
            tmp_psk = tmp_psk->next;
        } // end of for-loop jdx
    } // end of for-loop idx

    while (mock_psk_list != NULL) {
        tmp_psk = mock_psk_list;
        tlsRemoveItemFromList((tlsListItem_t **)&mock_psk_list, (tlsListItem_t *)tmp_psk);
        tlsFreePSKentry(tmp_psk);
    }
    mock_psk_list = NULL;
    tls_session->sec.psk_list = NULL;
    XMEMFREE(expect_sys_get_time_ms);
} // end of TEST(tlsDecodeRecordLayer, new_session_ticket_list_limit)
#undef TEST_NBYTES_NST_NONCE

#define TEST_APP_DATA_BYTE_MARK 0x78
#define TEST_APP_MSG_AUTH_TAG   0xe4
TEST(tlsDecodeRecordLayer, app_data_fragments) {
    mqttStr_t     expect_app_msg = {0, NULL};
    mqttStr_t     actual_app_msg = {0, NULL};
    word16        app_data_sz = 0;
    word16        nbytes_copied = 0;
    byte         *buf = NULL;
    byte         *expect_app_start = NULL;
    tlsRespStatus status = TLS_RESP_OK;
    word16        idx = 0;

    tls_session->flgs.hs_rx_encrypt = 1;
    tls_session->flgs.hs_server_finish = 1;
    tls_session->flgs.hs_client_finish = 1;
    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];

    app_data_sz = tls_session->inbuf.len << 1;
    expect_app_msg.len = TLS_RECORD_LAYER_HEADER_NBYTES + app_data_sz + 1 +
                         tls_session->sec.chosen_ciphersuite->tagSize;
    expect_app_msg.data = XMALLOC(sizeof(byte) * expect_app_msg.len);
    actual_app_msg.len = app_data_sz;
    actual_app_msg.data = XMALLOC(sizeof(byte) * actual_app_msg.len);
    buf = &expect_app_msg.data[0];
    *buf++ = TLS_CONTENT_TYPE_APP_DATA;
    buf += tlsEncodeWord16(buf, TLS_VERSION_ENCODE_1_2);
    buf += tlsEncodeWord16(buf, (expect_app_msg.len - TLS_RECORD_LAYER_HEADER_NBYTES));
    XMEMSET(buf, TEST_APP_DATA_BYTE_MARK, app_data_sz);
    expect_app_start = buf;
    buf += app_data_sz;
    *buf++ = TLS_CONTENT_TYPE_APP_DATA;
    XMEMSET(buf, TEST_APP_MSG_AUTH_TAG, tls_session->sec.chosen_ciphersuite->tagSize);
    buf += tls_session->sec.chosen_ciphersuite->tagSize;

    tls_session->app_pt.data = actual_app_msg.data;
    // decode first fragment of application message
    tls_session->num_frags_in = 2;
    tls_session->remain_frags_in = 2;
    tls_session->sec.flgs.ct_first_frag = 1;
    tls_session->sec.flgs.ct_final_frag = 0;
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    tls_session->inlen_decoded = 0;
    XMEMCPY(
        &tls_session->inbuf.data[0], &expect_app_msg.data[nbytes_copied],
        tls_session->inlen_decrypted
    );
    nbytes_copied += tls_session->inlen_decrypted;
    for (idx = 1; tls_session->inlen_decrypted > tls_session->inlen_decoded; idx++) {
        tls_session->app_pt.len = idx;
        status = tlsDecodeRecordLayer(tls_session);
        TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    }
    TEST_ASSERT_GREATER_THAN_UINT32(0, tls_session->app_pt.len);
    TEST_ASSERT_LESS_THAN_UINT32(idx, tls_session->app_pt.len);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
    // decode second fragment of application message
    tls_session->num_frags_in = 3;
    tls_session->remain_frags_in = 2;
    tls_session->sec.flgs.ct_first_frag = 0;
    tls_session->sec.flgs.ct_final_frag = 0;
    tls_session->inlen_decrypted = tls_session->inbuf.len;
    tls_session->inlen_decoded = 0;
    XMEMCPY(
        &tls_session->inbuf.data[0], &expect_app_msg.data[nbytes_copied],
        tls_session->inlen_decrypted
    );
    nbytes_copied += tls_session->inlen_decrypted;
    for (idx = 5; tls_session->inlen_decrypted > tls_session->inlen_decoded; idx++) {
        tls_session->app_pt.len = idx;
        status = tlsDecodeRecordLayer(tls_session);
    }
    TEST_ASSERT_GREATER_THAN_UINT32(0, tls_session->app_pt.len);
    TEST_ASSERT_LESS_THAN_UINT32(idx, tls_session->app_pt.len);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
    // decode third fragment of application message
    tls_session->num_frags_in = 3;
    tls_session->remain_frags_in = 1;
    tls_session->sec.flgs.ct_first_frag = 0;
    tls_session->sec.flgs.ct_final_frag = 1;
    tls_session->inlen_decrypted = expect_app_msg.len - nbytes_copied;
    tls_session->inlen_decoded = 0;
    XMEMCPY(
        &tls_session->inbuf.data[0], &expect_app_msg.data[nbytes_copied],
        tls_session->inlen_decrypted
    );
    nbytes_copied += tls_session->inlen_decrypted;
    for (idx = 2;; idx++) {
        tls_session->app_pt.len = idx;
        status = tlsDecodeRecordLayer(tls_session);
        if (tls_session->app_pt.len > 0) {
            break;
        }
    }
    TEST_ASSERT_EQUAL_UINT16(
        tls_session->inlen_decrypted,
        (tls_session->inlen_decoded + 1 + tls_session->sec.chosen_ciphersuite->tagSize)
    );
    TEST_ASSERT_EQUAL_UINT16(actual_app_msg.len, (tls_session->app_pt.data - actual_app_msg.data));
    TEST_ASSERT_EQUAL_STRING_LEN(expect_app_start, &actual_app_msg.data[0], actual_app_msg.len);
    XMEMFREE(expect_app_msg.data);
    XMEMFREE(actual_app_msg.data);
} // end of TEST(tlsDecodeRecordLayer, app_data_fragments)
#undef TEST_APP_DATA_BYTE_MARK
#undef TEST_APP_MSG_AUTH_TAG

TEST(tlsDecodeRecordLayer, change_cipher_spec) {
    byte         *buf = NULL;
    tlsRespStatus status = TLS_RESP_OK;

    buf = &tls_session->inbuf.data[0];
    *buf++ = TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC;
    buf += tlsEncodeWord16(buf, TLS_VERSION_ENCODE_1_2);
    buf += tlsEncodeWord16(buf, 0x1);
    *buf++ = 0x1;

    tls_session->inlen_decrypted = 6;
    tls_session->inlen_decoded = 0;
    tls_session->flgs.hs_rx_encrypt = 0;
    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(1, tls_session->flgs.hs_rx_encrypt);
    TEST_ASSERT_EQUAL_UINT16(tls_session->inlen_decrypted, tls_session->inlen_decoded);
} // end of TEST(tlsDecodeRecordLayer, change_cipher_spec)

TEST(tlsDecodeRecordLayer, alert) {
    byte         *buf = NULL;
    tlsRespStatus status = TLS_RESP_OK;
    tlsAlertType  mock_tls_alert_description = TLS_ALERT_TYPE_CLOSE_NOTIFY;

    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];

    buf = &tls_session->inbuf.data[0];
    *buf++ = TLS_CONTENT_TYPE_ALERT;
    buf += tlsEncodeWord16(buf, TLS_VERSION_ENCODE_1_2);
    buf += tlsEncodeWord16(buf, (2 + 1 + tls_session->sec.chosen_ciphersuite->tagSize));
    *buf++ = TLS_ALERT_LVL_WARNING;
    *buf++ = mock_tls_alert_description;
    *buf++ = TLS_CONTENT_TYPE_ALERT;
    buf += tls_session->sec.chosen_ciphersuite->tagSize;

    tls_session->inlen_decrypted = (word16)(buf - &tls_session->inbuf.data[0]);
    tls_session->inlen_decoded = 0;
    tls_session->flgs.hs_rx_encrypt = 1;

    status = tlsDecodeRecordLayer(tls_session);
    TEST_ASSERT_EQUAL_UINT8(tlsAlertTypeCvtToTlsResp(mock_tls_alert_description), status);
    TEST_ASSERT_EQUAL_UINT8(TLS_ALERT_LVL_WARNING, tls_session->log.alert.level);
    TEST_ASSERT_EQUAL_UINT8(mock_tls_alert_description, tls_session->log.alert.description);
    TEST_ASSERT_EQUAL_UINT16(
        tls_session->inlen_decrypted,
        (tls_session->inlen_decoded + 1 + tls_session->sec.chosen_ciphersuite->tagSize)
    );
} // end of TEST(tlsDecodeRecordLayer, alert)

static void RunAllTestGroups(void) {
    tls_session = (tlsSession_t *)XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->inbuf.len = MAX_RAWBYTE_BUF_SZ;
    tls_session->inbuf.data = (byte *)XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);
    tls_session->server_name = &mock_server_addr;

    RUN_TEST_GROUP(tlsPktDecodeMisc);
    RUN_TEST_GROUP(tlsDecodeRecordLayer);

    XMEMFREE(tls_session->inbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups

int main(int argc, const char *argv[]) {
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main
