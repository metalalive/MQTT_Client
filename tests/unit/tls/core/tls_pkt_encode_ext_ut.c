#include "mqtt_include.h"

// internal parameter for read buffer, DO NOT modify these values
#define MAX_RAWBYTE_BUF_SZ       0x200
#define TEST_NUM_EXTENSION_ITEMS 0x3

extern const tlsVersionCode tls_supported_versions[];
extern const tlsNamedGrp    tls_supported_named_groups[];
extern const tlsSignScheme  tls_supported_sign_scheme[];

static tlsSession_t *tls_session;
static word32        mock_sys_get_time_ms;
static byte          mock_keyshare_public_bytes[TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO][0x80];
static tlsRespStatus mock_keyshare_export_pubval_return_val;

static const tlsExtType mock_extension_types[TEST_NUM_EXTENSION_ITEMS] = {
    TLS_EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP, TLS_EXT_TYPE_SERVER_CERTIFICATE_TYPE,
    TLS_EXT_TYPE_SIGNATURE_ALGORITHMS_CERT
};

static const word16 mock_extension_content_len[TEST_NUM_EXTENSION_ITEMS] = {0x43, 0x5f, 0x70};

tlsHandshakeType tlsGetHSexpectedState(tlsSession_t *session) {
    return (session == NULL ? TLS_HS_TYPE_HELLO_REQUEST_RESERVED : session->hs_state);
} // end of tlsGetHSexpectedState

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

void tlsEncodeHandshakeHeader(tlsSession_t *session) {
    tlsHandshakeMsg_t *hs_header = NULL;
    word32             hs_msg_total_len = 0;
    // if the handshake message is split to multiple fragments(packets) to send,
    // then we only add handshake header to the first fragment.
    hs_header = (tlsHandshakeMsg_t *)&session->outbuf
                    .data[session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES];
    hs_header->type = tlsGetHSexpectedState(session);
    hs_msg_total_len =
        session->curr_outmsg_len - TLS_HANDSHAKE_HEADER_NBYTES - TLS_RECORD_LAYER_HEADER_NBYTES;
    tlsEncodeWord24((byte *)&hs_header->fragment.len[0], (word32)hs_msg_total_len);
} // end of tlsEncodeHandshakeHeader

word16 tlsKeyExGetKeySize(tlsNamedGrp grp_id) {
    word16 keysize = 0;
    switch (grp_id) {
    case TLS_NAMED_GRP_SECP256R1:
        keysize = 32;
        break;
    case TLS_NAMED_GRP_SECP384R1:
        keysize = 48;
        break;
    case TLS_NAMED_GRP_SECP521R1:
        keysize = 65;
        break;
    case TLS_NAMED_GRP_X25519:
        keysize = 32;
        break;
    default:
        break;
    } // end of switch-case statement
    return keysize;
} // end of tlsKeyExGetKeySize

word16 tlsKeyExGetExportKeySize(tlsNamedGrp grp_id) {
    word16 export_size = tlsKeyExGetKeySize(grp_id);
    switch (grp_id) {
    case TLS_NAMED_GRP_SECP256R1:
    case TLS_NAMED_GRP_SECP384R1:
    case TLS_NAMED_GRP_SECP521R1:
        export_size = (export_size << 1) + 1;
        break;
    default:
        break;
    } // end of switch-case statement
    return export_size;
} // end of tlsKeyExGetExportKeySize

static void mock_tlsAllocSpaceBeforeKeyEx(tlsKeyEx_t *keyexp) {
    byte  *buf = NULL;
    word16 len = 0;
    // initialize key-exchange structure
    keyexp->num_grps_total = tlsGetSupportedKeyExGrpSize();
    len = (sizeof(tlsKeyExState) + sizeof(void *)) * keyexp->num_grps_total;
    buf = XMALLOC(len);
    XMEMSET(buf, 0x00, (size_t)len);

    len = sizeof(tlsKeyExState) * keyexp->num_grps_total;
    keyexp->grp_nego_state = (tlsKeyExState *)&buf[0];
    // create a list of pointers, pointed to different key structures (e.g. ECC, X25519, DH)
    keyexp->keylist = (void **)&buf[len];
    // chosen_grp_idx  should NOT be greater than num_grps_total, here we set num_grps_total as
    // default value which means we haven't found appropriate named groups / key exchange algorithm
    keyexp->chosen_grp_idx = keyexp->num_grps_total;
} // end of mock_tlsAllocSpaceBeforeKeyEx

static void mock_tlsCleanSpaceAfterKeyEx(tlsKeyEx_t *keyexp) {
    // deallocate generated but unused key(s) after key-exchange algorithm is negotiated
    if (keyexp->grp_nego_state != NULL) {
        XMEMFREE((void *)keyexp->grp_nego_state);
        keyexp->grp_nego_state = NULL;
        keyexp->keylist = NULL;
    }
} // end of mock_tlsCleanSpaceAfterKeyEx

static tlsPSK_t *mock_createEmptyPSKitem(word16 id_len, byte key_len, word32 timestamp_ms) {
    tlsPSK_t *out = NULL;
    byte     *buf = NULL;
    if (id_len > 0 && key_len > 0) {
        out = (tlsPSK_t *)XMALLOC(sizeof(tlsPSK_t));
        buf = XMALLOC(id_len + key_len);
        out->key.data = buf;
        buf += key_len;
        out->id.data = buf;
        out->key.len = key_len;
        out->id.len = id_len;
        out->next = NULL;
        out->flgs.is_resumption = 1;
        out->time_param.ticket_lifetime = 0x500;
        out->time_param.timestamp_ms = timestamp_ms;
    }
    return out;
} // end of mock_createEmptyPSKitem

static tlsExtEntry_t *mock_createEmptyExtensionItem(tlsExtType type, word16 len) {
    tlsExtEntry_t *out = NULL;
    word16         idx = 0;
    if (len > 0) {
        out = XMALLOC(sizeof(tlsExtEntry_t));
        out->type = type;
        out->next = NULL;
        out->content.len = len;
        out->content.data = XMALLOC(len);
        for (idx = 0; idx < len; idx++) {
            out->content.data[idx] = (len + idx) % 0xff;
        }
    }
    return out;
} // end of mock_createEmptyExtensionItem

tlsRespStatus tlsGenEphemeralKeyPairs(mqttDRBG_t *drbg, tlsKeyEx_t *keyexp) {
    tlsRespStatus status = TLS_RESP_OK;
    byte          ngrps_chosen = 0;
    byte          ngrps_max = keyexp->num_grps_total;
    byte          idx = keyexp->chosen_grp_idx;

    if (idx == ngrps_max) { // if not specifying any algorithm, we choose first two available
                            // algorithms to generate keys
        for (idx = 0; (idx < ngrps_max) && (ngrps_chosen < TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO);
             idx++) {
            if (keyexp->grp_nego_state[idx] == TLS_KEYEX_STATE_NOT_NEGO_YET) {
                keyexp->keylist[idx] = (void *)&mock_keyshare_public_bytes[ngrps_chosen];
                keyexp->grp_nego_state[idx] = TLS_KEYEX_STATE_NEGOTIATING;
                ngrps_chosen++;
            }
        } // end of for-loop
        if ((idx == ngrps_max) && (ngrps_chosen == 0)) {
            // return error because the client already negotiated with all available key-exchange
            // methods (using all the supported named groups) without success
            status = TLS_RESP_ERR_NO_KEYEX_MTHD_AVAIL;
        }
    } else {
        status = TLS_RESP_ERR;
        XASSERT(0);
    }
    keyexp->num_grps_chosen = ngrps_chosen;
    return status;
} // end of tlsGenEphemeralKeyPairs

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

tlsRespStatus
tlsExportPubValKeyShare(byte *out, tlsNamedGrp grp_id, void *chosen_key, word16 chosen_key_sz) {
    XMEMCPY(out, (byte *)chosen_key, chosen_key_sz);
    return mock_keyshare_export_pubval_return_val;
} // end of tlsExportPubValKeyShare

void tlsFreeEphemeralKeyPairs(tlsKeyEx_t *keyexp) {
    byte ngrps_max = keyexp->num_grps_total;
    byte idx = 0;
    for (idx = 0; idx < ngrps_max; idx++) {
        if (keyexp->keylist[idx] != NULL) {
            keyexp->keylist[idx] = NULL;
        }
    } // end of for-loop
}

word32 mqttSysGetTimeMs(void) { return mock_sys_get_time_ms; }

tlsRespStatus tlsDerivePSKbinderKey(tlsPSK_t *pskin, tlsOpaque8b_t *out) { return TLS_RESP_OK; }

// ------------------------------------------------------------------------
TEST_GROUP(tlsGenExtensions);
TEST_GROUP(tlsEncodeExtensions);

TEST_GROUP_RUNNER(tlsGenExtensions) {
    RUN_TEST_CASE(tlsGenExtensions, clienthello_ext_ok);
    RUN_TEST_CASE(tlsGenExtensions, clienthello_gen_keyshare_fail);
}

TEST_GROUP_RUNNER(tlsEncodeExtensions) {
    RUN_TEST_CASE(tlsEncodeExtensions, fit_into_one_fragment);
    RUN_TEST_CASE(tlsEncodeExtensions, split_total_length_case1);
    RUN_TEST_CASE(tlsEncodeExtensions, split_total_length_case2);
    RUN_TEST_CASE(tlsEncodeExtensions, split_1st_ext_item_case1);
    RUN_TEST_CASE(tlsEncodeExtensions, split_1st_ext_item_case2);
    RUN_TEST_CASE(tlsEncodeExtensions, split_1st_ext_item_case3);
    RUN_TEST_CASE(tlsEncodeExtensions, split_1st_ext_item_case4);
    RUN_TEST_CASE(tlsEncodeExtensions, split_1st_ext_item_content);
    RUN_TEST_CASE(tlsEncodeExtensions, split_2nd_ext_item_case1);
    RUN_TEST_CASE(tlsEncodeExtensions, split_2nd_ext_item_case2);
    RUN_TEST_CASE(tlsEncodeExtensions, with_psk_binder_multi_frags);
}

TEST_SETUP(tlsGenExtensions) {}

TEST_SETUP(tlsEncodeExtensions) {
    tlsExtEntry_t *extitem = NULL;
    byte           idx = 0;
    tls_session->remain_frags_out = 0;
    tls_session->num_frags_out = 0;
    tls_session->sec.chosen_ciphersuite = NULL;
    tls_session->last_ext_entry_enc_len =
        0x1 << 15; // reset this value every time before we encode a new extension lists

    tls_session->exts =
        mock_createEmptyExtensionItem(mock_extension_types[0], mock_extension_content_len[0]);
    extitem = tls_session->exts;
    for (idx = 1; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        extitem->next = mock_createEmptyExtensionItem(
            mock_extension_types[idx], mock_extension_content_len[idx]
        );
        extitem = extitem->next;
    } // end of for loop
    tls_session->ext_enc_total_len = tlsGetExtListSize(tls_session->exts);
}

TEST_TEAR_DOWN(tlsGenExtensions) {}

TEST_TEAR_DOWN(tlsEncodeExtensions) {
    if (tls_session->exts != NULL) {
        tlsDeleteAllExtensions(tls_session->exts);
        tls_session->exts = NULL;
    }
}

TEST(tlsGenExtensions, clienthello_ext_ok) {
    mqttHost_t mock_server_name = {
        .domain_name = {.len = 17, .data = (byte *)&("www.yourbroker.io")},
        .ip_address = {.len = 0, .data = NULL},
    };
    tlsExtEntry_t *actual_ext_list = NULL, *extitem = NULL;
    tlsPSK_t      *mock_psk_list = NULL, *pskitem = NULL;

    word32 expect_value = 0, actual_value = 0;
    word16 idx, jdx = 0;
    byte  *buf = NULL;

    tls_session->flgs.hello_retry = 0;
    tls_session->hs_state = TLS_HS_TYPE_CLIENT_HELLO;
    tls_session->server_name = &mock_server_name;
    tls_session->sec.psk_list = &mock_psk_list;
    // create several PSK items, assume one of them expires
    pskitem = mock_createEmptyPSKitem(
        0x37, 0x21, 3
    ); // will be filtered out due to expiration, for testing purpose
    mock_psk_list = pskitem;
    pskitem = mock_createEmptyPSKitem(0x41, 0x30, 4);
    mock_psk_list->next = pskitem;
    pskitem = mock_createEmptyPSKitem(
        0x6a, 0x20, 2
    ); // will be filtered out due to expiration, for testing purpose
    mock_psk_list->next->next = pskitem;
    pskitem = mock_createEmptyPSKitem(0x82, 0x30, 5);
    mock_psk_list->next->next->next = pskitem;
    pskitem = mock_createEmptyPSKitem(0x82, 0x30, 1);
    mock_psk_list->next->next->next->next = pskitem;
    mock_sys_get_time_ms =
        mock_psk_list->time_param.timestamp_ms + mock_psk_list->time_param.ticket_lifetime * 1000;
    // set up test data for key exchange group
    mock_tlsAllocSpaceBeforeKeyEx(&tls_session->keyex);
    mock_keyshare_export_pubval_return_val = TLS_RESP_OK;
    for (idx = 0; idx < TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO; idx++) {
        for (jdx = 0; jdx < 0x80; jdx++) {
            mock_keyshare_public_bytes[idx][jdx] = ((idx + 1) * (jdx + 1)) % 0xff;
        }
    }

    actual_ext_list = tlsGenExtensions(tls_session);
    TEST_ASSERT_NOT_EQUAL(NULL, mock_psk_list);
    TEST_ASSERT_NOT_EQUAL(NULL, mock_psk_list->next);
    TEST_ASSERT_EQUAL_UINT(NULL, mock_psk_list->next->next);
    TEST_ASSERT_EQUAL_UINT32(4, mock_psk_list->time_param.timestamp_ms);
    TEST_ASSERT_EQUAL_UINT32(5, mock_psk_list->next->time_param.timestamp_ms);

    TEST_ASSERT_NOT_EQUAL(NULL, actual_ext_list);
    for (extitem = actual_ext_list; extitem != NULL; extitem = extitem->next) {
        buf = &extitem->content.data[0];
        switch (extitem->type) {
        case TLS_EXT_TYPE_SERVER_NAME:
            TEST_ASSERT_EQUAL_STRING_LEN(
                &mock_server_name.domain_name.data[0], &buf[2 + 1 + 2],
                mock_server_name.domain_name.len
            );
            break;
        case TLS_EXT_TYPE_SUPPORTED_VERSIONS:
            buf++; // skip duplicate length field
            for (idx = 0; idx < tlsGetSupportedVersionListSize(); idx++) {
                expect_value = tls_supported_versions[idx];
                buf += tlsDecodeWord16(buf, (word16 *)&actual_value);
                TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
            }
            break;
        case TLS_EXT_TYPE_SUPPORTED_GROUPS:
            buf += 2; // skip duplicate length field
            for (idx = 0; idx < tlsGetSupportedKeyExGrpSize(); idx++) {
                expect_value = tls_supported_named_groups[idx];
                buf += tlsDecodeWord16(buf, (word16 *)&actual_value);
                TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
            }
            break;
        case TLS_EXT_TYPE_SIGNATURE_ALGORITHMS:
            buf += 2; // skip duplicate length field
            for (idx = 0; idx < tlsGetSupportedSignSchemeListSize(); idx++) {
                expect_value = tls_supported_sign_scheme[idx];
                buf += tlsDecodeWord16(buf, (word16 *)&actual_value);
                TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
            }
            break;
        case TLS_EXT_TYPE_KEY_SHARE:
            jdx = 0;
            buf += 2; // skip duplicate length field
            for (idx = 0; (idx < tls_session->keyex.num_grps_total) &&
                          (jdx < TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO);
                 idx++) {
                if (tls_session->keyex.grp_nego_state[idx] == TLS_KEYEX_STATE_NEGOTIATING) {
                    expect_value = tls_supported_named_groups[idx]; // 2 bytes for named group ID
                    buf += tlsDecodeWord16(buf, (word16 *)&actual_value);
                    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
                    expect_value =
                        tlsKeyExGetExportKeySize(expect_value); // 2 bytes for size of public value
                    buf += tlsDecodeWord16(buf, (word16 *)&actual_value);
                    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
                    TEST_ASSERT_EQUAL_STRING_LEN(
                        &mock_keyshare_public_bytes[jdx][0], buf, expect_value
                    ); // compare the entire public value
                    buf += expect_value;
                    jdx++;
                }
            } // end of for-loop
            break;
        case TLS_EXT_TYPE_PSK_KEY_EXCHANGE_MODES:
            break;
        case TLS_EXT_TYPE_PRE_SHARED_KEY:
            TEST_ASSERT_EQUAL_UINT(NULL, extitem->next); // must be in the end of extension list
            buf += 2;                                    // skip length field of ID section
            for (pskitem = mock_psk_list; pskitem != NULL; pskitem = pskitem->next) {
                expect_value = pskitem->id.len;
                buf += tlsDecodeWord16(buf, (word16 *)&actual_value);
                TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
                buf += expect_value; // TODO: test PSK ID content ?
                expect_value =
                    mqttGetInterval(mqttSysGetTimeMs(), pskitem->time_param.timestamp_ms);
                expect_value += pskitem->time_param.ticket_age_add;
                buf += tlsDecodeWord32(buf, (word32 *)&actual_value);
                TEST_ASSERT_EQUAL_UINT32(expect_value, actual_value);
            } // end of for loop
            buf += 2; // skip length field of binder section
            for (pskitem = mock_psk_list; pskitem != NULL; pskitem = pskitem->next) {
                expect_value = pskitem->key.len;
                actual_value = *buf++;
                TEST_ASSERT_EQUAL_UINT8(expect_value, actual_value);
                buf += expect_value;
            } // end of for loop
            break;
        default:
            TEST_ASSERT(0);
            break;
        } // end of switch case statement
    } // end of for loop

    mock_tlsCleanSpaceAfterKeyEx(&tls_session->keyex);
    tlsDeleteAllExtensions(actual_ext_list);
    tlsFreePSKentry(mock_psk_list->next);
    tlsFreePSKentry(mock_psk_list);
    actual_ext_list = NULL;
    tls_session->sec.psk_list = NULL;
} // end of TEST(tlsGenExtensions, clienthello_ext_ok)

TEST(tlsGenExtensions, clienthello_gen_keyshare_fail) {
    mqttHost_t mock_server_name = {
        .domain_name = {.len = 16, .data = (byte *)&("www.hisbroker.io")},
        .ip_address = {.len = 0, .data = NULL}
    };
    tlsExtEntry_t *actual_ext_list = NULL;

    tls_session->flgs.hello_retry = 0;
    tls_session->hs_state = TLS_HS_TYPE_CLIENT_HELLO;
    tls_session->server_name = &mock_server_name;
    // set up test data for key exchange group
    mock_tlsAllocSpaceBeforeKeyEx(&tls_session->keyex);
    mock_keyshare_export_pubval_return_val = TLS_RESP_ERR_KEYGEN;
    tls_session->keyex.grp_nego_state[1] = TLS_KEYEX_STATE_NOT_APPLY;

    actual_ext_list = tlsGenExtensions(tls_session);
    TEST_ASSERT_EQUAL_UINT(NULL, actual_ext_list);

    mock_tlsCleanSpaceAfterKeyEx(&tls_session->keyex);
    tlsDeleteAllExtensions(actual_ext_list);
    actual_ext_list = NULL;
} // end of TEST(tlsGenExtensions, clienthello_gen_keyshare_fail)

TEST(tlsEncodeExtensions, fit_into_one_fragment) {
    byte         *encoded_ext_start = NULL;
    word32        expect_value = 0;
    word32        actual_value = 0;
    tlsRespStatus status = TLS_RESP_OK;
    byte          idx = 0;

    tls_session->outlen_encoded = tls_session->outbuf.len - 2 - tls_session->ext_enc_total_len;
    tls_session->curr_outmsg_start = 0x1a;
    tls_session->curr_outmsg_len = tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    tls_session->curr_outmsg_len += 2 + tls_session->ext_enc_total_len;
    encoded_ext_start = &tls_session->outbuf.data[tls_session->outlen_encoded];

    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(tls_session->outbuf.len, tls_session->outlen_encoded);

    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    expect_value = 0;
    for (idx = 0; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value += 2 + 2 + mock_extension_content_len[idx];
    } // end of for loop
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    // loop through all extension entries, which are in the same fragment.
    for (idx = 0; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value = mock_extension_types[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = mock_extension_content_len[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_ext_start += mock_extension_content_len[idx];
    } // end of for loop

    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsEncodeExtensions, fit_into_one_fragment)

TEST(tlsEncodeExtensions, split_total_length_case1) {
    byte         *encoded_ext_start = NULL;
    word32        expect_value = 0;
    word32        actual_value = 0;
    tlsRespStatus status = TLS_RESP_OK;
    byte          idx = 0;
    // assume to encode 1st fragment
    tls_session->outlen_encoded = tls_session->outbuf.len - 1;
    tls_session->curr_outmsg_start = tls_session->outbuf.len >> 1;
    tls_session->curr_outmsg_len = tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    tls_session->curr_outmsg_len += 2 + tls_session->ext_enc_total_len;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_EQUAL_UINT16(tls_session->outbuf.len, tls_session->outlen_encoded);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts); // none of extension entries is encoded
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[0], tls_session->exts->type);
    expect_value = 0x1 | (0x1 << 15);
    actual_value = tls_session->last_ext_entry_enc_len;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    // assume to encode 2nd fragment
    tls_session->outlen_encoded = 0;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x0, tls_session->last_ext_entry_enc_len);
    actual_value =
        (tls_session->outbuf.data[tls_session->outbuf.len - 1] << 8) | tls_session->outbuf.data[0];
    expect_value = 0;
    for (idx = 0; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value += 2 + 2 + mock_extension_content_len[idx];
    } // end of for loop
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    encoded_ext_start = &tls_session->outbuf.data[1];
    // loop through all extension entries, which are in the same fragment.
    for (idx = 0; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value = mock_extension_types[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = mock_extension_content_len[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_ext_start += mock_extension_content_len[idx];
    } // end of for loop

    expect_value = (word16)(encoded_ext_start - &tls_session->outbuf.data[0]);
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    TEST_ASSERT_LESS_THAN_UINT(tls_session->outbuf.len, tls_session->outlen_encoded);

    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsEncodeExtensions, split_total_length_case1)

TEST(tlsEncodeExtensions, split_total_length_case2) {
    byte         *encoded_ext_start = NULL;
    word32        expect_value = 0;
    word32        actual_value = 0;
    tlsRespStatus status = TLS_RESP_OK;
    byte          idx = 0;
    // assume to encode 1st fragment
    tls_session->outlen_encoded = tls_session->outbuf.len - 2;
    tls_session->curr_outmsg_start = tls_session->outbuf.len - 0x20;
    tls_session->curr_outmsg_len = tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    tls_session->curr_outmsg_len += 2 + tls_session->ext_enc_total_len;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_EQUAL_UINT16(tls_session->outbuf.len, tls_session->outlen_encoded);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts); // none of extension entries is encoded
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[0], tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->last_ext_entry_enc_len);
    tlsDecodeWord16(
        &tls_session->outbuf.data[tls_session->outbuf.len - 2], (word16 *)&actual_value
    );
    expect_value = 0;
    for (idx = 0; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value += 2 + 2 + mock_extension_content_len[idx];
    } // end of for loop
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    // assume to encode 2nd fragment
    tls_session->outlen_encoded = 0;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x0, tls_session->last_ext_entry_enc_len);
    encoded_ext_start = &tls_session->outbuf.data[0];
    // loop through all extension entries, which are in the same fragment.
    for (idx = 0; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value = mock_extension_types[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = mock_extension_content_len[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_ext_start += mock_extension_content_len[idx];
    } // end of for loop

    expect_value = (word16)(encoded_ext_start - &tls_session->outbuf.data[0]);
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    TEST_ASSERT_LESS_THAN_UINT(tls_session->outbuf.len, tls_session->outlen_encoded);

    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsEncodeExtensions, split_total_length_case2)

TEST(tlsEncodeExtensions, split_1st_ext_item_case1) {
    byte         *encoded_ext_start = NULL;
    word32        expect_value = 0;
    word32        actual_value = 0;
    tlsRespStatus status = TLS_RESP_OK;
    const byte    nbytes_in_first_frag = 1;
    byte          idx = 0;

    // assume to encode 1st fragment
    tls_session->outlen_encoded = tls_session->outbuf.len - 2 - nbytes_in_first_frag;
    tls_session->curr_outmsg_start = tls_session->outbuf.len - 0x20;
    tls_session->curr_outmsg_len = tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    tls_session->curr_outmsg_len += 2 + tls_session->ext_enc_total_len;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_EQUAL_UINT16(tls_session->outbuf.len, tls_session->outlen_encoded);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts); // none of extension entries is encoded
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[0], tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT16(nbytes_in_first_frag, tls_session->last_ext_entry_enc_len);
    tlsDecodeWord16(
        &tls_session->outbuf.data[tls_session->outbuf.len - 2 - nbytes_in_first_frag],
        (word16 *)&actual_value
    );
    expect_value = 0;
    for (idx = 0; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value += 2 + 2 + mock_extension_content_len[idx];
    } // end of for loop
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    // assume to encode 2nd fragment
    tls_session->outlen_encoded = 0;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x0, tls_session->last_ext_entry_enc_len);
    actual_value =
        (tls_session->outbuf.data[tls_session->outbuf.len - 1] << 8) | tls_session->outbuf.data[0];
    expect_value = mock_extension_types[0];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    encoded_ext_start = &tls_session->outbuf.data[1];
    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    encoded_ext_start += mock_extension_content_len[0];
    expect_value = mock_extension_content_len[0];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    // loop through rest of extension items, which should be in the second fragment in this test
    // case.
    for (idx = 1; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value = mock_extension_types[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = mock_extension_content_len[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_ext_start += mock_extension_content_len[idx];
    } // end of for loop

    expect_value = (word16)(encoded_ext_start - &tls_session->outbuf.data[0]);
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    TEST_ASSERT_LESS_THAN_UINT(tls_session->outbuf.len, tls_session->outlen_encoded);

    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsEncodeExtensions, split_1st_ext_item_case1)

TEST(tlsEncodeExtensions, split_1st_ext_item_case2) {
    byte         *encoded_ext_start = NULL;
    word32        expect_value = 0;
    word32        actual_value = 0;
    tlsRespStatus status = TLS_RESP_OK;
    const byte    nbytes_in_first_frag = 2;
    byte          idx = 0;

    // assume to encode 1st fragment
    tls_session->outlen_encoded = tls_session->outbuf.len - 2 - nbytes_in_first_frag;
    tls_session->curr_outmsg_start = tls_session->outbuf.len - 0x20;
    tls_session->curr_outmsg_len = tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    tls_session->curr_outmsg_len += 2 + tls_session->ext_enc_total_len;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts); // none of extension entries is encoded
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[0], tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT16(nbytes_in_first_frag, tls_session->last_ext_entry_enc_len);
    encoded_ext_start = &tls_session->outbuf.data[tls_session->outbuf.len - nbytes_in_first_frag];
    tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    expect_value = mock_extension_types[0];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    // assume to encode 2nd fragment
    tls_session->outlen_encoded = 0;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x0, tls_session->last_ext_entry_enc_len);
    // 2-byte length field, and the content field of the first extension item, should be entirely
    // in the second fragment, skip it
    encoded_ext_start = &tls_session->outbuf.data[0];
    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    encoded_ext_start += mock_extension_content_len[0];
    expect_value = mock_extension_content_len[0];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    // loop through rest of extension items, which should be in the second fragment in this test
    // case.
    for (idx = 1; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value = mock_extension_types[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = mock_extension_content_len[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_ext_start += mock_extension_content_len[idx];
    } // end of for loop
    expect_value = (word16)(encoded_ext_start - &tls_session->outbuf.data[0]);
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsEncodeExtensions, split_1st_ext_item_case2)

TEST(tlsEncodeExtensions, split_1st_ext_item_case3) {
    byte         *encoded_ext_start = NULL;
    word32        expect_value = 0;
    word32        actual_value = 0;
    tlsRespStatus status = TLS_RESP_OK;
    const byte    nbytes_in_first_frag = 3;
    byte          idx = 0;

    // assume to encode 1st fragment
    tls_session->outlen_encoded = tls_session->outbuf.len - 2 - nbytes_in_first_frag;
    tls_session->curr_outmsg_start = tls_session->outbuf.len - 0x20;
    tls_session->curr_outmsg_len = tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    tls_session->curr_outmsg_len += 2 + tls_session->ext_enc_total_len;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts); // none of extension entries is encoded
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[0], tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT16(nbytes_in_first_frag, tls_session->last_ext_entry_enc_len);
    encoded_ext_start = &tls_session->outbuf.data[tls_session->outbuf.len - nbytes_in_first_frag];
    tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    expect_value = mock_extension_types[0];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    // assume to encode 2nd fragment
    tls_session->outlen_encoded = 0;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x0, tls_session->last_ext_entry_enc_len);
    // the 2-byte length field of the first extension item should be split into 2 different fragment
    // (for transmission), in this test, the length field at here should be the last byte of first
    // fragment followed by the first byte of of second fragment.
    actual_value =
        (tls_session->outbuf.data[tls_session->outbuf.len - 1] << 8) | tls_session->outbuf.data[0];
    expect_value = mock_extension_content_len[0];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    // content bytes of the first extension item should be entirely in the second fragment, skip it
    encoded_ext_start = &tls_session->outbuf.data[1];
    encoded_ext_start += mock_extension_content_len[0];
    // loop through rest of extension items, which should be in the second fragment in this test
    // case.
    for (idx = 1; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value = mock_extension_types[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = mock_extension_content_len[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_ext_start += mock_extension_content_len[idx];
    } // end of for loop
    expect_value = (word16)(encoded_ext_start - &tls_session->outbuf.data[0]);
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsEncodeExtensions, split_1st_ext_item_case3)

TEST(tlsEncodeExtensions, split_1st_ext_item_case4) {
    byte         *encoded_ext_start = NULL;
    word32        expect_value = 0;
    word32        actual_value = 0;
    tlsRespStatus status = TLS_RESP_OK;
    const byte    nbytes_in_first_frag = 4;
    byte          idx = 0;

    // assume to encode 1st fragment
    tls_session->outlen_encoded = tls_session->outbuf.len - 2 - nbytes_in_first_frag;
    tls_session->curr_outmsg_start = tls_session->outbuf.len - 0x20;
    tls_session->curr_outmsg_len = tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    tls_session->curr_outmsg_len += 2 + tls_session->ext_enc_total_len;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts); // none of extension entries is encoded
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[0], tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT16(nbytes_in_first_frag, tls_session->last_ext_entry_enc_len);
    encoded_ext_start = &tls_session->outbuf.data[tls_session->outbuf.len - nbytes_in_first_frag];
    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    expect_value = mock_extension_types[0];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    expect_value = mock_extension_content_len[0];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    // assume to encode 2nd fragment
    tls_session->outlen_encoded = 0;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x0, tls_session->last_ext_entry_enc_len);
    // content bytes of the first extension item should be entirely in the second fragment, skip it
    encoded_ext_start = &tls_session->outbuf.data[mock_extension_content_len[0]];
    // loop through rest of extension items, which should be in the second fragment in this test
    // case.
    for (idx = 1; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value = mock_extension_types[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = mock_extension_content_len[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_ext_start += mock_extension_content_len[idx];
    } // end of for loop
    expect_value = (word16)(encoded_ext_start - &tls_session->outbuf.data[0]);
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsEncodeExtensions, split_1st_ext_item_case4)

TEST(tlsEncodeExtensions, split_1st_ext_item_content) {
    byte         *encoded_ext_start = NULL;
    word32        expect_value = 0;
    word32        actual_value = 0;
    tlsRespStatus status = TLS_RESP_OK;
    // should be greater than 4 bytes (2-byte type field + 2-byte length field)
    // , less than (and equal to) 4 + mock_extension_content_len[0] bytes
    word16 nbytes_in_first_frag = 5;
    word16 idx = 0;

    // assume to encode 1st fragment
    tls_session->outlen_encoded = tls_session->outbuf.len - 2 - nbytes_in_first_frag;
    tls_session->curr_outmsg_start = tls_session->outbuf.len - 0x20;
    tls_session->curr_outmsg_len = tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    tls_session->curr_outmsg_len += 2 + tls_session->ext_enc_total_len;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts); // none of extension entries is encoded
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[0], tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT16(nbytes_in_first_frag, tls_session->last_ext_entry_enc_len);
    encoded_ext_start = &tls_session->outbuf.data[tls_session->outbuf.len - nbytes_in_first_frag];
    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    expect_value = mock_extension_types[0];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    expect_value = mock_extension_content_len[0];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    // assume to encode 2nd fragment
    tls_session->outlen_encoded = 0;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x0, tls_session->last_ext_entry_enc_len);
    // check content field of the first extension item, it is split between first and second
    // fragments
    for (idx = 0; idx < (nbytes_in_first_frag - 4); idx++) {
        expect_value = (mock_extension_content_len[0] + idx) & 0xff;
        actual_value = *encoded_ext_start++;
        TEST_ASSERT_EQUAL_UINT8(expect_value, actual_value);
    } // end of for loop
    encoded_ext_start = &tls_session->outbuf.data[0];
    for (idx = (nbytes_in_first_frag - 4); idx < mock_extension_content_len[0]; idx++) {
        expect_value = (mock_extension_content_len[0] + idx) & 0xff;
        actual_value = *encoded_ext_start++;
        TEST_ASSERT_EQUAL_UINT8(expect_value, actual_value);
    } // end of for loop
    // loop through rest of extension items, which should be in the second fragment in this test
    // case.
    encoded_ext_start =
        &tls_session->outbuf.data[mock_extension_content_len[0] - nbytes_in_first_frag + 4];
    for (idx = 1; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value = mock_extension_types[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = mock_extension_content_len[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_ext_start += mock_extension_content_len[idx];
    } // end of for loop
    expect_value = (word16)(encoded_ext_start - &tls_session->outbuf.data[0]);
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsEncodeExtensions, split_1st_ext_item_content)

TEST(tlsEncodeExtensions, split_2nd_ext_item_case1) {
    byte         *encoded_ext_start = NULL;
    word32        expect_value = 0;
    word32        actual_value = 0;
    tlsRespStatus status = TLS_RESP_OK;
    word16        nbytes_in_first_frag = 4 + mock_extension_content_len[0] + 1;
    byte          idx = 0;

    // assume to encode 1st fragment
    tls_session->outlen_encoded = tls_session->outbuf.len - 2 - nbytes_in_first_frag;
    tls_session->curr_outmsg_start = tls_session->outbuf.len - 0x20;
    tls_session->curr_outmsg_len = tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    tls_session->curr_outmsg_len += 2 + tls_session->ext_enc_total_len;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts); // none of extension entries is encoded
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[1], tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT16(
        (nbytes_in_first_frag - 4 - mock_extension_content_len[0]),
        tls_session->last_ext_entry_enc_len
    );
    // first extension item should be entirely encoded in the first fragment, time to check this.
    encoded_ext_start = &tls_session->outbuf.data[tls_session->outbuf.len - nbytes_in_first_frag];
    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    expect_value = mock_extension_types[0];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    encoded_ext_start += mock_extension_content_len[0];
    expect_value = mock_extension_content_len[0];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    // assume to encode 2nd fragment
    tls_session->outlen_encoded = 0;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x0, tls_session->last_ext_entry_enc_len);
    // 2-byte type field of the second extension item, is seperated in the last byte of first
    // fragment, and the first byte of the second fragment.
    actual_value =
        (tls_session->outbuf.data[tls_session->outbuf.len - 1] << 8) | tls_session->outbuf.data[0];
    expect_value = mock_extension_types[1];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    // rest of the second extension item should be in the second fragment
    encoded_ext_start = &tls_session->outbuf.data[1];
    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    encoded_ext_start += mock_extension_content_len[1];
    expect_value = mock_extension_content_len[1];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    // loop through rest of extension items, all of which should be in the second fragment in this
    // test case.
    for (idx = 2; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        expect_value = mock_extension_types[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        expect_value = mock_extension_content_len[idx];
        encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
        TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
        encoded_ext_start += mock_extension_content_len[idx];
    } // end of for loop
    expect_value = (word16)(encoded_ext_start - &tls_session->outbuf.data[0]);
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsEncodeExtensions, split_2nd_ext_item_case1)

TEST(tlsEncodeExtensions, split_2nd_ext_item_case2) {
    byte         *encoded_ext_start = NULL;
    word32        expect_value = 0;
    word32        actual_value = 0;
    tlsRespStatus status = TLS_RESP_OK;
    word16        nbytes_in_first_frag = 4 + mock_extension_content_len[0] + 2;
    byte          idx = 0;

    // assume to encode 1st fragment
    tls_session->outlen_encoded = tls_session->outbuf.len - 2 - nbytes_in_first_frag;
    tls_session->curr_outmsg_start = tls_session->outbuf.len - 0x20;
    tls_session->curr_outmsg_len = tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    tls_session->curr_outmsg_len += 2 + tls_session->ext_enc_total_len;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts); // none of extension entries is encoded
    TEST_ASSERT_EQUAL_UINT16(mock_extension_types[1], tls_session->exts->type);
    // skip first extension item, jump to start of second extension item
    encoded_ext_start = &tls_session->outbuf.data[tls_session->outbuf.len - nbytes_in_first_frag];
    encoded_ext_start += 4 + mock_extension_content_len[0];
    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    expect_value = mock_extension_types[1];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    // assume to encode 2nd fragment
    tls_session->outlen_encoded = 0;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x0, tls_session->last_ext_entry_enc_len);
    // rest of the second extension item should be in the second fragment
    encoded_ext_start = &tls_session->outbuf.data[0];
    encoded_ext_start += tlsDecodeWord16(encoded_ext_start, (word16 *)&actual_value);
    encoded_ext_start += mock_extension_content_len[1];
    expect_value = mock_extension_content_len[1];
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    // loop through rest of extension items, all of which should be in the second fragment in this
    // test case.
    for (idx = 2; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        encoded_ext_start += 4 + mock_extension_content_len[idx];
    } // end of for loop
    expect_value = (word16)(encoded_ext_start - &tls_session->outbuf.data[0]);
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsEncodeExtensions, split_2nd_ext_item_case2)

TEST(tlsEncodeExtensions, with_psk_binder_multi_frags) {
    tlsPSK_t      *mock_psk_list = NULL;
    tlsPSK_t      *pskitem = NULL;
    tlsExtEntry_t *prev_ext = NULL;
    tlsExtEntry_t *curr_ext = NULL;
    word32         expect_value = 0;
    word32         actual_value = 0;
    word16         nbytes_total_binder = 0;
    word16         nbytes_total_pskID = 0;
    word16         nbytes_psk_ext = 0;
    word16         nbytes_in_first_frag = 0;
    tlsRespStatus  status = TLS_RESP_OK;
    byte          *buf = NULL;
    byte           idx = 0;
    const word16   mock_psk_ID_len[2] = {0xc, 0xf};
    const byte     mock_psk_binder_len[2] = {0x30, 0x20};
    tlsHash_t      mock_hash_obj[2] = {0};

    tls_session->sec.hashed_hs_msg.objsha256 = &mock_hash_obj[0];
    tls_session->sec.hashed_hs_msg.objsha384 = &mock_hash_obj[1];

    // assume 2 pre-shared keys will be encoded.
    tls_session->sec.psk_list = &mock_psk_list;
    pskitem = mock_createEmptyPSKitem(mock_psk_ID_len[0], mock_psk_binder_len[0], 4);
    mock_psk_list = pskitem;
    pskitem = mock_createEmptyPSKitem(mock_psk_ID_len[1], mock_psk_binder_len[1], 7);
    mock_psk_list->next = pskitem;
    nbytes_total_binder = 2 + (1 + mock_psk_binder_len[0]) + (1 + mock_psk_binder_len[1]);
    nbytes_total_pskID = 2 + (2 + mock_psk_ID_len[0] + 4) + (2 + mock_psk_ID_len[1] + 4);
    nbytes_psk_ext = nbytes_total_pskID + nbytes_total_binder;
    for (curr_ext = tls_session->exts; curr_ext != NULL; curr_ext = curr_ext->next) {
        prev_ext = curr_ext;
    } // end of for loop
    curr_ext = mock_createEmptyExtensionItem(TLS_EXT_TYPE_PRE_SHARED_KEY, nbytes_psk_ext);
    prev_ext->next = curr_ext;
    tls_session->ext_enc_total_len = tlsGetExtListSize(tls_session->exts);
    tls_session->sec.psk_binder_ptr.ext = &curr_ext->content.data[nbytes_total_pskID];
    tls_session->sec.psk_binder_ptr.len = nbytes_total_binder;
    tlsEncodeWord16(&curr_ext->content.data[0], nbytes_total_pskID);
    buf = &curr_ext->content.data[nbytes_total_pskID];
    buf += tlsEncodeWord16(buf, nbytes_total_binder);
    for (idx = 0; idx < 2; idx++) {
        *buf++ = mock_psk_binder_len[idx];
        buf += mock_psk_binder_len[idx];
    } // end of for loop
    TEST_ASSERT_EQUAL_UINT(&curr_ext->content.data[nbytes_psk_ext], buf);

    // assume to encode 1st fragment
    nbytes_in_first_frag = 0;
    for (idx = 0; idx < TEST_NUM_EXTENSION_ITEMS; idx++) {
        nbytes_in_first_frag += 4 + mock_extension_content_len[idx];
    } // end of for loop
    nbytes_in_first_frag +=
        4 + nbytes_total_pskID + 1; // 2-byte length field of PSK binder should be split.
    tls_session->outlen_encoded = tls_session->outbuf.len - 2 - nbytes_in_first_frag;
    tls_session->curr_outmsg_start = 0x10;
    tls_session->curr_outmsg_len = tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    tls_session->curr_outmsg_len += 2 + tls_session->ext_enc_total_len;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_REQ_MOREDATA, status);
    TEST_ASSERT_NOT_EQUAL(NULL, tls_session->exts); // none of extension entries is encoded
    // part of PSK extension item should be encoded in the first fragment
    TEST_ASSERT_EQUAL_UINT16(TLS_EXT_TYPE_PRE_SHARED_KEY, tls_session->exts->type);
    TEST_ASSERT_EQUAL_UINT((4 + nbytes_total_pskID + 1), tls_session->last_ext_entry_enc_len);

    // assume to encode 2nd fragment
    tls_session->remain_frags_out = 1;
    tls_session->num_frags_out = 1;
    tls_session->outlen_encoded = 0;
    status = tlsEncodeExtensions(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x0, tls_session->last_ext_entry_enc_len);
    // 2-byte type field of PSK binder section is seperated in the last byte of first fragment,
    // and the first byte of the second fragment.
    actual_value =
        (tls_session->outbuf.data[tls_session->outbuf.len - 1] << 8) | tls_session->outbuf.data[0];
    expect_value = nbytes_total_binder;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);
    buf = &tls_session->outbuf.data[1];
    for (idx = 0; idx < 2; idx++) {
        actual_value = *buf++;
        expect_value = mock_psk_binder_len[idx];
        buf += mock_psk_binder_len[idx];
        TEST_ASSERT_EQUAL_UINT8(expect_value, actual_value);
    } // end of for loop
    expect_value = (word16)(buf - &tls_session->outbuf.data[0]);
    actual_value = tls_session->outlen_encoded;
    TEST_ASSERT_EQUAL_UINT16(expect_value, actual_value);

    tlsFreePSKentry(mock_psk_list->next);
    tlsFreePSKentry(mock_psk_list);
    tls_session->sec.psk_list = NULL;
    tls_session->sec.hashed_hs_msg.objsha256 = NULL;
    tls_session->sec.hashed_hs_msg.objsha384 = NULL;
    TEST_ASSERT_EQUAL_UINT(NULL, tls_session->exts);
} // end of TEST(tlsEncodeExtensions, with_psk_binder_multi_frags)

static void RunAllTestGroups(void) {
    tls_session = (tlsSession_t *)XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->outbuf.len = MAX_RAWBYTE_BUF_SZ;
    tls_session->outbuf.data = (byte *)XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);

    RUN_TEST_GROUP(tlsGenExtensions);
    RUN_TEST_GROUP(tlsEncodeExtensions);

    XMEMFREE(tls_session->outbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups

int main(int argc, const char *argv[]) {
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main
