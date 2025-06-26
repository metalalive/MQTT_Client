#include "mqtt_include.h"

extern const tlsNamedGrp tls_supported_named_groups[];

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

static tlsRespStatus
tlsGenEphemeralKeyPairByGrp(mqttDRBG_t *drbg, void **keyout, tlsNamedGrp grp_id) {
    tlsRespStatus status = TLS_RESP_OK;
    int           keysize = 0;
    if ((drbg == NULL) || (keyout == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    keysize = (int)tlsKeyExGetKeySize(grp_id);
    switch (grp_id
    ) { // TODO: support other key-exchange methods if there is more memory in hardware platform
    case TLS_NAMED_GRP_SECP256R1:
    case TLS_NAMED_GRP_SECP384R1:
    case TLS_NAMED_GRP_SECP521R1:
        if ((*keyout) == NULL) {
            *keyout = XMALLOC(sizeof(tlsECCkey_t));
        }
        TLS_CFG_KEYEX_ECC_GEN_KEY_FN(status, drbg, *keyout, keysize);
        break;
    case TLS_NAMED_GRP_X25519:
        if ((*keyout) == NULL) {
            *keyout = XMALLOC(sizeof(tlsX25519Key_t));
        }
        TLS_CFG_KEYEX_X25519_GEN_KEY_FN(status, drbg, *keyout);
        break;
    default:
        status = TLS_RESP_ERRARGS;
        break;
    } // end of switch-case statement
    return status;
} // end of tlsGenEphemeralKeyPairByGrp

tlsRespStatus tlsFreeEphemeralKeyPairByGrp(void *keyout, tlsNamedGrp grp_id) {
    if (keyout == NULL) {
        return TLS_RESP_ERRARGS;
    }
    switch (grp_id) {
    case TLS_NAMED_GRP_SECP256R1:
    case TLS_NAMED_GRP_SECP384R1:
    case TLS_NAMED_GRP_SECP521R1:
        TLS_CFG_KEYEX_ECC_FREE_KEY_FN(keyout);
        break;
    case TLS_NAMED_GRP_X25519:
        TLS_CFG_KEYEX_X25519_FREE_KEY_FN(keyout);
        break;
    default:
        return TLS_RESP_ERRARGS;
    } // end of switch-case statement
    XMEMFREE(keyout);
    return TLS_RESP_OK;
} // end of tlsFreeEphemeralKeyPairByGrp

tlsRespStatus
tlsExportPubValKeyShare(byte *out, tlsNamedGrp grp_id, void *chosen_key, word16 chosen_key_sz) {
    if (chosen_key == NULL || out == NULL) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    switch (grp_id) {
    case TLS_NAMED_GRP_SECP256R1:
    case TLS_NAMED_GRP_SECP384R1:
    case TLS_NAMED_GRP_SECP521R1:
        TLS_CFG_KEYEX_ECC_EXPORT_PUBVAL_FN(status, out, chosen_key, chosen_key_sz);
        break;
    case TLS_NAMED_GRP_X25519:
        TLS_CFG_KEYEX_X25519_EXPORT_PUBVAL_FN(status, out, chosen_key, chosen_key_sz);
        break;
    default:
        status = TLS_RESP_ERRARGS;
        break;
    } // end of switch-case statement
    return status;
} // end of tlsExportPubValKeyShare

tlsRespStatus
tlsImportPubValKeyShare(byte *in, word16 inlen, tlsNamedGrp grp_id, void **chosen_key) {
    if (chosen_key == NULL || in == NULL) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    switch (grp_id) {
    case TLS_NAMED_GRP_SECP256R1:
    case TLS_NAMED_GRP_SECP384R1:
    case TLS_NAMED_GRP_SECP521R1: {
        if (*chosen_key == NULL) {
            *chosen_key = XMALLOC(sizeof(tlsECCkey_t));
        }
        const tlsECCcurve_t *cu = NULL;
        TLS_CFG_KEYEX_ECC_GET_CURVE_FN(status, grp_id, &cu);
        if (cu == NULL) {
            status = TLS_RESP_ERR_KEYGEN;
            break;
        }
        TLS_CFG_KEYEX_ECC_IMPORT_PUBVAL_FN(status, in, inlen, *chosen_key, cu);
        break;
    }
    case TLS_NAMED_GRP_X25519:
        if (*chosen_key == NULL) {
            *chosen_key = XMALLOC(sizeof(tlsX25519Key_t));
        }
        TLS_CFG_KEYEX_X25519_IMPORT_PUBVAL_FN(status, in, inlen, *chosen_key);
        break;
    default:
        status = TLS_RESP_ERRARGS;
        break;
    } // end of switch-case statement
    return status;
} // end of tlsImportPubValKeyShare

tlsRespStatus tlsGenEphemeralKeyPairs(mqttDRBG_t *drbg, tlsKeyEx_t *keyexp) {
    if ((drbg == NULL) || (keyexp == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    byte          ngrps_chosen = 0;
    byte          ngrps_max = keyexp->num_grps_total;
    byte          idx = keyexp->chosen_grp_idx;
    // in this implementation, client chooses 2 different key-exchange methods to generate 2 key
    // pairs accordingly and send the public part to its remote peer, if the peer (server) can
    // recognize & accept one of the key-exchange methods. The the peer will reply with its key
    // share extension in its ServerHello back to client, otherwise if the peer cannot recognize
    // both of them, the peer might return either Alert message or HelloRetryRequest back to client,
    // then client chooses another 2 key-exchange methods and negotiates again.
    if (idx < ngrps_max) { // check whether caller specifies any key-exchange algorithm
        if (keyexp->grp_nego_state[idx] == TLS_KEYEX_STATE_RENEGO_HRR) {
            // generate key share only when the client received first ClientHelloRetry (from server)
            // that indicate the peer will NOT use the key share of previous ClientHello
            ngrps_chosen = 1;
            if (keyexp->keylist[idx] == NULL) {
                status = tlsGenEphemeralKeyPairByGrp(
                    drbg, &keyexp->keylist[idx], tls_supported_named_groups[idx]
                );
            }
        } else {
            status = TLS_RESP_ERR_ENCODE;
        }
    } else if (idx == ngrps_max) { // if not specifying any algorithm, we choose first two available
                                   // algorithms to generate keys
        for (idx = 0; (idx < ngrps_max) && (ngrps_chosen < TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO);
             idx++) {
            if (keyexp->grp_nego_state[idx] == TLS_KEYEX_STATE_NOT_NEGO_YET) {
                status = tlsGenEphemeralKeyPairByGrp(
                    drbg, &keyexp->keylist[idx], tls_supported_named_groups[idx]
                );
                if (status != TLS_RESP_OK) {
                    break;
                }
                // after sending out the key share within ClientHello, this client will set the
                // state to TLS_KEYEX_STATE_NOT_APPLY for negotiation failure or
                // TLS_KEYEX_STATE_APPLIED if the peer decided to use this key-exchange method to
                // generate common shared secret. or client sets the state to
                // TLS_KEYEX_STATE_RENEGO_HRR when receiving HelloRetryRequest from the perr
                keyexp->grp_nego_state[idx] = TLS_KEYEX_STATE_NEGOTIATING;
                ngrps_chosen++;
            }
        } // end of for-loop
        // return error because the client already negotiated with all available key-exchange
        // methods (using all the supported named groups) without success from its peer
        if ((idx == ngrps_max) && (ngrps_chosen == 0)) {
            status = TLS_RESP_ERR_NO_KEYEX_MTHD_AVAIL;
        }
    } else {
        status = TLS_RESP_ERR;
        XASSERT(0);
    }
    keyexp->num_grps_chosen = ngrps_chosen;
    return status;
} // end of tlsGenEphemeralKeyPairs

void tlsFreeEphemeralKeyPairs(tlsKeyEx_t *keyexp) { // clean up all generated ephemeral keys
    if (keyexp == NULL) {
        return;
    }
    byte ngrps_max = keyexp->num_grps_total;
    byte idx = 0;
    for (idx = 0; idx < ngrps_max; idx++) {
        if (keyexp->keylist[idx] != NULL) {
            tlsFreeEphemeralKeyPairByGrp(keyexp->keylist[idx], tls_supported_named_groups[idx]);
            keyexp->keylist[idx] = NULL;
        }
    } // end of for-loop
} // end of tlsFreeEphemeralKeyPairs

tlsRespStatus tlsECDHEgenSharedSecret(tlsSession_t *session, tlsOpaque8b_t *out) {
    if ((session == NULL) || (out == NULL) ||
        (session->sec.agreed_keyex_named_grp == TLS_NAMED_GRP_UNALLOCATED_RESERVED)) {
        return TLS_RESP_ERRARGS;
    }
    if ((session->sec.ephemeralkeylocal == NULL) || (session->sec.ephemeralkeyremote == NULL)) {
        return TLS_RESP_ERRARGS;
    }

    tlsRespStatus status = TLS_RESP_OK;
    if (out->data != NULL) {
        XMEMFREE((void *)out->data);
    }
    out->len = tlsKeyExGetKeySize(session->sec.agreed_keyex_named_grp);
    out->data = XMALLOC(sizeof(byte) * out->len);
    switch (session->sec.agreed_keyex_named_grp) {
    case TLS_NAMED_GRP_SECP256R1:
    case TLS_NAMED_GRP_SECP384R1:
    case TLS_NAMED_GRP_SECP521R1:
        TLS_CFG_GEN_SHARED_SECRET_ECC_FN(
            status, session->sec.ephemeralkeylocal, session->sec.ephemeralkeyremote, out->data,
            out->len
        );
        break;
    case TLS_NAMED_GRP_X25519:
        TLS_CFG_GEN_SHARED_SECRET_X25519_FN(
            status, session->sec.ephemeralkeylocal, session->sec.ephemeralkeyremote, out->data,
            out->len
        );
        break;
    default:
        status = TLS_RESP_ERR_NOT_SUPPORT;
        break;
    } // end of switch case statement
    return status;
} // end of tlsECDHEgenSharedSecret
