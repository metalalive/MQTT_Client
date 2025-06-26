#include "mqtt_include.h"

// section 7.1 , Key Schedule, RFC8446
//
// Derive-Secret(Secret, Label, Messages)
//    = HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
//
static tlsRespStatus tlsDeriveSecret(
    tlsHashAlgoID hash_id, tlsOpaque8b_t *in_secret, tlsOpaque8b_t *label, tlsOpaque8b_t *trHashMsg,
    tlsOpaque8b_t *out_secret
) {
    tlsRespStatus status = TLS_RESP_OK;
    tlsOpaque8b_t trHashRdy = {0, NULL};
    word16        hash_sz = mqttHashGetOutlenBytes(hash_id);
    if ((hash_sz != in_secret->len) || (hash_sz != out_secret->len)) {
        return TLS_RESP_ERRARGS;
    }
    if (trHashMsg == NULL) {
        status = tlsCpyHashEmptyInput(
            hash_id, &trHashRdy
        ); // MUST NOT modify the hashed empty string from this function
        if (status < 0) {
            goto end_of_derive;
        }
    } else {
        if (hash_sz > trHashMsg->len) {
            return TLS_RESP_ERRARGS;
        }
        trHashRdy.len = trHashMsg->len;
        trHashRdy.data = trHashMsg->data;
    }
    status = tlsHKDFexpandLabel(hash_id, in_secret, label, &trHashRdy, out_secret);
end_of_derive:
    return status;
} // end of tlsDeriveSecret

tlsRespStatus tlsGenEarlySecret(
    const tlsCipherSpec_t *cs, tlsPSK_t *pskin, tlsOpaque8b_t *out
) { // HKDF-Extract(PSK) = Early Secret
    if ((cs == NULL && pskin == NULL) || (out == NULL) || (out->data == NULL) || (out->len == 0)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    tlsHashAlgoID hash_algo_id = TLS_HASH_ALGO_UNKNOWN;
    word16        hash_sz = 0;
    tlsOpaque8b_t pskval = {0, NULL};
    tlsOpaque8b_t zerosalt = {0, NULL};
    // HKDF-extract(psk, 0....0) = early secret
    if (pskin != NULL) { // TODO: check if early secret for the chosen PSK was already generated
                         // when encoding ClientHello with PSK binders
        hash_algo_id = tlsGetHashAlgoIDBySize((word16)pskin->key.len);
        hash_sz = mqttHashGetOutlenBytes((mqttHashLenType)hash_algo_id);
        if (hash_sz == 0) {
            status = TLS_RESP_ERR_HASH;
            goto end_of_gen;
        }
        pskval.len = (word16)pskin->key.len;
        pskval.data = pskin->key.data;
    } else { // for NULL psk, early secret = HKDF-extract(0...0, 0....0)
        hash_algo_id = TLScipherSuiteGetHashID(cs);
        hash_sz = mqttHashGetOutlenBytes(hash_algo_id);
        if (hash_sz == 0) {
            status = TLS_RESP_ERR_HASH;
            goto end_of_gen;
        }
        pskval.len = hash_sz;
        pskval.data = XMALLOC(sizeof(byte) * pskval.len);
        XMEMSET(pskval.data, 0x00, sizeof(byte) * pskval.len);
    }
    zerosalt.len = pskval.len;
    zerosalt.data = XMALLOC(sizeof(byte) * zerosalt.len);
    XMEMSET(zerosalt.data, 0x00, sizeof(byte) * zerosalt.len);
    status = tlsHKDFextract(hash_algo_id, hash_sz, out, &pskval, &zerosalt);
end_of_gen:
    if (pskin == NULL) {
        if (pskval.data != NULL) {
            XMEMFREE((void *)pskval.data);
            pskval.data = NULL;
        }
    }
    if (zerosalt.data != NULL) {
        XMEMFREE((void *)zerosalt.data);
        zerosalt.data = NULL;
    }
    return status;
} // end of tlsGenEarlySecret

tlsRespStatus tlsDerivePSKbinderKey(tlsPSK_t *pskin, tlsOpaque8b_t *out) {
    if ((pskin == NULL) || (pskin->key.data == NULL) || (pskin->id.data == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if ((out == NULL) || (out->len == 0) || (out->data == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsOpaque8b_t earlysecret = {0, NULL};
    tlsOpaque8b_t bindersecret = {0, NULL};
    tlsOpaque8b_t label = {0, NULL};
    tlsHashAlgoID hash_id = TLS_HASH_ALGO_UNKNOWN;
    word16        hash_sz = 0;
    tlsRespStatus status = TLS_RESP_OK;

    hash_id = tlsGetHashAlgoIDBySize((word16)pskin->key.len);
    hash_sz = mqttHashGetOutlenBytes((mqttHashLenType)hash_id);
    if (hash_sz != out->len) {
        status = TLS_RESP_ERRARGS;
        goto done;
    }
    earlysecret.len = hash_sz;
    bindersecret.len = hash_sz;
    earlysecret.data = XMALLOC(sizeof(byte) * (hash_sz << 1));
    bindersecret.data = &earlysecret.data[hash_sz];
    // step #1 : generate early secret with given PSK
    status = tlsGenEarlySecret(NULL, pskin, &earlysecret);
    if (status < 0) {
        goto done;
    }
    // step #2 : derive binder secret with early secret, and either of the labels below
    if (pskin->flgs.is_resumption == 0) {
        label.data = (byte *)&("ext binder");
        label.len = 10;
    } else {
        label.data = (byte *)&("res binder");
        label.len = 10;
    }
    status = tlsDeriveSecret(hash_id, &earlysecret, &label, NULL, &bindersecret);
    if (status < 0) {
        goto done;
    }
    // step #3: derive binder key with "finished" label, everything else is the same as
    //   finish_key is derived in tlsGenFinishedVerifyData()
    label.data = (byte *)&("finished");
    label.len = 8;
    status = tlsHKDFexpandLabel(hash_id, &bindersecret, &label, NULL, out);
done:
    if (earlysecret.data != NULL) {
        XMEMFREE((void *)earlysecret.data);
        earlysecret.data = NULL;
        bindersecret.data = NULL;
    }
    return status;
} // end of tlsDerivePSKbinderKey

tlsRespStatus tlsDeriveHStrafficSecret(tlsSession_t *session, tlsOpaque8b_t *earlysecret_in) {
    if ((session == NULL) || (earlysecret_in == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if ((earlysecret_in->data == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if ((earlysecret_in->len == 0)) {
        return TLS_RESP_ERRARGS;
    }
    tlsSecurityElements_t *sec = &session->sec;
    tlsRespStatus          status = TLS_RESP_OK;
    tlsHashAlgoID          hash_algo_id = TLS_HASH_ALGO_UNKNOWN;
    word16                 hash_sz = 0;
    tlsOpaque8b_t          derivedlabel = {7, (byte *)&("derived")};
    tlsOpaque8b_t          derived_secret = {0, NULL};
    tlsOpaque8b_t          shared_secret = {0, NULL};

    hash_algo_id = TLScipherSuiteGetHashID(sec->chosen_ciphersuite);
    hash_sz = mqttHashGetOutlenBytes(hash_algo_id);
    if (hash_sz != earlysecret_in->len) {
        return TLS_RESP_ERRARGS;
    }
    derived_secret.len = hash_sz;
    derived_secret.data = XMALLOC(sizeof(byte) * derived_secret.len);
    // Derive-Secret(early secret, "derived", "")
    status = tlsDeriveSecret(hash_algo_id, earlysecret_in, &derivedlabel, NULL, &derived_secret);
    if (status < 0) {
        goto end_of_derive;
    }
    // generate (EC)DHE shared secret
    status = tlsECDHEgenSharedSecret(session, &shared_secret);
    if (status < 0) {
        goto end_of_derive;
    }
    //  HKDF-Extract(derived_secret, ECDHE shared_secret) = handshake secret
    sec->secret.hs.hs.len =
        hash_sz; // must free up the space after master secret of the session is generated
    sec->secret.hs.hs.data = XMALLOC(sizeof(byte) * sec->secret.hs.hs.len * 4);
    sec->secret.hs.client.len = hash_sz;
    sec->secret.hs.client.data = &sec->secret.hs.hs.data[hash_sz];
    sec->secret.hs.server.len = hash_sz;
    sec->secret.hs.server.data = &sec->secret.hs.hs.data[hash_sz << 1];
    status =
        tlsHKDFextract(hash_algo_id, hash_sz, &sec->secret.hs.hs, &shared_secret, &derived_secret);
    if (status < 0) {
        goto end_of_derive;
    }
    // get TrHash(ClientHello...ServerHello)
    tlsOpaque8b_t trHash_CHtoSH = {
        derived_secret.len, derived_secret.data
    }; // reuse the allocated memory in derived_secret
    status =
        tlsTransHashTakeSnapshot(sec, hash_algo_id, trHash_CHtoSH.data, (word16)trHash_CHtoSH.len);
    if (status < 0) {
        goto end_of_derive;
    }
    // Derive-Secret(handshake secret, "c hs traffic", | TrHash(ClientHello...ServerHello)) =
    // client_handshake_traffic_secret
    tlsOpaque8b_t clientlabel = {12, (byte *)&("c hs traffic")};
    status = tlsDeriveSecret(
        hash_algo_id, &sec->secret.hs.hs, &clientlabel, &trHash_CHtoSH, &sec->secret.hs.client
    );
    if (status < 0) {
        goto end_of_derive;
    }
    // Derive-Secret(handshake secret, "s hs traffic", | TrHash(ClientHello...ServerHello)) =
    // server_handshake_traffic_secret
    tlsOpaque8b_t serverlabel = {12, (byte *)&("s hs traffic")};
    status = tlsDeriveSecret(
        hash_algo_id, &sec->secret.hs.hs, &serverlabel, &trHash_CHtoSH, &sec->secret.hs.server
    );
end_of_derive:
    if (earlysecret_in->data != NULL) {
        XMEMFREE((void *)earlysecret_in->data);
        earlysecret_in->data = NULL;
    } // it is safe to free up early secret from here
    if (derived_secret.data != NULL) {
        XMEMFREE((void *)derived_secret.data);
        derived_secret.data = NULL;
    }
    if (shared_secret.data != NULL) {
        XMEMFREE((void *)shared_secret.data);
        shared_secret.data = NULL;
    }
    return status;
} // end of tlsDeriveHStrafficSecret

tlsRespStatus tlsDeriveAPPtrafficSecret(tlsSession_t *session) {
    if ((session == NULL) || (session->sec.chosen_ciphersuite == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsSecurityElements_t *sec = &session->sec;
    if ((sec->hashed_hs_msg.snapshot_server_finished == NULL) || (sec->secret.hs.hs.data == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsHashAlgoID hash_id = TLS_HASH_ALGO_UNKNOWN;
    word16        hash_sz = 0;
    tlsOpaque8b_t derivedlabel = {7, (byte *)&("derived")};
    tlsOpaque8b_t derived_secret = {0, NULL};
    tlsOpaque8b_t tmp = {0, NULL};
    tlsRespStatus status = TLS_RESP_OK;

    hash_id = TLScipherSuiteGetHashID(sec->chosen_ciphersuite);
    hash_sz = mqttHashGetOutlenBytes(hash_id);
    if (hash_sz != sec->secret.hs.hs.len) {
        return TLS_RESP_ERRARGS;
    }
    derived_secret.len = hash_sz;
    derived_secret.data = XMALLOC(sizeof(byte) * hash_sz * 2);
    // Derive-Secret(handshake secret, "derived", "") --> derived secret
    status = tlsDeriveSecret(hash_id, &sec->secret.hs.hs, &derivedlabel, NULL, &derived_secret);
    if (status < 0) {
        goto end_of_derive;
    }
    // HKDF-Extract(derived_secret, 0...0) = master secret
    // Note that (1) sec->secret.hs  and  sec->secret.app  share the same allocated space.
    // (2) RFC8446, page 92, "0" indicates a string of Hash.length bytes set to zero.
    tmp.len = hash_sz;
    tmp.data = &derived_secret.data[hash_sz];
    XMEMSET(tmp.data, 0x00, sizeof(byte) * tmp.len);
    status = tlsHKDFextract(hash_id, hash_sz, &sec->secret.app.mst, &tmp, &derived_secret);
    if (status < 0) {
        goto end_of_derive;
    }
    // Derive-Secret(master secret, "c ap traffic", | TrHash(ClientHello...server Finished)) =
    // client_application_traffic_secret_0
    tmp.data = sec->hashed_hs_msg.snapshot_server_finished;
    tlsOpaque8b_t clientlabel = {12, (byte *)&("c ap traffic")};
    status =
        tlsDeriveSecret(hash_id, &sec->secret.app.mst, &clientlabel, &tmp, &sec->secret.app.client);
    if (status < 0) {
        goto end_of_derive;
    }
    // Derive-Secret(master secret, "s ap traffic", | TrHash(ClientHello...server Finished)) =
    // server_application_traffic_secret_0
    tlsOpaque8b_t serverlabel = {12, (byte *)&("s ap traffic")};
    status =
        tlsDeriveSecret(hash_id, &sec->secret.app.mst, &serverlabel, &tmp, &sec->secret.app.server);
    if (status < 0) {
        goto end_of_derive;
    }
    // generate resumption master secret,
    // Derive-Secret(master secret, "res master", | TrHash(ClientHello...client Finished)) =
    // resumption_master_secret
    tmp.data = &derived_secret.data[hash_sz];
    status = tlsTransHashTakeSnapshot(&session->sec, hash_id, tmp.data, tmp.len);
    if (status < 0) {
        goto end_of_derive;
    }
    sec->secret.app.resumption.len = sec->secret.app.mst.len;
    sec->secret.app.resumption.data = &sec->secret.app.mst.data[hash_sz * 3];
    tlsOpaque8b_t resumptionlabel = {10, (byte *)&("res master")};
    status = tlsDeriveSecret(
        hash_id, &sec->secret.app.mst, &resumptionlabel, &tmp, &sec->secret.app.resumption
    );
end_of_derive:
    if (derived_secret.data != NULL) {
        XMEMFREE((void *)derived_secret.data);
        derived_secret.data = NULL;
    }
    return status;
} // end of tlsDeriveAPPtrafficSecret

// RFC 8446, section 7.3 Traffic Keying material is calculated with following inputs :
// * A secret value, [sender]_handshake_traffic_secret  or  [sender]_application_traffic_secret_N
// * length of the key being generated
// * The fomulars below
// [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
// [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
//
// This routine updates read key, read IV (for decrypting encrypted packets from server)
// , or write key, write IV (for encrypting out-flight packets & send to server)
tlsRespStatus tlsDeriveTraffickey(
    tlsSecurityElements_t *sec, tlsOpaque8b_t *in_rd_secret, tlsOpaque8b_t *in_wr_secret
) {
    if (sec == NULL || in_rd_secret == NULL || in_wr_secret == NULL) {
        return TLS_RESP_ERRARGS;
    }
    if ((sec->chosen_ciphersuite == NULL) || (in_rd_secret->data == NULL) ||
        (in_wr_secret->data == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsHashAlgoID hash_id = TLScipherSuiteGetHashID(sec->chosen_ciphersuite);
    if ((hash_id == TLS_HASH_ALGO_UNKNOWN) || (hash_id == TLS_HASH_ALGO_NOT_NEGO)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    // read key / write key are determined in client's perspective
    //// tlsOpaque8b_t  *in_rd_secret = &sec->secret.hs.server;
    //// tlsOpaque8b_t  *in_wr_secret = &sec->secret.hs.client;
    tlsOpaque8b_t keylabel = {3, (byte *)&("key")};
    tlsOpaque8b_t ivlabel = {2, (byte *)&("iv")};
    tlsOpaque8b_t out = {0, NULL};
    // generate read key & IV
    out.data = &sec->readKey[0];
    out.len = sec->chosen_ciphersuite->keySize;
    status = tlsHKDFexpandLabel(hash_id, in_rd_secret, &keylabel, NULL, &out);
    if (status < 0) {
        goto end_of_gen_hs_key;
    }
    out.data = &sec->readIV[0];
    out.len = sec->chosen_ciphersuite->ivSize;
    status = tlsHKDFexpandLabel(hash_id, in_rd_secret, &ivlabel, NULL, &out);
    if (status < 0) {
        goto end_of_gen_hs_key;
    }
    // generate write key & IV
    out.data = &sec->writeKey[0];
    out.len = sec->chosen_ciphersuite->keySize;
    status = tlsHKDFexpandLabel(hash_id, in_wr_secret, &keylabel, NULL, &out);
    if (status < 0) {
        goto end_of_gen_hs_key;
    }
    out.data = &sec->writeIV[0];
    out.len = sec->chosen_ciphersuite->ivSize;
    status = tlsHKDFexpandLabel(hash_id, in_wr_secret, &ivlabel, NULL, &out);
end_of_gen_hs_key:
    return status;
} // end of tlsDeriveTraffickey

static tlsRespStatus tlsActivateHSkeyHelper(
    tlsSecurityElements_t *sec, const tlsCipherSpec_t *cs, const byte isDecrypt
) {
    if ((sec == NULL) || (cs == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    // recheck if we get correct cipher suite, the returned tlsCipherSpec_t item must be
    // from the static list tls_supported_cipher_suites
    const tlsCipherSpec_t *expected_cs = tlsGetCipherSuiteByID(cs->ident);
    if (expected_cs != cs) {
        return TLS_RESP_ERRARGS;
    }
    // perform init function for decryption
    return cs->init_fn(sec, isDecrypt);
} // end of tlsActivateHSkeyHelper

tlsRespStatus tlsActivateReadKey(tlsSecurityElements_t *sec) {
    const byte isDecrypt = 0x1;
    return tlsActivateHSkeyHelper(sec, sec->chosen_ciphersuite, isDecrypt);
} // end of tlsActivateReadKey

tlsRespStatus tlsActivateWriteKey(tlsSecurityElements_t *sec) {
    const byte isDecrypt = 0x0;
    return tlsActivateHSkeyHelper(sec, sec->chosen_ciphersuite, isDecrypt);
} // end of tlsActivateWriteKey
