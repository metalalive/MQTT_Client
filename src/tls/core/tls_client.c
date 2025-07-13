#include "mqtt_include.h"

// CA certificate which signed remote broker's certificate for this TLS client
// this MQTT/TLS implementation is supposed to run on microcontroller-based platform
// (with limited memory), not consume huge space to store long CA certificate chain,
// so I only store a single CA certificate for verifying broker. User applications
// SHOULD avoid long CA certificate chain.
static tlsCert_t *inner_broker_cacert;

// client's private key and certificate for 2-way authentication, used only when server requests
// client authentication via Certificate, in that case, client has to send certificate (in
// Certificate message), and signature (in CertificateVerify) to server.
// Note the client's certificate does not have to be CA.
static void      *inner_client_privkey;
static tlsCert_t *inner_client_cert;

// a ready list of PSKs contains :
// * a preserved pre-shared key from NewSessionTicket of previous secure connection (if exists),
// * PSKs that are explicitly established by user applications.
// Note that PSK is useful to make future connection more effecient, see section 2-2 in RFC8446.
static tlsPSK_t *tls_PSKs_rdy_list;

// set up RNG function, hash, and encryption functions in third-party library if necessary.
TLS_CFG_REG_3PARTY_CRYPTO_FN(tlsRegister3partyCryptoFn);

static tlsRespStatus
tlsInitCertHelper(tlsCert_t **cp, mqttRespStatus (*get_raw_data)(byte **, word16 *)) {
    word32     cert_len = 0;
    const byte final_item_rdy = 0x1;
    tlsCert_t *c = (tlsCert_t *)XMALLOC(sizeof(tlsCert_t));
    *cp = c;
    XMEMSET(c, 0x0, sizeof(tlsCert_t));
    get_raw_data(&c->rawbytes.data, (word16 *)&cert_len);
    XASSERT((cert_len > 0xff) && (cert_len <= TLS_MAX_BYTES_CERT_CHAIN));
    XASSERT(c->rawbytes.data != NULL);
    tlsEncodeWord24(&c->rawbytes.len[0], cert_len);
    return tlsDecodeCerts(c, final_item_rdy);
}

static void tlsFreeCertHelper(tlsCert_t **cp) {
    // raw bytes of given cert should be placed in .rodata section, which means
    // the memory cannot be deallocted , so simply set rawbytes to NULL.
    tlsCert_t *c = *cp;
    if (c != NULL) {
        c->rawbytes.data = NULL;
        tlsFreeCertChain(c, TLS_FREE_CERT_ENTRY_ALL);
        *cp = NULL;
    }
}

tlsRespStatus tlsClientInit(mqttCtx_t *mctx) {
    tlsRespStatus status = TLS_RESP_OK;
    // register RNG (Random Number Generator) associated functions to third-party crypto library
    tlsRegister3partyCryptoFn(mctx);
    // will add new PSK as soon as this client receives NewSessionTicket handshaking message
    // , which provides essential ingredient to build a PSK
    tls_PSKs_rdy_list = NULL;
    // load essential elements from CA private key, currently this implementation ONLY supports RSA
    // key
    const byte *priv_key_raw_data = NULL;
    word16      priv_key_raw_len = 0;
    mqttAuthClientPrivKeyRaw(&priv_key_raw_data, &priv_key_raw_len);
    if (priv_key_raw_data == NULL || priv_key_raw_len == 0) {
        status = TLS_RESP_ERRMEM;
        goto fail;
    }
    // this project forces 2-way authentication
    inner_client_privkey = NULL;
    status = tlsRSAgetPrivKey(priv_key_raw_data, priv_key_raw_len, &inner_client_privkey);
    if ((status < 0) || (inner_client_privkey == NULL)) {
        goto fail;
    }
    // load essential elements from external certificates.
    inner_broker_cacert = inner_client_cert = NULL;
    // note there's no way to verify client's cert in this project
    status = tlsInitCertHelper(&inner_client_cert, mqttAuthClientCertRaw);
    if (status < 0) {
        goto fail;
    }
    status = tlsInitCertHelper(&inner_broker_cacert, mqttAuthCACertBrokerRaw);
    if (status < 0) {
        goto fail;
    }
    // verify self-signed cert (the decoded CA cert) at here
    status = tlsVerifyCertChain(NULL, inner_broker_cacert);
    if (status < 0) {
        goto fail;
    }
    tlsFreeCertChain(inner_broker_cacert, TLS_FREE_CERT_ENTRY_SIGNATURE);
    goto done;
fail:
    tlsRSAfreePrivKey(inner_client_privkey);
    inner_client_privkey = NULL;
    tlsFreeCertHelper(&inner_broker_cacert);
    tlsFreeCertHelper(&inner_client_cert);
done:
    return status;
} // end of tlsClientInit

void tlsClientDeInit(mqttCtx_t *mctx) {
    while (tls_PSKs_rdy_list != NULL) {
        tlsPSK_t *prev_psk = tls_PSKs_rdy_list;
        tlsRemoveItemFromList(
            (tlsListItem_t **)&tls_PSKs_rdy_list, (tlsListItem_t *)tls_PSKs_rdy_list
        );
        tlsFreePSKentry(prev_psk);
    } // delete entire list of PSKs
    if (mctx->drbg != NULL) {
        mqttDRBGdeinit(mctx->drbg);
        mctx->drbg = NULL;
    }
    tlsFreeCertHelper(&inner_broker_cacert);
    tlsFreeCertHelper(&inner_client_cert);
    tlsRSAfreePrivKey(inner_client_privkey);
    inner_client_privkey = NULL;
}

static tlsRespStatus tlsClientSessionCreate(tlsSession_t **session) {
    if (session == NULL) {
        return TLS_RESP_ERRARGS;
    }
    if (inner_broker_cacert == NULL) {
        return TLS_RESP_ERR;
    }
    tlsSession_t *s = NULL;
    byte         *buf = NULL;
    word16        len = 0;

    len = sizeof(tlsSession_t) + TLS_DEFAULT_IN_BUF_BYTES + TLS_DEFAULT_OUT_BUF_BYTES;
    buf = XMALLOC(sizeof(byte) * len);
    XMEMSET(buf, 0x00, sizeof(byte) * len);
    s = (tlsSession_t *)buf;
    buf += sizeof(tlsSession_t);
    // initialize (receive) in buffer
    s->inbuf.len = TLS_DEFAULT_IN_BUF_BYTES;
    s->inbuf.data = (byte *)buf;
    buf += TLS_DEFAULT_IN_BUF_BYTES;
    // initialize (send) out buffer
    s->outbuf.len = TLS_DEFAULT_OUT_BUF_BYTES;
    s->outbuf.data = (byte *)buf;
    // load a list of available PSKs, which may include the PSK of previously successful connection,
    // (th PSK was received from New Session Ticket message of previously successful connection )
    // , or user-specified PSKs.
    s->sec.psk_list = &tls_PSKs_rdy_list;
    // the initail record type  is handshake(22), it will be changed whenever received message
    // (from the server) does not meet protocol requirement, or handshake is successfully completed
    // and both client and server start sending application-level message.
    s->record_type = TLS_CONTENT_TYPE_HANDSHAKE;
    // pass CA certificate & (optional) corresponding private key to currently established session
    s->broker_cacert = inner_broker_cacert;
    s->client_cert = inner_client_cert;
    s->client_privkey = inner_client_privkey;
    *session = s;
    return TLS_RESP_OK;
} // end of tlsClientSessionCreate

static tlsRespStatus tlsClientSessionDelete(tlsSession_t *session) {
    if (session == NULL) {
        return TLS_RESP_ERRARGS;
    }
    tlsSession_t          *s = session;
    tlsSecurityElements_t *sec = &s->sec;
    if (s != NULL) {
        XMEMSET(&s->ext_sysobjs[0], 0x00, sizeof(void *) * MQTT_MAX_NUM_EXT_SYSOBJS);
        // clean up data for symmetric encryption
        if (sec->chosen_ciphersuite) {
            sec->chosen_ciphersuite->done_fn(&s->sec);
            sec->chosen_ciphersuite = NULL;
        }
        if (sec->secret.app.mst.data != NULL) {
            XMEMFREE((void *)sec->secret.app.mst.data);
            sec->secret.app.mst.data = NULL;
            sec->secret.app.client.data = NULL;
            sec->secret.app.server.data = NULL;
            sec->secret.app.resumption.data = NULL;
        }
        s->inbuf.data = NULL;
        s->outbuf.data = NULL;
        XMEMFREE((void *)s);
    }
    return TLS_RESP_OK;
} // end of tlsClientSessionDelete

// this integrated function provides entry point to communite between application-lever MQTT message
// and TLS
mqttRespStatus mqttSecureNetconnStart(mqttCtx_t *mctx) {
    if (mctx == NULL) {
        return MQTT_RESP_ERRARGS;
    }
    mqttRespStatus status = MQTT_RESP_OK;
    tlsRespStatus  tls_status = TLS_RESP_OK;
    tlsSession_t  *session = NULL;
    // Initialize DRBG if we haven't done that
    if (mctx->drbg == NULL) {
        status = mqttDRBGinit(&mctx->drbg);
        if (status != MQTT_RESP_OK) {
            return status;
        }
    }
    status = mqttSysNetconnStart(mctx);
    if (status != MQTT_RESP_OK) {
        return status;
    }
    //// mqttAuthGetBrokerHost( &mctx->broker_host, &mctx->broker_port );
    // create new secure session
    tls_status = tlsClientSessionCreate(&session);
    if (tls_status >= 0) {
        // Here are shared items between mqttCtx_t and tlsSession_t
        session->cmd_timeout_ms = mctx->cmd_timeout_ms;
        session->server_name = mctx->broker_host;
        session->drbg = mctx->drbg;
        XMEMCPY(
            &session->ext_sysobjs[0], &mctx->ext_sysobjs[0],
            sizeof(void *) * MQTT_MAX_NUM_EXT_SYSOBJS
        );
        mctx->secure_session = (void *)session;
        tls_status = tlsClientStartHandshake(session); // start handshaking process
    }
    if (tls_status < 0) {
        mctx->secure_session = NULL;
        tlsClientSessionDelete(session);
    }
    status = tlsRespCvtToMqttResp(tls_status);
    return status;
} // end of mqttSecureNetconnStart

mqttRespStatus mqttSecureNetconnStop(mqttCtx_t *mctx) {
    if (mctx == NULL) {
        return MQTT_RESP_ERRARGS;
    }
    if (mctx->secure_session != NULL) {
        tlsClientSessionDelete((tlsSession_t *)mctx->secure_session);
        mctx->secure_session = NULL;
    }
    return mqttSysNetconnStop(mctx);
} // end of mqttSecureNetconnStop

int mqttSecurePktSend(mqttCtx_t *mctx, byte *buf, word32 buf_len) {
    if (mctx == NULL || mctx->secure_session == NULL || buf == NULL || buf_len == 0) {
        return MQTT_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    tlsSession_t *session = mctx->secure_session;
    status = tlsChkHSfinished(session);
    if (status < 0) {
        goto done;
    }
    session->record_type = TLS_CONTENT_TYPE_APP_DATA;
    session->app_pt.len = (word16)buf_len;
    session->app_pt.data = buf;
    do {
        status = tlsEncodeRecordLayer(session);
        if (status < 0) {
            goto done;
        }
        status = tlsEncryptRecordMsg(session);
        if (status < 0) {
            goto done;
        }
        status = tlsPktSendToPeer(session, 0x1);
        if (status < 0) {
            goto done;
        }
    } while (tlsChkFragStateOutMsg(session) != TLS_RESP_REQ_REINIT);
done:
    session->record_type = TLS_CONTENT_TYPE_HANDSHAKE;
    return (status < 0) ? (int)tlsRespCvtToMqttResp(status) : buf_len;
} // end of mqttSecurePktSend

int mqttSecurePktRecv(mqttCtx_t *mctx, byte *buf, word32 buf_len) {
    tlsRespStatus status = TLS_RESP_OK;
    if (mctx == NULL || mctx->secure_session == NULL || buf == NULL) {
        return MQTT_RESP_ERRARGS;
    }
    if (buf_len == 0) {
        goto done;
    }
    word16        nbytes_avail = 0;
    tlsSession_t *session = mctx->secure_session;
    status = tlsChkHSfinished(session);
    if (status < 0) {
        goto done;
    }
    session->app_pt.len = (word16)buf_len;
    session->app_pt.data = buf;
    do {
        nbytes_avail = tlsGetUndecodedNumBytes(session);
        if (nbytes_avail == 0) {
            status = tlsPktRecvFromPeer(session);
            if (status < 0) {
                goto done;
            }
            status = tlsDecryptRecordMsg(session);
            if (status < 0) {
                goto done;
            }
        }
        status = tlsDecodeRecordLayer(session);
        if (status < 0) {
            goto done;
        }
        nbytes_avail = tlsGetUndecodedNumBytes(session);
        if (nbytes_avail == 0) {
            tlsDecrementFragNumInMsg(session);
        }
    } while (session->app_pt.len > 0);
done:
    return (status < 0) ? (int)tlsRespCvtToMqttResp(status) : buf_len;
} // end of mqttSecurePktRecv
