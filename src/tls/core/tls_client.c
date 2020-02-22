#include "mqtt_include.h"


extern   tlsPSK_t    *tls_PSKs_rdy_list;
extern   tlsCert_t   *tls_CA_cert;
extern   void        *tls_CA_priv_key;


// set up RNG function, hash, and encryption functions in third-party library if necessary.
TLS_CFG_REG_3PARTY_CRYPTO_FN( tlsRegister3partyCryptoFn );


tlsRespStatus  tlsClientInit(mqttCtx_t *mctx)
{
    word32  cert_len = 0;
    tlsRespStatus status = TLS_RESP_OK;
    const byte final_item_rdy = 0x1;
    // register RNG (Random Number Generator) associated functions to third-party crypto library
    tlsRegister3partyCryptoFn(mctx);
    // will add new PSK as soon as this client receives NewSessionTicket handshaking message
    // , which provides essential ingredient to build a PSK
    tls_PSKs_rdy_list = NULL;
    // load essential elements from CA private key, currently this implementation ONLY supports RSA key
    const byte *priv_key_raw_data = NULL;
    word16      priv_key_raw_len = 0;
    mqttAuthGetCAprivKeyRawBytes(&priv_key_raw_data, &priv_key_raw_len);
    if(priv_key_raw_data == NULL || priv_key_raw_len == 0) {
        status = TLS_RESP_ERRMEM; goto fail;
    }
    tls_CA_priv_key = NULL;
    status = tlsRSAgetPrivKey(priv_key_raw_data, priv_key_raw_len, &tls_CA_priv_key);
    if((status < 0) || (tls_CA_priv_key == NULL)) { goto fail; }
    // load essential elements from CA certificate.
    tls_CA_cert = (tlsCert_t *) XMALLOC(sizeof(tlsCert_t));
    XMEMSET(tls_CA_cert, 0x0, sizeof(tlsCert_t));
    mqttAuthGetCertRawBytes(&tls_CA_cert->rawbytes.data, (word16 *)&cert_len);
    XASSERT((cert_len > 0xff) && (cert_len <= TLS_MAX_BYTES_CERT_CHAIN));
    XASSERT(tls_CA_cert->rawbytes.data != NULL);
    tlsEncodeWord24(&tls_CA_cert->rawbytes.len[0], cert_len);
    status = tlsDecodeCerts(tls_CA_cert, final_item_rdy);
    if(status < 0) { goto fail; }
    // verify self-signed cert (the decoded CA cert) at here
    status = tlsVerifyCertChain(NULL, tls_CA_cert);
    if(status < 0) { goto fail; }
    tlsFreeCertChain(tls_CA_cert, TLS_FREE_CERT_ENTRY_SIGNATURE);
    goto done;
fail:
    tlsRSAfreePrivKey(tls_CA_priv_key);
    tls_CA_priv_key = NULL;
    // raw bytes of CA cert will be placed in .rodata section, which means the memory cannot be deallocted
    // , so simply set rawbytes to NULL.
    if(tls_CA_cert != NULL) {
        tls_CA_cert->rawbytes.data = NULL;
        tlsFreeCertChain(tls_CA_cert, TLS_FREE_CERT_ENTRY_ALL);
        tls_CA_cert = NULL;
    }
done:
    return status;
} // end of tlsClientInit



void  tlsClientDeInit(mqttCtx_t *mctx)
{
    while(tls_PSKs_rdy_list != NULL) {
        tlsPSK_t *prev_psk = tls_PSKs_rdy_list;
        tlsRemoveItemFromList((tlsListItem_t **)&tls_PSKs_rdy_list, (tlsListItem_t *)tls_PSKs_rdy_list);
        tlsFreePSKentry(prev_psk);
    } // delete entire list of PSKs
    if(mctx->drbg != NULL) {
        mqttDRBGdeinit(mctx->drbg);
        mctx->drbg = NULL;
    }
    if(tls_CA_cert != NULL) {
        tls_CA_cert->rawbytes.data = NULL;
        tlsFreeCertChain(tls_CA_cert, TLS_FREE_CERT_ENTRY_ALL);
        tls_CA_cert = NULL;
    }
    tlsRSAfreePrivKey(tls_CA_priv_key);
    tls_CA_priv_key = NULL;
} // end of tlsClientDeInit



static tlsRespStatus   tlsClientSessionCreate(tlsSession_t **session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    if(tls_CA_cert == NULL) { return TLS_RESP_ERR; }
    tlsSession_t  *s = NULL;
    byte        *buf = NULL;
    word16       len = 0;

    len = sizeof(tlsSession_t) + TLS_DEFAULT_IN_BUF_BYTES + TLS_DEFAULT_OUT_BUF_BYTES;
    buf = XMALLOC(sizeof(byte) * len);
    XMEMSET(buf, 0x00, sizeof(byte) * len);
    s = (tlsSession_t *) buf;
    buf += sizeof(tlsSession_t);
    // initialize (receive) in buffer
    s->inbuf.len  = TLS_DEFAULT_IN_BUF_BYTES;
    s->inbuf.data = (byte *) buf;
    buf += TLS_DEFAULT_IN_BUF_BYTES;
    // initialize (send) out buffer
    s->outbuf.len  = TLS_DEFAULT_OUT_BUF_BYTES;
    s->outbuf.data = (byte *) buf;
    // load a list of available PSKs, which may include the PSK of previously successful connection,
    // (th PSK was received from New Session Ticket message of previously successful connection )
    // , or user-specified PSKs.
    s->sec.psk_list = &tls_PSKs_rdy_list;
    // the initail record type  is handshake(22), it will be changed whenever received message
    // (from the server) does not meet protocol requirement, or handshake is successfully completed
    // and both client and server start sending application-level message.
    s->record_type = TLS_CONTENT_TYPE_HANDSHAKE;
    // pass CA certificate & (optional) corresponding private key to currently established session
    s->CA_cert     = tls_CA_cert;
    s->CA_priv_key = tls_CA_priv_key;
    *session = s;
    return TLS_RESP_OK;
} // end of tlsClientSessionCreate



static tlsRespStatus    tlsClientSessionDelete(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsSession_t  *s = session;
    tlsSecurityElements_t  *sec = &s->sec;
    if(s != NULL) {
        XMEMSET(&s->ext_sysobjs[0], 0x00, sizeof(void *) * MQTT_MAX_NUM_EXT_SYSOBJS);
        // clean up data for symmetric encryption
        if(sec->chosen_ciphersuite) {
            sec->chosen_ciphersuite->done_fn( &s->sec );
            sec->chosen_ciphersuite = NULL;
        }
        if(sec->secret.app.mst.data != NULL) {
            XMEMFREE((void *)sec->secret.app.mst.data);
            sec->secret.app.mst.data    = NULL;
            sec->secret.app.client.data = NULL;
            sec->secret.app.server.data = NULL;
            sec->secret.app.resumption.data = NULL;
        }
        s->inbuf.data  = NULL;
        s->outbuf.data = NULL;
        XMEMFREE((void *)s);
    }
    return TLS_RESP_OK; 
} // end of tlsClientSessionDelete



// this integrated function provides entry point to communite between application-lever MQTT message and TLS
mqttRespStatus   mqttSecureNetconnStart(mqttCtx_t *mctx)
{
    if(mctx == NULL) { return MQTT_RESP_ERRARGS; }
    mqttRespStatus  status     = MQTT_RESP_OK;
    tlsRespStatus   tls_status = TLS_RESP_OK;
    tlsSession_t   *session    = NULL;
    // Initialize DRBG if we haven't done that
    if(mctx->drbg == NULL) {
        status = mqttDRBGinit(&mctx->drbg);
        if(status != MQTT_RESP_OK) { return status; }
    }
    status = mqttSysNetconnStart( mctx );
    if(status != MQTT_RESP_OK) { return status; }
    //// mqttAuthGetBrokerHost( &mctx->broker_host, &mctx->broker_port );
    // create new secure session
    tls_status = tlsClientSessionCreate(&session);
    if(tls_status >= 0) {
        // Here are shared items between mqttCtx_t and tlsSession_t
        session->cmd_timeout_ms = mctx->cmd_timeout_ms;
        session->server_name = mctx->broker_host;
        session->drbg        = mctx->drbg;
        XMEMCPY( &session->ext_sysobjs[0], &mctx->ext_sysobjs[0] , sizeof(void *) * MQTT_MAX_NUM_EXT_SYSOBJS );
        mctx->secure_session = (void *)session;
        tls_status = tlsClientStartHandshake( session ); // start handshaking process
    }
    if(tls_status < 0) {
        mctx->secure_session = NULL;
        tlsClientSessionDelete(session);
    }
    status = tlsRespCvtToMqttResp( tls_status );
    return status;
} // end of mqttSecureNetconnStart



mqttRespStatus   mqttSecureNetconnStop(mqttCtx_t *mctx)
{
    if(mctx == NULL) {  return MQTT_RESP_ERRARGS; }
    if(mctx->secure_session != NULL) {
        tlsClientSessionDelete((tlsSession_t *)mctx->secure_session);
        mctx->secure_session = NULL;
    }
    return  mqttSysNetconnStop( mctx );
} // end of mqttSecureNetconnStop


int  mqttSecurePktSend(mqttCtx_t *mctx, byte *buf, word32 buf_len)
{
    if(mctx == NULL || mctx->secure_session == NULL || buf == NULL || buf_len == 0) {
        return MQTT_RESP_ERRARGS;
    }
    tlsRespStatus   status = TLS_RESP_OK;
    tlsSession_t  *session = mctx->secure_session;
    status = tlsChkHSfinished(session);
    if(status < 0) { goto done; }
    session->record_type = TLS_CONTENT_TYPE_APP_DATA;
    session->app_pt.len  = (word16) buf_len;
    session->app_pt.data = buf;
    do {
        status = tlsEncodeRecordLayer(session);
        if(status < 0) { goto done; }
        status = tlsEncryptRecordMsg(session);
        if(status < 0) { goto done; }
        status = tlsPktSendToPeer(session, 0x1);
        if(status < 0) { goto done; }
    } while (tlsChkFragStateOutMsg(session) != TLS_RESP_REQ_REINIT);
done:
    session->record_type = TLS_CONTENT_TYPE_HANDSHAKE;
    return (status < 0) ? (int)tlsRespCvtToMqttResp(status): buf_len;
} // end of mqttSecurePktSend


int  mqttSecurePktRecv(mqttCtx_t *mctx, byte *buf, word32 buf_len)
{
    if(mctx == NULL || mctx->secure_session == NULL || buf == NULL || buf_len == 0) {
        return MQTT_RESP_ERRARGS;
    }
    word16    nbytes_avail = 0;
    tlsRespStatus   status = TLS_RESP_OK;
    tlsSession_t  *session = mctx->secure_session;
    status = tlsChkHSfinished(session);
    if(status < 0) { goto done; }
    session->app_pt.len  = (word16) buf_len;
    session->app_pt.data = buf;
    do {
        nbytes_avail = tlsGetUndecodedNumBytes(session);
        if(nbytes_avail == 0) {
            status = tlsPktRecvFromPeer(session);
            if(status < 0) { goto done; }
            status = tlsDecryptRecordMsg(session);
            if(status < 0) { goto done; }
        }
        status = tlsDecodeRecordLayer(session);
        if(status < 0) { goto done; }
        nbytes_avail = tlsGetUndecodedNumBytes(session);
        if(nbytes_avail == 0) {
            tlsDecrementFragNumInMsg(session);
        }
    } while (session->app_pt.len > 0);
done:
    return (status < 0) ? (int)tlsRespCvtToMqttResp(status): buf_len;
} // end of mqttSecurePktRecv


