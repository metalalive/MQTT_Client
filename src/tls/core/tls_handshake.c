#include "mqtt_include.h"


static void tlsAllocSpaceBeforeKeyEx(tlsSession_t *session)
{
    word16 len = 0;
    // initialize key-exchange structure
    session->keyex.num_grps_total = tlsGetSupportedKeyExGrpSize();
    len = sizeof(tlsKeyExState) * session->keyex.num_grps_total;
    session->keyex.grp_nego_state = (tlsKeyExState *) XMALLOC((size_t)len);
    XMEMSET( session->keyex.grp_nego_state, 0x00, (size_t)len );
    // create a list of pointers, pointed to different key structures (e.g. ECC, X25519, DH)
    len = sizeof(void *) * session->keyex.num_grps_total;
    session->keyex.keylist = (void **) XMALLOC((size_t)len);
    XMEMSET( session->keyex.keylist, 0x00, (size_t)len );
    // chosen_grp_idx  should NOT be greater than num_grps_total, here we set num_grps_total as default value
    // which means we haven't found appropriate named groups / key exchange algorithm
    session->keyex.chosen_grp_idx = session->keyex.num_grps_total;
    // allocate space for early hankshake phase.
    session->sec.client_rand = XMALLOC(sizeof(byte) * TLS_HS_RANDOM_BYTES);
    session->sec.server_rand = XMALLOC(sizeof(byte) * TLS_HS_RANDOM_BYTES);
    session->tmpbuf.session_id.len  = TLS_MAX_BYTES_SESSION_ID;
    session->tmpbuf.session_id.data = XMALLOC(sizeof(byte) * TLS_MAX_BYTES_SESSION_ID);
} // end of tlsAllocSpaceBeforeKeyEx


static void tlsCleanSpaceAfterKeyEx(tlsSession_t *session)
{
    if(session->tmpbuf.session_id.data != NULL) {
        XMEMFREE((void *)session->tmpbuf.session_id.data);
        session->tmpbuf.session_id.data = NULL;
    }
    if(session->sec.client_rand != NULL) {
        XMEMFREE((void *)session->sec.client_rand);
        session->sec.client_rand = NULL;
    }
    if(session->sec.server_rand != NULL) {
        XMEMFREE((void *)session->sec.server_rand);
        session->sec.server_rand = NULL;
    }
    // deallocate generated but unused key(s) after key-exchange algorithm is negotiated
    tlsFreeEphemeralKeyPairs(&session->keyex);
    if( session->keyex.keylist != NULL ) {
        XMEMFREE((void *)session->keyex.keylist);
        session->keyex.keylist = NULL;
    }
    if( session->keyex.grp_nego_state != NULL ){
        XMEMFREE((void *)session->keyex.grp_nego_state);
        session->keyex.grp_nego_state = NULL;
    }
} // end of tlsCleanSpaceAfterKeyEx


static void tlsCleanSpaceAfterGenHSkeys(tlsSession_t *session)
{ // clean up security elements of the session
    tlsFreeEphemeralKeyPairByGrp( session->sec.ephemeralkeyremote, session->sec.agreed_keyex_named_grp ); // ignore the return code
    tlsFreeEphemeralKeyPairByGrp( session->sec.ephemeralkeylocal,  session->sec.agreed_keyex_named_grp ); // ignore the return code
    session->sec.ephemeralkeyremote = NULL;
    session->sec.ephemeralkeylocal  = NULL;
} // end of tlsCleanSpaceAfterGenHSkeys



void tlsCleanSpaceOnClientCertSent(tlsSession_t *session)
{
    if(session->flgs.omit_client_cert_chk == 0) {
        if(session->tmpbuf.cert_req_ctx.data != NULL) {
            XMEMFREE((void *)session->tmpbuf.cert_req_ctx.data);
            session->tmpbuf.cert_req_ctx.data = NULL;
        }
    }
} // end of tlsCleanSpaceOnClientCertSent


static void tlsCleanSpaceAfterHS(tlsSession_t *session)
{   // if handshake process aborted in the middle, then we must clean up space with
    // respect to the current handshake state
    switch(tlsGetHSexpectedState(session)) {
        case TLS_HS_TYPE_CLIENT_HELLO  :
        case TLS_HS_TYPE_SERVER_HELLO  :
            tlsCleanSpaceAfterKeyEx(session);
        case TLS_HS_TYPE_ENCRYPTED_EXTENSIONS:
            tlsCleanSpaceAfterGenHSkeys(session);
        case TLS_HS_TYPE_CERTIFICATE_REQUEST:
        case TLS_HS_TYPE_CERTIFICATE:
        case TLS_HS_TYPE_CERTIFICATE_VERIFY:
        case TLS_HS_TYPE_FINISHED:
            tlsCleanSpaceOnClientCertSent(session);
            tlsFreeCertChain(session->peer_certs, TLS_FREE_CERT_ENTRY_ALL);            
        default:
            break;
    } // end of switch case

    session->sec.agreed_keyex_named_grp = TLS_NAMED_GRP_UNALLOCATED_RESERVED;
} // end of tlsCleanSpaceAfterHS


tlsHandshakeType  tlsGetHSexpectedState(tlsSession_t *session)
{
    return (session==NULL ? TLS_HS_TYPE_HELLO_REQUEST_RESERVED: session->hs_state);
} // end of tlsGetHSexpectedState



// handshake state transition on client's perspective
void   tlsHSstateTransition(tlsSession_t *session)
{
    switch(session->hs_state) {
        case TLS_HS_TYPE_CLIENT_HELLO        :
            session->hs_state = TLS_HS_TYPE_SERVER_HELLO;
            break;
        case TLS_HS_TYPE_SERVER_HELLO        :
            if(session->flgs.hello_retry == 0) {
                session->hs_state = TLS_HS_TYPE_ENCRYPTED_EXTENSIONS;
            } else {
                session->hs_state = TLS_HS_TYPE_CLIENT_HELLO;
            }
            break;
        case  TLS_HS_TYPE_ENCRYPTED_EXTENSIONS:
            session->hs_state = TLS_HS_TYPE_CERTIFICATE_REQUEST;
            break;
        case TLS_HS_TYPE_CERTIFICATE_REQUEST:
            if((session->flgs.omit_client_cert_chk == 1) && (session->flgs.omit_server_cert_chk == 1)) {
                session->hs_state = TLS_HS_TYPE_FINISHED;
            }
            else {
                session->hs_state = TLS_HS_TYPE_CERTIFICATE;
            }
            break;
        case TLS_HS_TYPE_CERTIFICATE  :
            session->hs_state = TLS_HS_TYPE_CERTIFICATE_VERIFY;
            break;
        case TLS_HS_TYPE_CERTIFICATE_VERIFY  :
            session->hs_state = TLS_HS_TYPE_FINISHED;
            break;
        case TLS_HS_TYPE_FINISHED :
            if(session->flgs.hs_server_finish == 0) {
                if(session->flgs.omit_client_cert_chk == 0) {
                    session->hs_state = TLS_HS_TYPE_CERTIFICATE;
                }
                session->flgs.hs_server_finish = 1;
                session->flgs.outflight_flush  = 0;
            } else if(session->flgs.hs_client_finish == 0) {
                session->flgs.hs_client_finish = 1;
                session->flgs.outflight_flush  = 1; // TODO: find the better way to let application toggle this flag
            } else {
                if(session->flgs.new_session_tkt != 0) { session->hs_state = TLS_HS_TYPE_NEW_SESSION_TICKET; }
                else if(session->flgs.key_update != 0) { session->hs_state = TLS_HS_TYPE_KEY_UPDATE; }
            }
            break;
        case TLS_HS_TYPE_KEY_UPDATE:
            if(session->flgs.new_session_tkt != 0) { session->hs_state = TLS_HS_TYPE_NEW_SESSION_TICKET; }
            break;
        case TLS_HS_TYPE_NEW_SESSION_TICKET:
            if(session->flgs.key_update != 0) { session->hs_state = TLS_HS_TYPE_KEY_UPDATE; }
            break;
        default:
            session->hs_state = TLS_HS_TYPE_CLIENT_HELLO;
            session->flgs.outflight_flush = 1;
            break;
    } // end of switch-case statement
} // end of tlsHSstateTransition


static tlsRespStatus  tlsActivateHSsecrets(tlsSession_t *session)
{
    tlsRespStatus  status       = TLS_RESP_OK;
    tlsHashAlgoID  hash_algo_id = TLScipherSuiteGetHashID(session->sec.chosen_ciphersuite);
    word16         hash_sz      = mqttHashGetOutlenBytes(hash_algo_id);
    tlsOpaque8b_t  early_secret = {0, NULL};
    if(hash_sz == 0) {
        status = TLS_RESP_ERR_NOT_SUPPORT;  goto done;
    }
    early_secret.len  = hash_sz;
    early_secret.data = XMALLOC(sizeof(byte) * early_secret.len);
    status =  tlsGenEarlySecret(session->sec.chosen_ciphersuite, session->sec.chosen_psk, &early_secret);
    if(status < 0) { goto done; }
    status =  tlsDeriveHStrafficSecret(session, &early_secret);
    if(status < 0) { goto done; }
    status =  tlsDeriveTraffickey(&session->sec, &session->sec.secret.hs.server, &session->sec.secret.hs.client);
    // RFC 8466, section 5.3 Per-Record Nonce
    // The sequence numbers for reading / writing records is set to zero whenever read/write key is updated
    session->log.num_enc_recmsg_sent = 0;
    session->log.num_enc_recmsg_recv = 0;
done:
    if(early_secret.data != NULL) {
        XMEMFREE((void *)early_secret.data);
        early_secret.data = NULL;
    }
    tlsCleanSpaceAfterGenHSkeys(session); // deallocate ephemeral keys
    return status;
} // end of tlsActivateHSsecrets



static tlsRespStatus  tlsActivateAPPsecrets(tlsSession_t *session)
{
    tlsRespStatus  status       = TLS_RESP_OK;
    status =  tlsDeriveAPPtrafficSecret(session);
    if(status < 0) { goto done; }
    // overwrite read/write key & IV for the handshake that was already complete
    status =  tlsDeriveTraffickey(&session->sec, &session->sec.secret.app.server, &session->sec.secret.app.client);
    // RFC 8466, section 5.3 Per-Record Nonce
    // The sequence numbers for reading / writing records is set to zero whenever read/write key is updated
    session->log.num_enc_recmsg_sent = 0;
    session->log.num_enc_recmsg_recv = 0;
    if(status < 0) { goto done; }
    status =  tlsActivateWriteKey(&session->sec);
    if(status < 0) { goto done; }
    status =  tlsActivateReadKey(&session->sec);
    if(status < 0) { goto done; }
done:
    return status;
} // end of tlsActivateAPPsecrets



// handshake process for TLS v1.3
tlsRespStatus  tlsClientStartHandshake(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus status = TLS_RESP_OK;

    tlsHSstateTransition(session); // initialize to ClientHello
    tlsAllocSpaceBeforeKeyEx(session);
    status = tlsTranscrptHashInit(&session->sec);
    if(status < 0) { goto end_of_hs; }

    do { // Step #1: hello messages for negotiating cryptography parameters
        do {
            status = tlsEncodeRecordLayer(session);
            if(status < 0) { goto end_of_hs; }
            status = tlsTranscrptHashHSmsgUpdate(session, &session->outbuf);
            if(status < 0) { goto end_of_hs; }
            status = tlsPktSendToPeer(session, session->flgs.outflight_flush);
            if(status < 0) { goto end_of_hs; }
        } while(tlsChkFragStateOutMsg(session) != TLS_RESP_REQ_REINIT);
        tlsHSstateTransition(session);
        // wait for reply from remote peer as soon as all fragment(s) of current TLS record message were sent.
        do {
            status = tlsPktRecvFromPeer(session);
            if(status < 0) { goto end_of_hs; }
            status = tlsDecodeRecordLayer(session);
            if(status < 0) { goto end_of_hs; }
            if((tlsChkFragStateInMsg(session) & TLS_RESP_FIRST_FRAG) == TLS_RESP_FIRST_FRAG){
                if(session->flgs.hello_retry != 0) {
                    // re-init transcript hash only when we decoded first fragment of the HelloRetryRequest
                    // (include the case that there's only one fragment in the HelloRetryRequest)
                    status = tlsTranscrptHashReInit(&session->sec);
                    if(status < 0) { goto end_of_hs; }
                }
            }
            status = tlsTranscrptHashHSmsgUpdate(session, &session->inbuf);
            if(status < 0) { goto end_of_hs; }
            tlsDecrementFragNumInMsg(session);
        } while (tlsChkFragStateInMsg(session) != TLS_RESP_REQ_REINIT);
        tlsHSstateTransition(session);
/*******************************
******************************/
    } while (session->flgs.hello_retry != 0); // end of hello_retry check loop
    // clean up space that is no longer used in current session.
    tlsCleanSpaceAfterKeyEx(session);
    status = tlsTransHashCleanUnsuedHashHandler(&session->sec); // find appropriate time to clean up the space
    if(status < 0) { goto end_of_hs; }
    // Step #2:
    // * generate handshake traffic secret, then activate handshake read (decrypt) keys
    // * client must receive the last unencrypted record message "Change Cipher Spec" then turn on flag hs_rx_encrypt
    status = tlsActivateHSsecrets(session);
    if(status < 0) { goto end_of_hs; }
    status =  tlsActivateReadKey(&session->sec);
    if(status < 0) { goto end_of_hs; }
    status = tlsPktRecvFromPeer(session);
    if(status < 0) { goto end_of_hs; }
    status = tlsDecodeRecordLayer(session);
    if(status < 0) { goto end_of_hs; }
    tlsDecrementFragNumInMsg(session);
    if(session->flgs.hs_rx_encrypt == 0) { status = TLS_RESP_ERR_DECODE; goto end_of_hs; }

    // Step #3: From here, the client is supposed to receive more encrypted record messages from the server
    while(session->flgs.hs_server_finish == 0) {
        do {
            status = tlsPktRecvFromPeer(session);
            if(status < 0) { goto end_of_hs; }
            status = tlsDecryptRecordMsg(session);
            if(status < 0) { goto end_of_hs; }
            status = tlsDecodeRecordLayer(session);
            if(status < 0) { goto end_of_hs; }
            status = tlsTranscrptHashHSmsgUpdate(session, &session->inbuf);
            if(status < 0) { goto end_of_hs; }
            tlsDecrementFragNumInMsg(session);
        } while (tlsChkFragStateInMsg(session) != TLS_RESP_REQ_REINIT);
        tlsHSstateTransition(session);
    } // end of while-loop
/******************************
**************************/

    // step #4:
    // * activate handshake write (encrypt) key
    // * client must send the last unencrypted record message "Change Cipher Spec" to the peer,
    //   then the peer will turn on encryption function
    session->record_type = TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC;
    status = tlsEncodeRecordLayer(session);
    session->record_type = TLS_CONTENT_TYPE_HANDSHAKE;
    if(status < 0) { goto end_of_hs; }
    status = tlsPktSendToPeer(session, 0x0);
    if(status < 0) { goto end_of_hs; }
    status =  tlsActivateWriteKey(&session->sec);
    if(status < 0) { goto end_of_hs; }
    session->flgs.hs_tx_encrypt = 1;

    // Step #5: the client is supposed to send finished message, or certificate message if required by the peer
    while (session->flgs.hs_client_finish == 0) {
        do {
            status = tlsEncodeRecordLayer(session);
            if(status < 0) { goto end_of_hs; }
            status = tlsTranscrptHashHSmsgUpdate(session, &session->outbuf);
            if(status < 0) { goto end_of_hs; }
            status = tlsEncryptRecordMsg(session);
            if(status < 0) { goto end_of_hs; }
            status = tlsPktSendToPeer(session, session->flgs.outflight_flush);
            if(status < 0) { goto end_of_hs; }
        } while (tlsChkFragStateOutMsg(session) != TLS_RESP_REQ_REINIT);
        tlsHSstateTransition(session);
    } // end of while-loop

    // Step #6: derive (1) master secret (2) client_application_traffic_secret_0
    // (3) server_application_traffic_secret_0  (4) application read / write key
    status = tlsActivateAPPsecrets(session);
end_of_hs:
    if(status < 0) {
        if(status == TLS_RESP_REQ_ALERT) {
            // TODO: send alert to the peer
        }
    }
    tlsTranscrptHashDone(&session->sec, NULL); // only de-initialize hash structure
    tlsCleanSpaceAfterHS(session);
    return status;
} // end of tlsClientStartHandshake



tlsRespStatus  tlsChkHSfinished(tlsSession_t  *session)
{
    tlsRespStatus   status = TLS_RESP_OK;
    if(session->flgs.hs_client_finish == 0 || session->flgs.hs_server_finish == 0 
           || session->sec.chosen_ciphersuite == NULL) {
        status = TLS_RESP_ERR;
    }
    return status;
} // end of tlsChkHSfinished


