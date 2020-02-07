#include "mqtt_include.h"

static const byte SHA256HelloRetryReqSequence[TLS_HS_RANDOM_BYTES] = {
    0xCF,  0x21,   0xAD,  0x74,    0xE5,  0x9A,   0x61,  0x11,
    0xBE,  0x1D,   0x8C,  0x02,    0x1E,  0x65,   0xB8,  0x91,
    0xC2,  0xA2,   0x11,  0x16,    0x7A,  0xBB,   0x8C,  0x5E,
    0x07,  0x9E,   0x09,  0xE2,    0xC8,  0xA8,   0x33,  0x9C,
};

static tlsRespStatus  tlsDecodeHSserverHello(tlsSession_t *session)
{ // decode ServerHello or HelloRetryRequest (since TLS v1.3)
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus status     =  TLS_RESP_OK;
    byte     *inbuf          = &session->inbuf.data[0];
    word16   inlen_decoded   =  session->inlen_decoded;
    word16   tmp = 0;

    if((tlsChkFragStateInMsg(session) & TLS_RESP_FIRST_FRAG) == TLS_RESP_FIRST_FRAG)
    {   // runs only for the first fragment
        inlen_decoded += 2; // skip unnecessary 2-byte TLS version code
        // For TLS v1.3, check whether the random number field is auctually replaced with special value
        // of SHA-256 of HelloRetryRequest.
        // Note that we DO NOT check last 8 bytes of the random number field since this implementation
        // ONLY supports TLS v1.3 and downgrading version negotiation is currently NOT allowed.
        if(XSTRNCMP( (const char *)&SHA256HelloRetryReqSequence[0], (const char *)&inbuf[inlen_decoded], TLS_HS_RANDOM_BYTES ) == 0) {
            session->flgs.hello_retry += 1;
        }
        else { // confirm that it is ServerHello
            session->flgs.hello_retry = 0;
            // copy 32-byte random value from the peer
            XMEMCPY( &session->sec.server_rand[0], &inbuf[inlen_decoded], TLS_HS_RANDOM_BYTES );
        }
        inlen_decoded += TLS_HS_RANDOM_BYTES;
        // abort connection if we receive more than one HelloRetryRequest in the same session.
        if(session->flgs.hello_retry > 1) {  goto fail_decode;  }
        // examine legacy_session_id_echo, should be the same as the session ID field in previous ClientHello
        if(session->tmpbuf.session_id.len != inbuf[inlen_decoded++]) { goto fail_decode; }
        if (XSTRNCMP((const char *)&inbuf[inlen_decoded], (const char *)&session->tmpbuf.session_id.data[0],
                         session->tmpbuf.session_id.len ) != 0) {
            goto fail_decode;
        }
        inlen_decoded += session->tmpbuf.session_id.len;
        // the selected cipher suite must be supported in this implementation ....
        inlen_decoded += tlsDecodeWord16( &inbuf[inlen_decoded], &tmp );
        session->sec.chosen_ciphersuite = tlsGetCipherSuiteByID(tmp);
        if(session->sec.chosen_ciphersuite == NULL) { goto fail_decode; }
        // check compression method
        tmp = 0;
        tmp = inbuf[inlen_decoded++];
        if(tmp != 0) { goto fail_decode; }
        session->inlen_decoded = inlen_decoded;
        session->last_ext_entry_dec_len = 0x1 << 15; // reset this value before parsing extension sections
    } // end of  if tlsChkFragStateInMsg(session) sets TLS_RESP_FIRST_FRAG flag
   
    // if received record message is split into multiple fragments, the parsing / decoding functions will be called multiple times
    status = tlsParseExtensions(session, &session->exts);
    if(status < 0) { goto end_of_decode; }
    status = tlsDecodeExtServerHello(session);
    goto end_of_decode;

fail_decode:
    session->inlen_decoded = inlen_decoded;
    status = TLS_RESP_REQ_ALERT; // should send unexpected_message alert
end_of_decode:
    return status;
} // end of tlsDecodeHSserverHello


static tlsRespStatus  tlsDecodeHSencryptedExt(tlsSession_t *session)
{ // we can confirm it is the first fragment (of a record message) by simply checking ct_first_frag from now on
    if(session->sec.flgs.ct_first_frag != 0) {
        session->last_ext_entry_dec_len = 0x1 << 15;
    }
    tlsRespStatus status = tlsParseExtensions(session, &session->exts);
    if(status < 0) { goto end_of_decode; }
    status = tlsDecodeExtEncryptExt(session);
end_of_decode:
    return status;
} // end of tlsDecodeHSencryptedExt


// struct {
//     select (certificate_type) {
//         case RawPublicKey:
//             /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
//             opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
//         case X509:
//             opaque cert_data<1..2^24-1>;
//     };
//     Extension extensions<0..2^16-1>;
// } CertificateEntry;
//
// struct {
//     opaque certificate_request_context<0..2^8-1>;
//     CertificateEntry certificate_list<0..2^24-1>;
// } Certificate;
static tlsRespStatus  tlsDecodeHScertificate(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus  status   =  TLS_RESP_OK;
    if(session->sec.flgs.ct_first_frag != 0) {
        byte   *inbuf          = &session->inbuf.data[0];
        word16  inlen_decoded  =  session->inlen_decoded;
        word32  tmp = 0;
        // certificate_request_context will be zero length for server authentication,
        tmp = inbuf[inlen_decoded++]; // copy the length field of certificate_request_context
        // if this implementation , we will simply skip this part.
        inlen_decoded += tmp;
        inlen_decoded += tlsDecodeWord24( &inbuf[inlen_decoded] , &tmp);
        session->nbytes.total_certs = tmp; // nbytes_remain at here means total #bytes of Certificate.certificate_list
        session->inlen_decoded = inlen_decoded;
        if(session->nbytes.total_certs  > TLS_MAX_BYTES_CERT_CHAIN) {
            status = TLS_RESP_ERR_CERT_OVFL;
            goto end_of_decode;
        } else if(session->nbytes.total_certs == 0x0) { // empty certificate_list is NOT allowed in TLS
            status = TLS_RESP_REQ_ALERT; // abort the handshake with a "decode_error" alert
            goto end_of_decode;
        }
        session->last_cpy_cert_len  = 0;
    }
    status = tlsCopyCertRawData(session);
    if(status < 0) { goto end_of_decode; }
    // Find the first certificate that is ready to decode
    // in this implementation, either the final cert item or its predecessor was completely
    // parsed & ready to decode in the given list.
    byte final_item_rdy = (session->last_cpy_cert_len != 0) ? 0 : 1;
    status = tlsDecodeCerts(session->peer_certs, final_item_rdy);
    // free the space in raw bytes pool of the cert chain
    tlsFreeCertEntryFlag option_flgs = (final_item_rdy == 0) ? TLS_FREE_CERT_ENTRY_SKIP_FINAL_ITEM: 0;
    tlsFreeCertChain(session->peer_certs, TLS_FREE_CERT_ENTRY_RAWBYTE | option_flgs);
    if(status < 0) { goto end_of_decode; }

    // verify peer's identity by verifying entire received certificate chain in the final fragment
    if(session->sec.flgs.ct_final_frag != 0) {
        // Note we can only verify this chain in the final fragment since the peer's cert chain would come
        // in arbitrary order. Ideally each cert in the chain list can be certified by the one immediately
        // proceding it (in the same chain) , however many TLS implementations don't work that way. 
        status = tlsVerifyCertChain(session->CA_cert, session->peer_certs);
    }
end_of_decode:
    if((status < 0) || (session->sec.flgs.ct_final_frag != 0)) {
        tlsFreeCertChain(session->peer_certs, TLS_FREE_CERT_ENTRY_SIGNATURE);
    } // deallocate space from some members of the cert chain since they are no longer used in the session
    return status;
} // end of tlsDecodeHScertificate


// struct {
//     opaque certificate_request_context<0..2^8-1>;
//     Extension extensions<2..2^16-1>;
// } CertificateRequest;
//
// RFC 8446, section 4.2 (extensions), section 4.2.6 (Post-Handshake Client Authentication)
// currently this implementation doesn't send post_handshake_auth in ClientHello, the client
// will NOT receive CertificateRequest from its peer after handshake is completed.
static tlsRespStatus  tlsDecodeHScertificateReq(tlsSession_t *session)
{
    if(session->sec.flgs.ct_first_frag != 0) {
        byte   *inbuf          = &session->inbuf.data[0];
        word16  inlen_decoded  =  session->inlen_decoded;
        // copy the length field of certificate_request_context
        session->tmpbuf.cert_req_ctx.len = inbuf[inlen_decoded++];
        // preserve certificate_request_context for later client authentication
        session->tmpbuf.cert_req_ctx.data = XMALLOC(sizeof(byte) * session->tmpbuf.cert_req_ctx.len);
        XMEMCPY(session->tmpbuf.cert_req_ctx.data, &inbuf[inlen_decoded], session->tmpbuf.cert_req_ctx.len);
        inlen_decoded  +=  session->tmpbuf.cert_req_ctx.len;
        session->inlen_decoded = inlen_decoded;
        session->flgs.omit_client_cert_chk = 0;
        session->last_ext_entry_dec_len = 0x1 << 15;
    }
    tlsRespStatus status = tlsParseExtensions(session, &session->exts);
    if(status < 0) { goto end_of_decode; }
    status = tlsDecodeExtCertReq(session);
end_of_decode:
    return status;
} // end of tlsDecodeHScertificateReq


// struct {
//     SignatureScheme algorithm;
//     opaque signature<0..2^16-1>;
// } CertificateVerify;
// Note :
// * this implementation doesn't consider CertificateVerify is split into several fragments
// * In TLS v1.3, RSA signature must use RSA-PSS algorithm, regardless of whether RSA PKCS#1 v1.5
//   is present in signature_algorithm extension in ClientHello. (RFC 8446, section 4.4.3)
static tlsRespStatus  tlsDecodeHScertificateVerify(tlsSession_t *session)
{
    tlsRespStatus  status  = TLS_RESP_OK;
    byte   *inbuf         = &session->inbuf.data[0];
    word16  inlen_decoded =  session->inlen_decoded;
    tlsSignScheme sig_scheme_id = 0;
    word16  tmp = 0;
    tlsOpaque16b_t  recvSig   = {0 , NULL};
    tlsOpaque16b_t  digiSig   = {0 , NULL};
    tlsRSApss_t     rsapssSig = {0 , 0};

    if(session->peer_certs == NULL) { status = TLS_RESP_ERRARGS; goto done; }
    inlen_decoded += tlsDecodeWord16( &inbuf[inlen_decoded] , &tmp);
    sig_scheme_id = (tlsSignScheme)tmp;
    // check whether the chosen signature algorithm is supported.
    switch (sig_scheme_id) {
        case TLS_SIGNATURE_RSA_PSS_PSS_SHA256:
        case TLS_SIGNATURE_RSA_PSS_RSAE_SHA256:
            rsapssSig.hash_id = TLS_HASH_ALGO_SHA256;
            break;
        case TLS_SIGNATURE_RSA_PSS_PSS_SHA384:
        case TLS_SIGNATURE_RSA_PSS_RSAE_SHA384:
            rsapssSig.hash_id = TLS_HASH_ALGO_SHA384;
            break;
        default:
            status = TLS_RESP_ERR_NOT_SUPPORT; goto done;
    } // end of switch case statement
    rsapssSig.salt_len = mqttHashGetOutlenBytes(rsapssSig.hash_id);
    // get total length of signature
    inlen_decoded += tlsDecodeWord16(&inbuf[inlen_decoded] , &tmp);
    recvSig.len  =  tmp;
    recvSig.data = &inbuf[inlen_decoded];
    inlen_decoded += recvSig.len;
    status =  tlsCertVerifyGenDigitalSig(&session->sec, (const tlsRSApss_t *)&rsapssSig, &digiSig, (const byte) 0x1);
    if(status < 0){ goto done; }

    status = tlsVerifyCertSignature(session->peer_certs->pubkey, &recvSig, TLS_ALGO_OID_RSASSA_PSS, &digiSig, &rsapssSig);
done:
    if(digiSig.data != NULL) {
        XMEMFREE((void *)digiSig.data);
        digiSig.data = NULL;
    }
    session->inlen_decoded = inlen_decoded;
    return status;
} // end of tlsDecodeHScertificateVerify


// RFC 8446, section 4.4.4, Finished
// Structure of this message:
// struct {
//     opaque verify_data[Hash.length];
// } Finished;
//
// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
//
// The verify_data value is computed as follows:
//
// verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
//
// "*" Only included if present.
//
// Note :
// * this implementation doesn't consider Finished message is split into several fragments
static tlsRespStatus  tlsDecodeHSfinished(tlsSession_t *session)
{
    tlsRespStatus status = TLS_RESP_OK;
    word32  hs_msg_sz    = 0;
    byte   *inbuf         = &session->inbuf.data[0];
    word16  inlen_decoded =  session->inlen_decoded;
    tlsOpaque8b_t *base_key = NULL;
    tlsOpaque8b_t  gened_verifydata = {0, NULL};
    // handshake message size must be hash output length of chosen cipher suite
    tlsHashAlgoID  hash_id = TLScipherSuiteGetHashID(session->sec.chosen_ciphersuite);

    gened_verifydata.len  = mqttHashGetOutlenBytes(hash_id);
    gened_verifydata.data = XMALLOC(sizeof(byte) * gened_verifydata.len);
    tlsDecodeWord24( &inbuf[inlen_decoded - 3] , &hs_msg_sz );
    if(hs_msg_sz != gened_verifydata.len) { status = TLS_RESP_ERR_DECODE; goto done; }
    // * compute finish_key, This is TLS client implementation,
    //   so server_handshake_traffic_secret is selected as the base key for verifying peer's Finished message
    base_key = &session->sec.secret.hs.server;
    status = tlsGenFinishedVerifyData(&session->sec, base_key, &gened_verifydata);
    if(status < 0){ goto done; }
    // compare generated verify_data with received verify_data
    if(XSTRNCMP((const char *)&inbuf[inlen_decoded], (const char *)&gened_verifydata.data[0], gened_verifydata.len) != 0) {
        status = TLS_RESP_HS_AUTH_FAIL;
    }
done:
    if(gened_verifydata.data != NULL) {
        XMEMFREE((void *)gened_verifydata.data);
        gened_verifydata.data = NULL;
    }
    session->inlen_decoded = inlen_decoded + hs_msg_sz;
    return status;
} // end of tlsDecodeHSfinished


// RFC 8446, section 4.6.1 New Session Ticket message
// struct {
//     uint32 ticket_lifetime;
//     uint32 ticket_age_add;
//     opaque ticket_nonce<0..255>;
//     opaque ticket<1..2^16-1>;  <-- used as the PSK identity
//     Extension extensions<0..2^16-2>;
// } NewSessionTicket;
//
// ticket_lifetime : indicate lifetime "in secords", in TLS v1.3.
// * this value MUST NOT be greater than 604800 seconds (7 days).
// * client also MUST NOT cache a PSK for longer than 7 days
// * the server may delete the PS earlier than the specified ticket_lifetime
// ticket_age_add : a 32-bit random value used to obscure the age of the ticket.
// (make man-in-the-middle attack more difficult ?), ClientHello with PSK extension
// must include obfuscated_ticket_age, which is addition of this ticket_age_add and
// "the age of the ticket".
//
// "the age of the ticket" in client's view is the time since the receipt of NewTicketMessage
//
static tlsRespStatus  tlsDecodeNewSessTkt(tlsSession_t *session)
{
    tlsRespStatus status = TLS_RESP_OK;
    tlsPSK_t    *pskitem = NULL;
    byte   *inbuf         = &session->inbuf.data[0];
    word16  inlen_decoded =  session->inlen_decoded;

    if(session->sec.flgs.ct_first_frag != 0) {
        tlsHashAlgoID  hash_id   = TLScipherSuiteGetHashID(session->sec.chosen_ciphersuite);
        word16         hash_sz   = mqttHashGetOutlenBytes(hash_id);
        tlsOpaque8b_t  reslabel  = {10, (byte *)&("resumption")};
        tlsOpaque8b_t  nst_nonce = {0, NULL};
        pskitem = (tlsPSK_t *) XMALLOC(sizeof(tlsPSK_t));
        pskitem->flgs.is_resumption = 0x1; //TODO: is it necessary to suport PSK imported by user application ?
        tlsAddItemToList((tlsListItem_t **) session->sec.psk_list, (tlsListItem_t *)pskitem, 0x1); // always insert to the front
        inlen_decoded += tlsDecodeWord32( &inbuf[inlen_decoded], &pskitem->time_param.ticket_lifetime );
        inlen_decoded += tlsDecodeWord32( &inbuf[inlen_decoded], &pskitem->time_param.ticket_age_add );
        // ticket nonce & ticket bytes are used to derive new PSK that can be used next time
        // when connecting to the same server, by specified expiration time
        nst_nonce.len  =  inbuf[inlen_decoded++];
        nst_nonce.data = &inbuf[inlen_decoded]; // no need to copy, the entire ticket_nonce must be in the first fragment
        inlen_decoded += nst_nonce.len;
        inlen_decoded += tlsDecodeWord16( &inbuf[inlen_decoded], &pskitem->id.len );
        // compute pre-shared key (PSK) associated with the ticket (RFC 8446, page 75)
        // * HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
        pskitem->key.len  =  hash_sz;
        pskitem->key.data =  XMALLOC(sizeof(byte) * (pskitem->key.len + pskitem->id.len));
        pskitem->id.data  = &pskitem->key.data[pskitem->key.len];
        status = tlsHKDFexpandLabel( hash_id, &session->sec.secret.app.resumption, &reslabel, &nst_nonce, &pskitem->key );
        if(status < 0) { goto end_of_decode; }
        pskitem->time_param.timestamp_ms  = mqttSysGetTimeMs(); // record timestamp on receipt of NewSessionTicket
        session->nbytes.remaining_to_recv = pskitem->id.len;
        ////session->last_ext_entry_dec_len = 0x1 << 15;
    } else {
        pskitem = *session->sec.psk_list;
    }
    // For copying opaque ticket<1..2^16-1> from one or more fragments
    if((session->nbytes.remaining_to_recv > 0) && (pskitem != NULL)) {
        word16    rdy_cpy_sz = 0;
        word16    copied_sz  = 0;
        copied_sz  = pskitem->id.len - session->nbytes.remaining_to_recv;
        rdy_cpy_sz = XMIN(session->inlen_decrypted - inlen_decoded, session->nbytes.remaining_to_recv);
        XMEMCPY(&pskitem->id.data[copied_sz], &inbuf[inlen_decoded], rdy_cpy_sz);
        inlen_decoded  += rdy_cpy_sz;
        session->nbytes.remaining_to_recv -= rdy_cpy_sz;
    }
    if(session->nbytes.remaining_to_recv == 0) {
        word16  tmp = 0;
        inlen_decoded += tlsDecodeWord16( &inbuf[inlen_decoded], &tmp );
        inlen_decoded += tmp;
    } // TODO: decode the only entension entry "early_data", currently just skip it
end_of_decode:
    if(session->sec.flgs.ct_final_frag != 0) {
        // get rid of old PSK entry once it exceeds its max. size
        word32 list_sz = tlsGetListItemSz((tlsListItem_t *)*session->sec.psk_list);
        if(list_sz > TLS_MAX_NUM_PSK_LISTITEM) {
            pskitem = (tlsPSK_t *) tlsGetFinalItemFromList((tlsListItem_t *)*session->sec.psk_list);
            tlsRemoveItemFromList((tlsListItem_t **)session->sec.psk_list, (tlsListItem_t *)pskitem);
            tlsFreePSKentry(pskitem);
        }
        session->flgs.new_session_tkt = 0;
    }
    session->inlen_decoded = inlen_decoded;
    return status;
} // end of tlsDecodeNewSessTkt


static tlsRespStatus  tlsDecodeHandshakeHeader(tlsSession_t *session)
{
    tlsHandshakeType hsstate = tlsGetHSexpectedState(session);
    // runs only for the first fragment
    const tlsHandshakeMsg_t *header = (tlsHandshakeMsg_t *)&session->inbuf.data[session->inlen_decoded];
    // decoded handshake type at here should be consistent as the state after running tlsHSstateTransition()
    // , however the only exception is the state transition from TLS_HS_TYPE_ENCRYPTED_EXTENSIONS.
    // Since in TLS v1.3  TLS_HS_TYPE_CERTIFICATE_REQUEST , TLS_HS_TYPE_CERTIFICATE, TLS_HS_TYPE_CERTIFICATE_VERIFY
    // are optional, the peer (server) might not request certificate check from client, and vice versa. In
    // such case, we need to update flags and handshake state and run tlsHSstateTransition() again.
    if (hsstate != header->type) {
        if((hsstate == TLS_HS_TYPE_CERTIFICATE_REQUEST) && (header->type == TLS_HS_TYPE_CERTIFICATE)) {
            session->flgs.omit_client_cert_chk = 1;
            session->flgs.omit_server_cert_chk = 0;
        }
        else if((hsstate == TLS_HS_TYPE_CERTIFICATE_REQUEST) && (header->type == TLS_HS_TYPE_FINISHED)) {
            session->flgs.omit_client_cert_chk = 1;
            session->flgs.omit_server_cert_chk = 1;
        }  // TODO: verify
        else if (session->flgs.hs_client_finish != 0) {
            if(header->type == TLS_HS_TYPE_NEW_SESSION_TICKET) {
                session->flgs.new_session_tkt = 1;
            } else if(header->type == TLS_HS_TYPE_KEY_UPDATE) {
                session->flgs.key_update = 1;
            }
        }
        else {
            return TLS_RESP_REQ_ALERT; // handshake error, alert must be sent;
        }
        tlsHSstateTransition(session);
    } // end of while-loop
    session->inlen_decoded += TLS_HANDSHAKE_HEADER_NBYTES;
    return  TLS_RESP_OK;
} // end of tlsDecodeHandshakeHeader



static tlsRespStatus  tlsDecodeHandshake(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus  status = TLS_RESP_OK;

    if((tlsChkFragStateInMsg(session) & TLS_RESP_FIRST_FRAG) == TLS_RESP_FIRST_FRAG) {
        status = tlsDecodeHandshakeHeader(session);
        if(status < 0) { return status; }
    }
    switch(tlsGetHSexpectedState(session)) {
        case TLS_HS_TYPE_SERVER_HELLO :
            status = tlsDecodeHSserverHello(session);
            break;
        case TLS_HS_TYPE_ENCRYPTED_EXTENSIONS:
            status = tlsDecodeHSencryptedExt(session);
            break;
        case TLS_HS_TYPE_CERTIFICATE :
            status = tlsDecodeHScertificate(session);
            break;
        case TLS_HS_TYPE_CERTIFICATE_REQUEST :
            status = tlsDecodeHScertificateReq(session);
            break;
        case TLS_HS_TYPE_CERTIFICATE_VERIFY  :
            status = tlsDecodeHScertificateVerify(session);
            break;
        case TLS_HS_TYPE_FINISHED :
            status = tlsDecodeHSfinished(session);
            break;
        case TLS_HS_TYPE_NEW_SESSION_TICKET:
            status = tlsDecodeNewSessTkt(session);
            break;
        case TLS_HS_TYPE_KEY_UPDATE :
        default:
            status = TLS_RESP_REQ_ALERT;
            break; // TODO: record type is NOT supported, should send alert to the peer
    } // end of switch-case statement
    return status;
} // end of tlsDecodeHandshake



static tlsRespStatus  tlsDecodeChangeCipherSpec(tlsSession_t *session)
{
    tlsRespStatus status = TLS_RESP_OK;
    if(session->flgs.hs_rx_encrypt == 0) {
        session->flgs.hs_rx_encrypt = 1;
    }
    session->inlen_decoded += 1;
    return status;
} // end of tlsDecodeChangeCipherSpec


static tlsRespStatus  tlsDecodeAlert(tlsSession_t *session)
{
    byte   *inbuf         = &session->inbuf.data[0];
    word16  inlen_decoded =  session->inlen_decoded;
    // log errors sent by the peer
    session->log.alert.level       = (tlsAlertLvl) inbuf[inlen_decoded++];
    session->log.alert.description = (tlsAlertType)inbuf[inlen_decoded++];
    session->inlen_decoded = inlen_decoded;
    // convert to useful return status code
    return  tlsAlertTypeCvtToTlsResp( session->log.alert.description );
} // end of tlsDecodeAlert



// get number of bytes that are decrypted but not decoded yet in current fragment of application record message
word16  tlsGetUndecodedNumBytes(tlsSession_t *session)
{
    word16 out = 0;
    tlsRespStatus  status = tlsChkFragStateInMsg(session);
    if(status == TLS_RESP_REQ_REINIT || session->flgs.hs_rx_encrypt == 0) {
        out = 0;
    } else {
        out = session->inlen_decrypted - session->inlen_decoded;
        if((status & TLS_RESP_FINAL_FRAG) == TLS_RESP_FINAL_FRAG) {
            byte trim_sz = (1 + session->sec.chosen_ciphersuite->tagSize);
            // decrease 1-byte content type, #bytes authentication tag in final fragment
            out = (out > trim_sz) ? (out - trim_sz): 0;
        }
    }
    return out;
} // end of tlsGetUndecodedNumBytes


static tlsRespStatus  tlsDecodeAppData(tlsSession_t *session)
{ // This function simply copies decrypted bytes to the buffer provided by application
    word16  nbytes_avail = tlsGetUndecodedNumBytes(session); // must be positive integer
    byte   *inbuf       = &session->inbuf.data[0];
    word16  rdy_cpy_len = XMIN(session->app_pt.len, nbytes_avail) ;
    tlsRespStatus status = TLS_RESP_OK;

    XMEMCPY( &session->app_pt.data[0], &inbuf[session->inlen_decoded], rdy_cpy_len);
    session->app_pt.len    -= rdy_cpy_len;
    session->app_pt.data   += rdy_cpy_len;
    session->inlen_decoded += rdy_cpy_len;
    return status;
} // end of tlsDecodeAppData


tlsRespStatus  tlsVerifyDecodeRecordType( tlsContentType rec_type )
{
    tlsRespStatus status = TLS_RESP_OK;
    switch(rec_type) {
        case TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC :
        case TLS_CONTENT_TYPE_ALERT              :
        case TLS_CONTENT_TYPE_HANDSHAKE          :
        case TLS_CONTENT_TYPE_APP_DATA           :
            break;
        case TLS_CONTENT_TYPE_INVALID            :
        case TLS_CONTENT_TYPE_HEARTBEAT          : // heartbeat is NOT support in this implementation
        default:
            status = TLS_RESP_MALFORMED_PKT;
            break;
    } // end of switch-case statement
    return status;
} // end of tlsVerifyDecodeRecordType


tlsRespStatus  tlsVerifyDecodeVersionCode( const byte *ver_in )
{   // TODO: consider future version checks
    if(ver_in == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus status =  TLS_RESP_OK;
    if(ver_in[0] != (TLS_VERSION_ENCODE_1_2 >> 8)) {
        status = TLS_RESP_MALFORMED_PKT;
    }
    else if(ver_in[1] != (TLS_VERSION_ENCODE_1_2 & 0xff)) {
        status = TLS_RESP_MALFORMED_PKT;
    }
    return status;
} // end of tlsVerifyDecodeVersionCode


tlsRespStatus  tlsDecodeRecordLayer(tlsSession_t *session)
{
    tlsRespStatus status = tlsChkFragStateInMsg(session);
    if((session == NULL) || (status == TLS_RESP_REQ_REINIT)) {
        return TLS_RESP_ERRARGS;
    }
    if((status & TLS_RESP_FIRST_FRAG) == TLS_RESP_FIRST_FRAG) {
        // runs only for the first fragment
        const tlsRecordLayer_t *rec_header = (tlsRecordLayer_t *)&session->inbuf.data[0];
        session->record_type    = rec_header->type;
        if(session->inlen_decoded == 0) {
            session->inlen_decoded = TLS_RECORD_LAYER_HEADER_NBYTES;
        } // MQTT packet-decoding function reads the first fragment at least 3 times (header, remain length, remain bytes)
    }
    switch(session->record_type)
    {
        case TLS_CONTENT_TYPE_HANDSHAKE:
            status = tlsDecodeHandshake(session);
            break;
        case TLS_CONTENT_TYPE_APP_DATA:
            status = tlsDecodeAppData(session);
            break;
        case TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
            status = tlsDecodeChangeCipherSpec(session);
            break;
        case TLS_CONTENT_TYPE_ALERT:
            status = tlsDecodeAlert(session);
            break;
        default:
            status = TLS_RESP_MALFORMED_PKT;
            break;
    } // end of switch-case statement
    return status;
} // end of tlsDecodeRecordLayer



