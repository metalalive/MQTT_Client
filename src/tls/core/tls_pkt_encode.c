#include "mqtt_include.h"

extern const tlsCipherSpec_t  tls_supported_cipher_suites[];

tlsRespStatus  tlsGenFinishedVerifyData(tlsSecurityElements_t *sec, tlsOpaque8b_t *base_key, tlsOpaque8b_t *out)
{
    tlsRespStatus  status      = TLS_RESP_OK;
    if(sec == NULL || sec->chosen_ciphersuite == NULL || base_key == NULL || base_key->data == NULL || out == NULL || out->data == NULL) {
        return TLS_RESP_ERRARGS;
    }
    byte   *trHash_hs_msg = NULL;
    tlsOpaque8b_t  keylabel    = {8, (byte *)&("finished") };
    tlsOpaque8b_t  finishedkey = {0, NULL};
    tlsHashAlgoID  hash_id = TLScipherSuiteGetHashID(sec->chosen_ciphersuite);
    word16        hash_len = mqttHashGetOutlenBytes(hash_id);

    if(out->len != hash_len) { status = TLS_RESP_ERRMEM; goto done; }
    // allocate space for both finished_key and Transcript Hash of handshake message
    finishedkey.len  = hash_len;
    finishedkey.data = XMALLOC(sizeof(byte) * hash_len * 2);
    // * compute finish_key with the given base key
    status = tlsHKDFexpandLabel(hash_id, base_key, &keylabel, NULL, &finishedkey);
    if(status < 0){ goto done; }
    // * compute Transcript-Hash(ClientHello || .... || CertificateVerify)
    trHash_hs_msg   = &finishedkey.data[hash_len];
    status =  tlsTransHashTakeSnapshot(sec, hash_id, trHash_hs_msg, (word16)hash_len);
    if(status < 0){ goto done; }
    // * compute verify_data = HMAC(finished_key, Transcript-Hash( ... ))
    TLS_CFG_HMAC_MEMBLOCK_FN(status, hash_id, finishedkey.data, hash_len, trHash_hs_msg, hash_len, &out->data[0], out->len);
done:
    if(finishedkey.data != NULL) {
        XMEMFREE((void *)finishedkey.data);
        finishedkey.data = NULL;
    }
    return status;
} // end of tlsGenFinishedVerifyData



static word16  tlsEncodeSupportedCipherSuite(byte  *out)
{
    word16  len = 0;
    word16  idx = 0;
    len = tlsGetSupportedCipherSuiteListSize() << 1;
    // first 2 bytes for storing size of the list of cipher suite
    out += tlsEncodeWord16(&out[0], (word16)len);
    // loop through the list & append 2-byte code of each supported cipher suite
    for( idx=0; idx<(len >> 1); idx++ ) {
        out += tlsEncodeWord16(&out[0], (word16)tls_supported_cipher_suites[idx].ident);
    } // end of for-loop
    len += 2;
    return len;
} // end of tlsEncodeSupportedCipherSuite



static tlsRespStatus  tlsEncodeHSclientHello(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus  status = TLS_RESP_OK;

    // assume that ClientHello message would be split to fragments
    if(tlsChkFragStateOutMsg(session) == TLS_RESP_REQ_REINIT)
    {
        word16  len  = 0;
        // argument check
        len = tlsGetSupportedCipherSuiteListSize() << 1;
        if((len < TLS_MIN_BYTES_CIPHER_SUITE_LIST) || (len > TLS_MAX_BYTES_CIPHER_SUITE_LIST)) {
            goto encode_failure;
        }
        mqttRespStatus  mqttstatus = MQTT_RESP_OK;
        word16     outlen_encoded  =  session->outlen_encoded;
        byte      *outbuf          = &session->outbuf.data[0];
        // add version code again
        len  = tlsEncodeWord16(&outbuf[outlen_encoded], (word16)TLS_VERSION_ENCODE_1_2);
        outlen_encoded += len;
        // append 32-byte random value
        mqttstatus = mqttUtilRandByteSeq(session->drbg, &session->sec.client_rand[0], (word16)TLS_HS_RANDOM_BYTES);
        if(mqttstatus != MQTT_RESP_OK) { goto encode_failure; }
        XMEMCPY( &outbuf[outlen_encoded], &session->sec.client_rand[0], TLS_HS_RANDOM_BYTES );
        outlen_encoded += TLS_HS_RANDOM_BYTES;
        // append session ID, at most 32 bytes, plus 1 byte to store its present size
        mqttstatus = mqttUtilRandByteSeq(session->drbg, &session->tmpbuf.session_id.data[0], TLS_MAX_BYTES_SESSION_ID);
        if(mqttstatus != MQTT_RESP_OK) { goto encode_failure; }
        outbuf[outlen_encoded++] = session->tmpbuf.session_id.len;
        XMEMCPY( &outbuf[outlen_encoded], &session->tmpbuf.session_id.data[0], TLS_MAX_BYTES_SESSION_ID );
        outlen_encoded += TLS_MAX_BYTES_SESSION_ID;
        // append a list of supported cipher suite. In practice , a ClientHello TLS packet can contain
        // the entire list of cipher suites, it is unlikely to divide the entire list & send it in multiple TLS packets.
        len = tlsEncodeSupportedCipherSuite( &outbuf[outlen_encoded] );
        outlen_encoded += len;
        // append compression methods (legacy)
        outbuf[outlen_encoded++] = 0x01; // length of compression method = 0x01
        outbuf[outlen_encoded++] = 0x00; // compression method = NULL
        // generate list of extensions that will be encoded to ClientHello message later
        session->exts = tlsGenExtensions(session);
        session->ext_enc_total_len = tlsGetExtListSize(session->exts);
        session->outlen_encoded  = outlen_encoded;
        session->curr_outmsg_len = outlen_encoded - session->curr_outmsg_start + 2 + session->ext_enc_total_len;
        session->last_ext_entry_enc_len = 0x1 << 15; // reset this value every time before we encode extension lists
    }
    // append extensions (note that all extensions may be sent in multiple TLS packets)

    if(session->exts == NULL) { // the extension chain must be present
        goto encode_failure;
    } // extension section must have something
    status = tlsEncodeExtensions(session);
    return status;

encode_failure:
    status = TLS_RESP_ERR_ENCODE;
    return status;
} // end of tlsEncodeHSclientHello



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
static tlsRespStatus  tlsEncodeHScertificate(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus  status = TLS_RESP_OK;
    byte   *outbuf        = &session->outbuf.data[0];
    word16 outlen_encoded =  session->outlen_encoded;
    word32 cert_sz    = 0;
    word16 rdy_cpy_sz = 0;
    word16 copied_sz  = 0;
    const byte empty_ext_sz = 2; // this implementation will NOT send extension at here

    // get size field of cert chain
    tlsDecodeWord24( &session->CA_cert->rawbytes.len[0], &cert_sz );
    if(cert_sz == 0) { status = TLS_RESP_ERR_ENCODE; goto done; }

    if(tlsChkFragStateOutMsg(session) == TLS_RESP_REQ_REINIT) {
        // copy certificate_request_context we previously recieved from the peer (page 61, RFC 8446)
        rdy_cpy_sz = session->tmpbuf.cert_req_ctx.len;
        outbuf[outlen_encoded++]  = rdy_cpy_sz;
        XMEMCPY(&outbuf[outlen_encoded], &session->tmpbuf.cert_req_ctx.data[0] , rdy_cpy_sz);
        tlsCleanSpaceOnClientCertSent(session);
        outlen_encoded += rdy_cpy_sz;
        // this TLS implementation ONLY provides one certificate in its cert chain
        outlen_encoded += tlsEncodeWord24(&outbuf[outlen_encoded] , (cert_sz + 3 + empty_ext_sz));
        outlen_encoded += tlsEncodeWord24(&outbuf[outlen_encoded] ,  cert_sz);
        session->curr_outmsg_len = outlen_encoded - session->curr_outmsg_start + cert_sz + empty_ext_sz;
        session->nbytes.remaining_to_send = cert_sz;
        session->ext_enc_total_len  = 0x0; // no extension entry
        session->last_ext_entry_enc_len = 0x1 << 15; // reset this value every time before we encode extension lists
    }
    if(session->nbytes.remaining_to_send > 0) {
        copied_sz  = cert_sz - session->nbytes.remaining_to_send;
        rdy_cpy_sz = XMIN(session->outbuf.len - outlen_encoded, session->nbytes.remaining_to_send);
        XMEMCPY(&outbuf[outlen_encoded], &session->CA_cert->rawbytes.data[copied_sz], rdy_cpy_sz);
        outlen_encoded    += rdy_cpy_sz;
        session->nbytes.remaining_to_send -= rdy_cpy_sz;
        if(outlen_encoded == session->outbuf.len) {
            status = TLS_RESP_REQ_MOREDATA; goto done;
        } // immediately return once outbuf is full in current fragment
    }
    if((session->nbytes.remaining_to_send == 0) && ((session->last_ext_entry_enc_len >> 15) != 0x0)) {
        if((outlen_encoded + empty_ext_sz) <= session->outbuf.len) {
            // time to insert 2-bytes 0x00 at the end, which means empty extension
            outlen_encoded += tlsEncodeWord16(&outbuf[outlen_encoded] , session->ext_enc_total_len);
            session->last_ext_entry_enc_len = 0x0;
        } else {
            status = TLS_RESP_REQ_MOREDATA;
        }
    }
done:
    session->outlen_encoded  = outlen_encoded;
    return status;
} // end of tlsEncodeHScertificate



// struct {
//     SignatureScheme algorithm;
//     opaque signature<0..2^16-1>;
// } CertificateVerify;
static tlsRespStatus  tlsEncodeHScertificateVerify(tlsSession_t *session)
{
    tlsOpaque16b_t  digiSig   = {0 , NULL};
    tlsRSApss_t     rsapssSig = {0 , 0};
    byte      *outbuf         = &session->outbuf.data[0];
    word16     outlen_encoded =  session->outlen_encoded;
    tlsRespStatus      status = TLS_RESP_OK;
    word16         rdy_cpy_sz = 0;
    word16         copied_sz  = 0;

    if(tlsChkFragStateOutMsg(session) == TLS_RESP_REQ_REINIT) {
        // currently this implementation only supports rsa_pss_rsae_sha256 for signing & verifying
        // signature on Certificate & CertificateVerify. (RFC 8446, section 9.1)
        rsapssSig.hash_id = TLS_HASH_ALGO_SHA256;
        rsapssSig.salt_len = mqttHashGetOutlenBytes(rsapssSig.hash_id);
        // generate TLS v1.3 ditial signature (plain text)
        status =  tlsCertVerifyGenDigitalSig(&session->sec, (const tlsRSApss_t *)&rsapssSig, &digiSig, (const byte)0x0);
        if(status < 0){ goto done; }
        // sign the digital signature (plain text)
        session->nbytes.remaining_to_send = (rsapssSig.salt_len << 3);
        session->client_signed_sig.len  = (rsapssSig.salt_len << 3);
        session->client_signed_sig.data = XMALLOC(sizeof(byte) * session->client_signed_sig.len);
        status =  tlsSignCertSignature(session->CA_priv_key, session->drbg, &digiSig, &session->client_signed_sig, TLS_ALGO_OID_RSASSA_PSS, &rsapssSig);
        if(status < 0){ goto done; }
        outlen_encoded += tlsEncodeWord16(&outbuf[outlen_encoded], TLS_SIGNATURE_RSA_PSS_RSAE_SHA256);
        outlen_encoded += tlsEncodeWord16(&outbuf[outlen_encoded], session->client_signed_sig.len);
        session->curr_outmsg_len = outlen_encoded - session->curr_outmsg_start + session->client_signed_sig.len;
    } // end of  first fragment check

    if(session->nbytes.remaining_to_send > 0) {
        copied_sz  = session->client_signed_sig.len - session->nbytes.remaining_to_send;
        rdy_cpy_sz = XMIN(session->outbuf.len - outlen_encoded, session->nbytes.remaining_to_send);
        XMEMCPY(&outbuf[outlen_encoded], &session->client_signed_sig.data[copied_sz], rdy_cpy_sz);
        outlen_encoded  += rdy_cpy_sz;
        session->nbytes.remaining_to_send -= rdy_cpy_sz;
        if(outlen_encoded == session->outbuf.len) {
            status = TLS_RESP_REQ_MOREDATA;
        } // outbuf is full in current fragment
    }
done:
    if(status < 0 || session->nbytes.remaining_to_send == 0) {
        if(session->client_signed_sig.data != NULL) {
            XMEMFREE((void *)session->client_signed_sig.data);
            session->client_signed_sig.data = NULL;
        }
    }
    if(digiSig.data != NULL) {
        XMEMFREE((void *)digiSig.data);
        digiSig.data = NULL;
    }
    session->outlen_encoded  = outlen_encoded;
    return status;
} // end of tlsEncodeHScertificateVerify



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
static tlsRespStatus  tlsEncodeHSfinished(tlsSession_t *session)
{
    byte      *outbuf         = &session->outbuf.data[0];
    word16     outlen_encoded =  session->outlen_encoded;
    word16     rdy_cpy_sz     = 0;
    word16     copied_sz      = 0;
    tlsRespStatus  status     = TLS_RESP_OK;
    tlsOpaque8b_t *base_key   = NULL;

    if(tlsChkFragStateOutMsg(session) == TLS_RESP_REQ_REINIT) {
        // handshake message size must be hash output length of chosen cipher suite
        tlsHashAlgoID  hash_id  = TLScipherSuiteGetHashID(session->sec.chosen_ciphersuite);
        session->tmpbuf.finish_verifydata.len  = mqttHashGetOutlenBytes(hash_id);
        session->tmpbuf.finish_verifydata.data = XMALLOC(sizeof(byte) * session->tmpbuf.finish_verifydata.len);
        base_key = &session->sec.secret.hs.client;
        status = tlsGenFinishedVerifyData(&session->sec, base_key, &session->tmpbuf.finish_verifydata);
        if(status < 0){ goto done; }
        session->nbytes.remaining_to_send = session->tmpbuf.finish_verifydata.len;
        session->curr_outmsg_len = outlen_encoded - session->curr_outmsg_start + session->tmpbuf.finish_verifydata.len;
    }
    if(session->nbytes.remaining_to_send > 0) {
        copied_sz  = session->tmpbuf.finish_verifydata.len - session->nbytes.remaining_to_send;
        rdy_cpy_sz = XMIN(session->outbuf.len - outlen_encoded, session->nbytes.remaining_to_send);
        XMEMCPY(&outbuf[outlen_encoded], &session->tmpbuf.finish_verifydata.data[copied_sz], rdy_cpy_sz);
        outlen_encoded  += rdy_cpy_sz;
        session->nbytes.remaining_to_send -= rdy_cpy_sz;
        if(outlen_encoded == session->outbuf.len) {
            status = TLS_RESP_REQ_MOREDATA;
        } // outbuf is full in current fragment
    }
done:
    if(status < 0 || session->nbytes.remaining_to_send == 0) {
        if(session->tmpbuf.finish_verifydata.data != NULL) {
            XMEMFREE((void *)session->tmpbuf.finish_verifydata.data);
            session->tmpbuf.finish_verifydata.data = NULL;
        }
    }
    session->outlen_encoded  = outlen_encoded;
    return status;
} // end of tlsEncodeHSfinished



void  tlsEncodeHandshakeHeader(tlsSession_t *session)
{
    tlsHandshakeMsg_t  *hs_header = NULL;
    word32       hs_msg_total_len = 0;
    // if the handshake message is split to multiple fragments(packets) to send,
    // then we only add handshake header to the first fragment.
    hs_header = (tlsHandshakeMsg_t *)&session->outbuf.data[session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES];
    hs_header->type  = tlsGetHSexpectedState(session);
    hs_msg_total_len = session->curr_outmsg_len - TLS_HANDSHAKE_HEADER_NBYTES - TLS_RECORD_LAYER_HEADER_NBYTES;
    tlsEncodeWord24((byte *)&hs_header->fragment.len[0], (word32)hs_msg_total_len);
} // end of tlsEncodeHandshakeHeader


static tlsRespStatus  tlsEncodeHandshake(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus  status = TLS_RESP_OK;
    tlsRespStatus  frag_status = tlsChkFragStateOutMsg(session);

    if(frag_status == TLS_RESP_REQ_REINIT) {
        if(session->outlen_encoded > (session->outbuf.len - TLS_HANDSHAKE_HEADER_NBYTES)) {
            return TLS_RESP_ERRMEM;
        } // report memory error because no sufficient space for placing 4-byte handshake header
        session->outlen_encoded  += TLS_HANDSHAKE_HEADER_NBYTES;
    }
    switch(tlsGetHSexpectedState(session)) {
        case TLS_HS_TYPE_CLIENT_HELLO      :
            status = tlsEncodeHSclientHello(session);
            break;
        case TLS_HS_TYPE_CERTIFICATE       :
            status = tlsEncodeHScertificate(session);
            break;
        case TLS_HS_TYPE_CERTIFICATE_VERIFY:
            status = tlsEncodeHScertificateVerify(session);
            break;
        case TLS_HS_TYPE_FINISHED          :
            status = tlsEncodeHSfinished(session);
            break;
        case TLS_HS_TYPE_END_OF_EARLY_DATA :
        default:
            status = TLS_RESP_ERR_NOT_SUPPORT;
            break;
    } // end of switch-case statement
    if(frag_status == TLS_RESP_REQ_REINIT) {
        tlsEncodeHandshakeHeader( session );
    }
    return status;
} // end of tlsEncodeHandshake


static tlsRespStatus  tlsEncodeAppData(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    byte      *outbuf         = &session->outbuf.data[0];
    word16     outlen_encoded =  session->outlen_encoded;
    word16     rdy_cpy_sz     = 0;
    word16     copied_sz      = 0;
    tlsRespStatus  status     = TLS_RESP_OK;

    if(tlsChkFragStateOutMsg(session) == TLS_RESP_REQ_REINIT) {
        session->curr_outmsg_len = outlen_encoded - session->curr_outmsg_start + session->app_pt.len;
        session->nbytes.remaining_to_send = session->app_pt.len;
    }
    if(session->nbytes.remaining_to_send > 0) {
        copied_sz  = session->app_pt.len - session->nbytes.remaining_to_send;
        rdy_cpy_sz = XMIN(session->outbuf.len - outlen_encoded, session->nbytes.remaining_to_send);
        XMEMCPY(&outbuf[outlen_encoded], &session->app_pt.data[copied_sz], rdy_cpy_sz);
        outlen_encoded  += rdy_cpy_sz;
        session->nbytes.remaining_to_send -= rdy_cpy_sz;
        if(outlen_encoded == session->outbuf.len) {
            status = TLS_RESP_REQ_MOREDATA;
        } // outbuf is full in current fragment
    }
    session->outlen_encoded  = outlen_encoded;
    return status;
} // end of tlsEncodeAppData


static tlsRespStatus  tlsEncodeChangeCipherSpec(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    session->outbuf.data[session->outlen_encoded++]  = (byte) 0x1;
    session->curr_outmsg_len = TLS_RECORD_LAYER_HEADER_NBYTES + 1;
    return TLS_RESP_OK;
} // end of tlsEncodeChangeCipherSpec


static tlsRespStatus  tlsEncodeAlert(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus  status = TLS_RESP_OK; // TODO: finish implementation
    return status;
} // end of tlsEncodeAlert


static void  tlsEncodeRecordHeader(tlsSession_t *session)
{   // if the record message is split to multiple fragments(packets) to send,
    // then we only add record layer header to the first fragment. first 5 bytes
    // are always reserved as record header
    tlsRecordLayer_t *rec_header = (tlsRecordLayer_t *)&session->outbuf.data[session->curr_outmsg_start];

    rec_header->majorVer  = TLS_VERSION_ENCODE_1_2 >> 8;
    rec_header->minorVer  = TLS_VERSION_ENCODE_1_2 & 0xff;
    if(session->flgs.hs_tx_encrypt == 0) { // for TLSplainText
        rec_header->type = session->record_type;
    }
    else { // for TLScipherText
        // add size for final part of TLSinnerPlainText (1-byte content-type, and variable-bytes authentication tag)
        session->curr_outmsg_len += 1 + session->sec.chosen_ciphersuite->tagSize;
        // modify content type
        rec_header->type = TLS_CONTENT_TYPE_APP_DATA;
    }
    tlsEncodeWord16((byte *)&rec_header->fragment.len, (session->curr_outmsg_len - TLS_RECORD_LAYER_HEADER_NBYTES));
} // end of tlsEncodeRecordHeader



static tlsRespStatus tlsEncodeInnerPlainTextFooter(tlsSession_t *session)
{   // this function may add up number of fragments if the required extra bytes of the footer cannot be fit
    // in current out-flight message (outbuf), in such case this function must return TLS_RESP_REQ_MOREDATA
    tlsRespStatus  status = TLS_RESP_OK;
    word16  outlen_encoded = session->outlen_encoded;
    int avail_buf_sz = session->outbuf.len - outlen_encoded - (1 + session->sec.chosen_ciphersuite->tagSize);
    if(avail_buf_sz >= 0) {
        session->outbuf.data[outlen_encoded++] = session->record_type;
        // still preserve last few bytes for authentication tag, which will be appended to outbuf later in encryotion function
        outlen_encoded += session->sec.chosen_ciphersuite->tagSize;
        session->outlen_encoded = outlen_encoded;
    } else {
        status = TLS_RESP_REQ_MOREDATA;
    }
    return status;
} // end of tlsEncodeInnerPlainTextFooter



tlsRespStatus  tlsEncodeRecordLayer(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus  status = TLS_RESP_OK;
    tlsRespStatus  frag_status = tlsChkFragStateOutMsg(session);
    // keep first 5 bytes for header of each record message
    if(frag_status == TLS_RESP_REQ_REINIT) { // runs only for the first fragment
        if(session->outlen_encoded > (session->outbuf.len - TLS_RECORD_LAYER_HEADER_NBYTES)) {
            return TLS_RESP_ERRMEM;
        } // report memory error because no sufficient space in outbuf for placing 5-byte record header
        session->curr_outmsg_start = session->outlen_encoded;
        session->outlen_encoded   += TLS_RECORD_LAYER_HEADER_NBYTES;
    } else { // if this encoding message split to several fragments (and the first fragment was already sent)
        session->curr_outmsg_start = 0;
    }
    switch(session->record_type)
    {
        case TLS_CONTENT_TYPE_HANDSHAKE:
            status = tlsEncodeHandshake(session);
            break;
        case TLS_CONTENT_TYPE_APP_DATA:
            status = tlsEncodeAppData(session);
            break;
        case TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
            status = tlsEncodeChangeCipherSpec(session);
            break;
        case TLS_CONTENT_TYPE_ALERT:
            status = tlsEncodeAlert(session);
        default:
            status = TLS_RESP_ERR_NOT_SUPPORT;
            break;
    } // end of switch-case statement
    if(status >= 0) {
        if(frag_status == TLS_RESP_REQ_REINIT) {
            tlsEncodeRecordHeader(session);
        } // encode record header only at the first fragment
        if(status == TLS_RESP_OK) {
            // for encoding functions, status == TLS_RESP_OK implicitly means we get final
            // fragment of current TLSInnerPlainText, otherwise it will be TLS_RESP_REQ_MOREDATA,
	    if(session->flgs.hs_tx_encrypt != 0) {
                status = tlsEncodeInnerPlainTextFooter(session);
            } // if encryption is enabled, it's time to encode footer of the TLSInnerPlainText
        }
    }
    session->log.last_encode_result = status;
    return status;
} // end of tlsEncodeRecordLayer

