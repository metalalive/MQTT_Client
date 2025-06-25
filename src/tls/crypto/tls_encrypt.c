#include "mqtt_include.h"

static byte tlsGetInnertextRecType(tlsSession_t *session, const byte *innertext, word32 len) {
    tlsSecurityElements_t *sec = &session->sec;
    byte                   out = 0;
    // TODO: figure out better way to handle post-handshake messages like KeyUpdate or
    // NewSessionTicket after handshake process is done, They may be sent from peer between
    // application data messages. Currently this implementation can ONLY recognize post-handshake
    // messages which fit into one single fragment.
    if ((sec->flgs.ct_first_frag) != 0 && (sec->flgs.ct_final_frag != 0)) {
        out = innertext[len - 1 - sec->chosen_ciphersuite->tagSize];
    } else if (session->flgs.hs_client_finish == 0) {
        out = (byte)TLS_CONTENT_TYPE_HANDSHAKE;
    } // For record messages consisting of multiple network fragments, check the flags & guess the
      // record type
    else {
        out = (byte)TLS_CONTENT_TYPE_APP_DATA;
    }
    return out;
} // end of tlsGetInnertextRecType

// session->outlen_encrypted = 0
// while (...) {
//     perform_encryption_with_cipher( ... )
//     session->outlen_encoded   -= xxxx;
//     session->outlen_encrypted += xxxx;
// }
tlsRespStatus tlsEncryptRecordMsg(tlsSession_t *session) {
    if ((session == NULL) || (session->sec.chosen_ciphersuite == NULL)) {
        return TLS_RESP_ERRARGS;
    } else if (session->outlen_encrypted > session->outlen_encoded) {
        return TLS_RESP_ERR;
    }
    tlsRespStatus status = TLS_RESP_OK;
    byte         *ct_start = &session->outbuf.data[session->curr_outmsg_start];
    word32        ct_len = session->outlen_encoded - session->curr_outmsg_start;
    // Note that #bytes encoded message may not be equal to #bytes encrypted message
    if (tlsChkFragStateOutMsg(session) == TLS_RESP_REQ_REINIT) {
        session->sec.flgs.ct_first_frag = 1;
        // update AAD for encryption operation
        XMEMCPY(&session->sec.aad[0], ct_start, TLS_MAX_BYTES_AAD);
        // update per-record nonce for encryption operation
        byte iv_sz = session->sec.chosen_ciphersuite->ivSize;
        XMEMCPY(&session->sec.nonce[0], &session->sec.writeIV[0], iv_sz);
        session->sec.nonce[iv_sz - 1] ^= session->log.num_enc_recmsg_sent;
        // skip 5-byte record header of encrypted  message
        session->outlen_encrypted += TLS_RECORD_LAYER_HEADER_NBYTES;
        ct_start += TLS_RECORD_LAYER_HEADER_NBYTES;
        ct_len -= TLS_RECORD_LAYER_HEADER_NBYTES;
    } else {
        session->sec.flgs.ct_first_frag = 0;
    }
    if (session->log.last_encode_result ==
        TLS_RESP_OK) { // implicit meaning : it's the final fragment
        XASSERT(ct_len >= (1 + session->sec.chosen_ciphersuite->tagSize));
        session->sec.flgs.ct_final_frag = 1;
    } else {
        XASSERT(session->log.last_encode_result == TLS_RESP_REQ_MOREDATA);
        session->sec.flgs.ct_final_frag = 0;
    }
    status =
        session->sec.chosen_ciphersuite->encrypt_fn(&session->sec, ct_start, ct_start, &ct_len);
    if (status >= 0) { // post processing after decryption succeed
        if (session->sec.flgs.ct_final_frag != 0) {
            session->log.num_enc_recmsg_sent++; // increment log counter by one, then overflow check
            XASSERT(session->log.num_enc_recmsg_sent != 0);
        }
        session->outlen_encrypted += ct_len;
    }
    return status;
} // end of tlsEncryptRecordMsg

tlsRespStatus tlsDecryptRecordMsg(tlsSession_t *session) {
    if ((session == NULL) || (session->sec.chosen_ciphersuite == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = tlsChkFragStateInMsg(session);
    // shouldn't perform decryption function before receiving new record message from peer
    if (status == TLS_RESP_REQ_REINIT) {
        return TLS_RESP_ERR;
    }
    // starting offset of current fragment (if exists) of TLSCiphertext
    byte  *ct_start = &session->inbuf.data[0];
    word32 ct_len = session->inlen_unprocessed;
    if ((status & TLS_RESP_FIRST_FRAG) == TLS_RESP_FIRST_FRAG) {
        session->sec.flgs.ct_first_frag = 1;
        // update AAD for decryption operation
        XMEMCPY(&session->sec.aad[0], ct_start, TLS_MAX_BYTES_AAD);
        // update per-record nonce for decryption operation
        byte iv_sz = session->sec.chosen_ciphersuite->ivSize;
        XMEMCPY(&session->sec.nonce[0], &session->sec.readIV[0], iv_sz);
        session->sec.nonce[iv_sz - 1] ^= session->log.num_enc_recmsg_recv;
        // skip 5-byte record header of encrypted  message
        session->inlen_decrypted = TLS_RECORD_LAYER_HEADER_NBYTES;
        session->inlen_unprocessed -= TLS_RECORD_LAYER_HEADER_NBYTES;
        ct_start += TLS_RECORD_LAYER_HEADER_NBYTES;
        ct_len -= TLS_RECORD_LAYER_HEADER_NBYTES;
    } else {
        session->sec.flgs.ct_first_frag = 0;
        session->inlen_decrypted = 0;
    }
    if ((status & TLS_RESP_FINAL_FRAG) == TLS_RESP_FINAL_FRAG) {
        session->sec.flgs.ct_final_frag = 1;
    } else {
        session->sec.flgs.ct_final_frag = 0;
    }
    // if we have next fragment smaller than authentication tag size, that means current fragment
    // contains part of authentication tag, then we can reduce the length of current ciphertext to
    // decrypt in advance, then next (final) fragment will verify the tag & decrypt final ciphertext
    // block.
    if ((session->inlen_total > 0) &&
        (session->inlen_total < session->sec.chosen_ciphersuite->tagSize)) {
        ct_len -= (session->sec.chosen_ciphersuite->tagSize - session->inlen_total);
    }
    status =
        session->sec.chosen_ciphersuite->decrypt_fn(&session->sec, ct_start, ct_start, &ct_len);
    if (status >= 0) { // post processing after decryption succeed
        if (session->sec.flgs.ct_first_frag != 0) {
            // update actual record type TLSInnerPlaintext.type
            session->inbuf.data[0] =
                tlsGetInnertextRecType(session, (const byte *)ct_start, ct_len);
        }
        if (session->sec.flgs.ct_final_frag != 0) {
            session->log.num_enc_recmsg_recv++; // increment log counter by one, then overflow check
            XASSERT(session->log.num_enc_recmsg_recv != 0);
        }
        session->inlen_decrypted += ct_len;
        session->inlen_unprocessed -= ct_len;
    }
    return status;
} // end of tlsDecryptRecordMsg
