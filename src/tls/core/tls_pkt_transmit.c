#include "mqtt_include.h"

tlsRespStatus tlsPktSendToPeer(tlsSession_t *session, byte flush_flg) {
    if ((session == NULL) || (session->outbuf.data == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    byte         *buf = NULL;
    word16        rdy_nbytes = 0; // number of bytes ready to send out
    word16        buf_len = 0;
    int           wr_len = 0;

    if (session->flgs.hs_tx_encrypt == 0) {
        session->outlen_encrypted = session->outlen_encoded;
    }
    rdy_nbytes = session->outlen_encrypted;
    if (rdy_nbytes > session->outbuf.len) {
        status = TLS_RESP_ERRMEM;
        goto end_of_pkt_write;
    }
    // re-calculate number of fragments for current encoding record message
    if (tlsChkFragStateOutMsg(session) == TLS_RESP_REQ_REINIT) {
        if (session->curr_outmsg_len > TLS_MAX_BYTES_RECORD_LAYER_PKT) {
            status = TLS_RESP_ERR_EXCEED_MAX_REC_SZ;
            goto end_of_pkt_write;
        }
        tlsInitFragNumOutMsg(session);
    }
    if (session->log.last_encode_result == TLS_RESP_REQ_MOREDATA) {
        // implicit meaning : (1) not the final fragment
        // (2) current fragment must be sent out in order to make more space avaiable in
        // session->outbuf
        tlsIncrementFragNumOutMsg(session);
        flush_flg = 1;
    }
    // flush the encrypted data to system-level send function if flush_flg is set
    buf_len = session->outbuf.len - rdy_nbytes;
    wr_len =
        TLS_RECORD_LAYER_HEADER_NBYTES + TLS_HANDSHAKE_HEADER_NBYTES + 17; // used as temp variable
    // if flush flag is NOT set, and there are less than 26 bytes avaiable, then we simply place
    // encoded or encrypted bytes in outbuf, set them at later time when there's more data bytes
    // written in.
    if ((flush_flg == 0) && (buf_len >= wr_len)) {
        status = TLS_RESP_REQ_MOREDATA;
    } else { // otherwise, we still send out all the encrypted data in outbuf
        // send bytes from outbuf to the remote peer
        buf_len = rdy_nbytes;
        buf = session->outbuf.data;
        do {
            wr_len = mqttSysPktWrite(&session->ext_sysobjs[0], buf, buf_len);
            if (wr_len < 0) {
                status = tlsRespCvtFromMqttResp((mqttRespStatus)wr_len);
                goto end_of_pkt_write;
            }
            buf += wr_len;
            buf_len -= wr_len;
        } while (buf_len > 0);
        // the current TLS record message may be too large to fit in out-flight buffer (a TCP
        // packet), it is split into multiple fragments, in that case we will encode and send the
        // subsequent fragments
        XASSERT(buf_len == 0); // should be always zero ?
        session->outlen_encoded -= rdy_nbytes;
        session->outlen_encrypted = 0;
        if (session->outlen_encoded > 0) {
            buf = session->outbuf.data;
            XMEMMOVE((void *)buf, (void *)&buf[rdy_nbytes], (size_t)session->outlen_encoded);
        } //  move encoded-but-not-encrypted bytes to the begining of session->outbuf
    } // end of if flush is enabled

    tlsDecrementFragNumOutMsg(session);
end_of_pkt_write:
    return status;
} // end of tlsPktSendToPeer

tlsRespStatus tlsPktRecvFromPeer(tlsSession_t *session) {
    if ((session == NULL) || (session->inbuf.data == NULL)) {
        return TLS_RESP_ERRARGS;
    } else if (session->inlen_unprocessed > session->inbuf.len) {
        return TLS_RESP_ERR;
    }
    tlsRespStatus status = TLS_RESP_OK;
    int           rd_len = 0;
    int           cpy_len = 0;
    byte         *buf = &session->inbuf.data[0];
    word16        bufmaxlen = session->inbuf.len;

    if (tlsChkFragStateInMsg(session) ==
        TLS_RESP_REQ_REINIT) { // the first fragment of in-flight message must contain record header
        const tlsRecordLayer_t *rec_header = (tlsRecordLayer_t *)buf;
        // read first 5 byte as header of the new TLS record message
        rd_len = mqttSysPktRead(
            &session->ext_sysobjs[0], buf, TLS_RECORD_LAYER_HEADER_NBYTES, session->cmd_timeout_ms
        );
        if (rd_len < 0) {
            status = tlsRespCvtFromMqttResp((mqttRespStatus)rd_len);
            goto end_of_pkt_read;
        } else if (rd_len != TLS_RECORD_LAYER_HEADER_NBYTES) {
            status = TLS_RESP_MALFORMED_PKT;
            goto end_of_pkt_read;
        }
        // check record type, version code, and message size
        status = tlsVerifyDecodeRecordType(rec_header->type);
        if (status < 0) {
            goto end_of_pkt_read;
        }
        status = tlsVerifyDecodeVersionCode(&rec_header->majorVer);
        if (status < 0) {
            goto end_of_pkt_read;
        }
        // received record header is verified, start reading record message body
        tlsDecodeWord16((byte *)&rec_header->fragment.len, &session->inlen_total);
        if (session->inlen_total > TLS_MAX_BYTES_RECORD_LAYER_PKT) {
            status = TLS_RESP_ERR_EXCEED_MAX_REC_SZ;
            goto end_of_pkt_read;
        }
        session->inlen_unprocessed = TLS_RECORD_LAYER_HEADER_NBYTES;
        bufmaxlen -= TLS_RECORD_LAYER_HEADER_NBYTES;
        tlsInitFragNumInMsg(session);
    } else { // if there are at least 2 fragments for current record message
        if (session->inlen_unprocessed > 0) {
            // adjust in-flight buffer if there is still received-but-undecrypted bytes (means we
            // have more bytes to receive in next fragment) (by calling memmove ??)
            XMEMMOVE(
                (void *)buf, (void *)&buf[session->inlen_decrypted],
                (size_t)session->inlen_unprocessed
            );
            bufmaxlen -= session->inlen_unprocessed;
        }
    }

    if (session->inlen_total > bufmaxlen) {
        tlsIncrementFragNumInMsg(session);
        cpy_len = bufmaxlen;
    } else {
        cpy_len = session->inlen_total;
    }
    do { // load message (in one or several rounds)
        rd_len = mqttSysPktRead(
            &session->ext_sysobjs[0], &buf[session->inlen_unprocessed], cpy_len,
            session->cmd_timeout_ms
        );
        if (rd_len < 0) {
            status = tlsRespCvtFromMqttResp((mqttRespStatus)rd_len);
            goto end_of_pkt_read;
        }
        cpy_len -= rd_len;
        session->inlen_total -= rd_len;
        session->inlen_unprocessed += rd_len;
    } while (cpy_len > 0);

    session->inlen_decoded = 0;
    if (session->flgs.hs_rx_encrypt == 0) { // for unencrypted record message
        session->inlen_decrypted = session->inlen_unprocessed;
        session->inlen_unprocessed = 0;
    }
end_of_pkt_read:
    return status;
} // end of tlsPktRecvFromPeer

// check the status of fragment calculation object for current encoding / sending record message
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

void tlsInitFragNumOutMsg(tlsSession_t *session) {
    if (session != NULL) {
        session->num_frags_out = 1;
        session->remain_frags_out = 1;
    }
} // end of tlsInitFragNumOutMsg

void tlsIncrementFragNumOutMsg(tlsSession_t *session) {
    if (session != NULL) {
        session->num_frags_out += 1;
        session->remain_frags_out += 1;
    }
} // end of tlsIncrementFragNumOutMsg

void tlsDecrementFragNumOutMsg(tlsSession_t *session) {
    if ((session != NULL) && (session->remain_frags_out > 0)) {
        session->remain_frags_out -= 1;
        if (session->remain_frags_out == 0) {
            session->num_frags_out = 0;
        }
    }
} // end of tlsDecrementFragNumOutMsg

// check the status of fragment calculation object for current decoding / receiving record message
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

void tlsInitFragNumInMsg(tlsSession_t *session) {
    if (session != NULL) {
        session->num_frags_in = 1;
        session->remain_frags_in = 1;
    }
} // end of tlsInitFragNumInMsg

void tlsIncrementFragNumInMsg(tlsSession_t *session) {
    if (session != NULL) {
        session->num_frags_in += 1;
        session->remain_frags_in += 1;
    }
} // end of tlsIncrementFragNumInMsg

void tlsDecrementFragNumInMsg(tlsSession_t *session) {
    if ((session != NULL) && (session->remain_frags_in > 0)) {
        session->remain_frags_in -= 1;
        if (session->remain_frags_in == 0) {
            session->num_frags_in = 0;
        }
    }
} // end of tlsDecrementFragNumInMsg
