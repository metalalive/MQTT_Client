#include "mqtt_include.h"

// ----------------- Hash function integration with third-party crypto library -------------------------
extern int MGTT_CFG_HASH_SHA256_FN_INIT(mqttHash_t *md);

extern int MGTT_CFG_HASH_SHA384_FN_INIT(mqttHash_t *md);

extern int MGTT_CFG_HASH_SHA256_FN_UPDATE(mqttHash_t *md, const byte *in, unsigned long inlen);

extern int MGTT_CFG_HASH_SHA384_FN_UPDATE(mqttHash_t *md, const byte *in, unsigned long inlen);

extern int MGTT_CFG_HASH_SHA256_FN_DONE(mqttHash_t *md, byte *out);

extern int MGTT_CFG_HASH_SHA384_FN_DONE(mqttHash_t *md, byte *out);

static const byte SHA256hashedEmptyInputString [0x20] = {
    0xe3,  0xb0,  0xc4,  0x42,   0x98,  0xfc,  0x1c,  0x14,
    0x9a,  0xfb,  0xf4,  0xc8,   0x99,  0x6f,  0xb9,  0x24,
    0x27,  0xae,  0x41,  0xe4,   0x64,  0x9b,  0x93,  0x4c,
    0xa4,  0x95,  0x99,  0x1b,   0x78,  0x52,  0xb8,  0x55,
};

static const byte SHA384hashedEmptyInputString [0x30] = {
     0x38,  0xb0, 0x60,  0xa7,  0x51,  0xac, 0x96,  0x38,
     0x4c,  0xd9, 0x32,  0x7e,  0xb1,  0xb1, 0xe3,  0x6a,
     0x21,  0xfd, 0xb7,  0x11,  0x14,  0xbe, 0x07,  0x43,
     0x4c,  0x0c, 0xc7,  0xbf,  0x63,  0xf6, 0xe1,  0xda,
     0x27,  0x4e, 0xde,  0xbf,  0xe7,  0x6f, 0x65,  0xfb,
     0xd5,  0x1a, 0xd2,  0xf1,  0x48,  0x98, 0xb9,  0x5b,
};

tlsRespStatus  tlsCpyHashEmptyInput(tlsHashAlgoID hash_id ,tlsOpaque8b_t *out)
{
    if((out == NULL) || (out->data != NULL)) { return TLS_RESP_ERRARGS; }
    tlsRespStatus  status  = TLS_RESP_OK;
    out->len = mqttHashGetOutlenBytes(hash_id);
    switch(hash_id) {
        case TLS_HASH_ALGO_SHA256:
            out->data = (byte *)&SHA256hashedEmptyInputString[0];
            break;
        case TLS_HASH_ALGO_SHA384:
            out->data = (byte *)&SHA384hashedEmptyInputString[0];
            break;
        default:
            status = TLS_RESP_ERRARGS;
            break;
    } // end of switch-case statement
    return  status;
} // end of tlsCpyHashEmptyInput


// when cipher suite has not been negotiated yet, this implementation enabled all acceptable hash handling
// object (for TLS v1.3 , there are SHA256 and SHA384). Once cipher suite is negotiated, hash algorithm is also
// selected, then we should clean up the hash handling object(s) for the unselected hash algorithm, by calling
// this internal function below, which deallocates space from the given hash handling object, also
// deallocates space from snapshot of the hashed message.
static void  tlsTransHashCleanHashHandler(tlsHash_t **hash_obj, byte **snapshot_hashed_msg)
{
    if((hash_obj != NULL) && (*hash_obj != NULL)) {
        XMEMFREE((void *)*hash_obj);
        *hash_obj = NULL;
    }
    if((snapshot_hashed_msg != NULL) && (*snapshot_hashed_msg != NULL)) {
        XMEMFREE((void *)*snapshot_hashed_msg);
        *snapshot_hashed_msg = NULL;
    }
} // end of tlsTransHashCleanHashHandler


static void  tlsTransHashCleanAll(tlsSecurityElements_t *sec)
{
    tlsTransHashCleanHashHandler( &sec->hashed_hs_msg.objsha256, &sec->hashed_hs_msg.snapshot_server_finished );
    tlsTransHashCleanHashHandler( &sec->hashed_hs_msg.objsha384, NULL );
} // end of tlsTransHashCleanAll



static tlsRespStatus  tlsTransHashUpdate(tlsSecurityElements_t *sec, const byte *in, word32 inlen)
{
    if((sec == NULL) || (in == NULL) || (inlen == 0)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus  status = TLS_RESP_ERR;
    tlsHash_t     *hash   = NULL;
    int       resultcode  = 0;
    tlsHashAlgoID hash_id = TLScipherSuiteGetHashID(sec->chosen_ciphersuite);

    if((hash_id == TLS_HASH_ALGO_NOT_NEGO) || (hash_id == TLS_HASH_ALGO_SHA256)) {
        hash = sec->hashed_hs_msg.objsha256;
        if(hash == NULL) {
            status = TLS_RESP_ERRARGS; goto end_of_update;
        }
        resultcode = MGTT_CFG_HASH_SHA256_FN_UPDATE(hash, in, inlen);
        if(resultcode != 0) {
            status = TLS_RESP_ERR_HASH; goto end_of_update;
        } else { status = TLS_RESP_OK; }
    }
    if((hash_id == TLS_HASH_ALGO_NOT_NEGO) || (hash_id == TLS_HASH_ALGO_SHA384)) {
        hash = sec->hashed_hs_msg.objsha384;
        if(hash == NULL) {
            status = TLS_RESP_ERRARGS; goto end_of_update;
        }
        resultcode = MGTT_CFG_HASH_SHA384_FN_UPDATE(hash, in, inlen);
        if(resultcode != 0) {
            status = TLS_RESP_ERR_HASH; goto end_of_update;
        } else { status = TLS_RESP_OK; }
    }
end_of_update:
    return  status;
} // end of tlsTransHashUpdate



tlsRespStatus  tlsTransHashCleanUnsuedHashHandler(tlsSecurityElements_t *sec)
{
    if(sec == NULL) {  return TLS_RESP_ERRARGS; }
    switch(TLScipherSuiteGetHashID(sec->chosen_ciphersuite)) { // clean up unused hash object when hash function is already negotiated
        case TLS_HASH_ALGO_SHA256:
            tlsTransHashCleanHashHandler( &sec->hashed_hs_msg.objsha384, NULL );
            break;
        case TLS_HASH_ALGO_SHA384:
            tlsTransHashCleanHashHandler( &sec->hashed_hs_msg.objsha256, NULL );
            break;
        default:
            break;
    } // end of switch case
    return  TLS_RESP_OK;
} // end of tlsTransHashCleanUnsuedHashHandler



tlsRespStatus  tlsTranscrptHashInit(tlsSecurityElements_t *sec)
{
    if(sec == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus status = TLS_RESP_ERR;
    int       resultcode = 0;
    tlsHashAlgoID  hash_id = TLScipherSuiteGetHashID( sec->chosen_ciphersuite );
    // before we start handshake process, the ciphersuite hasn't been negotiated with the remote peer,
    // the simple way is to initialize all hash functions supported in this TLS implementation, then
    // de-initialize many of them as soon as ciphersuite (what kind of hash function) is chosen.
    if((hash_id == TLS_HASH_ALGO_NOT_NEGO) || (hash_id == TLS_HASH_ALGO_SHA256)) {
        if(sec->hashed_hs_msg.objsha256 == NULL) {
            sec->hashed_hs_msg.objsha256 = (tlsHash_t *) XMALLOC(sizeof(tlsHash_t));
        }
        resultcode = MGTT_CFG_HASH_SHA256_FN_INIT(sec->hashed_hs_msg.objsha256);
        if(resultcode != 0) {
            status = TLS_RESP_ERR_HASH; goto end_of_init;
        } else { status = TLS_RESP_OK; }
    } // TODO: find better way to implement this
    if((hash_id == TLS_HASH_ALGO_NOT_NEGO) || (hash_id == TLS_HASH_ALGO_SHA384)) {
        if(sec->hashed_hs_msg.objsha384 == NULL) {
            sec->hashed_hs_msg.objsha384 = (tlsHash_t *) XMALLOC(sizeof(tlsHash_t));
        }
        resultcode = MGTT_CFG_HASH_SHA384_FN_INIT(sec->hashed_hs_msg.objsha384);
        if(resultcode != 0) {
            status = TLS_RESP_ERR_HASH; goto end_of_init;
        } else { status = TLS_RESP_OK; }
    }
end_of_init:
    return status;
} // end of tlsTranscrptHashInit



tlsRespStatus  tlsTranscrptHashReInit(tlsSecurityElements_t *sec)
{
    if(sec == NULL) { return TLS_RESP_ERRARGS; }
    tlsHashAlgoID hash_id = TLScipherSuiteGetHashID(sec->chosen_ciphersuite);
    if((hash_id == TLS_HASH_ALGO_UNKNOWN) || (hash_id == TLS_HASH_ALGO_NOT_NEGO)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    // store  Hash(ClientHello1) , this function is called only on receipt of HelloRetryRequest
    word16     len = mqttHashGetOutlenBytes(hash_id);
    byte      *buf = (byte *) XMALLOC(sizeof(byte) * (len + 4));
     // write hash value of ClientHello1 to snapshot_buf
    status =  tlsTransHashTakeSnapshot(sec, hash_id, &buf[4], len);
    if(status < 0) { goto end_of_reinit; }
    tlsTransHashCleanAll(sec);
    status =  tlsTranscrptHashInit(sec);
    if(status < 0) { goto end_of_reinit; }
    //  update hash with message_hash || 00 00  Hash.length ||  Hash(ClientHello1)
    //  note that message_hash = TLS_HS_TYPE_MESSAGE_HASH
    //  Hash.length in TLS v1.3 is either 32 or 48. TODO: verify
    buf[0] = TLS_HS_TYPE_MESSAGE_HASH;
    buf[1] = buf[2] = 0;
    buf[3] = (len & XGET_BITMASK(8));
    status = tlsTransHashUpdate(sec, (const byte *)buf, (4 + len));
end_of_reinit:
    XMEMFREE((void *)buf);
    return status;
} // end of tlsTranscrptHashReInit




tlsRespStatus  tlsTranscrptHashHSmsgUpdate(tlsSession_t  *session, tlsOpaque16b_t *buf)
{
    if(session->record_type != TLS_CONTENT_TYPE_HANDSHAKE) {
        return TLS_RESP_OK; // skip this function
    }
    if((session == NULL) || (buf==NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    byte         *in     = &buf->data[0];
    word32        inlen  =  0;

    // case #1 : perform transcript hash before encryption to first fragment
    if(buf == &session->outbuf) {
        in    += session->curr_outmsg_start; // might be several record messages in the same outgoing flight
        inlen  = session->outlen_encoded - session->curr_outmsg_start;
        if(tlsChkFragStateOutMsg(session) == TLS_RESP_REQ_REINIT) {
            // skip 5-byte record header for the first fragment of given handshake message
            in    += TLS_RECORD_LAYER_HEADER_NBYTES;
            inlen -= TLS_RECORD_LAYER_HEADER_NBYTES;
        }
        if(session->flgs.hs_tx_encrypt != 0) {
            if(session->log.last_encode_result == TLS_RESP_REQ_MOREDATA) {
                byte blocksize = session->sec.chosen_ciphersuite->tagSize;  // get cipher block size
                inlen -= inlen % blocksize;
            } else if (session->log.last_encode_result == TLS_RESP_OK) {
                // last_encode_result == TLS_RESP_OK implicit means it's the final fragment
                inlen -= (1 + session->sec.chosen_ciphersuite->tagSize);
            }
        } // end of encryption flag check
    }
    // case #2 : perform transcript hash after decryption from first fragment
    else if(buf == &session->inbuf) {
        inlen = session->inlen_decrypted;
        if((tlsChkFragStateInMsg(session) & TLS_RESP_FIRST_FRAG) == TLS_RESP_FIRST_FRAG) {
            // skip 5-byte record header for the first fragment of given handshake message
            in     += TLS_RECORD_LAYER_HEADER_NBYTES;
            inlen  -= TLS_RECORD_LAYER_HEADER_NBYTES;
        }
        if((session->flgs.hs_rx_encrypt != 0) && (session->sec.flgs.ct_final_frag != 0)) {
            inlen  -= (1 + session->sec.chosen_ciphersuite->tagSize);
        } // for TLScipherText, 1-byte record type, authentication tag, and padding bytes must be skipped.
    }
    if(inlen > 0) {
        status  = tlsTransHashUpdate(&session->sec, (const byte *)in, inlen);
    }
    // temporarily store Transcript-Hash(ClientHello || ... || server Finished) , for generating master secret at later time
    if(session->flgs.hs_server_finish == 0 && tlsGetHSexpectedState(session) == TLS_HS_TYPE_FINISHED) {
        tlsHashAlgoID  hash_id = TLScipherSuiteGetHashID(session->sec.chosen_ciphersuite);
        word16 hash_sz = mqttHashGetOutlenBytes(hash_id);
        if(session->sec.hashed_hs_msg.snapshot_server_finished == NULL) {
            session->sec.hashed_hs_msg.snapshot_server_finished = XMALLOC(sizeof(byte) * hash_sz);
        }
        status = tlsTransHashTakeSnapshot(&session->sec, hash_id, session->sec.hashed_hs_msg.snapshot_server_finished, hash_sz);
    }
////end_of_hs_hash_update:
    return status;
} // end of tlsTranscrptHashHSmsgUpdate



tlsRespStatus  tlsTransHashTakeSnapshot(tlsSecurityElements_t  *sec, tlsHashAlgoID hash_id, byte *out, word16 outlen)
{
    if((sec == NULL) || (out == NULL) || (outlen == 0)) {
        return TLS_RESP_ERRARGS;
    }
    word16  expect_hash_sz = mqttHashGetOutlenBytes(hash_id);
    if((expect_hash_sz < 2) || (outlen < expect_hash_sz)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus  status = TLS_RESP_OK;
    tlsHash_t     *hash_chosen = NULL;
    tlsHash_t     *hash_bak    = (tlsHash_t *) XMALLOC(sizeof(tlsHash_t));
    int       resultcode = 0;

    switch(hash_id) {
        case TLS_HASH_ALGO_SHA256:
            hash_chosen = sec->hashed_hs_msg.objsha256;
            if(hash_chosen == NULL) { status = TLS_RESP_ERRARGS; }
            else { // TODO: recheck whether it is good idea to backup & recover hash MD state inside this function
                XMEMCPY(hash_bak, hash_chosen, sizeof(tlsHash_t));
                resultcode = MGTT_CFG_HASH_SHA256_FN_DONE(hash_chosen, out);
                if(resultcode != 0) { status = TLS_RESP_ERR_HASH; }
            }
            break;
        case TLS_HASH_ALGO_SHA384:
            hash_chosen = sec->hashed_hs_msg.objsha384;
            if(hash_chosen == NULL) { status = TLS_RESP_ERRARGS; }
            else {
                XMEMCPY(hash_bak, hash_chosen, sizeof(tlsHash_t));
                resultcode = MGTT_CFG_HASH_SHA384_FN_DONE(hash_chosen, out);
                if(resultcode != 0) { status = TLS_RESP_ERR_HASH; }
            }
            break;
        default:
            status = TLS_RESP_ERRARGS;
            break;
    } // end of switch-case statement
    if(hash_chosen != NULL) { XMEMCPY(hash_chosen, hash_bak, sizeof(tlsHash_t)); }
    XMEMFREE((void *)hash_bak);
    return status;
} // end of tlsTransHashTakeSnapshot



// there are 2 cases when this DONE function should be called :
// (1) when client encodes FINISH handshake message, the hashed handshake message will be included as
//     part of authentication message.
// (2) when anything goes wrong & TLS session is abnormally closed, this function will be called for
//     de-initialization.
tlsRespStatus  tlsTranscrptHashDone(tlsSecurityElements_t *sec, tlsOpaque16b_t *outbuf)
{
    if(sec == NULL) {  return TLS_RESP_ERRARGS; }
    tlsRespStatus status = TLS_RESP_OK;
    // if we haven't negotiated cipher suite, then directly free up the space for hash structure
    tlsHashAlgoID hash_id = TLScipherSuiteGetHashID( sec->chosen_ciphersuite );
    if((hash_id != TLS_HASH_ALGO_UNKNOWN) && (hash_id != TLS_HASH_ALGO_NOT_NEGO))
    {
        if((outbuf == NULL) || (outbuf->data == NULL)) {
            status = TLS_RESP_ERRARGS;
        }
        else {
            status =  tlsTransHashTakeSnapshot(sec, hash_id, outbuf->data, outbuf->len);
        }
    } // end of if chosen_ciphersuite != NULL
    // de-initialization finally
    tlsTransHashCleanAll(sec);
    return status;
} // end of tlsTranscrptHashDone

