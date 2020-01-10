#include "mqtt_include.h"

extern const tlsVersionCode   tls_supported_versions[];
extern const tlsNamedGrp      tls_supported_named_groups[];
extern       tlsPSK_t        *tls_PSKs_rdy_list;


static tlsRespStatus  tlsDecodeExtsSupportVersion(tlsSession_t *session, tlsExtEntry_t *ext_in)
{
    if((session == NULL) || (ext_in == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if(ext_in->content.len != 2) { return TLS_RESP_ERR_DECODE; }
    tlsRespStatus status = TLS_RESP_OK;
    word16    idx  = 0;
    word16    len  = 0;
    if(session->chosen_tls_ver == 0) { // first time to update selected_version
        tlsDecodeWord16(&ext_in->content.data[0], (word16 *)&session->chosen_tls_ver);
        len = (word16) tlsGetSupportedVersionListSize();
        for (idx = 0; idx < len; idx++) {
            if(session->chosen_tls_ver == tls_supported_versions[idx]) { break; }
        }
        if(idx == len) {
            // should send illegal_perameter alert if selected_version from the peer (server) cannot be
            // found in the tls_supported_versions list 
            status = TLS_RESP_REQ_ALERT;
        }
        else { status = TLS_RESP_OK; }
    }
    else {
        // if this is second time to update selected_version, the previous update must be driven by HelloRetryRequest
        // , the update this time must be for ServerHello, and selected_version must not be changed.
        tlsDecodeWord16( &ext_in->content.data[0], &idx); // used idx as temporarily variable
        if(session->chosen_tls_ver != idx) { status = TLS_RESP_REQ_ALERT; }
    }
    return status;
} // end of tlsDecodeExtsSupportVersion



static tlsRespStatus  tlsDecodeExtsKeyShare(tlsSession_t *session, tlsExtEntry_t *ext_in)
{
    if((session == NULL) || (ext_in == NULL)) { return TLS_RESP_ERRARGS; }
    tlsRespStatus status = TLS_RESP_OK;
    tlsNamedGrp  srv_chosen_grp = 0;
    byte            *buf = &ext_in->content.data[0];
    tlsKeyEx_t   *keyexp = &session->keyex;
    byte       ngrps_max =  keyexp->num_grps_total;
    byte             idx =  0;

    buf += tlsDecodeWord16(buf, (word16 *)&srv_chosen_grp); // read the only 2 bytes as selected group
    for(idx=0; idx < ngrps_max; idx++) {
        // verify if the decoded (requested) named group was already in initial ClientHello
        if(srv_chosen_grp == tls_supported_named_groups[idx]) { // if srv_chosen_grp was added within initial ClientHello
            // if we can find the named group specified by HelloRetryRequest in tls_supported_named_groups
            // then we change the negotiation state first, then only send this key share in the later ClientHello
            if(session->flgs.hello_retry == 0) { // for ServerHello
                XASSERT(keyexp->keylist[idx] != NULL); // TODO: find better way to check this
                keyexp->grp_nego_state[idx] = TLS_KEYEX_STATE_APPLIED;
            }
            else { // for HelloRetryRequest
                keyexp->grp_nego_state[idx] = TLS_KEYEX_STATE_RENEGO_HRR;
            }
            if(keyexp->chosen_grp_idx == ngrps_max) {
                keyexp->chosen_grp_idx = idx;
            } // which means it's the first time to modify chosen_grp_idx
            else if(keyexp->chosen_grp_idx != idx) {
                keyexp->chosen_grp_idx = XGET_BITMASK(8);
            } // which means it's the second time to modify chosen_grp_idx, the previous value should NOT be changed again.
        }
        else { // if srv_chosen_grp was NOT added within initial ClientHello
            if(keyexp->grp_nego_state[idx] == TLS_KEYEX_STATE_NEGOTIATING) {
                //// if(keyexp->keylist[idx] != NULL) {
                ////     tlsFreeEphemeralKeyPairByGrp( keyexp->keylist[idx], tls_supported_named_groups[idx] );
                ////     keyexp->keylist[idx] = NULL;
                //// }
                keyexp->grp_nego_state[idx] = TLS_KEYEX_STATE_NOT_APPLY;
            } // clean up generated ephemeral keys that are NOT applied to this session
        }
    } // end of for-loop
    if(keyexp->chosen_grp_idx >= ngrps_max) {
        // the named group specified by ServerHello or HelloRetryRequest is NOT supported in this
        // implementation, so we will send illegal_parameter alert instead
        status = TLS_RESP_REQ_ALERT;
    }
    else if(session->flgs.hello_retry == 0) {
        // for ServerHello, we still need to create key (for the remote peer) & import public value to that key
        word16  chosen_key_sz = 0;
        buf += tlsDecodeWord16(buf, &chosen_key_sz);
        status = tlsImportPubValKeyShare( buf, chosen_key_sz, srv_chosen_grp, &session->sec.ephemeralkeyremote );
        XASSERT(keyexp->keylist[keyexp->chosen_grp_idx] != NULL); // TODO: find better way to check this
        // ephemeral local key must point to the one negotiated and applied to current session
        session->sec.ephemeralkeylocal = keyexp->keylist[keyexp->chosen_grp_idx];
        keyexp->keylist[keyexp->chosen_grp_idx] = NULL;
        // store the chosen group ID
        session->sec.agreed_keyex_named_grp = srv_chosen_grp;
    }
    return status;
} // end of tlsDecodeExtsKeyShare



// struct {
//     select (Handshake.msg_type) {
//         case client_hello: OfferedPsks;
//         case server_hello: uint16 selected_identity;
//     };
// } PreSharedKeyExtension;
static tlsRespStatus  tlsDecodeExtsPSK(tlsSession_t *session, tlsExtEntry_t *ext_in)
{
    if((session == NULL) || (ext_in == NULL)) { return TLS_RESP_ERRARGS; }
    tlsRespStatus status = TLS_RESP_OK;
    word16    chosen_psk_idx = 0;
    byte     *buf = &ext_in->content.data[0];
    tlsPSK_t *idx     = NULL;
    word16    pskcount = 0;
    // TODO: finish implementation
    buf += tlsDecodeWord16(buf, &chosen_psk_idx);
    session->sec.chosen_psk = NULL;
    for(idx = tls_PSKs_rdy_list; idx != NULL ; idx = idx->next) {
        if(chosen_psk_idx == pskcount) {
            session->sec.chosen_psk = idx;
            break;
        }
        pskcount++;
    } // end of for-loop
    if(session->sec.chosen_psk == NULL) { status = TLS_RESP_ERR_DECODE; }
    return status;
} // end of tlsDecodeExtsPSK



tlsRespStatus  tlsParseExtensions(tlsSession_t *session, tlsExtEntry_t **out)
{
    if((session == NULL) || (out == NULL)) { return TLS_RESP_ERRARGS; }
    tlsExtEntry_t *curr_ext  =  NULL;
    byte    *inbuf           = &session->inbuf.data[0];
    word16   inlen_decoded   =  session->inlen_decoded;
    word16   inlen_decrypted =  session->inlen_decrypted;
    word16   entry_copied_len = session->last_ext_entry_dec_len;
    word16   rdy_cpy_len      = 0;
    const    byte insert_to_front = 1;
    tlsRespStatus  status = TLS_RESP_OK;
    // adjust decrypted length due to the authentication tag appended to the entire decrypted bytes
    if(session->flgs.hs_rx_encrypt == 1) {
        if(session->sec.flgs.ct_final_frag == 1) {
            inlen_decrypted -= (1 + session->sec.chosen_ciphersuite->tagSize);
        } // actual content type & skip authentication tag (in the final fragment)
    }
    if((entry_copied_len >> 15) == 0x1) { // get first 2-byte total size field of the extension section
        entry_copied_len &= XGET_BITMASK(15);
        switch(entry_copied_len) { // in case there is zero byte or only one byte available to parse
            case 0:
            {
                rdy_cpy_len = inlen_decrypted - inlen_decoded;
                switch(rdy_cpy_len) {
                    case 0:
                        entry_copied_len = 0x8000; // 0 + (1 << 15)
                        break;
                    case 1:
                        session->ext_dec_total_len = inbuf[inlen_decoded++] << 8;
                        entry_copied_len = 0x8001; // 1 + (1 << 15)
                        break;
                    case 2:
                    default:
                        inlen_decoded += tlsDecodeWord16( &inbuf[inlen_decoded], &session->ext_dec_total_len );
                        entry_copied_len = 0;
                        break;
                } // end of switch-case  rdy_cpy_len
                break;
            }
            case 1:
                session->ext_dec_total_len |= (inbuf[inlen_decoded++] & XGET_BITMASK(8));
                entry_copied_len = 0;
                break;
            default: // MUST NOT get here
                XASSERT(0);
                break;
        } // end of switch-case entry_copied_len
    } // end of  if entry_copied_len == 0x8000

    while (inlen_decrypted > inlen_decoded)
    { // move part of remaining received bytes to  extension entries,
        if(entry_copied_len == 0) { // MUST be in the beginning of this loop,  TODO: refactor the code
            if(session->ext_dec_total_len == 0) {
                // There may be several CertificateEntry items, each of them appended with variable-sized extension
                // between any 2 consecutive CertificateEntry items, for zero-length extension, break the loop immediately
                // for next  CertificateEntry item.
                break;
            }
            curr_ext = (tlsExtEntry_t *) XMALLOC(sizeof(tlsExtEntry_t));
            curr_ext->content.data = NULL;
            curr_ext->next = NULL;
            tlsAddItemToList((tlsListItem_t **)out, (tlsListItem_t *)curr_ext, insert_to_front);
            // see whether we can load first 4 bytes for new extension entry (from current in-flight fragment)
            rdy_cpy_len = inlen_decrypted - inlen_decoded;
            // for little-endian CPU architecture, incoming byte sequence might be written to incorrect
            // position of a 16-byte field (e.g. type, length)  in the exception entry structure, the code
            // below can handle such issue.
            switch(rdy_cpy_len) {
                case 0: break;
                case 1:
                    entry_copied_len  = 1;
                    curr_ext->type    = inbuf[inlen_decoded++] << 8;
                    break;
                case 2:
                    entry_copied_len  = 2;
                    inlen_decoded    += tlsDecodeWord16( &inbuf[inlen_decoded], &curr_ext->type );
                    break;
                case 3:
                    entry_copied_len  = 3;
                    inlen_decoded    += tlsDecodeWord16( &inbuf[inlen_decoded], &curr_ext->type );
                    curr_ext->content.len = inbuf[inlen_decoded++] << 8;
                    break;
                case 4:
                default:
                    entry_copied_len  = 4;
                    inlen_decoded    += tlsDecodeWord16( &inbuf[inlen_decoded], &curr_ext->type );
                    inlen_decoded    += tlsDecodeWord16( &inbuf[inlen_decoded], &curr_ext->content.len );
                    break;
            } // end of switch-case statement
        } // end of if entry_copied_len equal to 0
        else { // CPU arrives in here ONLY at the first iteration of the loop (means we are parsing new received fragment)
            // grab the extension entry (from head item of the exception list) we didn't complete copying bytes
            // since the last time this function is called.
            curr_ext = *out;
            if(curr_ext == NULL) {
                status = TLS_RESP_ERRMEM;
                break;
            }
            switch(entry_copied_len) {
                case 1:
                    entry_copied_len += 3;
                    curr_ext->type   |= inbuf[inlen_decoded++];
                    inlen_decoded    += tlsDecodeWord16( &inbuf[inlen_decoded], &curr_ext->content.len );
                    break;
                case 2:
                    entry_copied_len += 2;
                    inlen_decoded    += tlsDecodeWord16( &inbuf[inlen_decoded], &curr_ext->content.len );
                    break;
                case 3:
                    entry_copied_len      += 1;
                    curr_ext->content.len |= inbuf[inlen_decoded++];
                    break;
                default:
                    break;
            } // end of switch-case statement
        } // end of if entry_copied_len NOT equal to 0
        if((curr_ext->content.data == NULL) && (entry_copied_len == 4)) {
            curr_ext->content.data = XMALLOC(sizeof(byte) * curr_ext->content.len);
        } // allocate space only when first 4 bytes of an extension entry is decoded
        if(inlen_decrypted > inlen_decoded) {
            // from here on, entry_copied_len must be (greater than or equal to) 4
            rdy_cpy_len = XMIN(curr_ext->content.len - (entry_copied_len - 4), inlen_decrypted - inlen_decoded);
            XMEMCPY(&curr_ext->content.data[entry_copied_len - 4], &inbuf[inlen_decoded], rdy_cpy_len);
            entry_copied_len += rdy_cpy_len;
            inlen_decoded    += rdy_cpy_len;
            if(entry_copied_len == (4 + curr_ext->content.len)) {
                session->ext_dec_total_len -= entry_copied_len; //decrease size once raw bytes of a extensionEntry are copied.
                entry_copied_len = 0; // finish parsing current extension entry & may iterate over again
                XASSERT(inlen_decrypted >= inlen_decoded);
            }
            else {
                XASSERT(entry_copied_len < (4 + curr_ext->content.len));
                XASSERT(inlen_decrypted == inlen_decoded);
            }
        }
    } // end of while-loop
    session->inlen_decoded = inlen_decoded;
    session->last_ext_entry_dec_len = entry_copied_len;
    return  status;
} // end of tlsParseExtensions


static inline tlsExtEntry_t* tlsGetFirstAvailParsedExtEntry(tlsExtEntry_t *in, word16 last_ext_cpy)
{ // TODO: find better way to generalize this function
    tlsExtEntry_t *out = in;
    if( out != NULL) {
        // in this implementation, either the first item or second item was completely
        // parsed & ready to decode in the extension list.
        last_ext_cpy = last_ext_cpy & XGET_BITMASK(15);
        if(last_ext_cpy != 0) {  out = out->next;  }
    }
    return out;
} // end of tlsGetFirstAvailParsedExtEntry


tlsRespStatus  tlsDecodeExtServerHello(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsExtEntry_t *curr_ext = tlsGetFirstAvailParsedExtEntry(session->exts, session->last_ext_entry_dec_len);
    tlsExtEntry_t *prev_ext = NULL;
    tlsRespStatus  status   = TLS_RESP_OK;

    // the only reason the head item cannot be decoded is that parsing is not complete on the head item
    if(curr_ext != NULL) {
        if(session->exts == curr_ext) {
            session->exts = NULL;
        } else {
            session->exts->next = NULL;
        }
    }
    while(curr_ext != NULL)
    {
        if(status >= 0) {
            switch(curr_ext->type) {
                case TLS_EXT_TYPE_SUPPORTED_VERSIONS:
                    status = tlsDecodeExtsSupportVersion(session, curr_ext);
                    break;
                case TLS_EXT_TYPE_KEY_SHARE :
                    status = tlsDecodeExtsKeyShare(session, curr_ext);
                    break;
                case TLS_EXT_TYPE_PRE_SHARED_KEY :
                    status = tlsDecodeExtsPSK(session, curr_ext);
                    break;
                case TLS_EXT_TYPE_COOKIE: //TODO: must be within HelloRetryRequest, NOT in ServerHello
                    break; 
                default:
                    status = TLS_RESP_REQ_ALERT;
                    break;
            } // end of swtich-case
        } // end of if status >= 0
        // remove the decoded entry from the parsed extension list
        prev_ext = curr_ext;
        tlsRemoveItemFromList((tlsListItem_t **)&curr_ext, (tlsListItem_t *)curr_ext);
        tlsFreeExtEntry(prev_ext);
    } // end of while-loop
    return status;
} // end of tlsDecodeExtServerHello


tlsRespStatus  tlsDecodeExtEncryptExt(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsExtEntry_t *curr_ext = tlsGetFirstAvailParsedExtEntry(session->exts, session->last_ext_entry_dec_len );
    tlsExtEntry_t *prev_ext = NULL;
    tlsRespStatus  status   = TLS_RESP_OK;
    // the only reason the head item cannot be decoded is that parsing is not complete on the head item
    if(curr_ext != NULL) {
        if(session->exts == curr_ext) {
            session->exts = NULL;
        } else {
            session->exts->next = NULL;
        }
    }
    while(curr_ext != NULL) {
        if(status >= 0) {
            switch(curr_ext->type) {
                case TLS_EXT_TYPE_SUPPORTED_GROUPS :
                    break;
                case TLS_EXT_TYPE_MAX_FRAGMENT_LENGTH  :
                    break;
                case TLS_EXT_TYPE_ALPN :
                    break;
                case TLS_EXT_TYPE_EARLY_DATA :
                    break;
                case TLS_EXT_TYPE_SERVER_NAME:
                    break;
                case TLS_EXT_TYPE_CLIENT_CERTIFICATE_TYPE :
                    break;
                case TLS_EXT_TYPE_SERVER_CERTIFICATE_TYPE :
                    break;
                case TLS_EXT_TYPE_USE_SRTP  :
                case TLS_EXT_TYPE_HEARTBEAT :
                    //// status = TLS_RESP_ERR_NOT_SUPPORT;
                    break;
                default:
                    status = TLS_RESP_REQ_ALERT;
                    break;
            } // end of swtich-case
        }
        // remove the decoded entry from the parsed extension list
        prev_ext = curr_ext;
        tlsRemoveItemFromList((tlsListItem_t **)&curr_ext, (tlsListItem_t *)curr_ext);
        tlsFreeExtEntry(prev_ext);
    } // end of while-loop
    return status;
} // end of tlsDecodeExtEncryptExt


tlsRespStatus  tlsDecodeExtCertReq(tlsSession_t *session)
{
    if(session == NULL) { return TLS_RESP_ERRARGS; }
    tlsExtEntry_t *curr_ext = tlsGetFirstAvailParsedExtEntry(session->exts, session->last_ext_entry_dec_len);
    tlsExtEntry_t *prev_ext = NULL;
    tlsRespStatus  status  = TLS_RESP_OK;
    // the only reason the head item cannot be decoded is that parsing is not complete on the head item
    if(curr_ext != NULL) {
        if(session->exts == curr_ext) {
            session->exts = NULL;
        } else {
            session->exts->next = NULL;
        }
    } // TODO: build test cases that contain the following extensions & finish the implementation
    while(curr_ext != NULL) {
        if(status >= 0) {
            switch(curr_ext->type) {
                case TLS_EXT_TYPE_SIGNATURE_ALGORITHMS:
                    break;
                case TLS_EXT_TYPE_STATUS_REQUEST      :
                    break;
                case TLS_EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP:
                    break;
                case TLS_EXT_TYPE_CERTIFICATE_AUTHORITIES   :
                    break;
                case TLS_EXT_TYPE_SIGNATURE_ALGORITHMS_CERT :
                    break;
                case TLS_EXT_TYPE_OID_FILTERS :
                    break;
                default:
                    status = TLS_RESP_REQ_ALERT;
                    break;
            } // end of swtich-case
        }
        // remove the decoded entry from the parsed extension list
        prev_ext = curr_ext;
        tlsRemoveItemFromList((tlsListItem_t **)&curr_ext, (tlsListItem_t *)curr_ext);
        tlsFreeExtEntry(prev_ext);
    } // end of while-loop
    return status;
} // end of tlsDecodeExtCertReq


tlsRespStatus  tlsDecodeExtCertificate(tlsCert_t *cert, word16 first_ext_unfinished)
{
    if(cert == NULL) { return TLS_RESP_ERRARGS; }
    tlsExtEntry_t *curr_ext = tlsGetFirstAvailParsedExtEntry(cert->exts, first_ext_unfinished); // session->last_ext_entry_dec_len
    tlsExtEntry_t *prev_ext = NULL;
    tlsRespStatus  status   = TLS_RESP_OK;
    // the only reason the head item cannot be decoded is that parsing is not complete on the head item
    if(curr_ext != NULL) {
        if(cert->exts == curr_ext) {
            cert->exts = NULL;
        } else {
            cert->exts->next = NULL;
        }
    }
    while(curr_ext != NULL) {
        if(status >= 0) {
            switch(curr_ext->type) {
                case TLS_EXT_TYPE_STATUS_REQUEST :
                    break;
                case TLS_EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP:
                    break; // TODO: create test case that produces this extension entry on server side
                default:
                    status = TLS_RESP_REQ_ALERT;
                    break;
            } // end of swtich-case
        }
        // remove the decoded entry from the parsed extension list
        prev_ext = curr_ext;
        tlsRemoveItemFromList((tlsListItem_t **)&curr_ext, (tlsListItem_t *)curr_ext);
        tlsFreeExtEntry(prev_ext);
    } // end of while-loop
    return status;
} // end of tlsDecodeExtCertificate


