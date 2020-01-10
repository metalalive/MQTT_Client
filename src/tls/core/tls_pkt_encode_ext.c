#include "mqtt_include.h"

extern const tlsVersionCode   tls_supported_versions[];
extern const tlsNamedGrp      tls_supported_named_groups[];
extern const tlsSignScheme    tls_supported_sign_scheme[];


static tlsRespStatus  tlsKeyExCopyPubValToExt(tlsOpaque16b_t *out, tlsKeyEx_t *keyexp)
{
    if((out == NULL) || (out->data != NULL) || (keyexp == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    byte          ngrps_max    = keyexp->num_grps_total;
    byte          ngrps_chosen = keyexp->num_grps_chosen;
    void         *chosen_key[TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO]   =  {0};
    word16        chosen_key_sz[TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO] = {0};
    tlsNamedGrp   chosen_grp_id[TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO] = {0};
    tlsNamedGrp   tmp_grp_id = 0;
    byte         *buf   = NULL;
    word16        len   = 2;  // 2-bytes for length of all key share entries
    byte          idx   = 0;
    byte          jdx   = 0;
    // Step #1: calculate output length first
    for(idx = 0; (idx < ngrps_max) && (jdx < ngrps_chosen) ; idx++) {
        if(keyexp->grp_nego_state[idx] == TLS_KEYEX_STATE_NEGOTIATING) {
            // internally store key size for each Key Shared Entry for future use
            tmp_grp_id =  tls_supported_named_groups[idx];
            chosen_grp_id[jdx] = tmp_grp_id;
            chosen_key_sz[jdx] = tlsKeyExGetExportKeySize(tmp_grp_id);
            chosen_key[jdx]    = keyexp->keylist[idx];
            // for each Key Share Entry, 2-bytes for named group ID, 2-bytes for size of public value
            len += 2 + 2 + chosen_key_sz[jdx++];
        }
    } // end of for-loop
    // Step #2: encoding
    buf  = XMALLOC(sizeof(byte) * len);
    out->data = buf;
    out->len  = len;
    buf += tlsEncodeWord16(&buf[0], (word16)(len - 2));
    for(jdx=0; jdx<ngrps_chosen; jdx++) {
        buf += tlsEncodeWord16(&buf[0], (word16)chosen_grp_id[jdx]); // 2 bytes for named group ID
        buf += tlsEncodeWord16(&buf[0], (word16)chosen_key_sz[jdx]); // 2 bytes for size of public value
        // Step #3: extract public value from key shares
        status = tlsExportPubValKeyShare( &buf[0], chosen_grp_id[jdx], chosen_key[jdx], chosen_key_sz[jdx] );
        if(status != TLS_RESP_OK) {
            XMEMFREE((void *)out->data);
            out->data = NULL;
            out->len  = 0;
            break;
        }
        buf += chosen_key_sz[jdx];
    } // end of for-loop
    return status;
} // end of tlsKeyExCopyPubValToExt



static tlsExtEntry_t*  tlsGenExtsServerName(mqttStr_t *host)
{
    tlsExtEntry_t  *out  = NULL;
    byte           *buf  = NULL;
    if((host != NULL) && (host->data != NULL)) {
        out = (tlsExtEntry_t *) XMALLOC(sizeof(tlsExtEntry_t));
        out->next = NULL;
        out->type = TLS_EXT_TYPE_SERVER_NAME;
        out->content.len  = host->len;
        out->content.len += 2; // server name list length
        out->content.len += 1; // server name type (usually host_name)
        out->content.len += 2; // server name length
        buf = (byte *) XMALLOC(sizeof(byte) * out->content.len);
        out->content.data = buf;
        buf += tlsEncodeWord16( buf, (word16)(out->content.len - 2) );
        buf[0] = 0x0; // server name type : host_name
        buf++;
        buf += tlsEncodeWord16( buf, (word16)host->len );
        XMEMCPY(buf, host->data, host->len);
    }
    return out;
} // end of tlsGenExtsServerName


static tlsExtEntry_t*  tlsGenExtsSupportVersion( void )
{
    tlsExtEntry_t  *out  = NULL;
    byte           *buf  = NULL;
    word16          idx  = 0;
    word16          len  = 0;
    out = (tlsExtEntry_t *) XMALLOC(sizeof(tlsExtEntry_t));
    out->next = NULL;
    out->type = TLS_EXT_TYPE_SUPPORTED_VERSIONS;
    // the length of supported version extension shouldn't exceed 254 bytes, 
    // since we only support TLS v1.3 , no need to check its length at here
    len = 1 + (tlsGetSupportedVersionListSize() << 1);
    buf = (byte *) XMALLOC(sizeof(byte) * len);
    out->content.len  = len;
    out->content.data = buf;
    *buf++ = tlsGetSupportedVersionListSize() << 1;
    for(idx=0; idx < tlsGetSupportedVersionListSize(); idx++) {
        buf += tlsEncodeWord16( &buf[0], (word16)tls_supported_versions[idx] );
    }
    return out;
} // end of tlsGenExtsSupportVersion


static tlsExtEntry_t*  tlsGenExtsNamedGrps( void )
{
    tlsExtEntry_t  *out  = NULL;
    byte           *buf  = NULL;
    word16          idx  = 0;
    word16          len  = 0;
    byte      support_name_grp_sz = tlsGetSupportedKeyExGrpSize();
    out = (tlsExtEntry_t *) XMALLOC(sizeof(tlsExtEntry_t));
    out->next = NULL;
    out->type = TLS_EXT_TYPE_SUPPORTED_GROUPS;
    len = 2 + (support_name_grp_sz << 1);
    buf = (byte *) XMALLOC(sizeof(byte) * len);
    out->content.len  = len;
    out->content.data = buf;
    buf += tlsEncodeWord16(&buf[0], (word16)(support_name_grp_sz << 1));
    for(idx=0; idx < support_name_grp_sz; idx++) {
        buf += tlsEncodeWord16(&buf[0], (word16)tls_supported_named_groups[idx]);
    }
    return out;
} // end of tlsGenExtsNamedGrps



static tlsExtEntry_t*  tlsGenExtsSignAlgos( void )
{
    tlsExtEntry_t  *out  = NULL;
    byte           *buf  = NULL;
    word16          idx  = 0;
    word16          len  = 0;
    out = (tlsExtEntry_t *) XMALLOC(sizeof(tlsExtEntry_t));
    out->next  = NULL;
    out->type = TLS_EXT_TYPE_SIGNATURE_ALGORITHMS;
    len = 2 + (tlsGetSupportedSignSchemeListSize() << 1);
    buf = (byte *) XMALLOC(sizeof(byte) * len);
    out->content.len  = len;
    out->content.data = buf;
    buf += tlsEncodeWord16(&buf[0], (word16)(tlsGetSupportedSignSchemeListSize() << 1));
    for(idx=0; idx < tlsGetSupportedSignSchemeListSize() ; idx++) {
        buf += tlsEncodeWord16(&buf[0], (word16)tls_supported_sign_scheme[idx]);
    }
    return out;
} // end of tlsGenExtsSignAlgos



static tlsExtEntry_t*  tlsGenExtsKeyShare( tlsSession_t *session )
{
    tlsRespStatus status = TLS_RESP_OK;
    tlsExtEntry_t  *out  = NULL;
    out = (tlsExtEntry_t *) XMALLOC(sizeof(tlsExtEntry_t));
    out->next = NULL;
    out->type = TLS_EXT_TYPE_KEY_SHARE;
    out->content.len  = 0;
    out->content.data = NULL;
    // generate key pairs based on PSK or ECDHE key exchange mechanism.
    status = tlsGenEphemeralKeyPairs(session->drbg , &session->keyex);
    if(status != TLS_RESP_OK) { goto failure_ext_gen; }
    // copy public key from chosen key-exchange methods to extension structure
    status = tlsKeyExCopyPubValToExt( &out->content, &session->keyex);
    if(status != TLS_RESP_OK) { goto failure_ext_gen; }
    return out;
failure_ext_gen:
    tlsFreeEphemeralKeyPairs(&session->keyex);
    if(out->content.data != NULL) {
        XMEMFREE((void *)out->content.data);
        out->content.data = NULL;
    }
    XMEMFREE((void *)out);
    return NULL;
} // end of tlsGenExtsKeyShare


static tlsExtEntry_t*  tlsGenExtsPSKexMode(void)
{ // TODO: verify
    tlsExtEntry_t  *out  = NULL;
    out = (tlsExtEntry_t *) XMALLOC(sizeof(tlsExtEntry_t));
    out->next = NULL;
    out->type = TLS_EXT_TYPE_PSK_KEY_EXCHANGE_MODES;
    // the implementation only supports psk_dhe_ke(1) for PSK exchange mode
    out->content.len  = 2;
    out->content.data = XMALLOC(sizeof(byte) * out->content.len);
    out->content.data[0] = 0x1; // total number of PskKeyExchangeMode
    out->content.data[1] = (byte) TLS_PSK_KEY_EX_MODE_PSK_DHE_KE;
    return out;
} // end of tlsGenExtsPSKexMode


// section 4.2.11 Pre-Shared Key Extension, RFC8446
//
// struct {
//     opaque identity<1..2^16-1>;
//     uint32 obfuscated_ticket_age;
// } PskIdentity;
//
// opaque PskBinderEntry<32..255>;
//
// struct {
//     PskIdentity identities<7..2^16-1>;
//     PskBinderEntry binders<33..2^16-1>;
// } OfferedPsks;
//
// struct {
//     select (Handshake.msg_type) {
//         case client_hello: OfferedPsks;
//         case server_hello: uint16 selected_identity;
//     };
// } PreSharedKeyExtension;
static tlsExtEntry_t*  tlsGenExtsPSK(tlsOpaque8b_t *binderstart, tlsPSK_t *psklist)
{ // TODO: verify
    tlsPSK_t       *pskitem    = NULL;
    tlsExtEntry_t  *out        = NULL;
    byte           *idbuf      = NULL;
    byte           *bindbuf    = NULL;
    word16          total_pskid_len   = 0;
    word16          total_binder_len  = 0;
    out = (tlsExtEntry_t *) XMALLOC(sizeof(tlsExtEntry_t));
    out->next = NULL;
    out->type = TLS_EXT_TYPE_PRE_SHARED_KEY;
    out->content.len  = 0;
    out->content.data = NULL;
    // ----- calculate number of bytes required to decode -----
    pskitem = psklist;
    while(pskitem != NULL) {
        tlsHashAlgoID  hash_algo_id = tlsGetHashAlgoIDBySize( (word16)pskitem->key.len );
        if(hash_algo_id != TLS_HASH_ALGO_UNKNOWN) {
            // first 2 bytes for storing size of each PskIdentity, then variable bytes of each
            // PskIdentity, then 4-byte obfuscated_ticket_age
            total_pskid_len   += 2 + pskitem->id.len + 4;
            // first byte for storing size of each PskBinderEntry, then variable bytes of each PskBinderEntry
            total_binder_len  += 1 + pskitem->key.len;
        } // TODO: filter out the PSKs whose binder size is not equal to output size of hash algorithms
          // supported in this implementation
        pskitem = pskitem->next;
    } // end of while loop
    total_pskid_len  += 2; // for storing total size of all PskIdentity items
    total_binder_len += 2; // for storing total size of all PskBinderEntry items
    out->content.len  = total_pskid_len + total_binder_len;
    out->content.data = XMALLOC(sizeof(byte) * out->content.len);

    // ----- encoding PSK identifies -----
    idbuf    =  out->content.data;
    idbuf   +=  tlsEncodeWord16(idbuf, (total_pskid_len - 2));
    pskitem = psklist;
    while(pskitem != NULL) {
        tlsHashAlgoID  hash_algo_id = tlsGetHashAlgoIDBySize( (word16)pskitem->key.len );
        if(hash_algo_id != TLS_HASH_ALGO_UNKNOWN) {
            idbuf  += tlsEncodeWord16(idbuf, pskitem->id.len);
            XMEMCPY(idbuf, pskitem->id.data, pskitem->id.len);
            idbuf  += pskitem->id.len;
            word32  nowtime_ms = mqttSysGetTimeMs();
            word32  obfuscated_tkt_age = pskitem->time_param.ticket_age_add;
            obfuscated_tkt_age        += mqttGetInterval(nowtime_ms, pskitem->time_param.timestamp_ms);
            idbuf  += tlsEncodeWord32(idbuf, obfuscated_tkt_age);
        }
        pskitem = pskitem->next;
    } // end of while loop

    // ----- encoding PSK binders -----
    bindbuf  = &out->content.data[total_pskid_len]; // skip entire OfferedPsks.identities
    XASSERT(bindbuf == idbuf); // TODO: will be removed since it is only for testing purpose
    binderstart->data = bindbuf;
    binderstart->len  = total_binder_len;
    bindbuf +=  tlsEncodeWord16(bindbuf, (total_binder_len - 2));
    pskitem = psklist;
    while(pskitem != NULL) {
        tlsHashAlgoID  hash_algo_id = tlsGetHashAlgoIDBySize( (word16)pskitem->key.len );
        if(hash_algo_id != TLS_HASH_ALGO_UNKNOWN) {
            *bindbuf++ = pskitem->key.len;
            // binder will be generated & filled in tlsTranscrptHashHSmsgUpdate()
            // RFC 8446, section 4.2.11.2 PSK Binder :
            // Each entry in the binders list is computed as an HMAC over a transcript hash,
            // , including all of the ClientHello but not the binders list itself.
            //
            // also, if the client receives HelloRetryRetry & send ClientHello again (e.g. say ClientHello2),
            // then the binder is derived by :
            //
            //     Transcript-Hash(ClientHello1, HelloRetryRequest, Truncate(ClientHello2))
            //
            XMEMSET( bindbuf, 0x00, sizeof(byte) * pskitem->key.len );
            bindbuf += pskitem->key.len;
        }
        pskitem = pskitem->next;
    } // end of while loop
    return out;
} // end of tlsGenExtsPSK



static tlsExtEntry_t*  tlsGenExtsClientHello( tlsSession_t *session )
{
    // arguments check
    if(session == NULL) { return NULL; }
    if(session->server_name==NULL || session->server_name->data==NULL) {
        return NULL;
    }
    tlsExtEntry_t  *curr = NULL;
    tlsExtEntry_t  *out  = NULL;
    word16          len  = 0;
    len = tlsGetSupportedVersionListSize() << 1;
    if ((len < TLS_MIN_BYTES_CIPHER_SUITE_LIST) || (len > TLS_MAX_BYTES_CIPHER_SUITE_LIST)) {
        return NULL;
    }
    len = tlsGetSupportedKeyExGrpSize() << 1;
    if ((len < TLS_MIN_BYTES_NAMED_GRPS) || (len > TLS_MAX_BYTES_NAMED_GRPS)) {
        return NULL;
    }
    len = tlsGetSupportedSignSchemeListSize() << 1;
    if ((len < TLS_MIN_BYTES_SIGN_ALGOS) || (len > TLS_MAX_BYTES_SIGN_ALGOS)) {
        return NULL;
    }
    // Step 1 : add mandatory-to-implement extensions
    // Step 1-1: Server Name indication
    curr = tlsGenExtsServerName( session->server_name );
    out  = curr;
    // Step 1-2: supported versions
    curr->next = tlsGenExtsSupportVersion();
    curr = curr->next;
    // Step 1-3: supported groups
    curr->next = tlsGenExtsNamedGrps();
    curr = curr->next;
    // Step 1-4: Cookie, ONLY if client receives HelloRetryRequest from server
    if(session->flgs.hello_retry == 1) {
        // TODO: finish the implementation
    }
    // Step 1-5: Signature Algorithms
    curr->next = tlsGenExtsSignAlgos();
    curr = curr->next;
    // Step 1-6: key share
    curr->next = tlsGenExtsKeyShare(session);
    curr = curr->next;
    if(curr == NULL) { goto failure_gen_ext_list; }
    if(*session->sec.psk_list != NULL) { // TODO: verify
        curr->next = tlsGenExtsPSKexMode();
        curr = curr->next;
        // PSK must be the latest extension entry in ClientHello
        curr->next = tlsGenExtsPSK(&session->sec.psk_binder, *session->sec.psk_list);
        curr = curr->next;
        if(curr == NULL) { goto failure_gen_ext_list; }
    } // NOTE: pre-shared key extension MUST be the last entry of the entire extension list
    return out;
failure_gen_ext_list:
    curr = out;
    tlsDeleteAllExtensions( curr );
    return NULL;
} // end of tlsGenExtsClientHello



tlsExtEntry_t*  tlsGenExtensions( tlsSession_t *session )
{
    tlsExtEntry_t  *out  = NULL;
    if(session != NULL) {
        switch(tlsGetHSexpectedState(session)) {
            case TLS_HS_TYPE_CLIENT_HELLO      :
                out = tlsGenExtsClientHello(session);
                break;
            case TLS_HS_TYPE_CERTIFICATE       :
            case TLS_HS_TYPE_END_OF_EARLY_DATA :
            case TLS_HS_TYPE_KEY_UPDATE        :
            default:
                break;
        } // end of switch-case statement
    }
    return out;
} // end of tlsGenExtensions



void  tlsDeleteAllExtensions( tlsExtEntry_t *ext_head )
{
    tlsExtEntry_t  *curr = ext_head;
    tlsExtEntry_t  *prev = NULL;
    while (curr != NULL) {
        XMEMFREE((void *)curr->content.data);
        curr->content.data = NULL;
        prev = curr;
        tlsRemoveItemFromList((tlsListItem_t **)&curr, (tlsListItem_t *)curr);
        tlsFreeExtEntry(prev);
    } // end of while-loop
} // end of tlsDeleteExtensions


word16  tlsGetExtListSize( tlsExtEntry_t *ext_head )
{
    tlsExtEntry_t  *curr = ext_head;
    word16        out_sz = 0;
    while (curr != NULL) {
        out_sz += (2 + 2 + curr->content.len);
        curr = curr->next;
    } // end of while-loop
    return out_sz;
} // end of tlsGetExtListSize



// given extension list, append it into outbuf (might be split to several out-flight fragments)
tlsRespStatus  tlsEncodeExtensions(tlsSession_t *session)
{
    if((session == NULL) || (session->exts == NULL)) { return TLS_RESP_ERRARGS; }
    tlsRespStatus  status     =  TLS_RESP_OK;
    word16     outlen_encoded =  session->outlen_encoded;
    byte      *outbuf         = &session->outbuf.data[0];
    tlsExtEntry_t *curr_ext   =  session->exts;
    word16     entry_copied_len = session->last_ext_entry_enc_len;
    word16     rdy_cpy_len   =  0;

    if((entry_copied_len >> 15) == 0x1) { // store the size of the entire extension list
        entry_copied_len &= XGET_BITMASK(15);
        switch(entry_copied_len) { // in case there is zero byte or only one byte available to encode
            case 0:
            {
                rdy_cpy_len = session->outbuf.len - outlen_encoded;
                switch(rdy_cpy_len) {
                    case 0:
                        entry_copied_len = 0x8000; // 0 + (1 << 15)
                        break;
                    case 1:
                        outbuf[outlen_encoded++] = (session->ext_enc_total_len >> 8);
                        entry_copied_len = 0x8001; // 1 + (1 << 15)
                        break;
                    default:
                        outlen_encoded += tlsEncodeWord16( &outbuf[outlen_encoded], session->ext_enc_total_len );
                        entry_copied_len = 0;
                        break;
                } // end of switch-case rdy_cpy_len
                break;
            }
            case 1:
                outbuf[outlen_encoded++] |= (session->ext_enc_total_len & XGET_BITMASK(8));
                entry_copied_len = 0;
                break;
            default: // MUST NOT get here
                XASSERT(0);
                break;
        } // end of switch-case entry_copied_len
    } // runs only when encoding the first part of extension section

    while ((session->outbuf.len > outlen_encoded) && (curr_ext != NULL))
    {   // check whether current extension entry can be fit into current fragment (packet) of the handshake message
        // , in this implementation, the order of each extension entry (from the same list) SHOULD be remained
        // the same while generating the list elsewhere. (it shouldn't be reordered even if any subsequent entry
        // occupies less memory space than the current entry to fit in)
        if(entry_copied_len == 0) { // TODO: refactor the code
            rdy_cpy_len = session->outbuf.len - outlen_encoded;
            switch(rdy_cpy_len) {
                case 0: break;
                case 1:
                    entry_copied_len  = 1;
                    outbuf[outlen_encoded++] = (curr_ext->type >> 8);
                    break;
                case 2:
                    entry_copied_len  = 2;
                    outlen_encoded += tlsEncodeWord16( &outbuf[outlen_encoded], (word16)curr_ext->type );
                    break;
                case 3:
                    entry_copied_len  = 3;
                    outlen_encoded += tlsEncodeWord16( &outbuf[outlen_encoded], (word16)curr_ext->type );
                    outbuf[outlen_encoded++] = (curr_ext->content.len >> 8);
                    break;
                case 4:
                default:
                    entry_copied_len  = 4;
                    outlen_encoded += tlsEncodeWord16( &outbuf[outlen_encoded], (word16)curr_ext->type );
                    outlen_encoded += tlsEncodeWord16( &outbuf[outlen_encoded], (word16)curr_ext->content.len );
                    break;
            } // end of switch-case statement
        } // end of if entry_copied_len equal to 0
        else {
            switch(entry_copied_len) {
                case 1:
                    entry_copied_len += 3;
                    outbuf[outlen_encoded++] = (curr_ext->type & XGET_BITMASK(8));
                    outlen_encoded += tlsEncodeWord16( &outbuf[outlen_encoded], (word16)curr_ext->content.len );
                    break;
                case 2:
                    entry_copied_len += 2;
                    outlen_encoded += tlsEncodeWord16( &outbuf[outlen_encoded], (word16)curr_ext->content.len );
                    break;
                case 3:
                    entry_copied_len += 1;
                    outbuf[outlen_encoded++] = (curr_ext->content.len & XGET_BITMASK(8));
                    break;
                default:
                    break;
            }
        } // end of if entry_copied_len NOT equal to 0

        if(session->outbuf.len > outlen_encoded) {
            rdy_cpy_len = XMIN(curr_ext->content.len - (entry_copied_len - 4), session->outbuf.len - outlen_encoded);
            XMEMCPY( &outbuf[outlen_encoded], &curr_ext->content.data[entry_copied_len - 4], rdy_cpy_len );
            outlen_encoded   += rdy_cpy_len;
            entry_copied_len += rdy_cpy_len;
            if(entry_copied_len == (4 + curr_ext->content.len)) { // if entire entry is copied to inbuf (current or previous fragment)
                entry_copied_len = 0; // finish parsing current extension entry & may iterate over again
                tlsExtEntry_t  *prev_ext = curr_ext;
                tlsRemoveItemFromList((tlsListItem_t **)&curr_ext, (tlsListItem_t *)curr_ext);
                tlsFreeExtEntry(prev_ext);
                session->exts = curr_ext;  // remove this entry from extension list, the number of entries should be decreased with one
                XASSERT(session->outbuf.len >= outlen_encoded);
            }
            else {
                XASSERT(entry_copied_len < (4 + curr_ext->content.len));
                XASSERT(session->outbuf.len == outlen_encoded);
            }
        } // end of  if session->outbuf.len > outlen_encoded
    } // end of while-loop
    session->outlen_encoded         = outlen_encoded;
    session->last_ext_entry_enc_len = entry_copied_len;
    // more buffer space is required for current handshake message
    if (session->outbuf.len >= outlen_encoded) {
        status = (session->exts != NULL) ? TLS_RESP_REQ_MOREDATA : TLS_RESP_OK ;
    }
    else { status = TLS_RESP_ERR_ENCODE; }
    return status;
} // end of tlsEncodeExtensions

