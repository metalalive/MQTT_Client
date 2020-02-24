#include "mqtt_include.h"

// [Note] : This MQTT/TLS implementation ONLY supports x509v3 certificate decoding

tlsRespStatus tlsSignCertSignature(void *privkey,  mqttDRBG_t *drbg, tlsOpaque16b_t *in, tlsOpaque16b_t *out,
                                    tlsAlgoOID sign_algo, tlsRSApss_t *rsapssextra)
{
    if((privkey == NULL) || (drbg == NULL) || (in == NULL) || (out == NULL) || (in->data == NULL) || (out->data == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    word16        rsapss_saltlen = 0;
    tlsHashAlgoID rsapss_hash_id = 0;
    switch(sign_algo) {
        case TLS_ALGO_OID_RSASSA_PSS: // feed extra information (hash algo ID & salt length) for RSA-PSS
            if(rsapssextra == NULL) { status = TLS_RESP_ERRARGS; break; }
            rsapss_hash_id = rsapssextra->hash_id;
            rsapss_saltlen = rsapssextra->salt_len;
        case TLS_ALGO_OID_RSA_KEY:
        case TLS_ALGO_OID_SHA256_RSA_SIG:
        case TLS_ALGO_OID_SHA384_RSA_SIG:
            TLS_CFG_RSA_SIGN_SIGNATURE_FN(status, drbg, &in->data[0], in->len, sign_algo, &out->data[0],
                                          out->len, privkey, rsapss_hash_id, rsapss_saltlen);
            break;
        default:
            status = TLS_RESP_ERR_NOT_SUPPORT;
            break;
    } // end of switch case statement
    return status;
} // end of tlsSignCertSignature



tlsRespStatus tlsVerifyCertSignature(void *pubkey, tlsOpaque16b_t *sig, tlsAlgoOID sign_algo, tlsOpaque16b_t *ref, tlsRSApss_t *rsapssextra)
{
    if((pubkey == NULL) || (sig == NULL) || (ref == NULL) || (sig->data == NULL) || (ref->data == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    word16        rsapss_saltlen = 0;
    tlsHashAlgoID rsapss_hash_id = 0;
    switch(sign_algo) {
        case TLS_ALGO_OID_RSASSA_PSS: // feed extra information (hash algo ID & salt length) for RSA-PSS
            if(rsapssextra == NULL) { status = TLS_RESP_ERRARGS; break; }
            rsapss_hash_id = rsapssextra->hash_id;
            rsapss_saltlen = rsapssextra->salt_len;
        case TLS_ALGO_OID_RSA_KEY:
        case TLS_ALGO_OID_SHA256_RSA_SIG:
        case TLS_ALGO_OID_SHA384_RSA_SIG:
            TLS_CFG_RSA_VERIFY_SIGN_FN(status, &sig->data[0], sig->len, sign_algo, &ref->data[0],
                                       ref->len, pubkey, rsapss_hash_id, rsapss_saltlen);
            break;
        default:
            status = TLS_RESP_ERR_NOT_SUPPORT;
            break;
    } // end of switch case statement
    return status;
} // end of tlsVerifyCertSignature


// In any TLS version, end-entity certificate (server certificate) must be the first item of the cert chain,
// ideally each cert in the chain list can be certified by the one immediately proceding it (in the same chain)
// however many implementations don't work that way. This funcion reorders the cert chain with the consideration
// above.
static void tlsReorderCertChain(tlsCert_t  *cert_list)
{
    tlsCert_t *curr_cert = cert_list;
    tlsCert_t *prev_cert = NULL;
    tlsCert_t *next_cert = NULL;
    // always use SHA256 to hash distinguished name section in this implementation
    word16     hash_sz = mqttHashGetOutlenBytes(MQTT_HASH_SHA256);
    while(curr_cert != NULL) {
        next_cert = curr_cert->next;
        while(next_cert != NULL) {
            // check whether issuer of current cert matches subject of next cert, by checking hashed DN section
            if(XSTRNCMP((const char *)&curr_cert->issuer.hashed_dn[0],
                        (const char *)&next_cert->subject.hashed_dn[0], hash_sz) == 0)
            {
                if(prev_cert != NULL) { // current item finds out its successor but doesn't point to it
                    // BEFORE: curr_cert -> ... -> prev_cert -> next_cert -> ...
                    // AFTER : curr_cert -> next_cert -> ... -> prev_cert -> ...
                    prev_cert->next = next_cert->next;
                    next_cert->next = curr_cert->next;
                    curr_cert->next = next_cert;
                    prev_cert = NULL;
                }
                break;
            } else { // current item doesn't match its successor, advance to next item & compare again.
                prev_cert = next_cert;
                next_cert = next_cert->next;
            }
        } // end of while loop
        curr_cert = curr_cert->next;
    } // end of while loop
} // end of tlsReorderCertChain



static tlsRespStatus  tlsVerifyCert(tlsCert_t *ic, tlsCert_t  *sc)
{
    tlsRespStatus status = TLS_RESP_OK;
    // check hashed distinguished name
    word16   hash_sz = mqttHashGetOutlenBytes(MQTT_HASH_SHA256);
    if(XSTRNCMP((const char *)&sc->issuer.hashed_dn[0], (const char *)&ic->subject.hashed_dn[0], hash_sz) != 0) {
        status = TLS_RESP_CERT_AUTH_FAIL; goto done;
    }
    // decrypt signature & compare with hashed cert holder
    status = tlsVerifyCertSignature( ic->pubkey, &sc->signature, sc->sign_algo, &sc->hashed_holder_info, &sc->rsapss );
done:
    sc->flgs.auth_done = 1;
    if(status == TLS_RESP_OK) { sc->flgs.auth_pass = 1; }
    return status;
} // end of tlsVerifyCert


// * this routine is called everytime when new fragment of Certificate message is received
tlsRespStatus  tlsVerifyCertChain(tlsCert_t  *issuer_cert, tlsCert_t  *subject_cert)
{
    tlsRespStatus status = TLS_RESP_OK;
    tlsCert_t *curr_cert = NULL;
    if(subject_cert == NULL) { return TLS_RESP_ERRARGS; }
    // note that server certificate is always the first item of the entire chain
    tlsReorderCertChain(subject_cert);
    // step #1, verify subject cert chain
    curr_cert = subject_cert;
    while (curr_cert != NULL && curr_cert->next != NULL) {
        // Note the sorted chain could still contain useless cert item(s), which cannot verify its
        // predecessor, In this implementation, this belongs to application error, therefore should
        // return error back.
        status = tlsVerifyCert(curr_cert->next, curr_cert);
        if(status < 0) { goto done; }
        curr_cert = curr_cert->next;
    }
    // curr_cert at here must be the final item of subject cert chain, which hasn't been (and shouldn't be) verified.
    if(curr_cert->flgs.auth_done != 0 || curr_cert->flgs.auth_pass != 0) {
        status = TLS_RESP_ERR; goto done; // report unknown error
    }
    // step #2-1, issuer cert is absent, so we simply check if last item (of the subject chain) is self-signed.
    if(issuer_cert == NULL) {
        status = tlsVerifyCert(curr_cert, curr_cert);
        if(status == TLS_RESP_OK && curr_cert->flgs.auth_pass == 1) {
            curr_cert->flgs.self_signed = 1;
        } // authentication succeeded, this is self-signed cert
    } else {
        // step #2-2, check whether any of cert from issuer chain can verify server cert (in subject chain)
        tlsCert_t *final_subj_cert = curr_cert;
        curr_cert = issuer_cert;
        while (curr_cert != NULL) {
            status = tlsVerifyCert(curr_cert, final_subj_cert);
            if(status < 0) { goto done; }
            if(final_subj_cert->flgs.auth_done == 1 && final_subj_cert->flgs.auth_pass == 1) { break; }
            curr_cert = curr_cert->next;
        }
        // report verification failure when all the certs in client side cannot verify the cert chain from peer.
        if(curr_cert == NULL) { status = TLS_RESP_CERT_AUTH_FAIL; }
    } // end of if issuer_cert == NULL
done:
    return status;
} // tlsVerifyCertChain



tlsRespStatus  tlsCopyCertRawData(tlsSession_t *session)
{
    if((session == NULL) || (session->sec.chosen_ciphersuite == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    tlsCert_t  *curr_cert   =  NULL;
    word32  cert_len        =  0;
    word32  cert_copied_len =  session->last_cpy_cert_len;
    byte   *inbuf           = &session->inbuf.data[0];
    word16  inlen_decoded   =  session->inlen_decoded;
    word16  inlen_decrypted =  session->inlen_decrypted;
    tlsRespStatus status = TLS_RESP_OK;
    word16   rdy_cpy_len = 0;

    // adjust decrypted length due to the authentication tag appended to the entire decrypted bytes
    if(session->flgs.hs_rx_encrypt == 1) {
        if(session->sec.flgs.ct_final_frag == 1) {
            inlen_decrypted -= (1 + session->sec.chosen_ciphersuite->tagSize);
        } // actual content type & skip authentication tag (in the final fragment)
    }
    while (inlen_decrypted > inlen_decoded)
    { // move part of remaining received bytes to certificate entries,
        // read first 3-byte certificate length field
        switch(cert_copied_len) {
            case 0:
                curr_cert = (tlsCert_t *) XMALLOC(sizeof(tlsCert_t));
                XMEMSET(curr_cert, 0x0, sizeof(tlsCert_t));
                // insert the cert item to the end of list
                tlsAddItemToList((tlsListItem_t **)&session->peer_certs, (tlsListItem_t *)curr_cert, 0x0);
                rdy_cpy_len = XMIN(0x3, inlen_decrypted - inlen_decoded);
                break;
            case 1:
            case 2:
                rdy_cpy_len = 0x3 - cert_copied_len;
                // copy operation hasn't been finished on the final cert item
                curr_cert = (tlsCert_t *) tlsGetFinalItemFromList((tlsListItem_t *) session->peer_certs);
                break;
            default:
                rdy_cpy_len = 0;
                curr_cert = (tlsCert_t *) tlsGetFinalItemFromList((tlsListItem_t *) session->peer_certs);
                // copy operation hasn't been finished on the final cert item
                break;
        } // end of switch case
        if(rdy_cpy_len > 0) {
            XMEMCPY( &curr_cert->rawbytes.len[cert_copied_len], &inbuf[inlen_decoded], rdy_cpy_len );
            inlen_decoded   += rdy_cpy_len;
            cert_copied_len += rdy_cpy_len;
        }
        if((curr_cert->rawbytes.data == NULL) && (cert_copied_len == 3)) {
            tlsDecodeWord24( &curr_cert->rawbytes.len[0] , &cert_len );
            if(cert_len > (session->nbytes.total_certs - 3)) {
                status = TLS_RESP_ERR_CERT_OVFL; break;
            }
            curr_cert->rawbytes.data = XMALLOC(sizeof(byte) * cert_len);
        } // allocate space only when first 4 bytes of an extension entry is decoded
        if(inlen_decrypted > inlen_decoded) {
            tlsDecodeWord24( &curr_cert->rawbytes.len[0] , &cert_len );
            if(cert_copied_len < (3 + cert_len)) {
                rdy_cpy_len = XMIN(cert_len - (cert_copied_len - 3), inlen_decrypted - inlen_decoded);
                XMEMCPY(&curr_cert->rawbytes.data[cert_copied_len - 3], &inbuf[inlen_decoded], rdy_cpy_len);
                cert_copied_len  += rdy_cpy_len;
                inlen_decoded    += rdy_cpy_len;
                // finish copying current certificate, start check extensions attached with this certificate
                if((cert_len + 3) == cert_copied_len) {
                    session->last_ext_entry_dec_len = 0x1 << 15;
                } else { // otherwise all decrypted bytes are copied to current cert item (but haven't been complete)
                    XASSERT(cert_copied_len < (3 + cert_len));
                    XASSERT(inlen_decrypted == inlen_decoded);
                }
            }
        } // end of  inlen_decrypted > inlen_decoded
        session->inlen_decoded = inlen_decoded;
        if(inlen_decrypted > inlen_decoded) {
            status = tlsParseExtensions(session, &curr_cert->exts);
            inlen_decoded = session->inlen_decoded;
            if(status >= 0) {
                if(session->ext_dec_total_len == 0 && session->last_ext_entry_dec_len == 0) {
                    cert_copied_len = 0;
                } // will be set to zero in the end of loop
            }
        } // end of inlen_decrypted > inlen_decoded
    } // end of while-loop

    session->last_cpy_cert_len = cert_copied_len;
    return status;
} // end of tlsCopyCertRawData


tlsRespStatus  tlsDecodeCerts(tlsCert_t *cert, byte final_item_rdy)
{
    tlsRespStatus status = TLS_RESP_OK;
    while(cert != NULL) {
        if(final_item_rdy == 0x0 && cert->next == NULL) {
            break; // final cert item is NOT ready, simply return OK
        }
        if(cert->rawbytes.data != NULL) { // skip those already decoded
            // This TLS v1.3 implementation ONLY supports DER-encoded x509v3 certificate
            status = tlsDecodeX509cert(cert);
            if(status < 0) { break; }
            // decode extensions attached within each CertificateEntry
            status = tlsDecodeExtCertificate(cert, 0); // TODO: find better way to implement decoding cert extensions
            if(status < 0) { break; }
        }
        cert =  cert->next;
    } // end of while-loop
    return status;
} // end of tlsDecodeCerts



tlsRespStatus  tlsCertVerifyGenDigitalSig(tlsSecurityElements_t *sec, const tlsRSApss_t *rsapss_attri, tlsOpaque16b_t *out, const byte is_server)
{
    if(sec == NULL || sec->chosen_ciphersuite == NULL || rsapss_attri == NULL || out == NULL) {
        return TLS_RESP_ERRARGS;
    }
    const byte clientlabel[] = "TLS 1.3, client CertificateVerify";
    const byte serverlabel[] = "TLS 1.3, server CertificateVerify";
    int   resultcode = 0;
    byte        *buf = NULL;
    word16  hash_len = 0;
    tlsRespStatus  status = TLS_RESP_OK;
    tlsHashAlgoID  hash_algo_id = TLS_HASH_ALGO_UNKNOWN;

    hash_algo_id = TLScipherSuiteGetHashID(sec->chosen_ciphersuite);
    hash_len     = mqttHashGetOutlenBytes(hash_algo_id);
    out->len  = 64 + sizeof(clientlabel) - 1 + 1 + hash_len;
    out->data = XMALLOC(sizeof(byte) * out->len);
    buf       = out->data;
    // repeat 0x20 64 times in the beginning of the digital signature (RFC 8446, section 4.4.3)
    XMEMSET(buf, 0x20, sizeof(byte) * 64);
    buf += 64;
    if(is_server != 0x0) {
        XMEMCPY(buf, &serverlabel[0], sizeof(serverlabel));
    } else {
        XMEMCPY(buf, &clientlabel[0], sizeof(clientlabel));
    }
    buf += sizeof(clientlabel);
    status = tlsTransHashTakeSnapshot(sec, hash_algo_id, buf, (word16) hash_len);
    if(status < 0){ goto done; }
    // hash the concatenated string
    tlsHash_t  *hashobj = (tlsHash_t *) XMALLOC(sizeof(tlsHash_t));
    switch(rsapss_attri->hash_id) {
        case TLS_HASH_ALGO_SHA256:
            resultcode |= MGTT_CFG_HASH_SHA256_FN_INIT(hashobj);
            resultcode |= MGTT_CFG_HASH_SHA256_FN_UPDATE(hashobj, out->data, out->len);
            resultcode |= MGTT_CFG_HASH_SHA256_FN_DONE(hashobj, out->data);
            break;
        case TLS_HASH_ALGO_SHA384:
            resultcode |= MGTT_CFG_HASH_SHA384_FN_INIT(hashobj);
            resultcode |= MGTT_CFG_HASH_SHA384_FN_UPDATE(hashobj, out->data, out->len);
            resultcode |= MGTT_CFG_HASH_SHA384_FN_DONE(hashobj, out->data);
            break;
        default:
            break;
    } // end of switch case statement
    XMEMFREE((void *)hashobj);
    if(resultcode != 0) { status = TLS_RESP_ERR_HASH; }
    out->len = rsapss_attri->salt_len;
done:
    return status;
} // end of tlsCertVerifyGenDigitalSig



void  tlsFreeCertChain(tlsCert_t *in, tlsFreeCertEntryFlag ctrl_flg)
{
    tlsCert_t *curr_cert = in;
    while(curr_cert != NULL)
    {   // raw byte array of CA cert CANNOT be deallocated since it's declared as const array
        if((ctrl_flg & TLS_FREE_CERT_ENTRY_SKIP_FINAL_ITEM)  == TLS_FREE_CERT_ENTRY_SKIP_FINAL_ITEM) {
            if(curr_cert->next == NULL) { break; }
        }
        if((ctrl_flg & TLS_FREE_CERT_ENTRY_RAWBYTE)  == TLS_FREE_CERT_ENTRY_RAWBYTE) {
            if(curr_cert->rawbytes.data != NULL) {
                XMEMFREE((void *)curr_cert->rawbytes.data);
                curr_cert->rawbytes.data = NULL;
            }
        }
        if((ctrl_flg & TLS_FREE_CERT_ENTRY_SIGNATURE) == TLS_FREE_CERT_ENTRY_SIGNATURE) {
            if(curr_cert->signature.data != NULL) {
                XMEMFREE((void *)curr_cert->signature.data);
                curr_cert->signature.data = NULL;
            }
            if(curr_cert->subject.common_name != NULL) {
                XMEMFREE((void *)curr_cert->subject.common_name);
                curr_cert->subject.common_name = NULL;
            }
            if(curr_cert->issuer.common_name != NULL) {
                XMEMFREE((void *)curr_cert->issuer.common_name);
                curr_cert->issuer.common_name = NULL;
            }
            if(curr_cert->subject.org_name != NULL) {
                XMEMFREE((void *)curr_cert->subject.org_name);
                curr_cert->subject.org_name = NULL;
            }
            if(curr_cert->issuer.org_name != NULL) {
                XMEMFREE((void *)curr_cert->issuer.org_name);
                curr_cert->issuer.org_name = NULL;
            }
            // deallocate certificate extensions
            if(curr_cert->cert_exts != NULL) {
                tlsX509FreeCertExt((tlsX509v3ext_t *)curr_cert->cert_exts);
                XMEMFREE(curr_cert->cert_exts);
                curr_cert->cert_exts = NULL;
            }
        } // end of if flag TLS_FREE_CERT_ENTRY_SIGNATURE is set
        if(ctrl_flg  == TLS_FREE_CERT_ENTRY_ALL) {
            tlsCert_t *prev_cert = NULL;
            prev_cert = curr_cert;
            tlsRemoveItemFromList((tlsListItem_t **)&curr_cert, (tlsListItem_t *)curr_cert);
            // deallocate entire extension list
            tlsExtEntry_t  *prev_ext = NULL;
            tlsExtEntry_t  *curr_ext = prev_cert->exts;
            while(curr_ext != NULL) {
                prev_ext = curr_ext;
                tlsRemoveItemFromList((tlsListItem_t **)&curr_ext, (tlsListItem_t *)curr_ext);
                tlsFreeExtEntry(prev_ext);
            }
            if(prev_cert->hashed_holder_info.data != NULL) {
                XMEMFREE((void *)prev_cert->hashed_holder_info.data);
                prev_cert->hashed_holder_info.data = NULL;
            }
            if(prev_cert->issuer.hashed_dn != NULL) {
                XMEMFREE((void *) prev_cert->issuer.hashed_dn);
                prev_cert->issuer.hashed_dn = NULL;
            }
            if(prev_cert->subject.hashed_dn != NULL) {
                XMEMFREE((void *) prev_cert->subject.hashed_dn);
                prev_cert->subject.hashed_dn = NULL;
            }
            // deallocate public key, public key of CA cert must be kpet until the end of application
            if(prev_cert->pubkey_algo == TLS_ALGO_OID_RSA_KEY) {
                tlsRSAfreePubKey(prev_cert->pubkey);
                prev_cert->pubkey = NULL;
            }
            prev_cert->next = NULL;
            XMEMFREE((void *)prev_cert);
        } else {
            curr_cert = curr_cert->next;
        } // end of if flag TLS_FREE_CERT_ENTRY_ALL is set
    } // end of while loop
} // end of tlsFreeCertChain

