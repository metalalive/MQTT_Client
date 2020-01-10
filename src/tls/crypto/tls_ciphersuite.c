#include "mqtt_include.h"

static tlsRespStatus  tlsSymEncryptCommonDone(tlsSecurityElements_t *sec)
{
    if(sec == NULL) { return TLS_RESP_ERRARGS; }
    if(sec->encrypt_ctx != NULL) {
        XMEMFREE( sec->encrypt_ctx );
        sec->encrypt_ctx = NULL;
    }
    if(sec->decrypt_ctx != NULL) {
        XMEMFREE( sec->decrypt_ctx );
        sec->decrypt_ctx = NULL;
    }
    return TLS_RESP_OK;
} // end of tlsSymEncryptCommonDone



static tlsRespStatus  tlsAESGCMinit (tlsSecurityElements_t *sec, byte isDecrypt)
{
    if(sec == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus  status  = TLS_RESP_OK;
    if(isDecrypt == 0) {
        if(sec->encrypt_ctx == NULL) {
            sec->encrypt_ctx = XMALLOC(sizeof(tlsAESgcm_t));
        }
        XMEMSET(sec->encrypt_ctx, 0x00, sizeof(tlsAESgcm_t));
        TLS_CFG_AES_GCM_INIT_FN(status, sec->encrypt_ctx, &sec->writeKey[0], sec->chosen_ciphersuite->keySize);
    }
    else {
        if(sec->decrypt_ctx == NULL) {
            sec->decrypt_ctx = XMALLOC(sizeof(tlsAESgcm_t));
        }
        XMEMSET(sec->decrypt_ctx, 0x00, sizeof(tlsAESgcm_t));
        TLS_CFG_AES_GCM_INIT_FN(status, sec->decrypt_ctx, &sec->readKey[0], sec->chosen_ciphersuite->keySize);
    }
    return status;
} // end of tlsAESGCMinit


static tlsRespStatus  tlsAESGCMencrypt (tlsSecurityElements_t *sec, byte *pt, byte *ct, word32 *len)
{
    if((sec == NULL) || (len == NULL) || (ct == NULL) || (pt == NULL)) {
        return TLS_RESP_ERRARGS;
    } else if ((*len == 0) || (*len > TLS_DEFAULT_OUT_BUF_BYTES )) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus  status  = TLS_RESP_OK;
    word32  ptlen = *len;
    // one must reset IV, AAD everytime when encrypting new TLSInnerPlainText to Ciphertext
    if(sec->flgs.ct_first_frag != 0) { // re-init, set IV & AAD in first fragment
        TLS_CFG_AES_GCM_RESET_FN(status, sec->encrypt_ctx);
        if(status < 0) { goto done; }
        TLS_CFG_AES_GCM_SET_IV_FN(status, sec->encrypt_ctx, &sec->nonce[0], sec->chosen_ciphersuite->ivSize);
        if(status < 0) { goto done; }
        TLS_CFG_AES_GCM_SET_AAD_FN(status, sec->encrypt_ctx, &sec->aad[0], TLS_MAX_BYTES_AAD);
        if(status < 0) { goto done; }
    }
    if(sec->flgs.ct_final_frag != 0) { // for the final fragment, we only exclude tag length from plaintext length
        if(ptlen < sec->chosen_ciphersuite->tagSize) {
            status = TLS_RESP_ERRMEM; goto done;
        }
        ptlen -= sec->chosen_ciphersuite->tagSize;
    } else { // otherwise, find maximal number of blocks that can be processed in current fragment of TLSInnerPlainText at once
        ptlen -= ptlen % AES_PROCESSING_BLOCK_BYTES;
    }
    if(ptlen > 0) {
        TLS_CFG_AES_GCM_PROCESS_FN(status, sec->encrypt_ctx, ct, pt, ptlen, 0);
        if(status < 0) { goto done; }
        if(sec->flgs.ct_final_frag != 0) {
            *len = ptlen + sec->chosen_ciphersuite->tagSize;
        } else {
            *len = ptlen;
        }
    }
    if(sec->flgs.ct_final_frag != 0) {
        // copy authentication tag to the end of TLSCipherText
        TLS_CFG_AES_GCM_GET_TAG_FN(status, sec->encrypt_ctx, &ct[ptlen], sec->chosen_ciphersuite->tagSize);
    }
done:
    return status;
} // end of tlsAESGCMencrypt


static tlsRespStatus  tlsAESGCMdecrypt (tlsSecurityElements_t *sec, byte *ct, byte *pt, word32 *len)
{
    if((sec == NULL) || (len == NULL) || (ct == NULL) || (pt == NULL)) {
        return TLS_RESP_ERRARGS;
    } else if ((*len == 0) || (*len > TLS_DEFAULT_IN_BUF_BYTES)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus  status  = TLS_RESP_OK;
    word32  ptlen = *len;
    // one must reset IV, AAD everytime when decrypting new TLSCiphertext, TODO: refactor
    if(sec->flgs.ct_first_frag != 0) { // re-init, set IV & AAD in first fragment
        TLS_CFG_AES_GCM_RESET_FN(status, sec->decrypt_ctx);
        if(status < 0) { goto done; }
        // Both of AEAD_AES_256_CCM  and AEAD_AES_256_CCM require 12-byte nouce, which is copied from read IV
        TLS_CFG_AES_GCM_SET_IV_FN(status, sec->decrypt_ctx, &sec->nonce[0], sec->chosen_ciphersuite->ivSize);
        if(status < 0) { goto done; }
        // currently only TLS v1.3 is considered, the ADD (Additional Authentication Data) will always be first 5-byte record header
        TLS_CFG_AES_GCM_SET_AAD_FN(status, sec->decrypt_ctx, &sec->aad[0], TLS_MAX_BYTES_AAD);
        if(status < 0) { goto done; }
    }
    if(sec->flgs.ct_final_frag != 0) { // for the final fragment, we only exclude tag length from plaintext length
        if(ptlen < sec->chosen_ciphersuite->tagSize) {
            status = TLS_RESP_ERRMEM; goto done;
        }
        ptlen -= sec->chosen_ciphersuite->tagSize;
    } else { // otherwise, find maximal number of blocks that can be processed in current fragment of TLSCiphertext at once
        ptlen -= ptlen % AES_PROCESSING_BLOCK_BYTES;
    }
    if(ptlen > 0) {
        TLS_CFG_AES_GCM_PROCESS_FN(status, sec->decrypt_ctx, ct, pt, ptlen, 1);
        if(status < 0) { goto done; }
        if(sec->flgs.ct_final_frag != 0) {
            *len = ptlen + sec->chosen_ciphersuite->tagSize;
        } else {
            *len = ptlen;
        }
    }
    if(sec->flgs.ct_final_frag != 0) {
        // get tag & verify authentication
        byte tag[TLS_MAX_BYTES_AEAD_TAG];
        TLS_CFG_AES_GCM_GET_TAG_FN(status, sec->decrypt_ctx, &tag[0], sec->chosen_ciphersuite->tagSize);
        if(status < 0) { goto done; }
        if(XSTRNCMP((const char *)&tag[0], (const char *)&ct[ptlen], (size_t)sec->chosen_ciphersuite->tagSize) != 0) {
            status = TLS_RESP_ERR_ENAUTH_FAIL;
        }
    }
done:
    return status;
} // end of tlsAESGCMdecrypt



static tlsRespStatus  tlsChaCha20Poly1305init (tlsSecurityElements_t *sec, byte isDecrypt)
{
    if(sec == NULL) { return TLS_RESP_ERRARGS; }
    tlsRespStatus  status  = TLS_RESP_OK;
    if(isDecrypt == 0) {
        if(sec->encrypt_ctx == NULL) {
            sec->encrypt_ctx = XMALLOC(sizeof(tlsCha20Poly1305_t));
        }
        XMEMSET(sec->encrypt_ctx, 0x00, sizeof(tlsCha20Poly1305_t));
        TLS_CFG_CHACHA_POLY_INIT_FN(status, sec->encrypt_ctx, &sec->writeKey[0], sec->chosen_ciphersuite->keySize);
    } else { // isDecrypt != 0
        if(sec->decrypt_ctx == NULL) {
            sec->decrypt_ctx = XMALLOC(sizeof(tlsCha20Poly1305_t));
        }
        XMEMSET(sec->decrypt_ctx, 0x00, sizeof(tlsCha20Poly1305_t));
        TLS_CFG_CHACHA_POLY_INIT_FN(status, sec->decrypt_ctx, &sec->readKey[0], sec->chosen_ciphersuite->keySize);
    }
    return status;
} // end of tlsChaCha20Poly1305init


static tlsRespStatus  tlsChaCha20Poly1305encrypt (tlsSecurityElements_t *sec, byte *pt, byte *ct, word32 *len)
{
    return TLS_RESP_OK;
} // end of tlsChaCha20Poly1305encrypt


static tlsRespStatus  tlsChaCha20Poly1305decrypt (tlsSecurityElements_t *sec, byte *ct, byte *pt, word32 *len)
{
    return TLS_RESP_OK;
} // end of tlsChaCha20Poly1305decrypt


// the list of supported cipher suites
// the cipher suites are listed below by their security strength.
const tlsCipherSpec_t  tls_supported_cipher_suites[] = {
    { // TLS_AES_128_GCM_SHA256, 0x1301
        TLS_CIPHERSUITE_ID_AES_128_GCM_SHA256   ,// ident
        (1 << TLS_ENCRYPT_ALGO_AES128) | (1 << TLS_ENC_CHAINMODE_GCM) | (1 << TLS_HASH_ALGO_SHA256)      ,// flags
        16        ,// tagSize
        16        ,// keySize
        12        ,// ivSize
        tlsAESGCMinit          ,// init_fn
        tlsAESGCMencrypt       ,// encrypt_fn
        tlsAESGCMdecrypt       ,// decrypt_fn
        tlsSymEncryptCommonDone,// done_fn
    },
    { // TLS_AES_256_GCM_SHA384, 0x1302
        TLS_CIPHERSUITE_ID_AES_256_GCM_SHA384   ,// ident
        (1 << TLS_ENCRYPT_ALGO_AES256) | (1 << TLS_ENC_CHAINMODE_GCM) | (1 << TLS_HASH_ALGO_SHA384)      ,// flags
        16        ,// tagSize
        32        ,// keySize
        12        ,// ivSize
        tlsAESGCMinit          ,// init_fn
        tlsAESGCMencrypt       ,// encrypt_fn
        tlsAESGCMdecrypt       ,// decrypt_fn
        tlsSymEncryptCommonDone,// done_fn
    },
    { // TLS_CHACHA20_POLY1305_SHA256, 0x1303
        TLS_CIPHERSUITE_ID_CHACHA20_POLY1305_SHA256  ,// ident
        (1 << TLS_ENCRYPT_ALGO_CHACHA) | (1 << TLS_HASH_ALGO_SHA256)        ,// flags
        16     ,// tagSize
        32     ,// keySize
        12     ,// ivSize
        tlsChaCha20Poly1305init       ,// init_fn
        tlsChaCha20Poly1305encrypt    ,// encrypt_fn
        tlsChaCha20Poly1305decrypt    ,// decrypt_fn
        tlsSymEncryptCommonDone       ,// done_fn
    },
}; // end of tls_supported_cipher_suites


tlsHashAlgoID  TLScipherSuiteGetHashID( const tlsCipherSpec_t *cs_in )
{
    if(cs_in != NULL) {
        if((cs_in->flags & (1 << TLS_HASH_ALGO_SHA256)) != 0x0) {
            return TLS_HASH_ALGO_SHA256;
        }
        if((cs_in->flags & (1 << TLS_HASH_ALGO_SHA384)) != 0x0) {
            return TLS_HASH_ALGO_SHA384;
        }
        return TLS_HASH_ALGO_UNKNOWN; // cipher suite selected but cannot be recognized
    }
    return TLS_HASH_ALGO_NOT_NEGO;
} // end of TLScipherSuiteGetHashID


byte  tlsGetSupportedCipherSuiteListSize( void )
{
    byte  out = XGETARRAYSIZE(tls_supported_cipher_suites);
    return out;
} // end of tlsGetSupportedCipherSuiteListSize


const tlsCipherSpec_t* tlsGetCipherSuiteByID(word16 idcode)
{
    const tlsCipherSpec_t  *out = NULL;
    word16 len = tlsGetSupportedCipherSuiteListSize();
    word16 idx = 0;
    for(idx = 0; idx < len; idx++) {
        if(idcode == tls_supported_cipher_suites[idx].ident) {
            out = &tls_supported_cipher_suites[idx];
            break;
        }
    }
    return out;
} // end of tlsGetCipherSuite


