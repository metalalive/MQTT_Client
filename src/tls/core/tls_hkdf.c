#include "mqtt_include.h"

tlsRespStatus
tlsHKDFexpand(tlsHashAlgoID hash_id, tlsOpaque8b_t *prk, tlsOpaque16b_t *info, tlsOpaque8b_t *okm) {
    if ((prk == NULL) || (info == NULL) || (okm == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if ((prk->data == NULL) || (info->data == NULL) || (okm->data == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if ((prk->len == 0) || (info->len == 0) || (okm->len == 0)) {
        return TLS_RESP_ERRARGS;
    }
    word16 hash_sz = mqttHashGetOutlenBytes(hash_id);
    // L = okm->len <= 255 * hash_sz , in this implementation , we set L <= (hash_sz << 2) instead
    if ((hash_sz > prk->len) || ((hash_sz << 2) < okm->len) ||
        (TLS_MAX_BYTES_HKDF_EXPAND_INFO < info->len)) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus status = TLS_RESP_OK;
    byte         *T = NULL;
    byte         *buf = NULL;
    byte         *ptr = NULL; // pointer to somewhere in buf
    word16        T_len = hash_sz;
    word16        outlen_copied = 0;
    byte          idx = 0;

    T = XMALLOC(sizeof(byte) * T_len);
    buf = XMALLOC(sizeof(byte) * (T_len + info->len + 1));
    // section 2.3, RFC5869, the output OKM is calculated as follows:
    // N = ceil(L/HashLen)
    // T = T(1) | T(2) | T(3) | ... | T(N)
    // OKM = first L octets of T
    outlen_copied = 0;
    idx = 1;
    while (1) {
        ptr = buf;
        // T(0) = empty string (zero length)
        // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01) = HMAC-Hash(PRK, info | 0x01)
        // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
        // ...
        // T(idx) = HMAC-Hash(PRK, T(idx-1) | info | idx)
        if (idx > 1) {
            XMEMCPY(ptr, T, T_len);
            ptr += T_len;
        }
        XMEMCPY(ptr, info->data, info->len);
        ptr += info->len;
        *ptr++ = idx++;
        // calculate  HMAC-Hash()
        // input buf[0 ..... (buf - ptr - 1)]
        TLS_CFG_HMAC_MEMBLOCK_FN(status, hash_id, prk->data, prk->len, buf, (ptr - buf), T, T_len);
        /// XASSERT(T_len == hash_sz);
        if (status < 0) {
            break;
        }
        if ((okm->len - outlen_copied) <= T_len) {
            XMEMCPY(&okm->data[outlen_copied], T, (okm->len - outlen_copied));
            //// outlen_copied += (okm->len - outlen_copied);
            break;
        } else {
            XMEMCPY(&okm->data[outlen_copied], T, T_len);
            outlen_copied += T_len;
        }
    } // end of loop
    XMEMFREE((void *)T);
    XMEMFREE((void *)buf);
    return status;
} // end of tlsHKDFexpand

tlsRespStatus tlsHKDFextract(
    tlsHashAlgoID hash_id, word16 hash_sz, tlsOpaque8b_t *out, tlsOpaque8b_t *ikm,
    tlsOpaque8b_t *salt
) {
    if ((out == NULL) || (ikm == NULL) || (salt == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if ((out->data == NULL) || (ikm->data == NULL) || (salt->data == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if ((out->len == 0) || (ikm->len == 0) || (salt->len == 0)) {
        return TLS_RESP_ERRARGS;
    }
    if (tlsValidateHashAlgoID(hash_id) < 0) {
        return TLS_RESP_ERRARGS;
    }
    if (hash_sz != mqttHashGetOutlenBytes(hash_id)) {
        return TLS_RESP_ERRARGS;
    } // hash output size doesn't match hash algorithm ID
    tlsRespStatus status = TLS_RESP_OK;
    TLS_CFG_HMAC_MEMBLOCK_FN(
        status, hash_id, salt->data, salt->len, ikm->data, ikm->len, out->data, out->len
    );
    return status;
} // end of tlsHKDFextract

// section 7.1 , Key Schedule, RFC8446
//
// HKDF-Expand-Label(Secret, Label, Context, Length)
//    = HKDF-Expand(Secret, HkdfLabel, Length)
//
// struct {
//     uint16 length = Length;
//     opaque label<7..255> = "tls13 " + Label;
//     opaque context<0..255> = Context;
// } HkdfLabel;
//
// * According to RFC 8446 (TLS v1.3), section 3.4 Vectors,
//   the encoding of HkdfLabel.context field will include 1-byte autual length field
//   prepended to the the vector context<0...255>
// * zero-length hashed context could be appended to HkdfLabel, in such case the
//   1-byte autual length field is still preserved.
tlsRespStatus tlsHKDFexpandLabel(
    tlsHashAlgoID hash_id, tlsOpaque8b_t *in_secret, tlsOpaque8b_t *label, tlsOpaque8b_t *context,
    tlsOpaque8b_t *out_secret
) {
    if ((in_secret == NULL) || (label == NULL) || (out_secret == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if ((in_secret->data == NULL) || (label->data == NULL) || (out_secret->data == NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if ((in_secret->len == 0) || (label->len == 0) || (out_secret->len == 0)) {
        return TLS_RESP_ERRARGS;
    }
    if (label->len > TLS_MAX_BYTES_HKDF_EXPAND_LABEL) {
        return TLS_RESP_ERRARGS;
    }
    tlsRespStatus  status = TLS_RESP_OK;
    tlsOpaque16b_t hkdflabel = {0, NULL};
    byte          *buf = NULL;
    const byte     tlslabellen = sizeof(TLS_HKDF_LABEL_PREFIX) - 1;
    hkdflabel.len = 2 + (1 + tlslabellen + label->len) + 1;
    if (context != NULL) {
        hkdflabel.len += context->len;
    }
    hkdflabel.data = XMALLOC(sizeof(byte) * hkdflabel.len);
    buf = hkdflabel.data;
    // encode to HkdfLabel.length
    buf += tlsEncodeWord16(buf, (word16)out_secret->len);
    // encode to HkdfLabel.label,  must exclude terminating NULL byte from the prefix string
    *buf++ = (tlslabellen + label->len);
    XMEMCPY(&buf[0], TLS_HKDF_LABEL_PREFIX, tlslabellen);
    XMEMCPY(&buf[tlslabellen], label->data, label->len);
    buf += (tlslabellen + label->len);
    // encode to HkdfLabel.context
    *buf++ = (context != NULL) ? context->len : 0;
    if (context != NULL) {
        XMEMCPY(&buf[0], context->data, context->len);
        //// buf += context->len;
    }
    status = tlsHKDFexpand(hash_id, in_secret, &hkdflabel, out_secret);
    XMEMFREE((void *)hkdflabel.data);
    return status;
} // end of tlsHKDFexpandLabel
