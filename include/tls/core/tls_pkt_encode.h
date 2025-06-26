#ifndef TLS_PKT_ENCODE_H
#define TLS_PKT_ENCODE_H

#ifdef __cplusplus
extern "C" {
#endif

void tlsEncodeHandshakeHeader(tlsSession_t *);

tlsRespStatus
tlsGenFinishedVerifyData(tlsSecurityElements_t *, tlsOpaque8b_t *base_key, tlsOpaque8b_t *out);

tlsRespStatus tlsEncodeRecordLayer(tlsSession_t *);

#ifdef __cplusplus
}
#endif
#endif // end of TLS_PKT_ENCODE_H
