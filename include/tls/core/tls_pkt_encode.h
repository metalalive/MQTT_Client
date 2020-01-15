#ifndef TLS_PKT_ENCODE_H
#define TLS_PKT_ENCODE_H

#ifdef __cplusplus
extern "C" {
#endif

void  tlsEncodeHandshakeHeader(tlsSession_t *session);

tlsRespStatus  tlsGenFinishedVerifyData(tlsSecurityElements_t *sec, tlsOpaque8b_t *base_key, tlsOpaque8b_t *out);

tlsRespStatus  tlsEncodeRecordLayer(tlsSession_t *session);


#ifdef __cplusplus
}
#endif
#endif // end of TLS_PKT_ENCODE_H
