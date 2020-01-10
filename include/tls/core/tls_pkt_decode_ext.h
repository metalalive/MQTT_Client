#ifndef TLS_PKT_DECODE_EXT_H
#define TLS_PKT_DECODE_EXT_H

#ifdef __cplusplus
extern "C" {
#endif

tlsRespStatus  tlsDecodeExtServerHello(tlsSession_t *session);

tlsRespStatus  tlsDecodeExtEncryptExt(tlsSession_t *session);

tlsRespStatus  tlsDecodeExtCertReq(tlsSession_t *session);

tlsRespStatus  tlsDecodeExtCertificate(tlsCert_t *cert, word16 first_ext_unfinished);

tlsRespStatus  tlsParseExtensions(tlsSession_t *session, tlsExtEntry_t **out);


#ifdef __cplusplus
}
#endif
#endif // end of TLS_PKT_DECODE_EXT_H
