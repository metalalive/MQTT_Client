#ifndef TLS_PKT_DECODE_EXT_H
#define TLS_PKT_DECODE_EXT_H

#ifdef __cplusplus
extern "C" {
#endif

tlsRespStatus tlsDecodeExtServerHello(tlsSession_t *);

tlsRespStatus tlsDecodeExtEncryptExt(tlsSession_t *);

tlsRespStatus tlsDecodeExtCertReq(tlsSession_t *);

tlsRespStatus tlsDecodeExtCertificate(tlsCert_t *, word16 first_ext_unfinished);

tlsRespStatus tlsParseExtensions(tlsSession_t *, tlsExtEntry_t **out);

#ifdef __cplusplus
}
#endif
#endif // end of TLS_PKT_DECODE_EXT_H
