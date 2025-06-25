#ifndef TLS_PKT_ENCODE_EXT_H
#define TLS_PKT_ENCODE_EXT_H

#ifdef __cplusplus
extern "C" {
#endif

// this function will generate a list of extensions with respect to the given handshake types,
// the output of the function is supposed to add to tlsSession_t.exts
tlsExtEntry_t *tlsGenExtensions(tlsSession_t *);

word16 tlsGetExtListSize(tlsExtEntry_t *ext_head);

void tlsDeleteAllExtensions(tlsExtEntry_t *ext_head);

tlsRespStatus tlsEncodeHSclientHelloExt(tlsSession_t *);

tlsRespStatus tlsEncodeExtensions(tlsSession_t *);

#ifdef __cplusplus
}
#endif
#endif // end of TLS_PKT_ENCODE_EXT_H
