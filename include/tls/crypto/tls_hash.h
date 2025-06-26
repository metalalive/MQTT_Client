#ifndef TLS_HASH_H
#define TLS_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

// perform transcript hash to hankshake message for authentication message

tlsRespStatus tlsCpyHashEmptyInput(tlsHashAlgoID hash_id, tlsOpaque8b_t *out);

tlsRespStatus tlsTranscrptHashHSmsgUpdate(tlsSession_t *, tlsOpaque16b_t *buf);

tlsRespStatus tlsTranscrptHashInit(tlsSecurityElements_t *);

tlsRespStatus tlsTranscrptHashDeInit(tlsSecurityElements_t *);

tlsRespStatus tlsTranscrptHashReInit(tlsSecurityElements_t *);

tlsRespStatus
tlsTransHashTakeSnapshot(tlsSecurityElements_t *, tlsHashAlgoID hash_id, byte *out, word16 outlen);

tlsRespStatus tlsTransHashCleanUnsuedHashHandler(tlsSecurityElements_t *);

#ifdef __cplusplus
}
#endif
#endif // end of  TLS_HASH_H
