#ifndef TLS_HKDF_H
#define TLS_HKDF_H

#ifdef __cplusplus
extern "C" {
#endif

tlsRespStatus  tlsHKDFextract(tlsHashAlgoID hash_algo_id, word16 hash_sz, tlsOpaque8b_t *out, tlsOpaque8b_t *ikm, tlsOpaque8b_t *salt);

tlsRespStatus  tlsHKDFexpand(tlsHashAlgoID hash_id, tlsOpaque8b_t *prk, tlsOpaque16b_t *info, tlsOpaque8b_t *okm);

tlsRespStatus  tlsHKDFexpandLabel(tlsHashAlgoID hash_id, tlsOpaque8b_t *in_secret, tlsOpaque8b_t *label,  tlsOpaque8b_t *context, tlsOpaque8b_t *out_secret);


#ifdef __cplusplus
}
#endif
#endif // end of  TLS_HKDF_H
