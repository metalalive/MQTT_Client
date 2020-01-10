#ifndef TLS_RSA_H
#define TLS_RSA_H

#ifdef __cplusplus
extern "C" {
#endif

// extract RSA public key bytes from the byte sequence "in" of a given DER-encoded X509 certificate
tlsRespStatus  tlsRSAgetPubKey(const byte *in, word32 *inlen, void **pubkey_p, word32 *datalen);

// extract RSA public key bytes from the byte sequence "in" that stores DER-encoded key file
tlsRespStatus  tlsRSAgetPrivKey(const byte *in, word16 inlen, void **privkey_p);

void  tlsRSAfreePubKey(void *pubkey_p);

void  tlsRSAfreePrivKey(void *privkey_p);


#ifdef __cplusplus
}
#endif
#endif // end of TLS_RSA_H
