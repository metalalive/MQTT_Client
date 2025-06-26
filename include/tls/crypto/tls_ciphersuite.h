#ifndef TLS_CIPHERSUITE_H
#define TLS_CIPHERSUITE_H

#ifdef __cplusplus
extern "C" {
#endif

// get hash ID from given cipher suite
tlsHashAlgoID TLScipherSuiteGetHashID(const tlsCipherSpec_t *cs_in);

const tlsCipherSpec_t *tlsGetCipherSuiteByID(word16 idcode);

byte tlsGetSupportedCipherSuiteListSize(void);

#ifdef __cplusplus
}
#endif
#endif // end of TLS_CIPHERSUITE_H
