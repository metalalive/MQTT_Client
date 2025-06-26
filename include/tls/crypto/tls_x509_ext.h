#ifndef TLS_X509_EXT_H
#define TLS_X509_EXT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    X509_EXT_TYPE_AUTH_ID = 0x23,
    X509_EXT_TYPE_SUBJ_ID = 0xe,
    X509_EXT_TYPE_KEY_UASGE = 0xf,
    X509_EXT_TYPE_BASIC_CONSTRAINT = 0x13,
} tlsX509extType;

typedef struct {
    // subject key identifier
    // TODO: might not be necessary to store these value ?
    tlsOpaque8b_t subjKeyID;
    tlsOpaque8b_t authKeyID; // authority key identifier
    struct {
        byte is_ca : 1; // CA certificate flgs
        struct {
            byte digital_signature : 1;
            byte non_repudiation   : 1;
            byte key_encipher      : 1;
            byte data_encipher     : 1;
            byte key_agreement     : 1;
            byte key_cert_sign     : 1;
            byte crl_sign          : 1;
            byte encipher_only     : 1;
            byte decipher_only     : 1;
        } key_usage; // flags to store key usage
    } flgs;
} tlsX509v3ext_t;

tlsRespStatus tlsX509getExtensions(byte *in, word32 *inlen, tlsX509v3ext_t **out, word32 *datalen);

void tlsX509FreeCertExt(tlsX509v3ext_t *in);

#ifdef __cplusplus
}
#endif
#endif // end of TLS_X509_EXT_H
