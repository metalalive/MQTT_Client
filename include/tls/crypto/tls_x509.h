#ifndef TLS_X509_H
#define TLS_X509_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    X509_V3 = 0x2,
    X509_V2 = 0x1,
    X509_V1 = 0x0,
} tlsX509versionCode;

// X509 distinguished name attributes supported & recorded in this implementation
typedef enum {
    X509_DN_ATTRI_CN   = 0x3, // common name
    X509_DN_ATTRI_ORG  = 0xa, // organization
} tlsX509DNattriOID;


tlsRespStatus  tlsDecodeX509cert(tlsCert_t *cert);


#ifdef __cplusplus
}
#endif
#endif // end of TLS_X509_H
