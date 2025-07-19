#ifndef TLS_X509_EXT_H
#define TLS_X509_EXT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    X509_EXT_TYPE_AUTH_ID = 0x23,
    X509_EXT_TYPE_SUBJ_ID = 0xe,
    X509_EXT_TYPE_KEY_UASGE = 0xf,
    X509_EXT_TYPE_SUBJ_ALT_NAME = 0x11, // Subject Alternative Name (OID 2.5.29.17)
    X509_EXT_TYPE_BASIC_CONSTRAINT = 0x13,
} tlsX509extType;

// Context-specific tag from GeneralName, e.g., 0x02 for dNSName, 0x07 for iPAddress
typedef enum {
    X509_EXT_SAN_DOMAIN_NAME = 0x02,
    X509_EXT_SAN_IP_ADDR = 0x07,
} tlsX509SANtype;

// for Subject Alternative Name entries
typedef struct __tlsX509SANEntry {
    tlsListItem_t  list_item; // Embed the generic list item
    tlsX509SANtype stype;
    union {
        tlsOpaque16b_t domain_name; // For dNSName (IA5String)
        tlsOpaque8b_t  ip_address;  // For iPAddress (OCTET STRING)
    } data;
} tlsX509SANEntry_t;

typedef struct {
    // subject key identifier
    // TODO: might not be necessary to store the key IDs below ?
    tlsOpaque8b_t  subjKeyID;
    tlsOpaque8b_t  authKeyID;    // authority key identifier
    tlsListItem_t *subjAltNames; // list of Subject Alternative Names (now a generic list)
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

tlsX509SANEntry_t *tlsX509FindSubjAltName(tlsX509v3ext_t *, mqttHost_t *keyword);

#ifdef __cplusplus
}
#endif
#endif // end of TLS_X509_EXT_H
