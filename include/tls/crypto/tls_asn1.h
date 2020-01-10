#ifndef TLS_ASN1_H
#define TLS_ASN1_H

#ifdef __cplusplus
extern "C" {
#endif

// bit masks for ASN.1 tag field
typedef enum {
    ASN_TAG_PRIMITIVE        =  0x0,
    ASN_TAG_UNIVERSAL        =  0x0,
    ASN_TAG_CONSTRUCTED      = 0x20,
    ASN_TAG_APPLICATION      = 0x40,
    ASN_TAG_CONTEXT_SPECIFIC = 0x80,
    ASN_TAG_PRIVATE          = 0xC0
} tlsASN1tagType;

// ASN.1 primitive data type
typedef enum {
    ASN_PRIMDATA_BOOLEAN       = 0x1,
    ASN_PRIMDATA_INTEGER,
    ASN_PRIMDATA_BIT_STRING,
    ASN_PRIMDATA_OCTET_STRING,
    ASN_PRIMDATA_NULL,
    ASN_PRIMDATA_OID,
    ASN_PRIMDATA_ENUMERATED    = 0xa,
    ASN_PRIMDATA_UTF8STRING    = 0xc,
    ASN_PRIMDATA_SEQUENCE      = 0x10,
    ASN_PRIMDATA_SET,
    ASN_PRIMDATA_PRINTABLESTRING = 0x13,
    ASN_PRIMDATA_T61STRING,
    ASN_PRIMDATA_IA5STRING     = 0x16,
    ASN_PRIMDATA_UTCTIME,
    ASN_PRIMDATA_GENERALIZEDTIME,
    ASN_PRIMDATA_VISIBLE_STRING = 0x1a,
    ASN_PRIMDATA_GENERAL_STRING,
    ASN_PRIMDATA_BMPSTRING      = 0x1e
} tlsASN1primDataType;


// inlen [in/out] :
//     size of input byte string, also store size of "1-byte ID + length field" of the ASN1 object
//     on returning from this function
//
// expected_idtag [in]:
//     check tag bits & ASN1 ID specified by caller
//
// datalen [out] :
//     store size of data section of the ASN1 object on returning from this function
//
tlsRespStatus  tlsASN1GetIDlen(const byte *in, word32 *inlen, byte expected_idtag, word32 *datalen);

tlsRespStatus  tlsASN1GetAlgoID(const byte *in, word32 *inlen, tlsAlgoOID *out, word32 *datalen);


#ifdef __cplusplus
}
#endif
#endif // end of TLS_ASN1_H
