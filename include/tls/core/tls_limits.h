#ifndef TLS_LIMITS_H
#define TLS_LIMITS_H

#ifdef __cplusplus
extern "C" {
#endif

#define REPORT_MAXVAL_ERROR( variable, maxval )   "[ERROR] "#variable" must be smaller than default value "#maxval" defined in this implementation. Recheck your configuration."


// --------------- Following parameters are defined in TLS v1.3 ---------------

#define  TLS_RECORD_LAYER_HEADER_NBYTES   5

#define  TLS_HANDSHAKE_HEADER_NBYTES      4

#define  TLS_DEFAULT_BYTES_RECORD_LAYER_PKT  0x1fff
// number of bytes in record layer must NOT exceed 8 KBytes - 1
#if    defined(TLS_PLATFORM_MAX_BYTES_RECORD_LAYER_PKT)
    #if (TLS_PLATFORM_MAX_BYTES_RECORD_LAYER_PKT <= TLS_DEFAULT_BYTES_RECORD_LAYER_PKT)
        #define  TLS_MAX_BYTES_RECORD_LAYER_PKT    TLS_PLATFORM_MAX_BYTES_RECORD_LAYER_PKT
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_PLATFORM_MAX_BYTES_RECORD_LAYER_PKT, TLS_DEFAULT_BYTES_RECORD_LAYER_PKT)
    #endif
#elif  defined(TLS_SYS_MAX_BYTES_RECORD_LAYER_PKT)
    #if (TLS_SYS_MAX_BYTES_RECORD_LAYER_PKT <= TLS_DEFAULT_BYTES_RECORD_LAYER_PKT)
        #define  TLS_MAX_BYTES_RECORD_LAYER_PKT    TLS_SYS_MAX_BYTES_RECORD_LAYER_PKT
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_SYS_MAX_BYTES_RECORD_LAYER_PKT, TLS_DEFAULT_BYTES_RECORD_LAYER_PKT)
    #endif
#else
    // default = 0xffff, but users can limit the packet size for resource-constraint embedded devices
    #define  TLS_MAX_BYTES_RECORD_LAYER_PKT    TLS_DEFAULT_BYTES_RECORD_LAYER_PKT
#endif  // end of TLS_MAX_BYTES_RECORD_LAYER_PKT


#define  TLS_DEFAULT_BYTES_HANDSHAKE_MSG       (TLS_MAX_BYTES_RECORD_LAYER_PKT - TLS_RECORD_LAYER_HEADER_NBYTES)
// this should be 24-bits integer value, no more than 16 MBytes
#if    defined(TLS_PLATFORM_MAX_BYTES_HANDSHAKE_MSG)
    #if (TLS_PLATFORM_MAX_BYTES_HANDSHAKE_MSG <= TLS_DEFAULT_BYTES_HANDSHAKE_MSG)
        #define  TLS_MAX_BYTES_HANDSHAKE_MSG   TLS_PLATFORM_MAX_BYTES_HANDSHAKE_MSG
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_PLATFORM_MAX_BYTES_HANDSHAKE_MSG, TLS_DEFAULT_BYTES_HANDSHAKE_MSG)
    #endif
#elif  defined(TLS_SYS_MAX_BYTES_HANDSHAKE_MSG)
    #if (TLS_SYS_MAX_BYTES_HANDSHAKE_MSG <= TLS_DEFAULT_BYTES_HANDSHAKE_MSG)
        #define  TLS_MAX_BYTES_HANDSHAKE_MSG   TLS_SYS_MAX_BYTES_HANDSHAKE_MSG
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_SYS_MAX_BYTES_HANDSHAKE_MSG, TLS_DEFAULT_BYTES_HANDSHAKE_MSG)
    #endif
#else
    #define  TLS_MAX_BYTES_HANDSHAKE_MSG       TLS_DEFAULT_BYTES_HANDSHAKE_MSG
#endif // end of TLS_MAX_BYTES_HANDSHAKE_MSG


#define  TLS_DEFAULT_BYTES_CIPHER_SUITE_LIST   0x30 // default = 0xfffe, defined in TLS v1.3 protocol
// maximum number of bytes that represent a list of supported cipher suites in ClientHello / ServerHello handshake message
#if    defined(TLS_PLATFORM_MAX_BYTES_CIPHER_SUITE_LIST)
    #if (TLS_PLATFORM_MAX_BYTES_CIPHER_SUITE_LIST <= TLS_DEFAULT_BYTES_CIPHER_SUITE_LIST)
        #define  TLS_MAX_BYTES_CIPHER_SUITE_LIST   TLS_PLATFORM_MAX_BYTES_CIPHER_SUITE_LIST
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_PLATFORM_MAX_BYTES_CIPHER_SUITE_LIST, TLS_DEFAULT_BYTES_CIPHER_SUITE_LIST)
    #endif
#elif  defined(TLS_SYS_MAX_BYTES_CIPHER_SUITE_LIST)
    #if (TLS_SYS_MAX_BYTES_CIPHER_SUITE_LIST <= TLS_DEFAULT_BYTES_CIPHER_SUITE_LIST)
        #define  TLS_MAX_BYTES_CIPHER_SUITE_LIST   TLS_SYS_MAX_BYTES_CIPHER_SUITE_LIST
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_SYS_MAX_BYTES_CIPHER_SUITE_LIST, TLS_DEFAULT_BYTES_CIPHER_SUITE_LIST)
    #endif
#else
    #define  TLS_MAX_BYTES_CIPHER_SUITE_LIST   TLS_DEFAULT_BYTES_CIPHER_SUITE_LIST
#endif // end of TLS_MAX_BYTES_CIPHER_SUITE_LIST



#define  TLS_DEFAULT_BYTES_EXTENSION_LIST   (TLS_MAX_BYTES_HANDSHAKE_MSG >> 1) 
// default = 0xffff, defined in TLS v1.3 protocol
#if    defined(TLS_PLATFORM_MAX_BYTES_EXTENSION_LIST)
    #if (TLS_PLATFORM_MAX_BYTES_EXTENSION_LIST <= TLS_DEFAULT_BYTES_EXTENSION_LIST)
        #define  TLS_MAX_BYTES_EXTENSION_LIST   TLS_PLATFORM_MAX_BYTES_EXTENSION_LIST
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_PLATFORM_MAX_BYTES_EXTENSION_LIST, TLS_DEFAULT_BYTES_EXTENSION_LIST)
    #endif
#elif  defined(TLS_SYS_MAX_BYTES_EXTENSION_LIST)
    #if (TLS_SYS_MAX_BYTES_EXTENSION_LIST <= TLS_DEFAULT_BYTES_EXTENSION_LIST)
        #define  TLS_MAX_BYTES_EXTENSION_LIST   TLS_SYS_MAX_BYTES_EXTENSION_LIST
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_SYS_MAX_BYTES_EXTENSION_LIST, TLS_DEFAULT_BYTES_EXTENSION_LIST)
    #endif
#else
    #define  TLS_MAX_BYTES_EXTENSION_LIST   TLS_DEFAULT_BYTES_EXTENSION_LIST
#endif // end of TLS_MAX_BYTES_EXTENSION_LIST



#define  TLS_DEFAULT_BYTES_NAMED_GRPS   0x20
// default = 0xfffe, defined in TLS v1.3 protocol
#if    defined(TLS_PLATFORM_MAX_BYTES_NAMED_GRPS)
    #if (TLS_PLATFORM_MAX_BYTES_NAMED_GRPS <= TLS_DEFAULT_BYTES_NAMED_GRPS)
        #define  TLS_MAX_BYTES_NAMED_GRPS   TLS_PLATFORM_MAX_BYTES_NAMED_GRPS
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_PLATFORM_MAX_BYTES_NAMED_GRPS, TLS_DEFAULT_BYTES_NAMED_GRPS)
    #endif
#elif  defined(TLS_SYS_MAX_BYTES_NAMED_GRPS)
    #if (TLS_SYS_MAX_BYTES_NAMED_GRPS <= TLS_DEFAULT_BYTES_NAMED_GRPS)
        #define  TLS_MAX_BYTES_NAMED_GRPS   TLS_SYS_MAX_BYTES_NAMED_GRPS
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_SYS_MAX_BYTES_NAMED_GRPS, TLS_DEFAULT_BYTES_NAMED_GRPS)
    #endif
#else
    #define  TLS_MAX_BYTES_NAMED_GRPS   TLS_DEFAULT_BYTES_NAMED_GRPS
#endif // end of TLS_MAX_BYTES_NAMED_GRPS


// for Certificate.certificate_request_context<0..2^8-1>
#define  TLS_MAX_BYTES_HS_CERT_REQ_CTX    0xff
// for Certificate.certificate_list<0..2^24-1>
#define  TLS_DEFAULT_BYTES_CERT_CHAIN     (TLS_MAX_BYTES_HANDSHAKE_MSG - TLS_HANDSHAKE_HEADER_NBYTES - 1 - TLS_MAX_BYTES_HS_CERT_REQ_CTX - 3)

#if    defined(TLS_PLATFORM_MAX_BYTES_CERT_CHAIN)
    #if (TLS_PLATFORM_MAX_BYTES_CERT_CHAIN <= TLS_DEFAULT_BYTES_CERT_CHAIN)
        #define  TLS_MAX_BYTES_CERT_CHAIN     TLS_PLATFORM_MAX_BYTES_CERT_CHAIN
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_PLATFORM_MAX_BYTES_CERT_CHAIN, TLS_DEFAULT_BYTES_CERT_CHAIN)
    #endif
#elif  defined(TLS_SYS_MAX_BYTES_CERT_CHAIN)
    #if (TLS_SYS_MAX_BYTES_CERT_CHAIN <= TLS_DEFAULT_BYTES_CERT_CHAIN)
        #define  TLS_MAX_BYTES_CERT_CHAIN     TLS_SYS_MAX_BYTES_CERT_CHAIN
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_SYS_MAX_BYTES_CERT_CHAIN, TLS_DEFAULT_BYTES_CERT_CHAIN)
    #endif
#else
    #define  TLS_MAX_BYTES_CERT_CHAIN     TLS_DEFAULT_BYTES_CERT_CHAIN
#endif // end of TLS_MAX_BYTES_CERT_CHAIN



#define   TLS_DEFAULT_BYTES_SIGN_ALGOS  0x20
// default = 0xfffe, defined in TLS v1.3 protocol
#if    defined(TLS_PLATFORM_MAX_BYTES_SIGN_ALGOS)
    #if(TLS_PLATFORM_MAX_BYTES_SIGN_ALGOS <= TLS_DEFAULT_BYTES_SIGN_ALGOS)
        #define   TLS_MAX_BYTES_SIGN_ALGOS  TLS_PLATFORM_MAX_BYTES_SIGN_ALGOS
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_PLATFORM_MAX_BYTES_SIGN_ALGOS, TLS_DEFAULT_BYTES_SIGN_ALGOS)
    #endif
#elif  defined(TLS_SYS_MAX_BYTES_SIGN_ALGOS)
    #if(TLS_SYS_MAX_BYTES_SIGN_ALGOS <= TLS_DEFAULT_BYTES_SIGN_ALGOS)
        #define   TLS_MAX_BYTES_SIGN_ALGOS  TLS_SYS_MAX_BYTES_SIGN_ALGOS
    #else
        #error   REPORT_MAXVAL_ERROR(TLS_SYS_MAX_BYTES_SIGN_ALGOS, TLS_DEFAULT_BYTES_SIGN_ALGOS)
    #endif
#else
    #define   TLS_MAX_BYTES_SIGN_ALGOS  TLS_DEFAULT_BYTES_SIGN_ALGOS
#endif // end of 


// number of bytes to represent alert message (in TLS v1.3)
#define  TLS_ALERT_MSG_BYTES               2

// maximum number of bytes that represent session ID in ClientHello / ServerHello handshake message
#define  TLS_MAX_BYTES_SESSION_ID          32

#define  TLS_MIN_BYTES_CIPHER_SUITE_LIST   0x2

#define  TLS_MIN_BYTES_EXTENSION_LIST      0x8

#define  TLS_HS_RANDOM_BYTES               32

#define  TLS_MAX_BYTES_SUPPORTED_VERSIONS    0x1e // default = 0xfe, defined in TLS v1.3 protocol
#define  TLS_MIN_BYTES_SUPPORTED_VERSIONS    2

#define  TLS_MIN_BYTES_NAMED_GRPS    2

#define  TLS_MIN_BYTES_SIGN_ALGOS    2

// max. number of named groups that can be added in key_share extension of ClientHello
#define  TLS_MAX_KEYSHR_ENTRIES_PER_CLIENTHELLO    2

// user label for HKDF-Expand(),need to consider few bytes for opaque  size
#define  TLS_MAX_BYTES_HKDF_EXPAND_INFO     80
#define  TLS_MAX_BYTES_HKDF_EXPAND_LABEL    (TLS_MAX_BYTES_HKDF_EXPAND_INFO - (sizeof(TLS_HKDF_LABEL_PREFIX) - 1) - 1 - 1 - 2)


// size of master secret depends on hash algorithm you used
// e.g. TLS v1.3 only allows SHA256 and SHA384 in its cipher suite,
// so the hash function (SHA384) should output at most 384 bits (48 bytes)
#define  TLS_HS_MASTER_SECRET_BYTES        48

// maximum number of bytes of symmetric key, in TLS v1.3, it will be AES-256 : 32 bytes
#define  TLS_MAX_BYTES_SYMMETRIC_KEY       32
#define  TLS_MIN_BYTES_SYMMETRIC_KEY       16

// number of bytes in each processing block of AES algorithm
#define  AES_PROCESSING_BLOCK_BYTES        16

// maximum number of bytes of symmetric key, in TLS v1.3, it will be 12 bytes
#define  TLS_MAX_BYTES_INIT_VEC            12

// AAD (additional authentication data) for AES encryption & TLS v1.3
// (see additional_data in section 5.2 "record payload protection", RFC 8446)
#define  TLS_MAX_BYTES_AAD                5

#define  TLS_MAX_BYTES_AEAD_TAG           16

// This implementation ONLY keeps the 2 most-recently-received PSK (pre-shared key) entries
#define  TLS_MAX_NUM_PSK_LISTITEM         2

// limit size of data in/out buffer used in TLS protocol
#define  TLS_DEFAULT_IN_BUF_BYTES         1440

#define  TLS_DEFAULT_OUT_BUF_BYTES        1440

// minimum number of bytes to decode ASN1 object ID & length
#define  TLS_MIN_BYTES_ASN1_OBJ_ID      1
#define  TLS_MIN_BYTES_ASN1_OBJ_LEN     1
#define  TLS_MIN_BYTES_ASN1_OBJ_DATA    1
#define  TLS_MIN_BYTES_ASN1_OID         0x2

#undef   REPORT_MAXVAL_ERROR
#ifdef __cplusplus
}
#endif
#endif // end of  TLS_LIMITS_H
