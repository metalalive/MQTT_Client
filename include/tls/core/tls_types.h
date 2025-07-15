#ifndef TLS_TYPES_H
#define TLS_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

// Content Type field at Record Layer
// currently we only support TLS v1.3,
// any new content type defined in future version of TLS should be added in this enum type below.
typedef enum {
    // for TLS v1.3
    TLS_CONTENT_TYPE_INVALID = 0,
    TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20,
    TLS_CONTENT_TYPE_ALERT = 21,
    TLS_CONTENT_TYPE_HANDSHAKE = 22,
    TLS_CONTENT_TYPE_APP_DATA = 23,
    TLS_CONTENT_TYPE_HEARTBEAT = 24,
} tlsContentType;

typedef enum {
    TLS_ALERT_LVL_WARNING = 1,
    TLS_ALERT_LVL_FATAL = 2,
} tlsAlertLvl;

typedef enum {
    TLS_ALERT_TYPE_CLOSE_NOTIFY = 0,
    TLS_ALERT_TYPE_UNEXPECTED_MESSAGE = 10,
    TLS_ALERT_TYPE_BAD_RECORD_MAC = 20,
    TLS_ALERT_TYPE_DECRYPTION_FAILED_RESERVED = 21,
    TLS_ALERT_TYPE_RECORD_OVERFLOW = 22,
    TLS_ALERT_TYPE_DECOMPRESSION_FAILURE_RESERVED = 30,
    TLS_ALERT_TYPE_HANDSHAKE_FAILURE = 40,
    TLS_ALERT_TYPE_NO_CERTIFICATE_RESERVED = 41,
    TLS_ALERT_TYPE_BAD_CERTIFICATE = 42,
    TLS_ALERT_TYPE_UNSUPPORTED_CERTIFICATE = 43,
    TLS_ALERT_TYPE_CERTIFICATE_REVOKED = 44,
    TLS_ALERT_TYPE_CERTIFICATE_EXPIRED = 45,
    TLS_ALERT_TYPE_CERTIFICATE_UNKNOWN = 46,
    TLS_ALERT_TYPE_ILLEGAL_PARAMETER = 47,
    TLS_ALERT_TYPE_UNKNOWN_CA = 48,
    TLS_ALERT_TYPE_ACCESS_DENIED = 49,
    TLS_ALERT_TYPE_DECODE_ERROR = 51,
    TLS_ALERT_TYPE_DECRYPT_ERROR = 50,
    TLS_ALERT_TYPE_EXPORT_RESTRICTION_RESERVED = 60,
    TLS_ALERT_TYPE_PROTOCOL_VERSION = 70,
    TLS_ALERT_TYPE_INSUFFICIENT_SECURITY = 71,
    TLS_ALERT_TYPE_INTERNAL_ERROR = 80,
    TLS_ALERT_TYPE_INAPPROPRIATE_FALLBACK = 86,
    TLS_ALERT_TYPE_USER_CANCELED = 90,
    TLS_ALERT_TYPE_NO_RENEGOTIATION_RESERVED = 100,
    TLS_ALERT_TYPE_MISSING_EXTENSION = 109,
    TLS_ALERT_TYPE_UNSUPPORTED_EXTENSION = 110,
    TLS_ALERT_TYPE_CERTIFICATE_UNOBTAINABLE_RESERVED = 111,
    TLS_ALERT_TYPE_UNRECOGNIZED_NAME = 112,
    TLS_ALERT_TYPE_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
    TLS_ALERT_TYPE_BAD_CERTIFICATE_HASH_VALUE_RESERVED = 114,
    TLS_ALERT_TYPE_UNKNOWN_PSK_IDENTITY = 115,
    TLS_ALERT_TYPE_CERTIFICATE_REQUIRED = 116,
    TLS_ALERT_TYPE_NO_APPLICATION_PROTOCOL = 120,
} tlsAlertType;

typedef enum {
    TLS_HS_TYPE_HELLO_REQUEST_RESERVED = 0,
    TLS_HS_TYPE_CLIENT_HELLO = 1,
    TLS_HS_TYPE_SERVER_HELLO = 2,
    TLS_HS_TYPE_HELLO_VERIFY_REQUEST_RESERVED = 3,
    TLS_HS_TYPE_NEW_SESSION_TICKET = 4,
    TLS_HS_TYPE_END_OF_EARLY_DATA = 5,
    TLS_HS_TYPE_HELLO_RETRY_REQUEST_RESERVED = 6,
    TLS_HS_TYPE_ENCRYPTED_EXTENSIONS = 8,
    TLS_HS_TYPE_CERTIFICATE = 11,
    TLS_HS_TYPE_SERVER_KEY_EXCHANGE_RESERVED = 12,
    TLS_HS_TYPE_CERTIFICATE_REQUEST = 13,
    TLS_HS_TYPE_SERVER_HELLO_DONE_RESERVED = 14,
    TLS_HS_TYPE_CERTIFICATE_VERIFY = 15,
    TLS_HS_TYPE_CLIENT_KEY_EXCHANGE_RESERVED = 16,
    TLS_HS_TYPE_FINISHED = 20,
    TLS_HS_TYPE_CERTIFICATE_URL_RESERVED = 21,
    TLS_HS_TYPE_CERTIFICATE_STATUS_RESERVED = 22,
    TLS_HS_TYPE_SUPPLEMENTAL_DATA_RESERVED = 23,
    TLS_HS_TYPE_KEY_UPDATE = 24,
    TLS_HS_TYPE_MESSAGE_HASH = 254,
} tlsHandshakeType;

typedef enum {
    TLS_EXT_TYPE_SERVER_NAME = 0,
    TLS_EXT_TYPE_MAX_FRAGMENT_LENGTH = 1,
    TLS_EXT_TYPE_STATUS_REQUEST = 5,
    TLS_EXT_TYPE_SUPPORTED_GROUPS = 10,
    TLS_EXT_TYPE_SIGNATURE_ALGORITHMS = 13,
    TLS_EXT_TYPE_USE_SRTP = 14,
    TLS_EXT_TYPE_HEARTBEAT = 15,
    TLS_EXT_TYPE_ALPN = 16,
    TLS_EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP = 18,
    TLS_EXT_TYPE_CLIENT_CERTIFICATE_TYPE = 19,
    TLS_EXT_TYPE_SERVER_CERTIFICATE_TYPE = 20,
    TLS_EXT_TYPE_PADDING = 21,
    TLS_EXT_TYPE_PRE_SHARED_KEY = 41,
    TLS_EXT_TYPE_EARLY_DATA = 42,
    TLS_EXT_TYPE_SUPPORTED_VERSIONS = 43,
    TLS_EXT_TYPE_COOKIE = 44,
    TLS_EXT_TYPE_PSK_KEY_EXCHANGE_MODES = 45,
    TLS_EXT_TYPE_CERTIFICATE_AUTHORITIES = 47,
    TLS_EXT_TYPE_OID_FILTERS = 48,
    TLS_EXT_TYPE_POST_HANDSHAKE_AUTH = 49,
    TLS_EXT_TYPE_SIGNATURE_ALGORITHMS_CERT = 50,
    TLS_EXT_TYPE_KEY_SHARE = 51,
    TLS_EXT_TYPE_MAX_VALUE_RESERVED = 0xffff,
} tlsExtType; // extension type

typedef enum {
    TLS_PSK_KEY_EX_MODE_PSK_KE = 0,
    TLS_PSK_KEY_EX_MODE_PSK_DHE_KE = 1,
} tlsPskKeyExMode;

typedef enum {
    // RSASSA-PKCS1-v1_5 algorithms
    TLS_SIGNATURE_RSA_PKCS1_SHA256 = 0x0401,
    TLS_SIGNATURE_RSA_PKCS1_SHA384 = 0x0501,
    TLS_SIGNATURE_RSA_PKCS1_SHA512 = 0x0601,
    // ECC-DSA algorithms
    TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 = 0x0403,
    TLS_SIGNATURE_ECDSA_SECP384R1_SHA384 = 0x0503,
    TLS_SIGNATURE_ECDSA_SECP521R1_SHA512 = 0x0603,
    // RSASSA-PSS algorithms with public key OID rsaEncryption
    TLS_SIGNATURE_RSA_PSS_RSAE_SHA256 = 0x0804,
    TLS_SIGNATURE_RSA_PSS_RSAE_SHA384 = 0x0805,
    TLS_SIGNATURE_RSA_PSS_RSAE_SHA512 = 0x0806,
    // EdDSA algorithms
    TLS_SIGNATURE_ED25519 = 0x0807,
    TLS_SIGNATURE_ED448 = 0x0808,
    // RSASSA-PSS algorithms with public key OID RSASSA-PSS
    TLS_SIGNATURE_RSA_PSS_PSS_SHA256 = 0x0809,
    TLS_SIGNATURE_RSA_PSS_PSS_SHA384 = 0x080a,
    TLS_SIGNATURE_RSA_PSS_PSS_SHA512 = 0x080b,
} tlsSignScheme; // signature scheme

typedef enum { // named groups for key exchange negotiation
    TLS_NAMED_GRP_UNALLOCATED_RESERVED = 0x0000,
    // Elliptic Curve Groups (ECDHE)
    TLS_NAMED_GRP_SECP256R1 = 0x0017,
    TLS_NAMED_GRP_SECP384R1 = 0x0018,
    TLS_NAMED_GRP_SECP521R1 = 0x0019,
    TLS_NAMED_GRP_X25519 = 0x001D,
    TLS_NAMED_GRP_X448 = 0x001E,
    // Finite Field Groups (DHE)
    TLS_NAMED_GRP_FFDHE2048 = 0x0100,
    TLS_NAMED_GRP_FFDHE3072 = 0x0101,
    TLS_NAMED_GRP_FFDHE4096 = 0x0102,
    TLS_NAMED_GRP_FFDHE6144 = 0x0103,
    TLS_NAMED_GRP_FFDHE8192 = 0x0104,
    // Reserved Code Points
    TLS_NAMED_GRP_FFDHE_PRIVATE_USE_MIN = 0x01FC,
    TLS_NAMED_GRP_FFDHE_PRIVATE_USE_MAX = 0x01FF,
    TLS_NAMED_GRP_ECDHE_PRIVATE_USE_MIN = 0xFE00,
    TLS_NAMED_GRP_ECDHE_PRIVATE_USE_MAX = 0xFEFF,
} tlsNamedGrp;

typedef enum {
    TLS_CERT_TYPE_X509 = 0,
    TLS_CERT_TYPE_OPENPGP_RESERVED = 1,
    TLS_CERT_TYPE_RAWPUBLICKEY = 2,
} tlsCertType; // certification type

typedef enum {
    TLS_CIPHERSUITE_ID_AES_128_GCM_SHA256 = 0x1301,
    TLS_CIPHERSUITE_ID_AES_256_GCM_SHA384 = 0x1302,
    TLS_CIPHERSUITE_ID_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_CIPHERSUITE_ID_AES_128_CCM_SHA256 = 0x1304,
    TLS_CIPHERSUITE_ID_AES_128_CCM_8_SHA256 = 0x1305,
} tlsCipherSuiteID;

typedef enum {
    TLS_VERSION_ENCODE_1_0 = 0x0301,
    TLS_VERSION_ENCODE_1_1 = 0x0302,
    TLS_VERSION_ENCODE_1_2 = 0x0303,
    TLS_VERSION_ENCODE_1_3 = 0x0304,
} tlsVersionCode;

typedef enum {
    TLS_HASH_ALGO_UNKNOWN = 0,
    TLS_HASH_ALGO_SHA256 = MQTT_HASH_SHA256,
    TLS_HASH_ALGO_SHA384 = MQTT_HASH_SHA384,
    TLS_HASH_ALGO_NOT_NEGO = 0xff, // hash algorithm has not been negotiated yet
} tlsHashAlgoID;

typedef enum {
    TLS_ENCRYPT_ALGO_AES128 = 3,
    TLS_ENCRYPT_ALGO_AES256 = 4,
    TLS_ENCRYPT_ALGO_CHACHA = 5,
} tlsEncryptAlgoID;

typedef enum {
    TLS_ENC_CHAINMODE_GCM = 8,
} tlsEncChainModeID;

typedef enum {
    TLS_KEYEX_STATE_NOT_NEGO_YET = 0,
    TLS_KEYEX_STATE_NEGOTIATING = 1,
    TLS_KEYEX_STATE_NOT_APPLY = 2,
    TLS_KEYEX_STATE_APPLIED = 3,
    // negotiate again since the client receives the first HelloRetryRequest
    TLS_KEYEX_STATE_RENEGO_HRR = 4,
} tlsKeyExState; // key exchange state

typedef enum {
    TLS_FREE_CERT_ENTRY_RAWBYTE = 1,
    TLS_FREE_CERT_ENTRY_SIGNATURE = 2,
    TLS_FREE_CERT_ENTRY_ALL = 7,
    TLS_FREE_CERT_ENTRY_SKIP_FINAL_ITEM = 8,
} tlsFreeCertEntryFlag;

// return code that represents status after executing TLS function
typedef enum {
    TLS_RESP_OK = 0,
    TLS_RESP_REQ_MOREDATA = 1,
    TLS_RESP_REQ_REINIT = 2,
    // indicate that current piece of data (ready to send or already received) is the first fragment
    // of record message
    TLS_RESP_FIRST_FRAG = 4,
    // indicate that current piece of data (ready to send or already received) is the final fragment
    // of record message
    TLS_RESP_FINAL_FRAG = 8,
    // error code below
    TLS_RESP_ERR = -1,
    TLS_RESP_ERRARGS = -2,
    TLS_RESP_ERRMEM = -3,
    TLS_RESP_MALFORMED_PKT = -4,
    TLS_RESP_ERR_ENCODE = -5,
    TLS_RESP_ERR_DECODE = -6,
    TLS_RESP_ERR_PARSE = -7,
    // features / functions defined in TLS protocol, but not supported in this implementation
    TLS_RESP_ERR_NOT_SUPPORT = -8,
    TLS_RESP_TIMEOUT = -9,
    TLS_RESP_ERR_NO_KEYEX_MTHD_AVAIL = -10,
    TLS_RESP_ERR_KEYGEN = -11,
    TLS_RESP_ERR_HASH = -12,
    // error on encryption / decryption functions (including initialization)
    TLS_RESP_ERR_ENCRYPT = -13,
    TLS_RESP_ERR_ENAUTH_FAIL = -14, // failure on authentication encryption
    TLS_RESP_ERR_CERT_OVFL = -15,   // certificate (chain) is too large to fit in
    TLS_RESP_CERT_AUTH_FAIL = -16,  // authentication failure on peer's certificate
    // error because received record message exceeds maximum size defined in this implementation
    TLS_RESP_ERR_EXCEED_MAX_REC_SZ = -17,
    TLS_RESP_ERR_SYS_SEND_PKT = -18,
    TLS_RESP_ERR_SYS_RECV_PKT = -19,
    TLS_RESP_HS_AUTH_FAIL = -20,   // authentication failure on the handshake messages
    TLS_RESP_PEER_CONN_FAIL = -21, // connection closed by the peer for whatever reason
    // errors which conform to formal protocol syntax, but are incorrect or inconsistent
    TLS_RESP_ILLEGAL_PARAMS = -22,
    // errors for the sevrer which cannot find (another) appropriate server specified in
    // "server_name" extension entry of ClientHello
    TLS_RESP_ERR_SERVER_NAME = -23,
    // errors found when decoding message from peer, then the client will send alert
    TLS_RESP_REQ_ALERT = -50,
} tlsRespStatus;

typedef struct {
    tlsAlertLvl  level       : 8; // strictly use 8 bits in this field
    tlsAlertType description : 8;
} tlsAlertMsg_t;

#pragma pack(push, 1)
// variable-sized field used in TLS handshaking process, its length is stored in a 8-bit variable
typedef struct {
    byte  len;
    byte *data; // point to the array of specified "len" bytes
} tlsOpaque8b_t;

// variable-sized field used in TLS handshaking process, its length is stored in a 16-bit variable
typedef struct {
    word16 len;
    byte  *data; // point to the array of specified "len" bytes
} tlsOpaque16b_t;

// variable-sized field used in TLS handshaking process, its length is stored in a 24-bit variable
typedef struct {
    byte  len[3]; // the length = (len[0] << 16) | (len[1] << 8) | len[2]
    byte *data;   // point to the array of specified "len" bytes
} tlsOpaque24b_t;
#pragma pack(pop)

// used for abstracting linked list structures used in this implementation
typedef struct __tlsListItem {
    struct __tlsListItem *next;
} tlsListItem_t;

#pragma pack(push, 1)
typedef struct {
    tlsContentType type : 8; // strictly use 8 bits in this field
    byte           majorVer; // legacy record version, e.g. it would be 0x0301, 0x0302, 0x0303
    byte           minorVer;
    tlsOpaque16b_t fragment; // starting offset of the content of the given record layer message
} tlsRecordLayer_t;

typedef struct __tlsExtEntry { // extension entry
    struct __tlsExtEntry *next;
    word16                type; // must be 16-bit tlsExtType enum
    tlsOpaque16b_t        content;
} tlsExtEntry_t;

typedef struct {
    tlsHandshakeType type : 8;
    // it takes actually 3 bytes, this value MUST NOT exceed TLS_MAX_BYTES_HANDSHAKE_MSG
    // , the length = (len[0] << 16) | (len[1] << 8) | len[2]
    // point to message body which is ready to transmit during the handshaking process
    tlsOpaque24b_t fragment;
} tlsHandshakeMsg_t; // handshake message
#pragma pack(pop)

// this implementation only considers following few certificate/signature algorithms
// [Note] no need to consider collision because this implementation ONLY supports few hash / public
// key algorithm
typedef enum {
    TLS_ALGO_OID_SHA256 = 414,
    TLS_ALGO_OID_SHA384 = 415,
    TLS_ALGO_OID_RSA_KEY = 645,
    TLS_ALGO_OID_RSASSA_PSS = 654,
    TLS_ALGO_OID_SHA256_RSA_SIG = 655,
    TLS_ALGO_OID_SHA384_RSA_SIG = 656,
} tlsAlgoOID;

typedef struct {
    word16        salt_len;
    tlsHashAlgoID hash_id;
} tlsRSApss_t;

typedef struct {
    byte *hashed_dn;   // hashed Distinguish Name of an recorded in a certificate
    byte *common_name; // common name in Distinguish Name section of a certificate
    byte *org_name;    // organization name
} tlsCertProfile_t;

// data structure for storing essential parts of certificate (chain),
// will be encoded & added to certificate handshake message
// [Note] : This MQTT/TLS implementation ONLY supports x509v3 certificate decoding
typedef struct __tlsCert {
    struct __tlsCert *next;
    tlsExtEntry_t    *exts; // extensions extracted from CertificateEntry.extensions<0..2^16-1>;
    void             *cert_exts; // extensions embedded in certificate
    void             *pubkey;    // public key from given CertificateEntry.cert_data<1..2^24-1>

    // a x509 certificate file can be split to (1) certificate part (2) signature part
    // , hash_cert is hashed byte sequence of the first part, which will be
    // compared with the decrypted signature (the second part) for verificcation.
    tlsOpaque16b_t   hashed_holder_info;
    tlsCertProfile_t issuer;
    tlsCertProfile_t subject;
    tlsOpaque16b_t   signature; // signature extracted from a CertificateEntry.cert_data<1..2^24-1>
    tlsAlgoOID       cert_algo;
    tlsAlgoOID       sign_algo;
    tlsAlgoOID       pubkey_algo;
    tlsRSApss_t      rsapss; // store extra information for RSA-PSS signature slgorithm
    // for temporarily storing raw bytes of CertificateEntry.cert_data<1..2^24-1> before decoding
    // it, once it's decoded, this implementation will free up the space from the rawbyte field.
    // Note this implementation restricts size of certificate chain (CertificateEntry.cert_data from
    // peer) , it should depend on RAM size of underlying hardware platform
    tlsOpaque24b_t rawbytes;
    struct {
        byte auth_done   : 1; // authentication completed
        byte auth_pass   : 1; // authentication passed = 1, failure = 0
        byte self_signed : 1;
    } flgs; // status flags
} tlsCert_t;

typedef struct __tlsPSK {
    struct __tlsPSK *next;
    struct {                 // updated since receipt of the last NewSessionTicket from Server
        word32 timestamp_ms; // initial timestamp in milliseconds, on receipt of this PSK
        word32 ticket_lifetime;
        word32 ticket_age_add;
    } time_param;
    tlsOpaque16b_t id;
    tlsOpaque8b_t  key;
    struct {
        byte is_resumption : 1;
    } flgs;
} tlsPSK_t;

typedef struct { // structure particularly used at key exchange phase of handshaking process
    // negotiation at key exchange phase
    void **keylist; // each item of the keylist can be pointer to (1) tlsECCkey_t (2) tlsX25519Key_t
    tlsKeyExState
        *grp_nego_state; // flags to set when a named group is negotiated at the key exchange phase.
    byte num_grps_total; // total number of items in the supported named group list
    byte num_grps_chosen; // number of items in the key share extension (in ClientHello), with
                          // respect to the supported named groups
    byte chosen_grp_idx;  // the index of grp_nego_state array item which is chosen at key-exchange
                          // phase
} tlsKeyEx_t;

struct __tlsCipherSpec_t;

#pragma pack(push, 1)
typedef struct { // necessary elements for building secure connection
    struct {     // the hashed handshake message so far, it will be examined when sending FINISHED
                 // handshake message.
        tlsHash_t *objsha256;
        tlsHash_t *objsha384;
        byte      *snapshot_server_finished;
    } hashed_hs_msg;

    // point to the negotiated cipher suite, note that the chosen cipher suite might NOT be
    // activated yet
    const struct __tlsCipherSpec_t *chosen_ciphersuite;
    void *decrypt_ctx; // third-party data structure for symmetric decryption.
    void *encrypt_ctx; // third-party data structure for symmetric encryption.

    byte *client_rand;
    byte *server_rand;
    // the read / write key here are used in either handshaking process or application data
    // encryption. It seems impossible to use both.
    byte writeKey[TLS_MAX_BYTES_SYMMETRIC_KEY];
    byte writeIV[TLS_MAX_BYTES_INIT_VEC];
    byte readKey[TLS_MAX_BYTES_SYMMETRIC_KEY];
    byte readIV[TLS_MAX_BYTES_INIT_VEC];
    // in TLS v1.3, per-record nonce (see section 5.3) is derived by 64-bit value (incremented by
    // one for each decrypting / encrypting record message) and IV derived by previous HKDF
    // procedure.
    byte nonce[TLS_MAX_BYTES_INIT_VEC];

    union {
        struct {
            tlsOpaque8b_t hs;
            tlsOpaque8b_t client;
            tlsOpaque8b_t server;
        } hs;
        struct {
            tlsOpaque8b_t mst; // max size : TLS_HS_MASTER_SECRET_BYTES
            tlsOpaque8b_t client;
            tlsOpaque8b_t server;
            tlsOpaque8b_t resumption;
        } app;
    } secret;
    // the pointers below point to starting address of the PSK binder section in different buffer
    // when encoding (but not sent yet) ClientHello, when we update transcript hash with the
    // ClientHello, we can easily seperate the binder section from the entire ClientHello message.
    struct {
        byte  *ext; // point to somewhere in PSK extension item
        word16 len;
    } psk_binder_ptr;
    // list of available PSK scheme (pre-shared key) for key exchange phase of the protocol
    tlsPSK_t **psk_list;
    tlsPSK_t  *chosen_psk;
    // store key exchange result for handshaking message encryption
    void *ephemeralkeylocal;  // chosen key on client side
    void *ephemeralkeyremote; // will import the public value (received from the peer) to this  key
    tlsNamedGrp agreed_keyex_named_grp : 16;
    // AAD (additional authentication data) for symmetric encryption algorithm like AES
    byte aad[TLS_MAX_BYTES_AAD];
    // extra information for symmetric encryption
    struct {
        // indicate that currently processing block is the first fragment of TLSciphertext (if split
        // to multiple packets to transmit)
        byte ct_first_frag : 1;
        // indicate that currently processing block is the final fragment of TLSciphertext, which
        // must contain authentication tag
        byte ct_final_frag : 1;
    } flgs;
} tlsSecurityElements_t;
#pragma pack(pop)

typedef struct __tlsCipherSpec_t { // collect essential information about a cuite suite
    tlsCipherSuiteID ident : 16;   // 16-bit Official cipher ID
    word32 flags; // flags that represent crypto algorithm, chaining mode, and hash function to use
    byte   tagSize; // auth tag size
    byte   keySize;
    byte   ivSize;
    // Init / encryption / decryption function
    tlsRespStatus (*init_fn)(tlsSecurityElements_t *sec, byte isDecrypt);
    tlsRespStatus (*encrypt_fn)(tlsSecurityElements_t *sec, byte *pt, byte *ct, word32 *len);
    tlsRespStatus (*decrypt_fn)(tlsSecurityElements_t *sec, byte *ct, byte *pt, word32 *len);
    tlsRespStatus (*done_fn)(tlsSecurityElements_t *sec);
} tlsCipherSpec_t;

#pragma pack(push, 1)
typedef struct {
    // copied from mqttCtx_t whenever the TLS session is created.
    int cmd_timeout_ms;
    // optional Deterministic Random Bit Generator (DRBG)
    mqttDRBG_t *drbg;
    // for extension: server name indication, TODO, add struct type `mqttServerHost_t`
    // which includes domain name and IP address
    mqttHost_t *server_name;
    // packet buffer
    tlsOpaque16b_t inbuf;     // buffer that store incoming bytes from remote peer
    tlsOpaque16b_t outbuf;    // buffer that store bytes & will be delivered to remote peer
    word16 inlen_decoded;     // number of bytes already received, decrypted, and decoded from inbuf
    word16 inlen_decrypted;   // number of bytes already received, decrypted from inbuf, but haven't
                              // been decoded yet
    word16 inlen_unprocessed; // number of bytes already received from peer, but haven't been
                              // decrypted/decoded yet in inbuf
    word16 inlen_total;       // total number of bytes for current in-flight record message
    word16 outlen_encoded; // number of bytes already encoded to outbuf, but haven't been encrypted
                           // & sent out yet
    word16 outlen_encrypted; // number of bytes already encoded & encrypted to outbuf, but haven't
                             // been sent out yet
    // point to starting address in outbuf.data for currently encoding message, if :
    // * we want to fit multiple small-sized encoded message in the same flight for delivery.
    // * the encoding message needs to be split to multiple out-flight fragments.
    word16 curr_outmsg_start;
    word16 curr_outmsg_len;

    // internally-generated extensions e.g. supported versions, named groups ...etc
    tlsExtEntry_t *exts;
    // for recording length of entire encoding/decoding extension list
    word16 ext_enc_total_len;
    word16 ext_dec_total_len;
    // used to store number of copied bytes for a decoding/encoding extension entry, if the entire
    // entry cannot be copied to current fragment of the in-flight/out-flight message & has to be
    // split to multiple fragments. The MSB of last_ext_entry_xxx_len is used to indicate whether it
    // stores copied bytes for : (1) total size of the given extension list, if bit 15 of
    // last_ext_entry_xxx_len is set (2) currently processing extension entry,   if bit 15 is clear
    word16 last_ext_entry_dec_len;
    word16 last_ext_entry_enc_len;
    // extensive objects that assist in working with underlying system/platform
    void *ext_sysobjs[MQTT_MAX_NUM_EXT_SYSOBJS];
    // for storing everything about key material at key-exchange phase
    tlsKeyEx_t keyex;
    // --- for decoding certificate chain ---
    // client's private key and certificate for 2-way authentication
    void      *client_privkey;
    tlsCert_t *client_cert;
    tlsCert_t *broker_cacert; // CA certificate which signed broker's certificate
    tlsCert_t *peer_certs;    // certificates received from peer
    union {
        // in this TLS implementation, only 24-bit LSB of total_certs is used, 8-bit MSB is reserved
        word32 total_certs;       // number of bytes in peer's certificate chain
        word32 remaining_to_send; // used for sending fragments of client's Certificate,
                                  // CertificateVerify, Finished
        word32 remaining_to_recv; // used for receiving fragments of server's NewSessionTicket
    } nbytes;
    word32 last_cpy_cert_len;  // number of bytes copied from last decrypted inbuf
                               // (a certificate may be split into fragments to transmit)
    tlsSecurityElements_t sec; // necessary elements for building secure connection

    tlsOpaque16b_t app_pt; // point to application-level plaintext buffer to send or receive
    tlsOpaque16b_t client_signed_sig; // signed signature that is ready to send with client's
                                      // CertificateVerify message
    union {
        tlsOpaque8b_t
            session_id; // preserve session ID (max #bytes : 32) during ClientHello, ServerHello
        tlsOpaque8b_t
            cert_req_ctx; // preserve certificate_request_context from server's CertificateRequest
        tlsOpaque8b_t
            finish_verifydata; // verify data that is ready to send with client's Finished message
    } tmpbuf;                  // temperary buffer pointer used in the TLS session

    // if current encoding/decoding record message is too large to fit in one single TCP packet,
    // then we split it to several fragments (smaller packets), and set this flag after first
    // fragment was sent/received. (the first fragment of a record message always contains record
    // header)
    byte num_frags_in; // number of fragments of current in-flight record message
    byte remain_frags_in;
    byte num_frags_out; // number of fragments of current out-flight record message
    byte remain_frags_out;

    tlsVersionCode chosen_tls_ver; // chosen version from either HelloRetryRequest or ServerHello

    tlsContentType   record_type : 8; // record type for current handshake process
    tlsHandshakeType hs_state    : 8; // handshake status

    struct { // temporarily store result since its last operation
        tlsRespStatus last_encode_result;
        // In this MQTT implementation, it is unlikely to send / receive over 256 encrypted record
        // messages for each established TLS session, so only 8-bit counting numbers are applied,
        // which represent number of write (sent) / read (received) encrypted record messages
        // accordingly. These values can be ingredients of deriving nonce to AEAD encryption /
        // decryption function.
        byte          num_enc_recmsg_sent;
        byte          num_enc_recmsg_recv;
        tlsAlertMsg_t alert;
    } log;

    struct {
        // it is set whenever the peer (server) reply with ClientHelloRetry to this client, clear if
        // client receives ServerHello
        byte hello_retry : 2; // possible value of this field : 0, 1, 2,
        // start encryption mode on in-flight / out-flight handshaking message among the connection
        byte hs_tx_encrypt : 1;
        byte hs_rx_encrypt : 1;
        // set if the peer does not run certificate-based verification
        byte omit_client_cert_chk : 1;
        byte omit_server_cert_chk : 1;
        byte hs_server_finish     : 1; // set after Finished message received from server is
                                       // successfully decoded.
        byte hs_client_finish : 1; // set after Finished message on client side is successfully sent
                                   // to the peer
        byte outflight_flush : 1;  // set to force the data in outbuf send out to the peer
        byte new_session_tkt : 1;
        byte key_update      : 1;
    } flgs;
} tlsSession_t;
#pragma pack(pop)

#ifdef __cplusplus
}
#endif
#endif // end of TLS_TYPES_H
