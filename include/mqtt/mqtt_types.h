#ifndef MQTT_TYPEDEF_H
#define MQTT_TYPEDEF_H

#ifdef __cplusplus
extern "C" {
#endif



typedef unsigned char   byte;
typedef unsigned short  word16;
typedef unsigned int    word32;


typedef enum {
    MQTT_DATA_TYPE_NONE = 0,
    MQTT_DATA_TYPE_BYTE  ,
    MQTT_DATA_TYPE_SHORT ,
    MQTT_DATA_TYPE_INT   ,
    MQTT_DATA_TYPE_VAR_INT ,
    MQTT_DATA_TYPE_BINARY,  
    MQTT_DATA_TYPE_STRING  ,
    MQTT_DATA_TYPE_STRING_PAIR  ,
} mqttDataType;



typedef enum {
    MQTT_PACKET_TYPE_RESERVED = 0,
    MQTT_PACKET_TYPE_CONNECT  = 1,
    MQTT_PACKET_TYPE_CONNACK  = 2,
    MQTT_PACKET_TYPE_PUBLISH  = 3,
    MQTT_PACKET_TYPE_PUBACK   = 4,
    MQTT_PACKET_TYPE_PUBRECV  = 5,
    MQTT_PACKET_TYPE_PUBREL   = 6,
    MQTT_PACKET_TYPE_PUBCOMP  = 7,
    MQTT_PACKET_TYPE_SUBSCRIBE = 8,
    MQTT_PACKET_TYPE_SUBACK   = 9,
    MQTT_PACKET_TYPE_UNSUBSCRIBE = 10,
    MQTT_PACKET_TYPE_UNSUBACK = 11,
    MQTT_PACKET_TYPE_PINGREQ  = 12,
    MQTT_PACKET_TYPE_PINGRESP = 13,
    MQTT_PACKET_TYPE_DISCONNECT = 14,
    MQTT_PACKET_TYPE_AUTH     = 15,
} mqttCtrlPktType;



typedef enum {
    MQTT_QOS_0 = 0 ,
    MQTT_QOS_1 = 1 ,
    MQTT_QOS_2 = 2 ,
} mqttQoS;


// identifier used to indicate properties of a MQTT endpoint
typedef enum {
    MQTT_PROP_NONE = 0x00,
    MQTT_PROP_PKT_FMT_INDICATOR = 0x01,
    MQTT_PROP_MSG_EXPIRY_INTVL  = 0x02,
    MQTT_PROP_CONTENT_TYPE      = 0x03,
    MQTT_PROP_RESP_TOPIC        = 0x08,
    MQTT_PROP_CORRELATION_DATA  = 0x09,
    MQTT_PROP_SUBSCRIBE_ID      = 0x0b,
    MQTT_PROP_SESSION_EXPIRY_INTVL = 0x11,
    MQTT_PROP_ASSIGNED_CLIENT_ID   = 0x12,
    MQTT_PROP_SERVER_KEEP_ALIVE    = 0x13,
    MQTT_PROP_AUTH_METHOD       = 0x15,
    MQTT_PROP_AUTH_DATA         = 0x16,
    MQTT_PROP_REQ_PROBLEM_INFO  = 0x17,
    MQTT_PROP_WILL_DELAY_INTVL  = 0x18,
    MQTT_PROP_REQ_RESP_INFO     = 0x19,
    MQTT_PROP_RESP_INFO         = 0x1a,
    MQTT_PROP_SERVER_REF        = 0x1c,
    MQTT_PROP_REASON_STR        = 0x1f,
    MQTT_PROP_RECV_MAX          = 0x21,
    MQTT_PROP_TOPIC_ALIAS_MAX   = 0x22,
    MQTT_PROP_TOPIC_ALIAS       = 0x23,
    MQTT_PROP_MAX_QOS           = 0x24,
    MQTT_PROP_RETAIN_AVAILABLE  = 0x25,
    MQTT_PROP_USER_PROPERTY     = 0x26,
    MQTT_PROP_MAX_PKT_SIZE      = 0x27,
    MQTT_PROP_WILDCARD_SUBS_AVAIL = 0x28,
    MQTT_PROP_SUBSCRIBE_ID_AVAIL  = 0x29,
    MQTT_PROP_SHARE_SUBSCRIBE_AVAIL = 0x2a,
    MQTT_PROP_MAX_ID                = 0x2a,
} mqttPropertyType;


typedef enum {
    // successful operation codes start from here
    MQTT_REASON_SUCCESS = 0x00,
    MQTT_REASON_NORMAL_DISCONNECTION = 0x00,
    MQTT_REASON_GRANTED_QOS_0 = 0x00,
    MQTT_REASON_GRANTED_QOS_1 = 0x01,
    MQTT_REASON_GRANTED_QOS_2 = 0x02,
    MQTT_REASON_DISCONNECT_W_WILL_MSG = 0x04,
    MQTT_REASON_NO_MATCH_SUBS = 0x10,
    MQTT_REASON_NO_SUB_EXIST  = 0x11,
    MQTT_REASON_CNTNU_AUTH    = 0x18,
    MQTT_REASON_REAUTH        = 0x19,
    // error code starts from here
    MQTT_REASON_UNSPECIFIED_ERR = 0x80,
    MQTT_REASON_MALFORMED_PACKET = 0x81,
    MQTT_REASON_PROTOCOL_ERR = 0x82,
    MQTT_REASON_IMPL_SPECIFIC_ERR = 0x83,
    MQTT_REASON_UNSUP_PROTO_VER = 0x84,
    MQTT_REASON_CLIENT_ID_NOT_VALID = 0x85,
    MQTT_REASON_BAD_USER_OR_PASS = 0x86,
    MQTT_REASON_NOT_AUTHORIZED = 0x87,
    MQTT_REASON_SERVER_UNAVAILABLE = 0x88,
    MQTT_REASON_SERVER_BUSY = 0x89,
    MQTT_REASON_BANNED = 0x8A,
    MQTT_REASON_SERVER_SHUTTING_DOWN = 0x8B,
    MQTT_REASON_BAD_AUTH_METHOD = 0x8C,
    MQTT_REASON_KEEP_ALIVE_TIMEOUT = 0x8D,
    MQTT_REASON_SESSION_TAKEN_OVER = 0x8E,
    MQTT_REASON_TOPIC_FILTER_INVALID = 0x8F,
    MQTT_REASON_TOPIC_NAME_INVALID = 0x90,
    MQTT_REASON_PACKET_ID_IN_USE = 0x91,
    MQTT_REASON_PACKET_ID_NOT_FOUND = 0x92,
    MQTT_REASON_RX_MAX_EXCEEDED = 0x93,
    MQTT_REASON_TOPIC_ALIAS_INVALID = 0x94,
    MQTT_REASON_PACKET_TOO_LARGE = 0x95,
    MQTT_REASON_MSG_RATE_TOO_HIGH = 0x96,
    MQTT_REASON_QUOTA_EXCEEDED = 0x97,
    MQTT_REASON_ADMIN_ACTION = 0x98,
    MQTT_REASON_PAYLOAD_FORMAT_INVALID = 0x99,
    MQTT_REASON_RETAIN_NOT_SUPPORTED = 0x9A,
    MQTT_REASON_QOS_NOT_SUPPORTED = 0x9B,
    MQTT_REASON_USE_ANOTHER_SERVER = 0x9C,
    MQTT_REASON_SERVER_MOVED = 0x9D,
    MQTT_REASON_SS_NOT_SUPPORTED = 0x9E,
    MQTT_REASON_CON_RATE_EXCEED = 0x9F,
    MQTT_REASON_MAX_CON_TIME = 0xA0,
    MQTT_REASON_SUB_ID_NOT_SUP = 0xA1,
    MQTT_REASON_WILDCARD_SUB_NOT_SUP = 0xA2,
} mqttReasonCode;



typedef enum{
    MQTT_FIX_HEAD_PKT_FLG_RETAIN = 0x1,
    MQTT_FIX_HEAD_PKT_FLG_QOS_SHIFT = 0x1,
    MQTT_FIX_HEAD_PKT_FLG_QOS_MASK = 0x6,
    MQTT_FIX_HEAD_PKT_FLG_DUPLICATE = 0x8,
} mqttPktFxHeadFlg ;



typedef enum {
    MQTT_CONNECT_FLG_RESERVED       = 0x01,
    MQTT_CONNECT_FLG_CLEAN_START    = 0x02,
    MQTT_CONNECT_FLG_WILL_FLAG      = 0x04,
    MQTT_CONNECT_FLG_WILL_QOS_SHIFT = 3,
    MQTT_CONNECT_FLG_WILL_QOS_MASK  = 0x18,
    MQTT_CONNECT_FLG_WILL_RETAIN    = 0x20,
    MQTT_CONNECT_FLG_PASSWORD       = 0x40,
    MQTT_CONNECT_FLG_USERNAME       = 0x80,
} mqttConnectFlg ;


typedef enum {
    MQTT_CONNACK_FLG_SESSION_PRESENT = 0x01,
} mqttConnackFlg;




// response status used in the functions of this implementation
typedef enum {
    MQTT_RESP_OK = 0,
    MQTT_RESP_OK_IGNOREMORE =  0, // Function succedded, but ignore subsequent payload bytes or properties to send / receive.
    MQTT_RESP_SKIP          = -2, // skip and return immediately from a function, without completion
    MQTT_RESP_ERR           = -3, // other unknown errors
    MQTT_RESP_BUSY          = -4, // busy signal from underlying system platform 
    MQTT_RESP_ERRARGS       = -5, // Wrong arguments on a function call 
    MQTT_RESP_ERRMEM        = -6, // Memory error occurred, e.g. memory leak, requesting space exceeds limit of the system platform
    MQTT_RESP_TIMEOUT       = -7, // Timeout on network connection, or control packet transmission, or no response from underlying system
    MQTT_RESP_INPROG        = -8, // MQTT packet incoming / outgoing transmission hasn't been finished, still in progress.  
    MQTT_RESP_MALFORMED_DATA = -9,  // packet format error 
    MQTT_RESP_NO_NET_DEV     = -10, // cannot find any network device module (e.g. ethernet, wifi)

    MQTT_RESP_ERR_EXCEED_PKT_SZ = -11, // error occurs if the receiving / sending packet size exceeds the limit in system platform or protocol (256MB)
    MQTT_RESP_ERR_TRANSMIT      = -12, // data transmission error through a network connection
    MQTT_RESP_ERR_CTRL_PKT_TYPE = -13, // MQTT control packet type error
    MQTT_RESP_ERR_CTRL_PKT_ID   = -14, // packet ID error
    MQTT_RESP_ERR_CONN          = -15, // Connection error (failed) to MQTT broker 
    MQTT_RESP_ERR_SECURE_CONN   = -16, // secure connection error, failed to start a session of secure connection
    MQTT_RESP_ERR_PROP          = -17, // peoperty error when encoding / decoding data bytes
    MQTT_RESP_ERR_PROP_REPEAT   = -18, // duplicate property present in a give property list (for few properties it doesn't matter)
    MQTT_RESP_ERR_INTEGRITY     = -19, // integrity error, used when a given C struct variable lacks some data which must be prepared.
    MQTT_RESP_INVALID_TOPIC     = -20, // error occurs when a topic string is incorrectly formed in SUBSCRIBE or PUBLISH packet
} mqttRespStatus;



typedef enum {
    MQTT_FN_DISABLE  = 0, 
    MQTT_FN_ENABLE   = 1, 
} mqttFnEn;


typedef enum {
    MQTT_HASH_OPERATION_INIT,
    MQTT_HASH_OPERATION_UPDATE,
    MQTT_HASH_OPERATION_DONE,
} mqttHashOpsType;


typedef enum {
    MQTT_HASH_SHA256,
    MQTT_HASH_SHA384,
} mqttHashLenType;


typedef struct {
    word16  len;
    byte   *data;
} mqttStr_t;



// property list
typedef struct __mqttProp {
    struct __mqttProp *next;
    mqttPropertyType  type;
    union {
        byte         u8;
        word16       u16;
        word32       u32;
        mqttStr_t    str;
        mqttStr_t    strpair[2];
    } body;
} mqttProp_t;



typedef struct {
    // topic string that will be subscribe / unsubscribed
    mqttStr_t    filter;
    mqttQoS      qos;
    byte         reason_code;
    byte         sub_id; // subscription ID
    word16       alias;
} mqttTopic_t;



// used only when encoding packet to send out
typedef struct {
    word32    remain_len;
    word32    props_len;
} mqttPktLenSet_t;



typedef struct __mqttMsg {
    word16            packet_id;
    mqttProp_t       *props;
    byte              retain;
    byte              duplicate;
    mqttQoS           qos;
    mqttStr_t         topic;
    // total length of the application specific data 
    word32            app_data_len; 
    byte             *buff; // to store application specific data
    mqttPktLenSet_t   pkt_len_set;
} mqttMsg_t;



// denote every single MQTT connection 
typedef struct __mqttConn {
    word16            keep_alive_sec;
    // optional properties for this MQTT connection
    mqttProp_t       *props;
    mqttStr_t         client_id;
    //  Optional login 
    mqttStr_t         username;
    mqttStr_t         password;
    // message structure for last will testament
    mqttMsg_t         lwt_msg;
    byte              protocol_lvl; // it will be 5 for MQTT v5.0
    struct {
        byte          clean_session: 1;
        byte          will_enable:   1;
    } flgs;
    mqttPktLenSet_t   pkt_len_set;
} mqttConn_t;

// here we allow users to add any third-party crypto library they want to use,
// but the hash functions from the chosen third-party library MUST have the same
// structure as shown in following :
typedef int (*mqttHashInitFp)(MGTT_CFG_HASH_STATE_STRUCT *md);

typedef int (*mqttHashUpdateFp)(MGTT_CFG_HASH_STATE_STRUCT *md, const byte *in, unsigned long inlen);

typedef int (*mqttHashDoneFp)(MGTT_CFG_HASH_STATE_STRUCT *md, byte *out);

typedef struct {
    mqttStr_t         V;
    mqttStr_t         C;
    mqttStr_t         Vtmp;
    // pointers to hash function integration
    MGTT_CFG_HASH_STATE_STRUCT  md;
    struct {
        mqttHashInitFp        init;
        mqttHashUpdateFp      update;
        mqttHashDoneFp        done;
    } mthd;
    // number of bytes produced after every single hash "done" operation completes.
    // (SP 800-90A Rev.1, section 10.1, "outlen" in Table 2)
    word16            nbytes_outlen;
} mqttDrbgHash_t; // the hash structure particularly applied to DRBG


typedef struct {
    mqttDrbgHash_t  hash;
    mqttStr_t       entropy;
    // once user calls PRNG function: mqttUtilPRNG() running the entire DRBG algorithm, and generates random byte sequence.
    // the generated byte sequence can be preserved as cache in case the current function call does ONLY need small portion
    // of the generated byte sequence, this means part of the generated byte sequence can be used for next few PRNG function
    // calls. Also when the all bytes of cache are read once, users MUST run the entire DRBG algorithm again
    mqttStr_t       cache;
    word16          cache_rd_ptr; // read pointer to outbuf
    byte            reseed_cnt;
    byte            reseed_intvl;
} mqttDRBG_t;



// [IMPORTANT NOTE]
// if developers integrate this MQTT implementation with any third-party math library.
// the chosen math library must define the same structure as shwon below for multiple-bytes integer
// the naming/data type of each struct member, and the order of the members should be the same.
typedef struct {
  word32        used;    // how many digits used
  word32        alloc;   // how many digits allocated
  byte          sign;    // sign of this quantity
  word16       *dp;      // point to the digits themselves
} multiBint_t;


#ifdef __cplusplus
}
#endif
#endif // end of  MQTT_TYPEDEF_H

