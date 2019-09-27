#ifndef MQTT_PACKET_H
#define MQTT_PACKET_H

#ifdef __cplusplus
extern "C" {
#endif

#define MQTT_CONN_PROTOCOL_NAME_LEN  4

#define MQTT_CONN_PROTOCOL_NAME      "MQTT"

#define MQTT_CONN_PROTOCOL_LEVEL_5   5 // for MQTT v5.0 

#define MQTT_CONN_PROTOCOL_LEVEL     MQTT_CONN_PROTOCOL_LEVEL_5

// MQTT protocol defines max bytes of packet data does NOT exceed 2^28 bytes --> 256 MBytes
#define MQTT_PROTOCOL_PKT_MAXBYTES  0x10000000

// check allowable max packet size
#if defined(MQTT_PLATFORM_PKT_MAXBYTES)
    #if (MQTT_PROTOCOL_PKT_MAXBYTES >= MQTT_PLATFORM_PKT_MAXBYTES)
        #define  MQTT_RECV_PKT_MAXBYTES   MQTT_PLATFORM_PKT_MAXBYTES
    #else
        #error  "MQTT_PROTOCOL_PKT_MAXBYTES must NOT be smaller than defined MQTT_PLATFORM_PKT_MAXBYTES, recheck your configuration."
    #endif
#else
    #define  MQTT_RECV_PKT_MAXBYTES   MQTT_PROTOCOL_PKT_MAXBYTES 
#endif // end of MQTT_RECV_PKT_MAXBYTES


// denote first few bytes of fixed header in a packet.
typedef struct  {
    // [7:4] control type
    // [3:0] flags that dedicates to the corresponding control type.
    byte  type_flgs;
    // 2nd to 5th byte are remaining length, it's encoded in variable bytes,
    // not all of them will be used, it depends on continuation bit of each
    // byte
    byte  remain_len[ MQTT_PKT_MAX_BYTES_REMAIN_LEN ];
} mqttPktFxHead_t;



// variable-sized header in CONNECT packet
typedef struct {
    byte      protocol_len[ MQTT_DSIZE_STR_LEN ];
    char      protocol_name[ MQTT_CONN_PROTOCOL_NAME_LEN ];
    byte      protocol_lvl; // it will be 5 for MQTT v5.0
    byte      flags; // filled with  mqttConnectFlg 
    word16    keep_alive;  
} mqttPktHeadConnect_t ;


// variable-sized header in CONNACK packet
typedef struct {
    byte        flags; // filled with mqttConnackFlg
    byte        reason_code;
    mqttProp_t *props;
} mqttPktHeadConnack_t ;


// variable-sized header in publish response packet e.g. PUBACK, PUBREC, PUBREL, PUBCOMP
//
// when a client sends packet PUBLISH (step #1) with different QoS levels ...
// If QoS = 0: No response 
// If QoS = 1: Expect response packet with PUBACK 
// If QoS = 2: Expect response packet with PUBREC (step #2)
// 
// Packet ID is required if QoS is 1 or 2 
// extra steps for Qos = 2:
// step #3 : after receiving PUBREC,  client sends PUBREL with the same Packet ID
//           (as shown in PUBLISH) to broker.
// step #4 : Expect response packet with type PUBCOMP, to ensure subscriber received 
//           the published message.
typedef struct {
    word16            packet_id; 
    mqttProp_t       *props;
    byte              reason_code;
    mqttPktLenSet_t   pkt_len_set;
} mqttPktPubResp_t ;

typedef mqttPktPubResp_t mqttPktPuback_t  ;
typedef mqttPktPubResp_t mqttPktPubrecv_t ;
typedef mqttPktPubResp_t mqttPktPubrel_t  ;
typedef mqttPktPubResp_t mqttPktPubcomp_t ;


// essential data in SUBSCRIBE packet
typedef struct {
    word16            packet_id; 
    // packet ID followed by continuous topic list with QoS to subscribe
    word16            topic_cnt; 
    mqttTopic_t      *topics;
    mqttProp_t       *props;
    mqttPktLenSet_t   pkt_len_set;
} mqttPktSubs_t;



typedef struct {
    word16        packet_id; 
    mqttProp_t   *props;
    // a list of reason codes for all topics we want to subscribe
    byte         *return_codes; 
} mqttPktSuback_t ;


// UNSUBSCRIBE packet format
typedef mqttPktSubs_t  mqttPktUnsubs_t;

// UNSUBACK packet format
typedef mqttPktSuback_t mqttPktUnsuback_t ; 

// DISCONNECT packet format
typedef struct {
    mqttProp_t        *props;
    byte               reason_code;
    mqttPktLenSet_t    pkt_len_set;
} mqttPktDisconn_t ;


// early declaration
struct __mqttCtx ;
struct __mqttConn;
struct __mqttMsg ;

// AUTH packet format
typedef mqttPktDisconn_t mqttAuth_t; 


// ----- Application Interface for MQTT client code operations -----
// interface to read/write packet data
mqttRespStatus  mqttPktRead(  struct __mqttCtx *mctx, byte *buf, word32 buf_max_len,  word32 *copied_len );
mqttRespStatus  mqttPktWrite( struct __mqttCtx *mctx, byte *buf, word32 buf_len );

// element encoders / decoders
// 16-bit number from/to consecutive given 2 bytes
word32 mqttDecodeWord16( byte *buf , word16 *value );
word32 mqttEncodeWord16( byte *buf , word16  value );

// 32-bit number from/to consecutive given 4 bytes
word32 mqttDecodeWord32( byte *buf , word32 *value );
word32 mqttEncodeWord32( byte *buf , word32  value );

// encode/decode string, with string length ahead
word32 mqttDecodeStr( byte *buf, byte        *str, word16  *strlen );
word32 mqttEncodeStr( byte *buf, const byte  *str, word16   strlen );

// encode/decode variable-bytes number
word32 mqttDecodeVarBytes( const byte *buf, word32 *value );
word32 mqttEncodeVarBytes(       byte *buf, word32  value );

// encode/decode property for certain types of packets
int  mqttDecodeProps( byte *buf, mqttProp_t **props, word32  props_len );
int  mqttEncodeProps( byte *buf, mqttProp_t  *props );

int  mqttGetPktLenConnect ( mqttConn_t *conn, word32 max_pkt_sz );
int  mqttGetPktLenPublish ( mqttMsg_t  *msg, word32 max_pkt_sz );
int  mqttGetPktLenPubResp ( mqttPktPubResp_t *resp, word32 max_pkt_sz );
int  mqttGetPktLenSubscribe ( mqttPktSubs_t *subs, word32 max_pkt_sz );
int  mqttGetPktLenUnsubscribe ( mqttPktUnsubs_t *unsubs, word32 max_pkt_sz );
int  mqttGetPktLenDisconn ( mqttPktDisconn_t *disconn, word32 max_pkt_sz );
int  mqttGetPktLenAuth ( mqttAuth_t *auth, word32 max_pkt_sz );

// encode/decode  different types of MQTT packet 
int  mqttDecodePktConnack( byte *rx_buf, word32 rx_buf_len,  mqttPktHeadConnack_t *connack );
int  mqttDecodePktPublish( byte *rx_buf, word32 rx_buf_len, struct __mqttMsg *msg );
int  mqttDecodePktPubResp( byte *rx_buf, word32 rx_buf_len, mqttPktPubResp_t *resp, mqttCtrlPktType cmdtype );
int  mqttDecodePktSuback( byte *rx_buf, word32 rx_buf_len, mqttPktSuback_t *suback );
int  mqttDecodePktUnsuback( byte *rx_buf, word32 rx_buf_len, mqttPktUnsuback_t *unsuback );
int  mqttDecodePktDisconn( byte *rx_buf,  word32 rx_buf_len, mqttPktDisconn_t *disconn );
int  mqttDecodePktPing( byte *rx_buf, word32 rx_buf_len );
int  mqttDecodePktAuth( byte *rx_buf, word32 rx_buf_len, mqttAuth_t *auth );

int  mqttEncodePktConnect( byte *tx_buf, word32 tx_buf_len, mqttConn_t  *conn );
int  mqttEncodePktPublish( byte *tx_buf, word32 tx_buf_len, struct __mqttMsg  *msg );
int  mqttEncodePktPubResp( byte *tx_buf, word32 tx_buf_len, mqttPktPubResp_t *resp, mqttCtrlPktType cmdtype );
int  mqttEncodePktSubscribe( byte *tx_buf, word32 tx_buf_len, mqttPktSubs_t *subs );
int  mqttEncodePktUnsubscribe( byte *tx_buf, word32 tx_buf_len, mqttPktUnsubs_t *unsubs );
int  mqttEncodePktDisconn( byte *tx_buf, word32 tx_buf_len, mqttPktDisconn_t *disconn );
int  mqttEncodePktPing( byte *tx_buf, word32 tx_buf_len );
int  mqttEncodePktAuth( byte *tx_buf, word32 tx_buf_len, mqttAuth_t *auth );

// internally assign packet ID for PUBLISH / SUBSCRIBE / UNSUBSCRIBE packet
word16  mqttGetPktID( void );

// decode the received packet, it will call other decode functions according
// to the type of received packet.
mqttRespStatus   mqttDecodePkt( struct __mqttCtx *mctx, byte *buf, word32 buf_len, mqttCtrlPktType   cmdtype, void **p_decode, word16 *recv_pkt_id );


#ifdef __cplusplus
}
#endif
#endif // end of MQTT_PACKET_H

