// -------------------------------------------------------------------
// Data structures, high-level API functions related to MQTT protocol
// implementation, will be declared in this header file.
// -------------------------------------------------------------------
#ifndef MQTT_CLIENT_CONN_H
#define MQTT_CLIENT_CONN_H

#ifdef __cplusplus
extern "C" {
#endif

typedef mqttRespStatus (* mqttAuthSetupCallback_t)( const mqttStr_t *auth_data_in,  mqttStr_t *auth_data_out,
                                                    mqttStr_t *reason_str_out );

typedef mqttRespStatus (* mqttAuthFinalCallback_t)( mqttStr_t *auth_data_sent,  mqttStr_t *auth_reason_out );



// context for MQTT operations
typedef struct __mqttCtx{
    byte       *tx_buf;
    word32      tx_buf_len;
    byte       *rx_buf;
    word32      rx_buf_len;

    mqttStr_t   *broker_host; // can be either IP address or host name
    word16       broker_port;

    int              cmd_timeout_ms;
    mqttCtrlPktType  last_recv_cmdtype;
    mqttCtrlPktType  last_send_cmdtype;
    // callback for authentication method,  users must implement their authentication
    // method, pass their data to the output of this callback.
    mqttAuthSetupCallback_t   eauth_setup_cb;
    mqttAuthFinalCallback_t   eauth_final_cb;

    union {
        mqttConn_t           conn;
        mqttPktDisconn_t     disconn;
        // published message, in some cases, it's possible that this client device publishes a message
        // meanwhile receiving other messages with certain types of topics it subscribed previously.
        mqttMsg_t            pub_msg;
        mqttPktPubResp_t     pub_resp; // can be either mqttPktPuback_t or mqttPktPubrecv_t 
        // subscribe / unsubscribe to a topic(s)        
        mqttPktSubs_t        subs;
        mqttPktUnsubs_t      unsubs;
        mqttAuth_t           auth;
    } send_pkt;
    // extract received message to this member, TODO: test 
    union {
        mqttPktHeadConnack_t    connack;
        mqttPktDisconn_t        disconn; // it's likely to receive DISCONNECT from server due to some protocol error made by this client.
        mqttMsg_t               pub_msg;
        mqttPktPubResp_t        pub_resp; // can be either mqttPktPuback_t or mqttPktPubrecv_t
        // acknowledgement of subscribe / unsubscribe 
        mqttPktSuback_t         suback;
        mqttPktUnsuback_t       unsuback;
        mqttAuth_t              auth;
    } recv_pkt;
    union {
        mqttPktPubResp_t     pub_resp; // can be either mqttPktPubcomp_t or  mqttPktPubrel_t 
    } send_pkt_qos2;
    union {
        mqttPktPubResp_t     pub_resp; // can be either mqttPktPubcomp_t or  mqttPktPubrel_t 
    } recv_pkt_qos2;
    // ---------- properties / flags recorded for each MQTT session ----------
    word32           send_pkt_maxbytes; // determined by the server that sends CONNACK to this client
    word16           recv_topic_alias_max; // the greatest allowable integer that can represent topic alias on client side
    word16           send_topic_alias_max; // the greatest allowable integer that can represent topic alias on server side
    word16           keep_alive_sec;       // keep alive (in seconds) agreed on both client and server
    mqttQoS          max_qos_server:4;     // max acceptable QoS value on server side
    mqttQoS          max_qos_client:4;     // max acceptable QoS value on client side
    struct {
        byte    req_probm_info:1;
        byte    req_resp_info:1;
        byte    retain_avail:1;
        byte    wildcard_subs_avail:1;
        byte    subs_id_avail:1;
        byte    shr_subs_avail:1;
        byte    recv_mode:1; // set when decoding received packet, clear when calling API functions to encode & send a new packet.
    } flgs;
    struct {
        mqttReasonCode    reason_code;  // 8-bit reason code in MQTT protocol
        mqttPropertyType  prop_id:8;      // 8-bit property ID in MQTT protocol
    } err_info;
    // extended objects that can assist in underlying system / platform implementation (optional)
    void*        ext_sysobjs[2];
} mqttCtx_t;



// ----- Application Interface for MQTT client code operations -----

// initialize / de-initialize the global data structure  mqttCtx_t
mqttRespStatus  mqttClientInit( mqttCtx_t **mctx, int cmd_timeout_ms );

mqttRespStatus  mqttClientDeinit( mqttCtx_t *mctx );

// encodes & sends MQTT CONNECT packet, and waits for CONNACK packet
// this is a blocking function 
mqttRespStatus  mqttSendConnect( mqttCtx_t *mctx, mqttPktHeadConnack_t **connack_out );

// encodes & sends PUBLISH packet, for QoS > 0, this function waits for
// publish response packets, 
//     If QoS level = 1 then will wait for PUBLISH_ACK.
//     If QoS level = 2 then will wait for PUBLISH_REC then send
//         PUBLISH_REL and finally wait for PUBLISH_COMP.
// return structure:
//     For QoS level = 0, pubresp_out will be NULL
//     For QoS level = 1, pubresp_out will be the structure containing information of PUBACK
//     For QoS level = 2, pubresp_out will be the structure containing information of PUBCOMP
mqttRespStatus  mqttSendPublish( mqttCtx_t *mctx, mqttPktPubResp_t **pubresp_out );

// send publish response packet
mqttRespStatus  mqttSendPubResp( mqttCtx_t *mctx, mqttCtrlPktType  cmdtype, mqttPktPubResp_t **pubresp_out );

// encodes & sends MQTT SUBSCRIBE packet, then waits for SUBACK packet
mqttRespStatus  mqttSendSubscribe( mqttCtx_t *mctx, mqttPktSuback_t  **suback_out );

// encodes & sends MQTT UNSUBSCRIBE packet, waits for UNSUBACK packet
mqttRespStatus  mqttSendUnsubscribe( mqttCtx_t *mctx, mqttPktUnsuback_t  **unsuback_out );

// encodes & sends MQTT PING request packet, and waits for PING response packet, TODO: implement this function
mqttRespStatus  mqttSendPingReq( mqttCtx_t *mctx );

// encodes & sends MQTT AUTH packet if client enabled enhanced authentication
// by adding properties "Authentication method" / "Authentication Data" to
// CONNECT packet, then client will send this AUTH packet and waits for CONNACK
// packet with authentication success status.
mqttRespStatus  mqttSendAuth( mqttCtx_t *mctx );

// encodes & sends MQTT DISCONNECT packet, then client must closse the TCP
// connection (no need to wait for broker's response).
mqttRespStatus  mqttSendDisconnect( mqttCtx_t *mctx );



// create new property node to a given list, return the added item
mqttProp_t*  mqttPropertyCreate( mqttProp_t **head );

// delete/free the allocated space to entire list, start from the given head
void         mqttPropertyDel( mqttProp_t *head );

// check content of the given property list
mqttRespStatus  mqttPropErrChk( mqttCtx_t *mctx, mqttCtrlPktType cmdtype, mqttProp_t *prop_head );



// waits for receiving packets with given type, it could be incoming
// PUBLISH packet, or acknowledgement of PUBLISH / SUBSCRIBE / UNSUBSCRIBE
// packet the client has sent.
mqttRespStatus  mqttClientWaitPkt( mqttCtx_t *mctx, mqttCtrlPktType wait_cmdtype, word16 wait_packet_id, void **pp_recv_out );




#ifdef __cplusplus
}
#endif
#endif // end of MQTT_CLIENT_CONN_H

