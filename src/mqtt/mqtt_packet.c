#include "mqtt_include.h"

extern const mqttDataType mqttQueryPropDataType[];

static word16 __mqtt_global_packet_id = 0;



word32 mqttEncodeVarBytes( byte *buf, word32  value )
{
    word32  len = 0;
    byte    enc_val = 0; // encoded part of value
    const   byte    continuation_bit = 0x80;
    do {
        enc_val   = value & 0x7f;
        value   >>= 7;
        if( value > 0 ){
            enc_val |= continuation_bit;
        }
        if(buf != NULL) {
            buf[len] = enc_val;
        }
        len++;
    } while( value > 0 ) ; // end of while-loop
    return  len;
} // end of mqttEncodeVarBytes




word32 mqttDecodeVarBytes(const byte *buf, word32 *value )
{
    word32  val = 0;
    word16  idx = 0;
    byte    enc_val = 0; 
    const   byte  continuation_bit = 0x80;
    do {
        enc_val  = buf[idx];
        val     |= (enc_val & 0x7f) << (idx * 7);
        idx++;
    } while((enc_val & continuation_bit) != 0x0);
    *value = val;
    return  idx;
} // end of mqttDecodeVarBytes




word32 mqttEncodeWord16( byte *buf , word16 value )
{
    if(buf != NULL){
        buf[0] = value >> 8; 
        buf[1] = value &  0xff; 
    }
    // return number of bytes used to store the encoded value
    return  (word32)2; 
} // end of mqttEncodeWord16




word32 mqttDecodeWord16( byte *buf , word16 *value )
{
    if((buf != NULL) && (value != NULL)) {
        *value  =  buf[1]; 
        *value |=  buf[0] << 8 ;
    }
    return  (word32)2; 
} // end of mqttDecodeWord16




word32 mqttEncodeWord32( byte *buf , word32  value )
{
    if(buf != NULL){
        buf[0] =  value >> 24; 
        buf[1] = (value >> 16) & 0xff; 
        buf[2] = (value >> 8 ) & 0xff; 
        buf[3] =  value &  0xff; 
    }
    // return number of bytes used to store the encoded value
    return  (word32)4;
} // end of mqttEncodeWord32




word32 mqttDecodeWord32( byte *buf , word32 *value )
{
    if((buf != NULL) && (value != NULL)) {
        *value  = buf[3]; 
        *value |= buf[2] << 8  ;
        *value |= buf[1] << 16 ;
        *value |= buf[0] << 24 ;
    }
    return  (word32)4; 
} // end of mqttDecodeWord32




word32 mqttEncodeStr( byte *buf, const byte   *str, word16   strlen )
{
    word32  len  = 0;
    len = mqttEncodeWord16( buf, strlen );
    if((buf != NULL) && (str != NULL)){
        buf += len;
        XMEMCPY( buf, str, strlen );
    }
    len += strlen;
    return  len;
} // end of mqttEncodeStr




word32 mqttDecodeStr( byte *buf, byte *str, word16 *strlen )
{
    word32  len  = 0;
    if(buf != NULL && strlen != NULL) {
        len    = mqttDecodeWord16( buf, strlen );
        if(str != NULL) {  //// *pstr  = &buf[len];
            XMEMCPY( str, &buf[len], *strlen );
        }
        len   += *strlen;
    }
    return  len;
} // end of mqttDecodeStr





int mqttEncodeProps( byte *buf, mqttProp_t *props )
{
    mqttProp_t *curr_prop   = NULL;
    word32      total_len   = 0;
    word32      len         = 0;
    for( curr_prop = props; curr_prop != NULL ; curr_prop = curr_prop->next ) 
    {
        // get property type (ID code)
        len        = mqttEncodeVarBytes( buf, (word32)curr_prop->type );
        total_len += len;
        if(buf != NULL) { buf += len; }
        // get length (number of bytes) of each property
        switch( mqttQueryPropDataType[curr_prop->type] )
        {
            case MQTT_DATA_TYPE_BYTE         : 
                len = 1;
                if(buf != NULL){ *buf  = curr_prop->body.u8; }
                break;
            case MQTT_DATA_TYPE_SHORT        :
                len = mqttEncodeWord16( buf, curr_prop->body.u16 );
                break;
            case MQTT_DATA_TYPE_INT          : 
                len = mqttEncodeWord32( buf, curr_prop->body.u32 );
                break;
            case MQTT_DATA_TYPE_VAR_INT      :
                len = mqttEncodeVarBytes( buf, curr_prop->body.u32 );
                break;
            case MQTT_DATA_TYPE_BINARY       : 
            case MQTT_DATA_TYPE_STRING       :
                len = mqttEncodeStr( buf, (const byte *)curr_prop->body.str.data,  curr_prop->body.str.len );
                break;
            case MQTT_DATA_TYPE_STRING_PAIR  :
                len  = mqttEncodeStr( buf, (const byte *)curr_prop->body.strpair[0].data,  curr_prop->body.strpair[0].len );
                if(buf != NULL){ buf  += len; }
                total_len += len;
                len  = mqttEncodeStr( buf, (const byte *)curr_prop->body.strpair[1].data,  curr_prop->body.strpair[1].len );
                break;
            default:
                len = 0;
                break;
        } // end of switch-case statement

        if(buf != NULL){ buf  += len; }
        total_len += len;
    } // end of for-loop

    return  total_len;
} // end of mqttEncodeProps





int mqttDecodeProps( byte *buf, mqttProp_t **props , word32  props_len )
{
    mqttProp_t *curr_prop  = NULL;
    word32      copied_len = 0;
    word32      len ;
    word16      tmp ;

    if((buf == NULL) || (props == NULL)){
        return MQTT_RESP_ERRARGS;
    }
    while(props_len > 0)
    {   // create new empty node to the given property list.
        curr_prop = mqttPropertyCreate( props );
        // no property item available, we skip rest of property bytes that hasn't been copied.
        if(curr_prop == NULL) { return MQTT_RESP_ERRMEM; }
        // first byte of each property must represent the type
        len           = mqttDecodeVarBytes((const byte *)buf, (word32 *)&curr_prop->type );
        props_len    -= len;
        copied_len   += len;
        buf          += len;
        switch( mqttQueryPropDataType[curr_prop->type] )
        {
            case MQTT_DATA_TYPE_BYTE         : 
                len  = 1;
                curr_prop->body.u8 = *buf;
                break;
            case MQTT_DATA_TYPE_SHORT        :
                len = mqttDecodeWord16( buf, &curr_prop->body.u16 );
                break;
            case MQTT_DATA_TYPE_INT          : 
                len = mqttDecodeWord32( buf, &curr_prop->body.u32 );
                break;
            case MQTT_DATA_TYPE_VAR_INT      :
                len = mqttDecodeVarBytes( (const byte *)buf, &curr_prop->body.u32 );
                break;
            case MQTT_DATA_TYPE_BINARY       : 
            case MQTT_DATA_TYPE_STRING       :
            {
                tmp  = 0;
                mqttDecodeStr( buf, NULL,  &tmp );
                curr_prop->body.str.len  = tmp;
                curr_prop->body.str.data = (byte *) XMALLOC( sizeof(byte) * tmp );
                len = mqttDecodeStr( buf, curr_prop->body.str.data, &tmp );
                break;
            }
            case MQTT_DATA_TYPE_STRING_PAIR  :
            {
                tmp  = 0;
                mqttDecodeStr( &buf[0], NULL, &tmp );
                curr_prop->body.strpair[0].len  = tmp;
                curr_prop->body.strpair[0].data = (byte *) XMALLOC( sizeof(byte) * tmp );
                len  = mqttDecodeStr( &buf[0], curr_prop->body.strpair[0].data,  &curr_prop->body.strpair[0].len );

                mqttDecodeStr( &buf[len], NULL, &tmp );
                curr_prop->body.strpair[1].len  = tmp;
                curr_prop->body.strpair[1].data = (byte *) XMALLOC( sizeof(byte) * tmp );
                len += mqttDecodeStr( &buf[len], curr_prop->body.strpair[1].data,  &curr_prop->body.strpair[1].len );
                break;
            }
            case MQTT_DATA_TYPE_NONE:
                len = 0;
                break;
            default: // treat as decode error
                return MQTT_RESP_ERR_PROP;
        } // end of switch-case statement
        props_len    -= len;
        copied_len   += len;
        buf          += len;
    } // end of loop
    return  copied_len;
} // end of mqttDecodeProps


word16  mqttGetPktID( void )
{ // TODO: set up semaphore for multithreading case
    __mqtt_global_packet_id = 1 + (__mqtt_global_packet_id) % 0xffff;
    return __mqtt_global_packet_id;
} // end of mqttGetPktID
    


static word32 mqttEncodeFxHeader( byte *tx_buf, word32 tx_buf_len, word32 remain_len, 
                                  mqttCtrlPktType cmdtype, byte retain, byte qos, byte duplicate )
{
    word32  len = 0;
    mqttPktFxHead_t  *header = (mqttPktFxHead_t *) tx_buf;
    header->type_flgs  = 0;
    MQTT_CTRL_PKT_TYPE_SET( header->type_flgs, cmdtype );
    header->type_flgs |= (duplicate & 0x1) << 3 ;
    header->type_flgs |= (qos       & 0x3) << 1 ;
    header->type_flgs |= (retain    & 0x1) << 0 ;
    len += mqttEncodeVarBytes( &header->remain_len[0], remain_len );
    len  = len + 1; 
    return  len;
} // end of  mqttEncodeFxHeader



static word32 mqttDecodeFxHeader( byte *rx_buf, word32 rx_buf_len, word32 *remain_len, 
                                  mqttCtrlPktType cmdtype, byte *retain, byte *qos, byte *duplicate )
{
    const    mqttPktFxHead_t  *header = (mqttPktFxHead_t *) rx_buf;
    word32   len = 0;
    word32   _remain_len ;

    if(MQTT_CTRL_PKT_TYPE_GET(header->type_flgs) != cmdtype) {
        return len;
    }
    if(retain != NULL) {    *retain    = (header->type_flgs >> 0) & 0x1; }
    if(qos != NULL) {       *qos       = (header->type_flgs >> 1) & 0x3; }
    if(duplicate != NULL) { *duplicate = (header->type_flgs >> 3) & 0x1; }
    len += 1;
    len += mqttDecodeVarBytes( &header->remain_len[0], &_remain_len );
    if(remain_len != NULL) { *remain_len = _remain_len; }
    return  len;
} // end of mqttDecodeFxHeader



int  mqttGetPktLenConnect ( mqttConn_t *conn, word32 max_pkt_sz )
{
    uint8_t  head_len    = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    if(conn == NULL) { return MQTT_RESP_ERRARGS; }
    // size of variable header in CONNECT packet, should be 10 bytes in MQTT v5.0
    remain_len += sizeof(mqttPktHeadConnect_t); 
    // size of all properties in the header of this CONNECT packet
    props_len   =  mqttEncodeProps( NULL, conn->props );
    remain_len +=  props_len;
    // number of variable bytes to store "property length"
    remain_len += mqttEncodeVarBytes(NULL, props_len);
    // length of client identifier in CONNECT payload section
    remain_len += MQTT_DSIZE_STR_LEN + conn->client_id.len ; 
    // check whether will message is added
    if(conn->flgs.will_enable != 0) {
        mqttMsg_t   *lwtmsg  = &conn->lwt_msg; 
        // size of the will properties. 
        // TODO: figure out where to correctly add will properties : lwtmsg->props 
        word32 lwt_props_len = mqttEncodeProps( NULL,  lwtmsg->props );
        lwtmsg->pkt_len_set.props_len = lwt_props_len;
        remain_len += lwt_props_len;
        // number of variable bytes to store "property length"
        remain_len += mqttEncodeVarBytes(NULL, lwt_props_len);
        // length of will topic 
        remain_len += MQTT_DSIZE_STR_LEN + lwtmsg->topic.len ;
        // length of will payload
        remain_len += MQTT_DSIZE_STR_LEN + lwtmsg->app_data_len;
    }
    if(conn->username.data != NULL) {
        remain_len += MQTT_DSIZE_STR_LEN + conn->username.len ; 
    }
    if(conn->password.data != NULL) {
        remain_len += MQTT_DSIZE_STR_LEN + conn->password.len ; 
    }
    head_len  = mqttEncodeVarBytes(NULL, remain_len);
    head_len += 1;
    if((remain_len + head_len) > max_pkt_sz) {
        return MQTT_RESP_ERR_EXCEED_PKT_SZ ;
    }
    if((remain_len + head_len) > MQTT_RECV_PKT_MAXBYTES) {
        return MQTT_RESP_ERRMEM;
    } // report error because there might not be sufficient memory space to allocate.
    conn->pkt_len_set.remain_len = remain_len;
    conn->pkt_len_set.props_len  = props_len;
    return (remain_len + head_len);
} // end of mqttGetPktLenConnect



int  mqttGetPktLenPublish( mqttMsg_t *msg, word32 max_pkt_sz )
{
    uint8_t  head_len    = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    if(msg == NULL) { return  MQTT_RESP_ERRARGS; }
    if((msg->topic.data==NULL) || (msg->topic.len < 1)) {
        return  MQTT_RESP_ERRARGS; // topic is a must when publishing message
    }
    // number of bytes taken to encode topic string
    if(msg->qos > MQTT_QOS_0 && msg->packet_id > 0) {
        // when QoS > 0, packet ID must be non-zero 16-bit number
        remain_len += 2; // 2 bytes for packet ID
    }
    else if( msg->qos == MQTT_QOS_0 && msg->packet_id == 0) {}
    else {
        return  MQTT_RESP_ERR_CTRL_PKT_ID;
    }
    remain_len += MQTT_DSIZE_STR_LEN + msg->topic.len ;
    // size of all properties in the PUBLISH packet
    props_len   =  mqttEncodeProps( NULL, msg->props );
    remain_len +=  props_len;
    // number of variable bytes to store "property length"
    remain_len += mqttEncodeVarBytes(NULL, props_len);
    // length of payload -- application specific data 
    remain_len += msg->app_data_len;
    head_len  = mqttEncodeVarBytes(NULL, remain_len);
    head_len += 1;
    if((remain_len + head_len) > max_pkt_sz) { 
        return MQTT_RESP_ERR_EXCEED_PKT_SZ ;
    }
    if((remain_len + head_len) > MQTT_RECV_PKT_MAXBYTES) {
        return MQTT_RESP_ERRMEM;
    } // report error because there might not be sufficient memory space to allocate.
    msg->pkt_len_set.remain_len = remain_len;
    msg->pkt_len_set.props_len  = props_len;
    return (remain_len + head_len);
} // end of mqttGetPktLenPublish



int  mqttGetPktLenPubResp ( mqttPktPubResp_t *resp, word32 max_pkt_sz )
{
     if(resp == NULL) { return  MQTT_RESP_ERRARGS; }
    word32    remain_len  = 0;
    word32    props_len   = 0;
    uint8_t   head_len    = 0;

    remain_len  = 2;  // 2 bytes for packet ID
    if(resp->reason_code != MQTT_REASON_SUCCESS || resp->props != NULL) {
        remain_len += 1; // 1 byte for reason code 
    }
    if(resp->props != NULL) {
        props_len   = mqttEncodeProps( NULL, resp->props );
        remain_len += props_len; 
        remain_len += mqttEncodeVarBytes( NULL, props_len );
    }
    head_len  = mqttEncodeVarBytes(NULL, remain_len);
    head_len += 1;
    if((remain_len + head_len) > max_pkt_sz) {
        return MQTT_RESP_ERR_EXCEED_PKT_SZ ;
    }
    if((remain_len + head_len) > MQTT_RECV_PKT_MAXBYTES) {
        return MQTT_RESP_ERRMEM;
    } // report error because there might not be sufficient memory space to allocate.
    resp->pkt_len_set.remain_len = remain_len;
    resp->pkt_len_set.props_len  = props_len;
    return (remain_len + head_len);
} // end of mqttGetPktLenPubResp



int  mqttGetPktLenSubscribe ( mqttPktSubs_t *subs, word32 max_pkt_sz )
{
    if(subs == NULL) { return  MQTT_RESP_ERRARGS ; }
    word32    remain_len  = 0;
    word32    props_len   = 0;
    uint8_t   head_len    = 0;
    word16    idx         = 0;
    mqttTopic_t  *curr_topic = NULL;

    // 2 bytes for packet ID
    remain_len = 2; 
    // size of all properties in the packet
    props_len   =  mqttEncodeProps( NULL, subs->props );
    remain_len +=  props_len;
    remain_len +=  mqttEncodeVarBytes( NULL, props_len );
    // loop through the topic lists , to determine payload length
    for( idx=0; idx<subs->topic_cnt; idx++ ){
        curr_topic  = &subs->topics[idx];
        if(curr_topic != NULL) {
            // preserve space for each topic, encoded as UTF-8 string
            remain_len += curr_topic->filter.len + 2; 
            remain_len += 1; // 1 byte for QoS field of each topic, 
            // the only difference between mqttGetPktLenSubscribe() and mqttGetPktLenUnsubscribe()
        }
        else{ return MQTT_RESP_MALFORMED_DATA; }
    }
    head_len  = mqttEncodeVarBytes(NULL, remain_len);
    head_len += 1;
    if((remain_len + head_len) > max_pkt_sz) {
        return MQTT_RESP_ERR_EXCEED_PKT_SZ ;
    }
    if((remain_len + head_len) > MQTT_RECV_PKT_MAXBYTES) {
        return MQTT_RESP_ERRMEM;
    } // report error because there might not be sufficient memory space to allocate.
    subs->pkt_len_set.remain_len = remain_len;
    subs->pkt_len_set.props_len  = props_len;
    return (remain_len + head_len);
} // end of mqttGetPktLenSubscribe



int  mqttGetPktLenUnsubscribe ( mqttPktUnsubs_t *unsubs, word32 max_pkt_sz )
{
    if(unsubs == NULL) { return  MQTT_RESP_ERRARGS ; }
    word32    remain_len  = 0;
    word32    props_len   = 0;
    uint8_t   head_len    = 0;
    word16    idx         = 0;
    mqttTopic_t  *curr_topic = NULL;

    // 2 bytes for packet ID
    remain_len = 2; 
    // size of all properties in the packet
    props_len   =  mqttEncodeProps( NULL, unsubs->props );
    remain_len +=  props_len;
    remain_len +=  mqttEncodeVarBytes( NULL, props_len );
    for( idx=0; idx<unsubs->topic_cnt; idx++ ){
        curr_topic  = &unsubs->topics[idx];
        if(curr_topic != NULL) {
            // preserve space for each topic, encoded as UTF-8 string
            remain_len += curr_topic->filter.len + 2; 
        }
        else{ return MQTT_RESP_MALFORMED_DATA; }
    }
    head_len  = mqttEncodeVarBytes(NULL, remain_len);
    head_len += 1;
    if((remain_len + head_len) > max_pkt_sz) {
        return MQTT_RESP_ERR_EXCEED_PKT_SZ ;
    }
    if((remain_len + head_len) > MQTT_RECV_PKT_MAXBYTES) {
        return MQTT_RESP_ERRMEM;
    } // report error because there might not be sufficient memory space to allocate.
    unsubs->pkt_len_set.remain_len = remain_len;
    unsubs->pkt_len_set.props_len  = props_len;
    return (remain_len + head_len);
} // end of mqttGetPktLenUnsubscribe



int  mqttGetPktLenDisconn ( mqttPktDisconn_t *disconn, word32 max_pkt_sz )
{
    if(disconn == NULL) { return  MQTT_RESP_ERRARGS; }
    word32   remain_len  = 0;
    word32   props_len   = 0;
    uint8_t  head_len    = 0;
    byte     reason_code = disconn->reason_code;
    // if reason code is 0x0 (normal disconnection), and there's no property to send, then
    // the reason code field can be omitted in the DISCONNECT packet, in such case the
    // remaining length should be zero.
    // Otherwise if there's property to send, then reason code field should be present
    // regardless of its value
    if(reason_code != MQTT_REASON_NORMAL_DISCONNECTION || disconn->props!=NULL) {
        // 1 byte is preserved for non-zero reason code
        remain_len +=  1;
    }
    if(disconn->props!=NULL) {
        // size of all properties in the DISCONNECT packet
        props_len   =  mqttEncodeProps( NULL, disconn->props );
        remain_len +=  props_len;
        // number of variable bytes to store "property length"
        remain_len += mqttEncodeVarBytes(NULL, props_len);
    }
    head_len  = mqttEncodeVarBytes(NULL, remain_len);
    head_len += 1;
    if((remain_len + head_len) > max_pkt_sz) {
        return MQTT_RESP_ERR_EXCEED_PKT_SZ ;
    }
    if((remain_len + head_len) > MQTT_RECV_PKT_MAXBYTES) {
        return MQTT_RESP_ERRMEM;
    } // report error because there might not be sufficient memory space to allocate.
    disconn->pkt_len_set.remain_len = remain_len;
    disconn->pkt_len_set.props_len  = props_len;
    return (remain_len + head_len);
} // end of mqttGetPktLenDisconn



int  mqttGetPktLenAuth ( mqttAuth_t *auth, word32 max_pkt_sz )
{
    if(auth == NULL) { return  MQTT_RESP_ERRARGS; }
    word32    remain_len  = 0;
    word32    props_len   = 0;
    uint8_t   head_len    = 0;
    if(auth->reason_code != MQTT_REASON_SUCCESS) {
        remain_len += 1; // 1 byte for reason code 
    }
    if(auth->props != NULL) {
        props_len   = mqttEncodeProps( NULL, auth->props );
        remain_len += props_len; 
        remain_len += mqttEncodeVarBytes( NULL, props_len );
    }
    head_len  = mqttEncodeVarBytes(NULL, remain_len);
    head_len += 1;
    if((remain_len + head_len) > max_pkt_sz) {
        return MQTT_RESP_ERR_EXCEED_PKT_SZ ;
    }
    if((remain_len + head_len) > MQTT_RECV_PKT_MAXBYTES) {
        return MQTT_RESP_ERRMEM;
    } // report error because there might not be sufficient memory space to allocate.
    auth->pkt_len_set.remain_len = remain_len;
    auth->pkt_len_set.props_len  = props_len;
    return (remain_len + head_len);
} // end of mqttGetPktLenAuth



int  mqttEncodePktConnect( byte *tx_buf, word32 tx_buf_len, mqttConn_t *conn )
{
    word32   fx_head_len = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    mqttPktHeadConnect_t  var_head = {{0, MQTT_CONN_PROTOCOL_NAME_LEN}, {'M','Q','T','T'}, 0, 0, 0}; 
    byte    *curr_buf_pos ;

    if((conn == NULL) || (tx_buf == NULL) || (tx_buf_len == 0)) { 
        return MQTT_RESP_ERRARGS; 
    }
    remain_len = conn->pkt_len_set.remain_len ;
    props_len  = conn->pkt_len_set.props_len  ;
    // build fixed header of CONNECT packet 
    fx_head_len = mqttEncodeFxHeader( tx_buf, tx_buf_len, remain_len, 
                                      MQTT_PACKET_TYPE_CONNECT,  0, 0, 0 );
    
    curr_buf_pos = &tx_buf[fx_head_len];
    var_head.protocol_lvl = conn->protocol_lvl; 
    if(conn->flgs.clean_session != 0) {
        var_head.flags |=  MQTT_CONNECT_FLG_CLEAN_START; 
    }
    if(conn->flgs.will_enable != 0) {
        var_head.flags |=  MQTT_CONNECT_FLG_WILL_FLAG;
        var_head.flags |= (conn->lwt_msg.qos << MQTT_CONNECT_FLG_WILL_QOS_SHIFT);
        if(conn->lwt_msg.retain != 0) {
            var_head.flags |= MQTT_CONNECT_FLG_WILL_RETAIN;
        }
    }
    if(conn->username.data != NULL) {
        var_head.flags |= MQTT_CONNECT_FLG_USERNAME ; 
    }
    if(conn->password.data != NULL) {
        var_head.flags |= MQTT_CONNECT_FLG_PASSWORD ; 
    }
    mqttEncodeWord16( (byte *)&var_head.keep_alive, conn->keep_alive_sec );
    XMEMCPY( curr_buf_pos, (byte *)&var_head, sizeof(mqttPktHeadConnect_t) );
    curr_buf_pos += sizeof(mqttPktHeadConnect_t);

    // copy all properties to buffer
    curr_buf_pos += mqttEncodeVarBytes( curr_buf_pos, props_len );
    curr_buf_pos += mqttEncodeProps( curr_buf_pos, conn->props );

    // copy all elements of the payload to buffer
    curr_buf_pos += mqttEncodeStr( curr_buf_pos, (const byte *)conn->client_id.data,  conn->client_id.len );
    // copy data for last will testament
    if(conn->flgs.will_enable != 0) {
        mqttMsg_t  *lwtmsg  = &conn->lwt_msg;
        word32      lwt_props_len  = lwtmsg->pkt_len_set.props_len;
        // TODO: figure out where to correctly append will properties in CONNECT packet for MQTT v5 protocol. 
        curr_buf_pos += mqttEncodeVarBytes( curr_buf_pos, lwt_props_len );
        curr_buf_pos += mqttEncodeProps( curr_buf_pos, lwtmsg->props ); 
        // append will topic
        curr_buf_pos += mqttEncodeStr( curr_buf_pos, (const byte *)lwtmsg->topic.data, lwtmsg->topic.len );
        // append will payload
        curr_buf_pos += mqttEncodeStr( curr_buf_pos, (const byte *)lwtmsg->buff, lwtmsg->app_data_len);
    }
    if(conn->username.data != NULL) {
        curr_buf_pos += mqttEncodeStr( curr_buf_pos, (const byte *)conn->username.data,  conn->username.len );
    }
    else {
        // [Note]
        // A server may allow a client to provide empty clientID (has length of zero byte),
        // server must assign unique ID to such CONNECT packet (with zero-byte clientID), and then
        // return CONNACK packet with the property "Assigned Client Identifier" back to client .
        curr_buf_pos += mqttEncodeWord16( curr_buf_pos, (word16)0 );
    }
    if(conn->password.data != NULL) {
        curr_buf_pos += mqttEncodeStr( curr_buf_pos, (const byte *)conn->password.data,  conn->password.len );
    }
    return  (remain_len + fx_head_len);
} // end of mqttEncodePktConnect




int  mqttDecodePktConnack( byte *rx_buf, word32 rx_buf_len,  mqttPktHeadConnack_t *connack )
{
    if((connack == NULL) || (rx_buf == NULL) || (rx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS ;
    }
    word32   fx_head_len = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    byte    *curr_buf_pos ;
    byte    *end_of_buf ;
    fx_head_len = mqttDecodeFxHeader( rx_buf, rx_buf_len, &remain_len, 
                                      MQTT_PACKET_TYPE_CONNACK, NULL, NULL, NULL );
    if(fx_head_len == 0) { return MQTT_RESP_ERR_CTRL_PKT_TYPE; }
    curr_buf_pos = &rx_buf[fx_head_len];
    end_of_buf   =  curr_buf_pos + remain_len;
    connack->flags        = *curr_buf_pos++;
    connack->reason_code  = *curr_buf_pos++;
    if(end_of_buf > curr_buf_pos) {
        // copy all properties from buffer
        curr_buf_pos += mqttDecodeVarBytes( (const byte *)curr_buf_pos, &props_len );
        int autual_copied_len  = mqttDecodeProps( curr_buf_pos, &connack->props, props_len );
        if(autual_copied_len < 0){ return autual_copied_len; }
        curr_buf_pos  += autual_copied_len ;
    }
    return  (fx_head_len + remain_len);
} // end of mqttDecodePktConnack




int  mqttEncodePktDisconn( byte *tx_buf, word32 tx_buf_len, mqttPktDisconn_t *disconn )
{
    if((disconn == NULL) || (tx_buf == NULL) || (tx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS;
    }
    word32   fx_head_len = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    byte    *curr_buf_pos ;
    byte     reason_code = disconn->reason_code;
    remain_len = disconn->pkt_len_set.remain_len ;
    props_len  = disconn->pkt_len_set.props_len  ;
    // build fixed header of CONNECT packet 
    fx_head_len = mqttEncodeFxHeader( tx_buf, tx_buf_len, remain_len, 
                                      MQTT_PACKET_TYPE_DISCONNECT,  0, 0, 0 );
    curr_buf_pos = &tx_buf[fx_head_len];
    if(reason_code != MQTT_REASON_NORMAL_DISCONNECTION || disconn->props!=NULL) {
        // 1 byte is preserved for non-zero reason code
        *curr_buf_pos++  = reason_code;
    }
    if(disconn->props!=NULL) {
        // copy all properties to buffer
        curr_buf_pos +=  mqttEncodeVarBytes( curr_buf_pos, props_len );
        curr_buf_pos +=  mqttEncodeProps( curr_buf_pos, disconn->props );
    }
    return (fx_head_len + remain_len);
} // end of mqttEncodePktDisconn




int  mqttEncodePktPublish( byte *tx_buf, word32 tx_buf_len, struct __mqttMsg  *msg )
{
    word32   fx_head_len  = 0;
    word32   remain_len   = 0;
    word32   props_len    = 0;
    byte    *curr_buf_pos ;
    byte    *end_of_buf ;

    if((msg == NULL) || (tx_buf == NULL) || (tx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS;
    }
    if((msg->topic.data==NULL) || (msg->topic.len < 1)) {
        return  MQTT_RESP_ERRARGS; // topic is a must when publishing message
    }
    // number of bytes taken to encode topic string
    if(msg->qos > MQTT_QOS_0 && msg->packet_id == 0) {
        // when QoS > 0, packet ID must be non-zero 16-bit number
        return  MQTT_RESP_ERR_CTRL_PKT_ID;
    }

    remain_len = msg->pkt_len_set.remain_len ;
    props_len  = msg->pkt_len_set.props_len  ;
    // build fixed header of PUBLISH packet 
    fx_head_len = mqttEncodeFxHeader( tx_buf, tx_buf_len, remain_len, 
                                      MQTT_PACKET_TYPE_PUBLISH, msg->retain,
                                      msg->qos,  msg->duplicate );

    curr_buf_pos  = &tx_buf[fx_head_len]; 
    end_of_buf    =  curr_buf_pos + remain_len;
    // variable header : topic filter
    curr_buf_pos += mqttEncodeStr( curr_buf_pos, (const byte *)msg->topic.data, msg->topic.len );
    // variable header : packet ID (if QoS > 0)
    if(msg->qos > MQTT_QOS_0) {
        curr_buf_pos += mqttEncodeWord16( curr_buf_pos, msg->packet_id );
    }
    // variable header : properties
    curr_buf_pos += mqttEncodeVarBytes(curr_buf_pos , props_len);
    curr_buf_pos += mqttEncodeProps(curr_buf_pos , msg->props );
    if(end_of_buf > (curr_buf_pos + msg->app_data_len)) {
        return  MQTT_RESP_ERR_EXCEED_PKT_SZ ;
    }
    XMEMCPY( curr_buf_pos, &msg->buff[0], msg->app_data_len );
    return (fx_head_len + remain_len);
} // end of mqttEncodePktPublish





int  mqttDecodePktPublish( byte *rx_buf, word32 rx_buf_len, struct __mqttMsg *msg )
{
    if((msg == NULL) || (rx_buf == NULL) || (rx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS;
    }
    word32   fx_head_len  = 0;
    word32   var_head_len = 0;
    word32   payload_len  = 0;
    word32   props_len    = 0;

    int      curr_cp_len  = 0;
    word16   tmp = 0;
    byte    *curr_buf_pos ;

    fx_head_len = mqttDecodeFxHeader( rx_buf, rx_buf_len, &payload_len, MQTT_PACKET_TYPE_PUBLISH,
                                      &msg->retain,  &msg->qos, &msg->duplicate );
    if(fx_head_len == 0) { return MQTT_RESP_ERR_CTRL_PKT_TYPE; }
    curr_buf_pos  = &rx_buf[fx_head_len]; 
    // variable header : topic filter, there must be string of topic, check its length
    tmp = 0;
    mqttDecodeStr( curr_buf_pos, NULL, &tmp );
    if(tmp == 0){ return MQTT_RESP_MALFORMED_DATA; }
    msg->topic.len  = tmp;
    msg->topic.data = (byte *)XMALLOC(sizeof(byte) * tmp);
    var_head_len  = mqttDecodeStr( curr_buf_pos, msg->topic.data, &tmp );
    curr_buf_pos += var_head_len;
    // variable header : check QoS & see if we have packet ID field in the received PUBLISH packet
    if(msg->qos > MQTT_QOS_0) {
        tmp            = mqttDecodeWord16( curr_buf_pos, &msg->packet_id );
        curr_buf_pos  += tmp;
        var_head_len  += tmp;
    }
    // variable header : optional properties
    tmp = mqttDecodeVarBytes( (const byte *)curr_buf_pos, &props_len );
    var_head_len  += tmp;
    curr_buf_pos  += tmp;
    var_head_len  += props_len;
    {
        curr_cp_len = mqttDecodeProps( curr_buf_pos, &msg->props, props_len );
        if(curr_cp_len < 0){ return (mqttRespStatus)curr_cp_len; }
        if(curr_cp_len != props_len) { return MQTT_RESP_ERR_PROP; } // TODO: test 
        curr_buf_pos  += curr_cp_len; // at here , curr_cp_len  must be equal to props_len
    }
    payload_len   -= var_head_len;
    msg->buff = (byte *) XMALLOC(sizeof(byte) * payload_len);
    if(msg->buff == NULL) { return MQTT_RESP_ERRMEM; }
    msg->app_data_len = payload_len; 
    curr_cp_len = XMIN( payload_len, rx_buf_len - fx_head_len - var_head_len);
    XMEMCPY( &msg->buff[0], curr_buf_pos, curr_cp_len );
    return (fx_head_len + var_head_len + curr_cp_len);
} // end of mqttDecodePktPublish




int  mqttEncodePktSubscribe( byte *tx_buf, word32 tx_buf_len, mqttPktSubs_t *subs )
{
    if((subs == NULL) || (tx_buf == NULL) || (tx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS ;
    }
    word32        fx_head_len = 0;
    word32        remain_len  = 0;
    word32        props_len   = 0;
    word16        idx = 0;
    byte         *curr_buf_pos = NULL;
    mqttTopic_t  *curr_topic = NULL;

    remain_len = subs->pkt_len_set.remain_len ;
    props_len  = subs->pkt_len_set.props_len  ;
    // build fixed header of SUBSCRIBE packet, 
    // TODO: figure out why it's 0010 at the reserved field 
    fx_head_len = mqttEncodeFxHeader( tx_buf, tx_buf_len, remain_len, 
                                      MQTT_PACKET_TYPE_SUBSCRIBE, 0, MQTT_QOS_1, 0 );
    curr_buf_pos  = &tx_buf[fx_head_len]; 
    // variable header, packet ID, and optional properties
    curr_buf_pos += mqttEncodeWord16( curr_buf_pos, subs->packet_id );
    curr_buf_pos += mqttEncodeVarBytes( curr_buf_pos, props_len );
    curr_buf_pos += mqttEncodeProps( curr_buf_pos , subs->props );
    // copy topics to payload
    for( idx=0; idx<subs->topic_cnt; idx++ ) {
        curr_topic    = &subs->topics[idx];
        curr_buf_pos += mqttEncodeStr( curr_buf_pos, (const byte *)curr_topic->filter.data, curr_topic->filter.len );
        *curr_buf_pos = (byte) curr_topic->qos; // TODO: implement all fields of the subscription options byte
        curr_buf_pos++;
    }
    return (fx_head_len + remain_len);
} // end of mqttEncodePktSubscribe




int  mqttEncodePktUnsubscribe( byte *tx_buf, word32 tx_buf_len, mqttPktUnsubs_t *unsubs )
{
    if((unsubs == NULL) || (tx_buf == NULL) || (tx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS;
    }
    word32   fx_head_len = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    word16   idx = 0;
    byte    *curr_buf_pos ;
    mqttTopic_t  *curr_topic = NULL;

    remain_len = unsubs->pkt_len_set.remain_len ;
    props_len  = unsubs->pkt_len_set.props_len  ;
    // build fixed header of UNSUBSCRIBE packet 
    fx_head_len = mqttEncodeFxHeader( tx_buf, tx_buf_len, remain_len, 
                                      MQTT_PACKET_TYPE_UNSUBSCRIBE, 0, MQTT_QOS_1, 0 );
    curr_buf_pos  = &tx_buf[fx_head_len]; 
    // variable header, packet ID, and optional properties
    curr_buf_pos += mqttEncodeWord16( curr_buf_pos, unsubs->packet_id );
    curr_buf_pos += mqttEncodeVarBytes( curr_buf_pos, props_len );
    curr_buf_pos += mqttEncodeProps( curr_buf_pos , unsubs->props );
    // copy topics to payload
    for( idx=0; idx<unsubs->topic_cnt; idx++ ){
        curr_topic    = &unsubs->topics[idx];
        curr_buf_pos += mqttEncodeStr( curr_buf_pos, (const byte *)curr_topic->filter.data, curr_topic->filter.len );
    }
    return (fx_head_len + remain_len);
} // end of mqttEncodePktUnsubscribe



int  mqttEncodePktPubResp( byte *tx_buf, word32 tx_buf_len, mqttPktPubResp_t *resp, mqttCtrlPktType cmdtype )
{
    if((resp == NULL) || (tx_buf == NULL) || (tx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS;
    }
    word32   fx_head_len = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    byte    *curr_buf_pos ;
    mqttQoS  qos  = (cmdtype == MQTT_PACKET_TYPE_PUBREL ? MQTT_QOS_1: MQTT_QOS_0);
                  // special case in MQTT v5 protocol ?
    remain_len = resp->pkt_len_set.remain_len ;
    props_len  = resp->pkt_len_set.props_len  ;
    fx_head_len   = mqttEncodeFxHeader( tx_buf, tx_buf_len, remain_len, cmdtype, 0, qos, 0 );
    curr_buf_pos  = &tx_buf[fx_head_len] ;
    curr_buf_pos += mqttEncodeWord16( curr_buf_pos, resp->packet_id );
    if(resp->reason_code != MQTT_REASON_SUCCESS || resp->props != NULL) {
        *curr_buf_pos++ = resp->reason_code ;
    }
    if(resp->props != NULL) {
        curr_buf_pos += mqttEncodeVarBytes( curr_buf_pos, props_len );
        curr_buf_pos += mqttEncodeProps( curr_buf_pos, resp->props );
    }
    return  (fx_head_len + remain_len);
} // end of mqttEncodePktPubResp




int  mqttEncodePktAuth( byte *tx_buf, word32 tx_buf_len, mqttAuth_t *auth )
{
    if((auth == NULL) || (tx_buf == NULL) || (tx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS;
    }
    word32   fx_head_len = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    byte    *curr_buf_pos ;

    remain_len = auth->pkt_len_set.remain_len;
    props_len  = auth->pkt_len_set.props_len ; 
    fx_head_len  = mqttEncodeFxHeader( tx_buf, tx_buf_len, remain_len, 
                                       MQTT_PACKET_TYPE_AUTH, 0, 0, 0 );
    curr_buf_pos  = &tx_buf[fx_head_len] ;
    if(auth->reason_code != MQTT_REASON_SUCCESS) {
        *curr_buf_pos++ = auth->reason_code ;
    }
    if(auth->props != NULL) {
        curr_buf_pos += mqttEncodeVarBytes( curr_buf_pos, props_len );
        curr_buf_pos += mqttEncodeProps( curr_buf_pos, auth->props );
    }
    return  (fx_head_len + remain_len);
} // end of mqttEncodePktAuth




int  mqttEncodePktPing( byte *tx_buf, word32 tx_buf_len )
{
    if((tx_buf == NULL) || (tx_buf_len == 0)) {
        return  MQTT_RESP_ERRARGS;
    }
    word32   fx_head_len = 0;
    word32   remain_len  = 0;
    fx_head_len  = mqttEncodeFxHeader( tx_buf, tx_buf_len, remain_len,
                                       MQTT_PACKET_TYPE_PINGREQ, 0, 0, 0 );
    return  (fx_head_len + remain_len);
} // end of mqttEncodePktPing



int  mqttDecodePktPubResp( byte *rx_buf, word32 rx_buf_len, mqttPktPubResp_t *resp, mqttCtrlPktType cmdtype )
{
    if((resp == NULL) || (rx_buf == NULL) || (rx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS;
    }
    word32   fx_head_len = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    byte    *curr_buf_pos ;
    byte    *end_of_buf;
    fx_head_len = mqttDecodeFxHeader( rx_buf, rx_buf_len, &remain_len, cmdtype, NULL, NULL, NULL );
    if(fx_head_len == 0) { return MQTT_RESP_ERR_CTRL_PKT_TYPE; }
    curr_buf_pos  = &rx_buf[fx_head_len];
    end_of_buf    = curr_buf_pos + remain_len;
    // there must be packet ID when receiving publish response packet(s)
    // (QoS must be greater than 0)
    curr_buf_pos += mqttDecodeWord16( curr_buf_pos, &resp->packet_id );

    if(end_of_buf > curr_buf_pos) {
        resp->reason_code = *curr_buf_pos++; 
    }
    else {
        // Reason code might not be present in the variable header, 
        // that means success code (0x00) is used as reason code.
        resp->reason_code = MQTT_REASON_SUCCESS; 
    }
    if(end_of_buf > curr_buf_pos) {
        // copy all properties from buffer
        curr_buf_pos += mqttDecodeVarBytes( (const byte *)curr_buf_pos, &props_len );
        int autual_copied_len = mqttDecodeProps( curr_buf_pos, &resp->props, props_len );
        if(autual_copied_len < 0){ return autual_copied_len; }
        if(autual_copied_len != props_len) { return MQTT_RESP_ERR_PROP; }
        curr_buf_pos  += autual_copied_len ; // at here , autual_copied_len must be equal to props_len
    }
    return  (fx_head_len + remain_len);
} // end of mqttDecodePktPubResp




int  mqttDecodePktSuback( byte *rx_buf, word32 rx_buf_len, mqttPktSuback_t *suback )
{
    if((suback == NULL) || (rx_buf == NULL) || (rx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS;
    }
    word32   fx_head_len = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    word16   reason_codes_len = 0;
    byte    *curr_buf_pos ;
    byte    *end_of_buf;
    fx_head_len = mqttDecodeFxHeader( rx_buf, rx_buf_len, &remain_len, 
                                      MQTT_PACKET_TYPE_SUBACK, NULL, NULL, NULL );
    if(fx_head_len == 0) { return MQTT_RESP_ERR_CTRL_PKT_TYPE; }
    curr_buf_pos  = &rx_buf[fx_head_len];
    end_of_buf    = curr_buf_pos + remain_len;
    curr_buf_pos += mqttDecodeWord16( curr_buf_pos, &suback->packet_id );
    curr_buf_pos += mqttDecodeVarBytes( (const byte *)curr_buf_pos, &props_len );

    int autual_copied_len = mqttDecodeProps( curr_buf_pos, &suback->props, props_len );
    if(autual_copied_len < 0){ return autual_copied_len; }
    if(autual_copied_len != props_len) { return MQTT_RESP_ERR_PROP; }
    curr_buf_pos  += autual_copied_len ; // at here , autual_copied_len must be equal to props_len
    // the SUBACK payload must contains a list of return codes that indicate whether the topic 
    // filters were subscribed successfully on the borker side.
    if(end_of_buf <= curr_buf_pos){ return MQTT_RESP_MALFORMED_DATA; }
    reason_codes_len = (word16)(end_of_buf - curr_buf_pos);
    suback->return_codes = (byte *) XMALLOC(sizeof(byte) * reason_codes_len); // TODO: find better way to allocate / free the space
    if(suback->return_codes == NULL) { return MQTT_RESP_ERRMEM; }
    XMEMCPY( suback->return_codes, curr_buf_pos, reason_codes_len);
    return  (fx_head_len + remain_len);
} // end of mqttDecodePktSuback




int  mqttDecodePktUnsuback( byte *rx_buf, word32 rx_buf_len, mqttPktUnsuback_t *unsuback )
{
    if((unsuback == NULL) || (rx_buf == NULL) || (rx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS;
    }
    word32   fx_head_len = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    word16   reason_codes_len = 0;
    byte    *curr_buf_pos ;
    byte    *end_of_buf;
    fx_head_len = mqttDecodeFxHeader( rx_buf, rx_buf_len, &remain_len, 
                                      MQTT_PACKET_TYPE_UNSUBACK, NULL, NULL, NULL );
    if(fx_head_len == 0) { return MQTT_RESP_ERR_CTRL_PKT_TYPE; }
    curr_buf_pos  = &rx_buf[fx_head_len];
    end_of_buf    = curr_buf_pos + remain_len;
    curr_buf_pos += mqttDecodeWord16( curr_buf_pos, &unsuback->packet_id );
    curr_buf_pos += mqttDecodeVarBytes( (const byte *)curr_buf_pos, &props_len );

    int autual_copied_len = mqttDecodeProps( curr_buf_pos, &unsuback->props, props_len );
    if(autual_copied_len < 0){ return autual_copied_len; }
    if(autual_copied_len != props_len) { return MQTT_RESP_ERR_PROP; }
    curr_buf_pos  += autual_copied_len ; // at here , autual_copied_len must be equal to props_len
    // the UNSUBACK payload contains a list of return codes that indicate whether the topic
    // filters are unsubscribed successfully on the borker side.
    if(end_of_buf <= curr_buf_pos){ return MQTT_RESP_MALFORMED_DATA; }
    reason_codes_len = (word16)(end_of_buf - curr_buf_pos);
    unsuback->return_codes = (byte *) XMALLOC(sizeof(byte) * reason_codes_len); // TODO: find better way to allocate / free the space
    if(unsuback->return_codes == NULL) { return MQTT_RESP_ERRMEM; }
    XMEMCPY(unsuback->return_codes, curr_buf_pos, reason_codes_len);
    return  (fx_head_len + remain_len);
} // end of mqttDecodePktUnsuback



int  mqttDecodePktAuth( byte *rx_buf, word32 rx_buf_len, mqttAuth_t *auth )
{
    if((auth == NULL) || (rx_buf == NULL) || (rx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS;
    }
    word32   fx_head_len = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    byte    *curr_buf_pos ;
    byte    *end_of_buf;
    fx_head_len = mqttDecodeFxHeader( rx_buf, rx_buf_len, &remain_len, 
                                      MQTT_PACKET_TYPE_AUTH, NULL, NULL, NULL );
    if(fx_head_len == 0) { return MQTT_RESP_ERR_CTRL_PKT_TYPE; }
    curr_buf_pos  = &rx_buf[fx_head_len];
    end_of_buf    = curr_buf_pos + remain_len; // remain length can be 0
    // reason code can be omitted if it is 0x00 (SUCCESS)
    auth->reason_code = (end_of_buf > curr_buf_pos) ? *curr_buf_pos++ : MQTT_REASON_SUCCESS ;

    if(end_of_buf > curr_buf_pos) { // there might not be property sections in the AUTH packet
        curr_buf_pos += mqttDecodeVarBytes( (const byte *)curr_buf_pos, &props_len );
        int autual_copied_len = mqttDecodeProps( curr_buf_pos, &auth->props, props_len );
        if(autual_copied_len < 0){ return autual_copied_len; }
        if(autual_copied_len != props_len) { return MQTT_RESP_ERR_PROP; }
        curr_buf_pos  += autual_copied_len ; // at here , autual_copied_len must be equal to props_len
    }
    return  (fx_head_len + remain_len);
} // end of mqttDecodePktAuth



int  mqttDecodePktDisconn( byte *rx_buf,  word32 rx_buf_len, mqttPktDisconn_t *disconn )
{
    if((disconn == NULL) || (rx_buf == NULL) || (rx_buf_len == 0)) { 
        return  MQTT_RESP_ERRARGS;
    }
    word32   fx_head_len = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;
    byte    *curr_buf_pos ;
    byte    *end_of_buf;
    byte     reservebits[3] = {0, 0, 0};
    fx_head_len = mqttDecodeFxHeader( rx_buf, rx_buf_len, &remain_len,  MQTT_PACKET_TYPE_DISCONNECT,
                                     &reservebits[0] , &reservebits[1], &reservebits[2] );
    if(fx_head_len == 0) { return MQTT_RESP_ERR_CTRL_PKT_TYPE; }
    if(reservebits[0] != 0 || reservebits[1] != 0 || reservebits[2] != 0) {
        return MQTT_RESP_MALFORMED_DATA;
    } // in received DISCONNECT the reserved fields of fixed header must be zero.
    curr_buf_pos  = &rx_buf[fx_head_len];
    end_of_buf    = curr_buf_pos + remain_len; // remain length can be 0
    // reason code can be omitted if it is 0x00 (SUCCESS)
    disconn->reason_code = (end_of_buf > curr_buf_pos) ? *curr_buf_pos++ : MQTT_REASON_NORMAL_DISCONNECTION;
    // there might not be property sections in the AUTH packet
    if(end_of_buf > curr_buf_pos) {
        curr_buf_pos += mqttDecodeVarBytes( (const byte *)curr_buf_pos, &props_len );
        int autual_copied_len = mqttDecodeProps( curr_buf_pos, &disconn->props, props_len );
        if(autual_copied_len < 0){ return autual_copied_len; }
        if(autual_copied_len != props_len) { return MQTT_RESP_ERR_PROP; }
        curr_buf_pos  += autual_copied_len ; // at here , autual_copied_len must be equal to props_len
    }
    return  (fx_head_len + remain_len);
} // end of mqttDecodePktDisconn



mqttRespStatus mqttPktWrite( struct __mqttCtx *mctx, byte *buf, word32 buf_len )
{
    if((mctx == NULL) || (buf == NULL) || (buf_len == 0)) { 
        return MQTT_RESP_ERRARGS;
    }
    int  wr_len = 0;
    do {
        wr_len  =  mqttPktLowLvlWrite( mctx, buf, buf_len );
        if(wr_len < 0) { return (mqttRespStatus)wr_len; }
        buf        +=  wr_len;
        buf_len    -=  wr_len;
    } // end of loop
    while( buf_len > 0 );
    return  MQTT_RESP_OK;
} // end of mqttPktWrite




mqttRespStatus  mqttPktRead( struct __mqttCtx *mctx, byte *buf, word32 buf_max_len, word32 *copied_len )
{
    if((mctx == NULL) || (buf == NULL) || (copied_len == NULL)) {
        return MQTT_RESP_ERRARGS;
    }
    word32  remain_len = 0;
    int     rd_len     = 0;
    word16  idx        = 0;
    const   byte  continuation_bit = 0x80;
    const mqttPktFxHead_t  *header = (mqttPktFxHead_t *) buf;

    *copied_len = 0;
    // ----------- get fixed header -----------
    rd_len = mqttPktLowLvlRead( mctx, buf, 0x1 );
    if(rd_len < 0) { return (mqttRespStatus)rd_len; }
    if(rd_len != 0x1) { return MQTT_RESP_MALFORMED_DATA; }
    buf         += rd_len;
    *copied_len  = rd_len;
    buf_max_len -= rd_len;

    // ----------- get remaining length ----------- 
    // read from the 2nd byte, determined remain length encoded in variable bytes.
    for(idx=0; idx<MQTT_PKT_MAX_BYTES_REMAIN_LEN ; idx++) {
        rd_len = mqttPktLowLvlRead( mctx, &buf[idx], 0x1 );
        if(rd_len < 0) { return rd_len; }
        if(rd_len != 0x1) { return MQTT_RESP_MALFORMED_DATA; }
        if((header->remain_len[idx] & continuation_bit) == 0x0) {
            break;
        }
    } // end of for-loop
    if(idx == MQTT_PKT_MAX_BYTES_REMAIN_LEN) {
        return  MQTT_RESP_MALFORMED_DATA;
    }
    *copied_len += idx + 1;
    buf_max_len -= idx + 1;
    // extract remaining length, the return of the following function below should be the same as idx + 1
    buf         += mqttDecodeVarBytes( &header->remain_len[0], &remain_len );

    // ----------- get rest of data bytes ----------- 
    word32  curr_max_cp_len = XMIN(remain_len , buf_max_len);
    do {  // read remaining part
        rd_len = mqttPktLowLvlRead( mctx, buf, curr_max_cp_len );
        // report other read error from low-level system. 
        if(rd_len < 0) { return (mqttRespStatus)rd_len; }
        *copied_len     += rd_len ;
        curr_max_cp_len -= rd_len ;
        buf             += rd_len ;
    } // end of loop
    while(curr_max_cp_len > 0);
    // current Rx buffer cannot hold entire incoming packet, this should be protocol
    // error, in such case we return MQTT_RESP_ERR_EXCEED_PKT_SZ instead,
    if(remain_len > buf_max_len) {
        mctx->err_info.reason_code = MQTT_REASON_RX_MAX_EXCEEDED;
        return MQTT_RESP_ERR_EXCEED_PKT_SZ;
    }
    else {
        return MQTT_RESP_OK;
    }
} // end of mqttPktRead





mqttRespStatus  mqttDecodePkt( struct __mqttCtx *mctx, byte *buf, word32 buf_len,  mqttCtrlPktType  cmdtype, void **p_decode, word16 *recv_pkt_id )
{
    mqttRespStatus  status = MQTT_RESP_OK;
    if((mctx==NULL) || (buf==NULL) || (buf_len==0) || (p_decode==NULL)) {
        return MQTT_RESP_ERRARGS;
    }
    mctx->flgs.recv_mode = 1;
    switch (cmdtype)
    {
        case MQTT_PACKET_TYPE_CONNACK      : 
            status = mqttDecodePktConnack( buf, buf_len, *(mqttPktHeadConnack_t **)p_decode );
            if(status < 0) { break; }
            status = mqttPropErrChk( mctx, cmdtype, (*(mqttPktHeadConnack_t **)p_decode)->props );
            break;
        case MQTT_PACKET_TYPE_PUBLISH      :
        {
            status = mqttDecodePktPublish( buf, buf_len, *(mqttMsg_t **)p_decode );
            *recv_pkt_id = (*(mqttMsg_t **)p_decode)->packet_id;
            if(status == MQTT_RESP_OK) {
                status = mqttPropErrChk( mctx, cmdtype, (*(mqttMsg_t **)p_decode)->props );
            }
            mqttQoS qos =  (*(mqttMsg_t **)p_decode)->qos;
            if(qos > MQTT_QOS_0) {
                cmdtype = ( qos == MQTT_QOS_1 ? MQTT_PACKET_TYPE_PUBACK: MQTT_PACKET_TYPE_PUBRECV );
                mqttPktPubResp_t *pub_resp = &mctx->send_pkt.pub_resp ;
                pub_resp->props            = NULL; // don't send extra properties in response packet for simplicity
                pub_resp->packet_id        = *recv_pkt_id ;
                pub_resp->reason_code      = MQTT_REASON_SUCCESS;
                status = mqttSendPubResp( mctx, cmdtype, (mqttPktPubResp_t **)p_decode );
            }
            break; 
        }
        case MQTT_PACKET_TYPE_PUBACK   :   
        case MQTT_PACKET_TYPE_PUBRECV  :   
        case MQTT_PACKET_TYPE_PUBREL   :   
        case MQTT_PACKET_TYPE_PUBCOMP  :  
        {
            status = mqttDecodePktPubResp( buf, buf_len, *(mqttPktPubResp_t **)p_decode, cmdtype );
            *recv_pkt_id = (*(mqttPktPubResp_t **)p_decode)->packet_id ;
            if(status == MQTT_RESP_OK) {
                status = mqttPropErrChk( mctx, cmdtype, (*(mqttPktPubResp_t **)p_decode)->props );
            } // TODO: test publish response packet when QoS = 2
            if((cmdtype==MQTT_PACKET_TYPE_PUBRECV) || (cmdtype==MQTT_PACKET_TYPE_PUBREL)) {
                // if error is found in reason code & QoS = 2, then we abort subsequent packet transmission (TODO: recheck this logic)
                status = mqttChkReasonCode((mqttReasonCode)(*(mqttPktPubResp_t **)p_decode)->reason_code);
                // send next publish response packet.
                mqttPktPubResp_t *pub_resp = &mctx->send_pkt_qos2.pub_resp ;
                pub_resp->props       = NULL; // don't send extra properties in response packet for simplicity
                pub_resp->packet_id   = *recv_pkt_id ;
                pub_resp->reason_code =  MQTT_REASON_SUCCESS;
                status = mqttSendPubResp( mctx, (cmdtype + 1), (mqttPktPubResp_t **)p_decode );
            }
            break; 
        }
        case MQTT_PACKET_TYPE_SUBACK       :  
            status = mqttDecodePktSuback( buf, buf_len, *(mqttPktSuback_t **)p_decode );
            *recv_pkt_id = (*(mqttPktSuback_t **)p_decode)->packet_id ;
            if(status < 0) { break; }
            status = mqttPropErrChk( mctx, cmdtype, (*(mqttPktSuback_t **)p_decode)->props );
            break; 
        case MQTT_PACKET_TYPE_UNSUBACK     :  
            status = mqttDecodePktUnsuback( buf, buf_len, *(mqttPktUnsuback_t **)p_decode );
            *recv_pkt_id = (*(mqttPktUnsuback_t **)p_decode)->packet_id ;
            if(status < 0) { break; }
            status = mqttPropErrChk( mctx, cmdtype, (*(mqttPktUnsuback_t **)p_decode)->props );
            break;
        // TODO: implement PING packet
        case MQTT_PACKET_TYPE_PINGREQ      :  break; 
        case MQTT_PACKET_TYPE_PINGRESP     :  break;
        case MQTT_PACKET_TYPE_AUTH         :
        {
            status = mqttDecodePktAuth( buf, buf_len, *(mqttAuth_t **)p_decode );
            if(status < 0){ break; }
            // we don't do error check at here, instead we do so in mqttSendAuth()
            byte reason_code = (*(mqttAuth_t **)p_decode)->reason_code ;
            if(reason_code == MQTT_REASON_CNTNU_AUTH) {
                // clean up property space to avoid overlapping address between
                // mctx->send_pkt.conn and  mctx->send_pkt.auth
                if(mctx->last_recv_cmdtype == MQTT_PACKET_TYPE_CONNECT) {
                    mqttPropertyDel( mctx->send_pkt.conn.props );
                }
                else if(mctx->last_recv_cmdtype == MQTT_PACKET_TYPE_AUTH) {
                    mqttPropertyDel( mctx->send_pkt.auth.props );
                }
                status = mqttSendAuth( mctx );
            }
            break;
        }
        case MQTT_PACKET_TYPE_DISCONNECT   :
            status = mqttDecodePktDisconn( buf, buf_len, *(mqttPktDisconn_t **)p_decode );
            if(status < 0){ break; }
            status = mqttPropErrChk( mctx, cmdtype, (*(mqttPktDisconn_t **)p_decode)->props );
            // the only reason this client receives DISCONNECT will be some errors were made on this
            // client beforehand, so the reason code from received DISCONNECT packet is pretty likely 
            // greater than 0x80. TODO: take actions if a client receives DISCONNECT packet.
            mctx->err_info.reason_code = (*(mqttPktDisconn_t **)p_decode)->reason_code;
            break;
        default:
            status = MQTT_RESP_ERR_CTRL_PKT_TYPE;
            break;
    } // end of switch-case statement
    if((int)status >= 0) { status = MQTT_RESP_OK; }
    return  status ;
} // end of mqttDecodePkt



