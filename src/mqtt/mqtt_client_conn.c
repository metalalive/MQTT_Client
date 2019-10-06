#include "mqtt_include.h"

static mqttProp_t availPropertyPool[MQTT_MAX_NUM_PROPS] = {0};

// ------------------- global variables that are accessed by implementation files -------------------
// find appropriate data type for each property defined in MQTT protocol
const mqttDataType mqttQueryPropDataType [] = 
{
    MQTT_DATA_TYPE_NONE, // MQTT_PROP_NONE = 0x00,
    MQTT_DATA_TYPE_BYTE, // MQTT_PROP_PKT_FMT_INDICATOR = 0x01,
    MQTT_DATA_TYPE_INT , // MQTT_PROP_MSG_EXPIRY_INTVL  = 0x02,
    MQTT_DATA_TYPE_STRING, // MQTT_PROP_CONTENT_TYPE      = 0x03,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_STRING,  // MQTT_PROP_RESP_TOPIC        = 0x08,
    MQTT_DATA_TYPE_BINARY,  // MQTT_PROP_CORRELATION_DATA  = 0x09,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_VAR_INT, // MQTT_PROP_SUBSCRIBE_ID      = 0x0b,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_INT ,   // MQTT_PROP_SESSION_EXPIRY_INTVL = 0x11,
    MQTT_DATA_TYPE_STRING, // MQTT_PROP_ASSIGNED_CLIENT_ID   = 0x12,
    MQTT_DATA_TYPE_SHORT,  // MQTT_PROP_SERVER_KEEP_ALIVE    = 0x13,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_STRING, // MQTT_PROP_AUTH_METHOD       = 0x15,
    MQTT_DATA_TYPE_BINARY, // MQTT_PROP_AUTH_DATA         = 0x16,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_REQ_PROBLEM_INFO  = 0x17,
    MQTT_DATA_TYPE_INT ,   // MQTT_PROP_WILL_DELAY_INTVL  = 0x18,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_REQ_RESP_INFO     = 0x19,
    MQTT_DATA_TYPE_STRING, // MQTT_PROP_RESP_INFO         = 0x1a,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_STRING, // MQTT_PROP_SERVER_REF        = 0x1c,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_STRING, // MQTT_PROP_REASON_STR        = 0x1f,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_SHORT,  // MQTT_PROP_RECV_MAX          = 0x21,
    MQTT_DATA_TYPE_SHORT,  // MQTT_PROP_TOPIC_ALIAS_MAX   = 0x22,
    MQTT_DATA_TYPE_SHORT,  // MQTT_PROP_TOPIC_ALIAS       = 0x23,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_MAX_QOS           = 0x24,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_RETAIN_AVAILABLE  = 0x25,
    MQTT_DATA_TYPE_STRING_PAIR, // MQTT_PROP_USER_PROPERTY     = 0x26,
    MQTT_DATA_TYPE_INT ,   // MQTT_PROP_MAX_PKT_SIZE      = 0x27,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_WILDCARD_SUBS_AVAIL = 0x28,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_SUBSCRIBE_ID_AVAIL  = 0x29,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_SHARE_SUBSCRIBE_AVAIL = 0x2a,
}; // end of mqttGetPropLength



static mqttRespStatus mqttCleanUpRecvpkt( mqttCtx_t *mctx, mqttCtrlPktType next_recv_cmdtype )
{
    mqttRespStatus  status = MQTT_RESP_OK;
    if(mctx==NULL) { return MQTT_RESP_ERRARGS; }
    mqttCtrlPktType last_recv_cmdtype = mctx->last_recv_cmdtype ;
    mctx->last_recv_cmdtype = next_recv_cmdtype;

    switch(last_recv_cmdtype)
    {
        case MQTT_PACKET_TYPE_RESERVED:
            break;
        case MQTT_PACKET_TYPE_CONNACK  :
        {
            mqttPktHeadConnack_t *connack = &mctx->recv_pkt.connack ; 
            // free the properties here if we take some space on availPropertyPool[...] while decoding the packet
            mqttPropertyDel( connack->props );
            XMEMSET((void *)connack, 0x00, sizeof(mqttPktHeadConnack_t));
            break;
        }
        case MQTT_PACKET_TYPE_PUBACK   :
        case MQTT_PACKET_TYPE_PUBRECV  : 
        {
            mqttPktPubResp_t  *pub_resp = &mctx->recv_pkt.pub_resp;
            mqttPropertyDel( pub_resp->props );
            XMEMSET( (void *)pub_resp, 0x00, sizeof(mqttPktPubResp_t) );
            break;
        }
        case MQTT_PACKET_TYPE_PUBREL   : 
        case MQTT_PACKET_TYPE_PUBCOMP  : 
        {
            mqttPktPubResp_t  *pub_resp = &mctx->recv_pkt_qos2.pub_resp;
            mqttPropertyDel( pub_resp->props );
            XMEMSET( (void *)pub_resp, 0x00, sizeof(mqttPktPubResp_t) );
            if(last_recv_cmdtype == MQTT_PACKET_TYPE_PUBCOMP) { break; }
            // for PUBREL packet, we'll continue to free memory which was
            // allocated for received PUBLISH packet
        }
        case MQTT_PACKET_TYPE_PUBLISH  :
        {   // TODO: find appropriate way to free the memory here, if QoS = 2
            if(next_recv_cmdtype != MQTT_PACKET_TYPE_PUBREL) {
                mqttMsg_t  *recv_msg  = &mctx->recv_pkt.pub_msg ;
                if(recv_msg->topic.data != NULL) {
                    XMEMFREE( (void *) recv_msg->topic.data ); 
                }
                if(recv_msg->buff != NULL) {
                    XMEMFREE( (void *) recv_msg->buff );
                }
                mqttPropertyDel( recv_msg->props );
                XMEMSET( (void *)recv_msg, 0x00, sizeof(mqttMsg_t) );
            }
            break; 
        }
        case MQTT_PACKET_TYPE_SUBACK   :
        {
            mqttPktSuback_t  *suback = &mctx->recv_pkt.suback;
            mqttPropertyDel( suback->props );
            if(suback->return_codes != NULL){ XMEMFREE((void *)suback->return_codes); }
            XMEMSET( (void *)suback, 0x00, sizeof(mqttPktSuback_t) );
            break;
        }
        case MQTT_PACKET_TYPE_UNSUBACK :
        {
            mqttPktUnsuback_t   *unsuback = &mctx->recv_pkt.unsuback;
            mqttPropertyDel( unsuback->props );
            if(unsuback->return_codes != NULL){ XMEMFREE((void *)unsuback->return_codes); }
            XMEMSET( (void *)unsuback, 0x00, sizeof(mqttPktUnsuback_t) );
            break;
        }
        case MQTT_PACKET_TYPE_PINGREQ  : 
            break; 
        case MQTT_PACKET_TYPE_PINGRESP : 
            break; 
        case MQTT_PACKET_TYPE_AUTH     :
        {
            mqttAuth_t *auth = &mctx->recv_pkt.auth ; 
            mqttPropertyDel( auth->props );
            XMEMSET((void *)auth, 0x00, sizeof(mqttAuth_t));
            break;
        }
        default:
            status = MQTT_RESP_ERR_CTRL_PKT_TYPE;
            break;
    } // end of switch-case statement
    return  status;
} // end of mqttCleanUpRecvpkt



    
static mqttRespStatus mqttSelectStructRecvPkt( mqttCtx_t *mctx, mqttCtrlPktType wait_cmdtype, void **pp_dst )
{
    mqttRespStatus  status = MQTT_RESP_OK;
    if((mctx==NULL) || (pp_dst==NULL)) { return MQTT_RESP_ERRARGS; }
    switch(wait_cmdtype)
    {
        case MQTT_PACKET_TYPE_CONNACK  :
            *pp_dst = (void *) &mctx->recv_pkt.connack ; 
            break; 
        case MQTT_PACKET_TYPE_PUBLISH  :
            *pp_dst = (void *) &mctx->recv_pkt.pub_msg ;
            break; 
        case MQTT_PACKET_TYPE_PUBACK   :
        case MQTT_PACKET_TYPE_PUBRECV  :
            *pp_dst = (void *) &mctx->recv_pkt.pub_resp;
            break; 
        case MQTT_PACKET_TYPE_PUBREL   :
        case MQTT_PACKET_TYPE_PUBCOMP  :
            *pp_dst = (void *) &mctx->recv_pkt_qos2.pub_resp;
            break; 
        case MQTT_PACKET_TYPE_SUBACK   :
            *pp_dst = (void *) &mctx->recv_pkt.suback;
            break; 
        case MQTT_PACKET_TYPE_UNSUBACK :
            *pp_dst = (void *) &mctx->recv_pkt.unsuback;
            break; 
        case MQTT_PACKET_TYPE_PINGREQ  :
            break; 
        case MQTT_PACKET_TYPE_PINGRESP :
            break; 
        case MQTT_PACKET_TYPE_AUTH     :
            *pp_dst = (void *) &mctx->recv_pkt.auth ;
            break; 
        default:
            *pp_dst = NULL;
            status  = MQTT_RESP_ERR_CTRL_PKT_TYPE;
            break;
    } // end of switch-case statement
    return  status;
} // end of mqttSelectStructRecvPkt



static mqttRespStatus   mqttSharedSubsChk( byte is_allow_shr_subs, byte *filter_data, word16 filter_len, mqttReasonCode *reason_code  )
{
    mqttRespStatus    status = MQTT_RESP_OK;
    if( XSTRNCMP((void *)filter_data, "$share/" , 7) == 0 ) {
        if(is_allow_shr_subs == 0) {
            *reason_code = MQTT_REASON_SS_NOT_SUPPORTED;
            status  = MQTT_RESP_INVALID_TOPIC;
        }
        else {
            byte  *lvl_sep_2 = NULL;
            // this shared subscription topic filter should include 2nd level seperator
            lvl_sep_2 = XMEMCHR( &filter_data[7], MQTT_TOPIC_LEVEL_SEPERATOR, (filter_len - 7));
            if(lvl_sep_2 == NULL || lvl_sep_2 == &filter_data[7]) {
                status = MQTT_RESP_INVALID_TOPIC;
            }
        } // end of checking topic filter string with respect to shared subscription
    }
    return status;
} // end of mqttSharedSubsChk



static mqttRespStatus   mqttTopicWildcardChk( byte is_allow_wc, byte *filter_data, word16 filter_len, mqttReasonCode *reason_code )
{
    mqttRespStatus    status = MQTT_RESP_OK;
    byte *mlvl_wildcard = XMEMCHR(filter_data, MQTT_TOPIC_LEVEL_MULTI,  filter_len);
    byte *slvl_wildcard = XMEMCHR(filter_data, MQTT_TOPIC_LEVEL_SINGLE, filter_len);

    if (is_allow_wc == 0) {
        if(mlvl_wildcard != NULL || slvl_wildcard != NULL) {
            *reason_code = MQTT_REASON_WILDCARD_SUB_NOT_SUP;
            status = MQTT_RESP_INVALID_TOPIC;
        }
    }
    else {
        if(mlvl_wildcard != NULL) {
            if( mlvl_wildcard < &filter_data[filter_len - 1] ) {
                status = MQTT_RESP_INVALID_TOPIC;
            } // '#' must be present only once, at the latest char byte of topic string
            else if((mlvl_wildcard > &filter_data[0]) && (mlvl_wildcard[-1] != MQTT_TOPIC_LEVEL_SEPERATOR)) {
                status = MQTT_RESP_INVALID_TOPIC;
            } // '#' must immediately follow the seperator  '/'
        }
        if(slvl_wildcard != NULL) { // TODO: recheck whether it's ok to use negative index
            if((slvl_wildcard[-1] != MQTT_TOPIC_LEVEL_SEPERATOR) && (slvl_wildcard > &filter_data[0])) {
                status = MQTT_RESP_INVALID_TOPIC;
            }
            else if((slvl_wildcard[1] != MQTT_TOPIC_LEVEL_SEPERATOR) && (slvl_wildcard < &filter_data[filter_len - 1])) {
                status = MQTT_RESP_INVALID_TOPIC;
            }
        }
    } // end of wildcard check
    return status;
} // end of mqttTopicWildcardChk



static mqttRespStatus   mqttSubsTopicsErrChk( mqttCtx_t *mctx, mqttPktSubs_t *subs )
{
    mqttTopic_t  *curr_topic = NULL;
    mqttRespStatus    status = MQTT_RESP_OK;
    byte             *curr_filter_data;
    word16            curr_filter_len;
    word16            idx = 0;

    for( idx=0; idx<subs->topic_cnt; idx++ ){
        curr_topic  = &subs->topics[idx];
        if(curr_topic == NULL) {
            status = MQTT_RESP_ERR_INTEGRITY;
            break;
        }
        curr_filter_data = curr_topic->filter.data;
        curr_filter_len  = curr_topic->filter.len;
        if(curr_filter_data == NULL || curr_filter_len == 0) {
            status = MQTT_RESP_ERR_INTEGRITY;
            break;
        }
        status = mqttTopicWildcardChk( mctx->flgs.wildcard_subs_avail, curr_filter_data,
                                       curr_filter_len,  &mctx->err_info.reason_code );
        if(status < 0) { break; }
        status = mqttSharedSubsChk( mctx->flgs.shr_subs_avail, curr_filter_data,
                                    curr_filter_len, &mctx->err_info.reason_code );
        if(status < 0) { break; }
    } // end of for-loop
    return status;
} // end of mqttSubsTopicsErrChk



static mqttRespStatus   mqttPubTopicErrChk( mqttCtx_t *mctx, mqttStr_t *topic_name )
{
    if((mctx==NULL) || (topic_name==NULL)) { return MQTT_RESP_ERRARGS; }
    mqttRespStatus    status = MQTT_RESP_OK;
    byte             *curr_filter_data;
    word16            curr_filter_len;

    curr_filter_data = topic_name->data;
    curr_filter_len  = topic_name->len;
    if(curr_filter_data == NULL || curr_filter_len == 0) {
        return MQTT_RESP_ERR_INTEGRITY;
    }
    status = mqttTopicWildcardChk( 0, curr_filter_data, curr_filter_len,
                                  &mctx->err_info.reason_code );
    if(status < 0) { return status; }
    status = mqttSharedSubsChk( mctx->flgs.shr_subs_avail, curr_filter_data,
                                curr_filter_len, &mctx->err_info.reason_code );
    return status;
} // end of mqttPubTopicErrChk



// initialize the  mqttCtx_t  structure
mqttRespStatus  mqttClientInit( mqttCtx_t **mctx, int cmd_timeout_ms )
{
#define  MQTT_CTX_TX_BUF_SIZE             0x100
#define  MQTT_CTX_RX_BUF_SIZE             MQTT_RECV_PKT_MAXBYTES
    mqttRespStatus  status;
    // initialize underlying system platform first.
    status = mqttSysInit();
    if(status != MQTT_RESP_OK) { return status; }
    // clear static data, we internally use it to store property data for each MQTT command
    XMEMSET( &availPropertyPool, 0x00, sizeof(mqttProp_t) * MQTT_MAX_NUM_PROPS );
    // create global structure mqttCtx_t object
    mqttCtx_t *c = NULL;
    c  =  XMALLOC( sizeof(mqttCtx_t) );
    if( c == NULL ){
        return MQTT_RESP_ERRMEM ;
    }
    XMEMSET( c, 0x00, sizeof(mqttCtx_t) );
    // TODO : the Tx / Rx buffer size should depend on transmission capability of underlying system
    c->tx_buf = XMALLOC( sizeof(byte) * MQTT_CTX_TX_BUF_SIZE );
    c->tx_buf_len = MQTT_CTX_TX_BUF_SIZE ;
    if( c->tx_buf == NULL ) {
        return MQTT_RESP_ERRMEM ;
    }
    c->rx_buf = XMALLOC( sizeof(byte) * MQTT_CTX_RX_BUF_SIZE );
    c->rx_buf_len = MQTT_CTX_RX_BUF_SIZE;
    if( c->rx_buf == NULL ) {
        return MQTT_RESP_ERRMEM ;
    }
    c->cmd_timeout_ms     = cmd_timeout_ms;
    // TODO: might need to refactor these code below, it will be used when re-connecting MQTT broker
    //       many of these state variables / flags need to be reset.
    c->max_qos_server     = MQTT_QOS_2;
    c->max_qos_client     = MQTT_QOS_2;
    // would be updated when the client receives CONNACK packet with property ID = 0x27 (max packet size)
    c->send_pkt_maxbytes  = MQTT_RECV_PKT_MAXBYTES;
    c->keep_alive_sec     = MQTT_DEFAULT_KEEPALIVE_SEC;
    c->flgs.req_probm_info  = 1;
    c->flgs.retain_avail    = 1;
    c->flgs.subs_id_avail   = 1;
    c->flgs.shr_subs_avail  = 1;
    c->flgs.wildcard_subs_avail = 1;
    *mctx  =  c;
    // TODO: create semaphores from packet send/receive operations in multithreading case.
    return  MQTT_RESP_OK;
#undef  MQTT_CTX_TX_BUF_SIZE 
#undef  MQTT_CTX_RX_BUF_SIZE 
} // end of mqttClientInit



mqttRespStatus  mqttClientDeinit( mqttCtx_t *mctx )
{
    if(mctx == NULL){ return MQTT_RESP_ERRARGS; }
    mqttCleanUpRecvpkt( mctx, MQTT_PACKET_TYPE_RESERVED );
    XMEMFREE( mctx->tx_buf );
    XMEMFREE( mctx->rx_buf );
    mctx->tx_buf = NULL;
    mctx->rx_buf = NULL;
    XMEMFREE( mctx );
    // de-initialize underlying system platform
    return  mqttSysDeInit();
} // end of  mqttClientDeinit




mqttRespStatus  mqttClientWaitPkt( mqttCtx_t *mctx, mqttCtrlPktType wait_cmdtype, word16 wait_packet_id, void **pp_recv_out )
{
    byte       *rx_buf;
    word32      rx_buf_len;
    word32      curr_rd_len = 0;

    mqttRespStatus    status ;
    mqttPktFxHead_t  *recv_header  = NULL;
    mqttCtrlPktType   recv_cmdtype = MQTT_PACKET_TYPE_RESERVED;
    word16            recv_pkt_id  = 0;
    void             *p_dst        = NULL;
    void             *p_dst_bak    = NULL; 

    rx_buf       = mctx->rx_buf;
    rx_buf_len   = mctx->rx_buf_len;
    recv_header  = (mqttPktFxHead_t *)rx_buf;

    while(1) {
        // wait until we receive packet.
        status = mqttPktRead( mctx, rx_buf, rx_buf_len, &curr_rd_len );
        if(status < 0){ return status; }
        recv_cmdtype = MQTT_CTRL_PKT_TYPE_GET(recv_header->type_flgs);
        // clean up allocated memory space last time when we received packet bytes.
        status = mqttCleanUpRecvpkt( mctx, recv_cmdtype );
        if(status < 0){ return status; }
        // select structure in mqttCtx_t to store part of received MQTT packet information.
        status = mqttSelectStructRecvPkt( mctx, recv_cmdtype, &p_dst );
        if(status < 0){ return status; }
        if(p_dst != NULL) { p_dst_bak = p_dst; }
        // start decoding the received packet
        recv_pkt_id = 0;
        status = mqttDecodePkt( mctx, rx_buf, curr_rd_len, recv_cmdtype, &p_dst, &recv_pkt_id );
        // check whether the received packet is what we're waiting for. 
        if(wait_cmdtype == recv_cmdtype) {
            if(wait_packet_id==0) { break; }
            else if(wait_packet_id==recv_pkt_id){ break; }
        }
    } // end of outer while-loop

    // when we wait for incoming PUBLISH packet with QoS = 2, p_dst should point to the data structure
    // in which we store the received entire PUBLISH packet, then we pass p_dst to output pointer pp_recv_out.
    // For few cases p_dst will be changed in the middle of the function mqttDecodePkt(), which runs decode
    // function, send subsequent PUBREC packet, then call this wait function again for incoming PUBREL packet.
    // We make a backup of the pointer for secenarios like this. 
    // TODO: find better way to implement this.
    if(pp_recv_out != NULL) {
        *pp_recv_out = ((recv_cmdtype==MQTT_PACKET_TYPE_PUBLISH && p_dst_bak!=p_dst) ? p_dst_bak:  p_dst);
    }
    return  status;
} // end of mqttClientWaitPkt





mqttProp_t*  mqttPropertyCreate( mqttProp_t **head )
{ // TODO: mutex is required in multithreading case
    mqttProp_t*  curr_node = *head;
    mqttProp_t*  prev_node = NULL;
    uint8_t      idx = 0;
    while( curr_node != NULL ) {
        prev_node = curr_node;
        curr_node = curr_node->next; 
    }
    // pick up one available node 
    for(idx=0; idx<MQTT_MAX_NUM_PROPS ; idx++) {
        if(availPropertyPool[idx].type == MQTT_PROP_NONE) {
            curr_node = &availPropertyPool[idx] ;
            break;
        }
    }
    if(curr_node != NULL){
        if(prev_node == NULL){
            *head = curr_node;
        }
        else{
            prev_node->next = curr_node; 
        }
    }
    return  curr_node;
} // end of mqttPropertyCreate




void   mqttPropertyDel( mqttProp_t *head )
{ // TODO: mutex is required in multithreading case
    mqttProp_t*  curr_prop = head;
    mqttProp_t*  next_prop = NULL;
    while( curr_prop != NULL ){
        switch( mqttQueryPropDataType[curr_prop->type] )
        {
            case MQTT_DATA_TYPE_BINARY       : 
            case MQTT_DATA_TYPE_STRING       :
                if(curr_prop->body.str.data != NULL) {
                    XMEMFREE((void *)curr_prop->body.str.data);
                    curr_prop->body.str.data = NULL;
                }
                curr_prop->body.str.len = 0;
                break;
            case MQTT_DATA_TYPE_STRING_PAIR  :
                if(curr_prop->body.strpair[0].data != NULL) {
                    XMEMFREE((void *)curr_prop->body.strpair[0].data);
                    curr_prop->body.strpair[0].data = NULL; 
                }
                if(curr_prop->body.strpair[1].data != NULL) {
                    XMEMFREE((void *)curr_prop->body.strpair[1].data);
                    curr_prop->body.strpair[1].data = NULL;
                }
                curr_prop->body.strpair[0].len = 0; 
                curr_prop->body.strpair[1].len = 0;
                break;
            default:
                curr_prop->body.u32 = 0; 
                break;
        } // end of switch-case statement
        next_prop = curr_prop->next;
        curr_prop->type = MQTT_PROP_NONE;
        curr_prop->next = NULL; 
        curr_prop = next_prop;
    } // end of loop
} // end of mqttPropertyDel



mqttRespStatus  mqttPropErrChk( mqttCtx_t *mctx,  mqttCtrlPktType cmdtype, mqttProp_t *prop_head )
{
    if(mctx == NULL) { return MQTT_RESP_ERRARGS; }
    word32            prop_present_flgs[(MQTT_PROP_MAX_ID >> 5) + 1] = {0};
    word32            rd_out_flg   = 0;
    mqttRespStatus    status       = MQTT_RESP_OK;
    mqttProp_t       *curr_prop    = NULL;

    // TODO: should we give further error information for each property ?
    for( curr_prop = prop_head; curr_prop != NULL ; curr_prop = curr_prop->next ) 
    {   // PART 1 : check number of times the property is present in current list.
        word32            present_flg   = 0;
        mqttPropertyType  proptype      = curr_prop->type;
        XBIT_READ(prop_present_flgs[proptype >> 5], proptype & 0x1f, 0x1, present_flg);
        if( present_flg == 0x1 ) {
            switch(proptype) {
                case MQTT_PROP_USER_PROPERTY:
                    break;
                case MQTT_PROP_SUBSCRIBE_ID:
                    if(cmdtype == MQTT_PACKET_TYPE_PUBLISH) { break; }
                default : // any other property cannot be present more than once
                    mctx->err_info.prop_id  = proptype;
                    mctx->err_info.reason_code = MQTT_REASON_PROTOCOL_ERR;
                    return  MQTT_RESP_ERR_PROP_REPEAT;
            } // end of switch-case statement
        }
        else{
            XBIT_SET( prop_present_flgs[proptype >> 5], proptype & 0x1f, 0x1 );
        }
        // PART 2 : check content integrity of each property
        switch(mqttQueryPropDataType[proptype])
        {
            case MQTT_DATA_TYPE_BINARY       : 
            case MQTT_DATA_TYPE_STRING       :
                if(curr_prop->body.str.data == NULL || curr_prop->body.str.len == 0) {
                    status = MQTT_RESP_ERR_INTEGRITY;
                }
                break;
            case MQTT_DATA_TYPE_STRING_PAIR  :
                if(curr_prop->body.strpair[0].data == NULL || curr_prop->body.strpair[0].len == 0) {
                    status = MQTT_RESP_ERR_INTEGRITY;  break;
                }
                if(curr_prop->body.strpair[1].data == NULL || curr_prop->body.strpair[1].len == 0) {
                    status = MQTT_RESP_ERR_INTEGRITY;
                }
                break;
            case MQTT_DATA_TYPE_VAR_INT      :
                if((curr_prop->body.u32 >> 28) != 0) {
                    status = MQTT_RESP_ERR_PROP;
                } // it means the variable-byte integer exceeds the its limit 0xfffffff , 2^28 bytes.
                break;
            default : 
                break;
        } // end of switch-case statement
        if( status < 0 ){
            mctx->err_info.prop_id  = proptype;
            return status; 
        }
        // PART 3: check acceptable value in each property
        switch(proptype)
        {
            case MQTT_PROP_MSG_EXPIRY_INTVL      :
            case MQTT_PROP_CONTENT_TYPE          :
            case MQTT_PROP_CORRELATION_DATA      :
            case MQTT_PROP_SESSION_EXPIRY_INTVL  :
            case MQTT_PROP_ASSIGNED_CLIENT_ID    :
            case MQTT_PROP_AUTH_METHOD           :
            case MQTT_PROP_AUTH_DATA             :
            case MQTT_PROP_WILL_DELAY_INTVL      :
            case MQTT_PROP_RESP_INFO             :
            case MQTT_PROP_SERVER_REF            :
            case MQTT_PROP_USER_PROPERTY         :
                break;
            case MQTT_PROP_SERVER_KEEP_ALIVE     :
                mctx->keep_alive_sec = curr_prop->body.u16;
                break;
            case MQTT_PROP_TOPIC_ALIAS_MAX: 
                // TODO: better NOT to modify context at here below, find another better way to do so
                if(cmdtype == MQTT_PACKET_TYPE_CONNECT) {
                    mctx->recv_topic_alias_max = curr_prop->body.u16;
                }
                else if(cmdtype == MQTT_PACKET_TYPE_CONNACK){
                    mctx->send_topic_alias_max = curr_prop->body.u16;
                }
                break;
            case MQTT_PROP_TOPIC_ALIAS :
            { 
                word16 alias_max = (mctx->flgs.recv_mode == 0 ? mctx->send_topic_alias_max : mctx->recv_topic_alias_max);
                if(alias_max < curr_prop->body.u16 || curr_prop->body.u16 == 0) {
                    mctx->err_info.reason_code = MQTT_REASON_TOPIC_ALIAS_INVALID;
                    status = MQTT_RESP_ERR_PROP;
                }
                break;
            }
            case MQTT_PROP_RECV_MAX :
                if(curr_prop->body.u16 == 0) {
                    mctx->err_info.reason_code = MQTT_REASON_PROTOCOL_ERR;
                    status = MQTT_RESP_ERR_PROP;
                }
                break;
            case MQTT_PROP_MAX_PKT_SIZE     :
                if(curr_prop->body.u32 == 0) {
                    mctx->err_info.reason_code = MQTT_REASON_PROTOCOL_ERR;
                    status = MQTT_RESP_ERR_PROP;
                }
                if(curr_prop->body.u32 > MQTT_RECV_PKT_MAXBYTES && cmdtype == MQTT_PACKET_TYPE_CONNECT) {
                    // we only consider implementation on client side in this project, so we report this
                    // error only before the property is encoded within CONNECT packet on client side.
                    mctx->err_info.reason_code = MQTT_REASON_RX_MAX_EXCEEDED;
                    status = MQTT_RESP_ERR_PROP;
                }
                if(curr_prop->body.u32 > MQTT_PROTOCOL_PKT_MAXBYTES && cmdtype == MQTT_PACKET_TYPE_CONNACK) {
                    // for server side, we simply check whether this number exceeds the limit in protocol.
                    mctx->err_info.reason_code = MQTT_REASON_PROTOCOL_ERR;
                    status = MQTT_RESP_ERR_PROP;
                }
                break;
            case MQTT_PROP_RETAIN_AVAILABLE:
                if(curr_prop->body.u8 < 2) {
                    mctx->flgs.retain_avail = curr_prop->body.u8;
                    break;
                }// .... fall through ....
            case MQTT_PROP_WILDCARD_SUBS_AVAIL   : 
                if(curr_prop->body.u8 < 2) {
                    mctx->flgs.wildcard_subs_avail  = curr_prop->body.u8;
                    break;
                }// .... fall through ....
            case MQTT_PROP_SUBSCRIBE_ID_AVAIL    : 
                if(curr_prop->body.u8 < 2) {
                    mctx->flgs.subs_id_avail  = curr_prop->body.u8;
                    break;
                }// .... fall through ....
            case MQTT_PROP_SHARE_SUBSCRIBE_AVAIL : 
                if(curr_prop->body.u8 < 2) {
                    mctx->flgs.shr_subs_avail = curr_prop->body.u8;
                    break;
                }// .... fall through ....
            case MQTT_PROP_MAX_QOS:
                if(curr_prop->body.u8 < MQTT_QOS_2) {
                    mctx->max_qos_server = curr_prop->body.u8; 
                    break;
                } // .... fall through ....
            case MQTT_PROP_REQ_RESP_INFO:
                if(curr_prop->body.u8 < 2) {
                    mctx->flgs.req_resp_info  = curr_prop->body.u8;
                    break;
                } // .... fall through ....
            case MQTT_PROP_REQ_PROBLEM_INFO :
                if(curr_prop->body.u8 < 2) {
                    mctx->flgs.req_probm_info = curr_prop->body.u8;
                    break;
                } // .... fall through ....
            case MQTT_PROP_PKT_FMT_INDICATOR     : // TODO: refactor the code here
                if(curr_prop->body.u8 >= 2) {
                    mctx->err_info.reason_code = MQTT_REASON_PROTOCOL_ERR;
                    status = MQTT_RESP_ERR_PROP;
                } // these properties must be either 0 or 1
                break;
            case MQTT_PROP_REASON_STR:
                // if request problem information property is applied, then we must ensure there are no reason
                // string included in a packet other than CONNACK, DISCONNECT, and PUBLISH
                if(mctx->flgs.req_probm_info == 0) {
                    switch(cmdtype) {
                        case MQTT_PACKET_TYPE_AUTH: 
                        case MQTT_PACKET_TYPE_CONNACK    :
                        case MQTT_PACKET_TYPE_PUBLISH    :
                        case MQTT_PACKET_TYPE_DISCONNECT :
                            break;
                        default:
                            mctx->err_info.reason_code = MQTT_REASON_PROTOCOL_ERR;
                            status = MQTT_RESP_ERR_PROP;
                    }
                }
                break;
            case MQTT_PROP_SUBSCRIBE_ID          :
                if( mctx->flgs.subs_id_avail == 0) {
                    mctx->err_info.reason_code = MQTT_REASON_SUB_ID_NOT_SUP;
                    status = MQTT_RESP_ERR_PROP;
                }
                else if( mctx->flgs.recv_mode == 0 && cmdtype == MQTT_PACKET_TYPE_PUBLISH )
                { // a PUBLISH packet sent from client to server MUST NOT contain subscription identifier
                    mctx->err_info.reason_code = MQTT_REASON_PROTOCOL_ERR;
                    status = MQTT_RESP_ERR_PROP;
                }
                else if(curr_prop->body.u32 == 0) {
                    mctx->err_info.reason_code = MQTT_REASON_PROTOCOL_ERR;
                    status = MQTT_RESP_ERR_PROP;
                }
                break;
            case MQTT_PROP_RESP_TOPIC : // if wildcard is found, report error
                status = mqttTopicWildcardChk( 0, curr_prop->body.str.data, curr_prop->body.str.len, 
                                               &mctx->err_info.reason_code );
                break;
            default : 
                mctx->err_info.reason_code = MQTT_REASON_MALFORMED_PACKET;
                status = MQTT_RESP_ERR_PROP;
        } // end of switch-case statement
        if( status < 0 ){
            mctx->err_info.prop_id  = proptype;
            return status;
        }
    } // end of for-loop

    // PART 4 :
    switch(cmdtype) {
        case MQTT_PACKET_TYPE_CONNECT:
        case MQTT_PACKET_TYPE_AUTH:
            // if enhanced authentication is enabled, then we must ensure authentication callback
            // is set, so users can handle different types of authentication operations through the callback.
            XBIT_READ( prop_present_flgs[MQTT_PROP_AUTH_METHOD >> 5], MQTT_PROP_AUTH_METHOD & 0x1f, 0x2, rd_out_flg  );
            if(rd_out_flg == 0x3){
                if(mctx->eauth_setup_cb == NULL || mctx->eauth_final_cb == NULL){
                    status = MQTT_RESP_ERR_INTEGRITY; // implementation error, callback must be set.
                }
            }
            else if(rd_out_flg == 0x0){
                // do nothing here, no enhanced authentication in the CONNECT packet 
            }
            else { // for all other cases e.g. flag = 0x1 or 0x2, it should be protocol error
                mctx->err_info.prop_id  = ( rd_out_flg == 0x2 ? MQTT_PROP_AUTH_METHOD : MQTT_PROP_AUTH_DATA);
                mctx->err_info.reason_code = MQTT_REASON_PROTOCOL_ERR;
                status = MQTT_RESP_ERR_PROP;
            }
            break;
        default : 
            break;
    } //  end of switch-case statement
    return status;
} // end of mqttPropErrChk




mqttRespStatus  mqttSendConnect( mqttCtx_t *mctx, mqttPktHeadConnack_t **connack_out )
{
    byte            *tx_buf;
    word32           tx_buf_len;
    int              pkt_total_len;
    mqttRespStatus   status ;
    mqttConn_t      *conn = NULL;

    if( mctx == NULL ){ return MQTT_RESP_ERRARGS;  }
    conn  = &mctx->send_pkt.conn;
    mctx->flgs.recv_mode  = 0;
    // check whether all the properties are set properly.
    status = mqttPropErrChk( mctx, MQTT_PACKET_TYPE_CONNECT, conn->props );
    if(status < 0) { return status; }
    tx_buf     =  mctx->tx_buf;
    tx_buf_len =  mctx->tx_buf_len;

    pkt_total_len = mqttGetPktLenConnect( conn, mctx->send_pkt_maxbytes );
    if(pkt_total_len < 0) { // could return error code defined in
        return  (mqttRespStatus)pkt_total_len;
    }
    else if(pkt_total_len == 0) {
        return  MQTT_RESP_MALFORMED_DATA;
    }
    else if(pkt_total_len > tx_buf_len){
        tx_buf = (byte *)XMALLOC( sizeof(byte) * pkt_total_len );
    }
    mqttEncodePktConnect( tx_buf, pkt_total_len, conn );
    status = mqttPktWrite( mctx, tx_buf, pkt_total_len );
    // free the extra allocated space before we check result state
    if(pkt_total_len > tx_buf_len){ XMEMFREE((void *)tx_buf); }
    mctx->last_send_cmdtype = MQTT_PACKET_TYPE_CONNECT;
    if( status < 0 ) { return status; }
    status = mqttClientWaitPkt( mctx, MQTT_PACKET_TYPE_CONNACK, 0,  (void **)connack_out );
    return  status;
} // end of mqttSendConnect



// users MUST NOT directly call this function, this function is ONLY for internal use
mqttRespStatus  mqttSendAuth( mqttCtx_t *mctx )
{
    byte            *tx_buf;
    word32           tx_buf_len;
    int              pkt_total_len;
    mqttRespStatus   status ;
    mqttAuth_t      *auth_recv = NULL;
    mqttAuth_t      *auth_send = NULL;
    mqttProp_t      *auth_recv_mthd = NULL;
    mqttProp_t      *auth_recv_data = NULL;
    mqttProp_t      *auth_send_mthd = NULL;
    mqttProp_t      *auth_send_data = NULL;
    mqttProp_t      *auth_send_reason_str = NULL;
    mqttStr_t        reason_str = {0, NULL};

    if( mctx == NULL ){ return MQTT_RESP_ERRARGS; }
    else if(mctx->eauth_final_cb == NULL){ return MQTT_RESP_ERRARGS; }
    else if(mctx->eauth_setup_cb == NULL){ return MQTT_RESP_ERRARGS; }
    // get auth method & data that previously received, the information could
    // be referred to this AUTH packet
    auth_recv  = &mctx->recv_pkt.auth;
    auth_recv_mthd = mqttGetPropByType( auth_recv->props, MQTT_PROP_AUTH_METHOD );
    auth_recv_data = mqttGetPropByType( auth_recv->props, MQTT_PROP_AUTH_DATA )  ;
    if(auth_recv_mthd == NULL){ return MQTT_RESP_ERR_PROP; }
    if(auth_recv_data == NULL){ return MQTT_RESP_ERR_PROP; }

    auth_send  = &mctx->send_pkt.auth;
    auth_send->props = NULL;
    auth_send_mthd  = mqttPropertyCreate( &auth_send->props );
    auth_send_data  = mqttPropertyCreate( &auth_send->props );
    if(auth_send_mthd == NULL) { mqttPropertyDel(auth_send->props);  return MQTT_RESP_ERRMEM; }
    if(auth_send_data == NULL) { mqttPropertyDel(auth_send->props);  return MQTT_RESP_ERRMEM; }
    // run callback to fill in  authentication method / data .
    // NOTE: the callback callee must handle memory management on their own 
    //       (e.g. free & allocate in user application, this MQTT implementation
    //        will NOT help to do that )
    mctx->eauth_setup_cb(  &auth_recv_data->body.str, &auth_send_data->body.str, &reason_str );
    // reason string is optional in AUTH packet
    if((reason_str.data != NULL) && (reason_str.len > 0)) {
        auth_send_reason_str = mqttPropertyCreate( &auth_send->props );
        if(auth_send_reason_str == NULL) { mqttPropertyDel(auth_send->props);  return MQTT_RESP_ERRMEM; }
        auth_send_reason_str->type = MQTT_PROP_REASON_STR;
        auth_send_reason_str->body.str.data = reason_str.data;
        auth_send_reason_str->body.str.len  = reason_str.len;
    }
    // copy authentication method from previous AUTH packet, to this AUTH packet which is ready to send
    // it's mandatory in MQTT v5 protocol.
    auth_send_mthd->body.str.data = auth_recv_mthd->body.str.data ; // TODO: recheck to avoid memory leak issues
    auth_send_mthd->body.str.len  = auth_recv_mthd->body.str.len ;
    auth_send_mthd->type   = MQTT_PROP_AUTH_METHOD;
    auth_send_data->type   = MQTT_PROP_AUTH_DATA;
    auth_send->reason_code = MQTT_REASON_CNTNU_AUTH;

    mctx->flgs.recv_mode  = 0;
    status = mqttPropErrChk( mctx, MQTT_PACKET_TYPE_AUTH, auth_send->props );
    if(status < 0) { return status; }

    tx_buf     =  mctx->tx_buf;
    tx_buf_len =  mctx->tx_buf_len;

    pkt_total_len  = mqttGetPktLenAuth( auth_send, mctx->send_pkt_maxbytes );
    if(pkt_total_len < 0) { // could return error code defined in 
        return  (mqttRespStatus)pkt_total_len;
    }
    else if(pkt_total_len == 0) {
        return  MQTT_RESP_MALFORMED_DATA;
    }
    else if(pkt_total_len > tx_buf_len){
        tx_buf = (byte *)XMALLOC( sizeof(byte) * pkt_total_len );
    }
    mqttEncodePktAuth( tx_buf, pkt_total_len, auth_send );
    status = mqttPktWrite( mctx, tx_buf, pkt_total_len );
    // free the extra allocated space before we check result state
    if(pkt_total_len > tx_buf_len){ XMEMFREE((void *)tx_buf); }
    mctx->last_send_cmdtype = MQTT_PACKET_TYPE_AUTH;
    // run finalize callback after sending out the AUTH packet
    mctx->eauth_final_cb( &auth_send_data->body.str,  &reason_str );
    // note that the next received packet will be either another AUTH packet or CONNACK packet,
    // since this function mqttSendAuth() is internally called in the loop of mqttClientWaitPkt()
    // , we'll simply return back to that loop and wait for next incoming packet at there.
    return status;
} // end of mqttSendAuth



mqttRespStatus  mqttSendDisconnect( mqttCtx_t *mctx )
{
    if( mctx == NULL ){ return MQTT_RESP_ERRARGS; }
    mqttRespStatus  status ;
    byte     *tx_buf;
    word32    tx_buf_len;
    int       pkt_total_len;
    mqttPktDisconn_t  *disconn = NULL;

    mctx->flgs.recv_mode  = 0;
    disconn    = &mctx->send_pkt.disconn;
    status     = mqttPropErrChk( mctx, MQTT_PACKET_TYPE_DISCONNECT, disconn->props );
    if( status < 0 ) { return status; }

    tx_buf     = mctx->tx_buf;
    tx_buf_len = mctx->tx_buf_len;
    pkt_total_len  = mqttGetPktLenDisconn( disconn, mctx->send_pkt_maxbytes );
    if(pkt_total_len < 0) { // could return error code defined in 
        return  (mqttRespStatus)pkt_total_len;
    }
    else if(pkt_total_len == 0) {
        return  MQTT_RESP_MALFORMED_DATA;
    }
    else if(pkt_total_len > tx_buf_len){
        tx_buf = (byte *)XMALLOC( sizeof(byte) * pkt_total_len );
    }
    mqttEncodePktDisconn( tx_buf, pkt_total_len, disconn );
    status = mqttPktWrite( mctx, tx_buf, pkt_total_len );
    // free the extra allocated space before we check result state
    if(pkt_total_len > tx_buf_len){ XMEMFREE((void *)tx_buf); }
    mctx->last_send_cmdtype = MQTT_PACKET_TYPE_DISCONNECT;
    return  status;
} // end of  mqttSendDisconnect



#define  MQTT_PUBLISH_QOS1_PKT_MAX_SEND  0x3
mqttRespStatus  mqttSendPublish( mqttCtx_t *mctx, mqttPktPubResp_t **pubresp_out )
{
    byte             *tx_buf;
    word32            tx_buf_len;
    int               pkt_total_len;
    mqttMsg_t        *msg = NULL;
    mqttQoS           qos;
    mqttCtrlPktType   wait_cmdtype;
    mqttRespStatus    status;
    byte              repeat_send = 0; // only for QoS = 1

    if( mctx == NULL ){ 
        return MQTT_RESP_ERRARGS;
    }
    qos = mctx->send_pkt.pub_msg.qos;
    if(qos > mctx->max_qos_server) {
        mctx->err_info.reason_code = MQTT_REASON_QOS_NOT_SUPPORTED;
        return MQTT_RESP_ERRARGS;
    }
    else if( mctx->send_pkt.pub_msg.retain==1 && mctx->flgs.retain_avail==0 ) {
        return MQTT_RESP_ERRARGS;
    }

    mctx->flgs.recv_mode  = 0;
    msg    = &mctx->send_pkt.pub_msg;
    status = mqttPubTopicErrChk( mctx, &msg->topic );
    if( status < 0 ) { return status; }
    status = mqttPropErrChk( mctx, MQTT_PACKET_TYPE_PUBLISH, msg->props );
    if( status < 0 ) { return status; }

    tx_buf         =  mctx->tx_buf;
    tx_buf_len     =  mctx->tx_buf_len;
    // abort packet transmission when something goes wrong in underlying system functions
    while(1) 
    {
        msg->packet_id = msg->qos > MQTT_QOS_0 ? mqttGetPktID() : 0;
        pkt_total_len = mqttGetPktLenPublish( msg, mctx->send_pkt_maxbytes );
        if(pkt_total_len < 0) { // could return error code defined in 
            status = (mqttRespStatus)pkt_total_len;
            break;
        }
        else if(pkt_total_len == 0) {
            status = MQTT_RESP_MALFORMED_DATA;
            break;
        }
        else if(pkt_total_len > tx_buf_len){
            tx_buf = (byte *)XMALLOC( sizeof(byte) * pkt_total_len );
        }
        mqttEncodePktPublish( tx_buf, pkt_total_len, msg );
        status = mqttPktWrite( mctx, tx_buf, pkt_total_len );
        // free the extra allocated space before we check result state
        if(pkt_total_len > tx_buf_len){ XMEMFREE((void *)tx_buf); }
        mctx->last_send_cmdtype = MQTT_PACKET_TYPE_PUBLISH;
        if( status < 0 ) { return status; }

        // TODO: clean up members of mctx->send_pkt.pub_msg before following if-statement
        if(qos > MQTT_QOS_0) {
            wait_cmdtype = (qos==MQTT_QOS_1) ? MQTT_PACKET_TYPE_PUBACK: MQTT_PACKET_TYPE_PUBRECV;
            // implement qos=1 or 2 wait for response packet
            status = mqttClientWaitPkt( mctx, wait_cmdtype, msg->packet_id, (void **)pubresp_out );
            if(status < 0) { break; }
        }
        if((qos == MQTT_QOS_1) && (status == MQTT_RESP_TIMEOUT) && (repeat_send < MQTT_PUBLISH_QOS1_PKT_MAX_SEND)) {
            // we send PUBLISH packet again if QoS = 1 and we didn't get PUBACK from the
            // broker after a period of time passed.
            repeat_send++;
            msg->duplicate = 1;
        }
        else {
           // for QoS = 0 delivery procotol, this publisher shot and forgot, it never
           // checks whether receiver really got this published message.
           // for QoS = 2 delivery procotol, this publisher will send PUBREL in
           // mqttDecodePkt() immediately after receiving PUBRECV, then wait for 
           // PUBCOMP packet, the publisher will NOT send PUBLISH packet again.
           break;
        }
    } // end of outer while-loop
    return status;
} // end of mqttSendPublish
#undef  MQTT_PUBLISH_QOS1_PKT_MAX_SEND




mqttRespStatus  mqttSendPubResp( mqttCtx_t *mctx, mqttCtrlPktType cmdtype, mqttPktPubResp_t  **pubresp_out )
{
    byte        *tx_buf;
    word32       tx_buf_len;
    int          pkt_total_len;
    mqttPktPubResp_t  *pub_resp = NULL;
    mqttRespStatus     status;

    if( mctx == NULL ){  return MQTT_RESP_ERRARGS; }
    switch(cmdtype) {
        case MQTT_PACKET_TYPE_PUBACK   :   
        case MQTT_PACKET_TYPE_PUBRECV  :   
            pub_resp  = &mctx->send_pkt.pub_resp;
            break;
        case MQTT_PACKET_TYPE_PUBREL   :   
        case MQTT_PACKET_TYPE_PUBCOMP  :
            pub_resp  = &mctx->send_pkt_qos2.pub_resp;
            break;
        default: 
            return MQTT_RESP_ERRARGS;
    }
    mctx->flgs.recv_mode  = 0;
    status    = mqttPropErrChk( mctx, cmdtype, pub_resp->props );
    if( status < 0 ) { return status; }

    tx_buf         =  mctx->tx_buf;
    tx_buf_len     =  mctx->tx_buf_len;
    pkt_total_len  = mqttGetPktLenPubResp( pub_resp, mctx->send_pkt_maxbytes ); 
    if(pkt_total_len < 0) { // could return error code defined in 
        return  (mqttRespStatus)pkt_total_len;
    }
    else if(pkt_total_len == 0) {
        return  MQTT_RESP_MALFORMED_DATA;
    }
    else if(pkt_total_len > tx_buf_len){
        tx_buf = (byte *)XMALLOC( sizeof(byte) * pkt_total_len );
    }
    mqttEncodePktPubResp( tx_buf, pkt_total_len, pub_resp, cmdtype );
    status = mqttPktWrite( mctx, tx_buf, pkt_total_len );
    // free the extra allocated space before we check result state
    if(pkt_total_len > tx_buf_len){ XMEMFREE((void *)tx_buf); }
    mctx->last_send_cmdtype = cmdtype;
    if( status < 0 ){ return status; }
    if((cmdtype==MQTT_PACKET_TYPE_PUBRECV) || (cmdtype==MQTT_PACKET_TYPE_PUBREL)) 
    { // wait for subsequent response if QoS = 2
        word16  packet_id = pub_resp->packet_id;
        status = mqttClientWaitPkt( mctx, (cmdtype + 1), packet_id, (void **)pubresp_out );
    }
    return status;
} // end of mqttSendPubResp



mqttRespStatus   mqttSendSubscribe( mqttCtx_t *mctx, mqttPktSuback_t  **suback_out )
{
    byte            *tx_buf;
    word32           tx_buf_len;
    int              pkt_total_len;
    mqttRespStatus   status;

    if( mctx == NULL ){ return MQTT_RESP_ERRARGS; }
    mqttPktSubs_t *subs = &mctx->send_pkt.subs ;
    // there must be at least one topic to subscribe
    if((subs->topics == NULL) || (subs->topic_cnt == 0) || (subs->topic_cnt >= MQTT_RECV_PKT_MAXBYTES)) {
        mctx->err_info.reason_code = MQTT_REASON_PROTOCOL_ERR;
        return MQTT_RESP_INVALID_TOPIC;
    }
    mctx->flgs.recv_mode  = 0;
    status = mqttSubsTopicsErrChk( mctx, subs );
    if(status < 0) { return status; }
    status = mqttPropErrChk( mctx, MQTT_PACKET_TYPE_SUBSCRIBE, subs->props );
    if( status < 0 ) { return status; }

    subs->packet_id = mqttGetPktID();
    tx_buf         =  mctx->tx_buf;
    tx_buf_len     =  mctx->tx_buf_len;
    pkt_total_len  =  mqttGetPktLenSubscribe( subs, mctx->send_pkt_maxbytes );
    if(pkt_total_len < 0) { // could return error code defined in 
        return  (mqttRespStatus)pkt_total_len;
    }
    else if(pkt_total_len == 0) {
        return  MQTT_RESP_MALFORMED_DATA;
    }
    else if(pkt_total_len > tx_buf_len){
        tx_buf = (byte *)XMALLOC( sizeof(byte) * pkt_total_len );
    }
    mqttEncodePktSubscribe( tx_buf, pkt_total_len, subs );
    status = mqttPktWrite( mctx, tx_buf, pkt_total_len );
    // free the extra allocated space before we check result state
    if(pkt_total_len > tx_buf_len){ XMEMFREE((void *)tx_buf); }
    mctx->last_send_cmdtype = MQTT_PACKET_TYPE_SUBSCRIBE;
    if( status < 0 ) { return status; }
    status = mqttClientWaitPkt( mctx, MQTT_PACKET_TYPE_SUBACK, subs->packet_id, 
                                (void **)suback_out );
    return status;
} // end of mqttSendSubscribe




mqttRespStatus  mqttSendUnsubscribe( mqttCtx_t *mctx, mqttPktUnsuback_t  **unsuback_out)
{
    byte        *tx_buf;
    word32       tx_buf_len;
    int          pkt_total_len;
    mqttRespStatus   status;

    if( mctx == NULL ){  return MQTT_RESP_ERRARGS;  }
    mqttPktUnsubs_t *unsubs = &mctx->send_pkt.unsubs ;
    // there must be at least one topic to unsubscribe
    if((unsubs->topics == NULL) || (unsubs->topic_cnt == 0) || (unsubs->topic_cnt >= MQTT_RECV_PKT_MAXBYTES)) {
        mctx->err_info.reason_code = MQTT_REASON_PROTOCOL_ERR;
        return MQTT_RESP_INVALID_TOPIC;
    }
    mctx->flgs.recv_mode  = 0;
    status = mqttSubsTopicsErrChk( mctx, (mqttPktSubs_t *)unsubs );
    if(status < 0) { return status; }
    status = mqttPropErrChk( mctx,  MQTT_PACKET_TYPE_UNSUBSCRIBE, unsubs->props );
    if( status < 0 ) { return status; }

    unsubs->packet_id = mqttGetPktID();
    tx_buf         =  mctx->tx_buf;
    tx_buf_len     =  mctx->tx_buf_len;
    pkt_total_len  =  mqttGetPktLenUnsubscribe( unsubs, mctx->send_pkt_maxbytes );
    if(pkt_total_len < 0) { // could return error code defined in 
        return  (mqttRespStatus)pkt_total_len;
    }
    else if(pkt_total_len == 0) {
        return  MQTT_RESP_MALFORMED_DATA;
    }
    else if(pkt_total_len > tx_buf_len){
        tx_buf = (byte *)XMALLOC( sizeof(byte) * pkt_total_len );
    }
    mqttEncodePktUnsubscribe( tx_buf, pkt_total_len, unsubs );
    status = mqttPktWrite( mctx, tx_buf, pkt_total_len );
    // free the extra allocated space before we check result state
    if(pkt_total_len > tx_buf_len){ XMEMFREE((void *)tx_buf); }
    mctx->last_send_cmdtype = MQTT_PACKET_TYPE_UNSUBSCRIBE;
    if(status < 0) { return status; }
    status = mqttClientWaitPkt( mctx, MQTT_PACKET_TYPE_UNSUBACK, unsubs->packet_id , 
                                (void **)unsuback_out );
    return status;
} // end of mqttSendUnsubscribe



