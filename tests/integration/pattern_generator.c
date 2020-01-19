#include "pattern_generator.h"


static mqttPropertyType connectPropTypeList[] = {
    MQTT_PROP_SESSION_EXPIRY_INTVL ,
    MQTT_PROP_RECV_MAX             ,
    MQTT_PROP_MAX_PKT_SIZE         ,
    MQTT_PROP_TOPIC_ALIAS_MAX      ,
    MQTT_PROP_REQ_RESP_INFO        ,
    MQTT_PROP_REQ_PROBLEM_INFO     ,
    MQTT_PROP_USER_PROPERTY        ,
    MQTT_PROP_USER_PROPERTY        ,
    //// MQTT_PROP_AUTH_METHOD     , // TODO: implement & test enhanced authentication, which is optional.
    //// MQTT_PROP_AUTH_DATA       ,
};


static mqttPropertyType willPropTypeList[] = {
    MQTT_PROP_WILL_DELAY_INTVL   ,
    MQTT_PROP_PKT_FMT_INDICATOR  ,
    MQTT_PROP_MSG_EXPIRY_INTVL   ,
    MQTT_PROP_CONTENT_TYPE       ,
    MQTT_PROP_RESP_TOPIC         ,
    // MQTT_PROP_CORRELATION_DATA   ,
    MQTT_PROP_USER_PROPERTY      ,
    MQTT_PROP_USER_PROPERTY      ,
};


static mqttPropertyType publishPropTypeList[] = {
    MQTT_PROP_PKT_FMT_INDICATOR    ,
    MQTT_PROP_MSG_EXPIRY_INTVL     ,
    MQTT_PROP_CONTENT_TYPE         ,
    MQTT_PROP_RESP_TOPIC           ,
    // MQTT_PROP_CORRELATION_DATA     ,
    // MQTT_PROP_SUBSCRIBE_ID         , // refer to MQTT-3.3.4-6
    MQTT_PROP_TOPIC_ALIAS          ,
    MQTT_PROP_USER_PROPERTY        ,
    MQTT_PROP_USER_PROPERTY        ,
};


static mqttPropertyType subscribePropTypeList[] = {
    MQTT_PROP_SUBSCRIBE_ID         ,
    MQTT_PROP_USER_PROPERTY        ,
    MQTT_PROP_USER_PROPERTY        ,
};


static mqttPropertyType unsubscribePropTypeList[] = {
    MQTT_PROP_USER_PROPERTY        ,
    MQTT_PROP_USER_PROPERTY        ,
};


static mqttPropertyType disconnPropTypeList[] = {
    MQTT_PROP_REASON_STR           ,
    MQTT_PROP_USER_PROPERTY        ,
    MQTT_PROP_USER_PROPERTY        ,
};




static void mqttTestRandGenStr( mqttDRBG_t *drbg, byte* dst, word16 len )
{
    mqttUtilRandByteSeq(drbg, dst, len);
    word16 idx = 0;
    byte   tmpc = 0;
    for(idx = 0; idx < len; idx++) {
        // recheck that every byte ranges from 0x30 t0 0x7a in ASCII code
        tmpc = dst[idx];
        if((tmpc < 0x30) || (tmpc > 0x7a)) {
            dst[idx] = 0x30 + (tmpc % 0x4a);
        }
    } // end of for-loop
} // end of mqttTestRandGenStr



// the 4 x 4 matrix array provides topic name selections at all levels in this test
#define  MQTT_TEST_TOPIC_LVL_NAMES_ARRAY_LENGTH  4
static const mqttStr_t mqttTestTopicLevelName[MQTT_TEST_TOPIC_LVL_NAMES_ARRAY_LENGTH][MQTT_TEST_TOPIC_LVL_NAMES_ARRAY_LENGTH] = {
    { //  topic name selection at level 0 
        { 10, (byte *)&("dev_status")  },
        { 7 , (byte *)&("control"   )  },
        { 6 , (byte *)&("report"    )  },
        { 4 , (byte *)&("ping"      )  },
    },
    { //  topic name selection at level 1 
        { 9 , (byte *)&("apartment" )  },
        { 6 , (byte *)&("studio"    )  },
        { 10, (byte *)&("greenhouse")  },
        { 9 , (byte *)&("warehouse" )  },
    },
    { //  topic name selection at level 2 
        { 5 , (byte *)&("light"      )  },
        { 11, (byte *)&("temperature")  },
        { 8 , (byte *)&("humidity"   )  },
        { 3 , (byte *)&("co2"        )  },
    },
    { //  topic name selection at level 3 
        { 3 , (byte *)&("now"        )  },
        { 11, (byte *)&("last_record")  },
        { 9 , (byte *)&("last30min"  )  },
        { 9 , (byte *)&("last3hour"  )  },
    },
}; // end of mqttTestTopicLevelName


    
static mqttRespStatus mqttTestRandGenTopic( mqttDRBG_t *drbg, mqttStr_t *topic )
{
    mqttRespStatus  status = MQTT_RESP_OK;
    uint8_t   chosen_name_idx[MQTT_TEST_TOPIC_LVL_NAMES_ARRAY_LENGTH];
    uint8_t   num_seperator = 0;
    uint8_t   idx  = 0;
    byte     *dst  = NULL;
    if(topic == NULL) { return MQTT_RESP_ERRARGS; }
    // at most 3 seperators are written to the topic string
    num_seperator = 1 + mqttUtilPRNG(drbg, 0x2);
    topic->len    = num_seperator;
    for (idx=0 ; idx <= num_seperator; idx++) {
        chosen_name_idx[idx] = mqttUtilPRNG( drbg, MQTT_TEST_TOPIC_LVL_NAMES_ARRAY_LENGTH - 1 );
        topic->len += mqttTestTopicLevelName[idx][ chosen_name_idx[idx] ].len  ;
    } // end of for-loop
    dst = (byte *) XMALLOC( sizeof(byte) * topic->len );
    if(dst == NULL){ return MQTT_RESP_ERRMEM; }
    topic->data = dst;
    for (idx=0 ; idx <= num_seperator; idx++) {
        word16   src_len  = mqttTestTopicLevelName[idx][ chosen_name_idx[idx] ].len;
        byte    *src_data = mqttTestTopicLevelName[idx][ chosen_name_idx[idx] ].data;
        XMEMCPY( dst, src_data, src_len );
        dst += src_len;
        if(idx < num_seperator) {
            *dst++ = MQTT_TOPIC_LEVEL_SEPERATOR;
        }
    } // end of for-loop
    return status;
} // end of mqttTestRandGenTopic
#undef MQTT_TEST_TOPIC_LVL_NAMES_ARRAY_LENGTH



static mqttRespStatus mqttTestRandGenSubsTopics(mqttDRBG_t *drbg, mqttTopic_t **topics , word16 topic_cnt)
{
    mqttRespStatus  status = MQTT_RESP_OK;
    word32        idx = 0;
    mqttTopic_t  *topics_p  = NULL;

    if(topic_cnt == 0 || topics == NULL) { return MQTT_RESP_ERRARGS; }
    topics_p = (mqttTopic_t *)XMALLOC(sizeof(mqttTopic_t) * topic_cnt) ;
    if(topics_p == NULL){ return MQTT_RESP_ERRMEM; }
    *topics = topics_p;

    for(idx=0; idx < topic_cnt; idx++) {
        status = mqttTestRandGenTopic( drbg, &topics_p[idx].filter );
        if(status < 0) { break; }
        topics_p[idx].reason_code = MQTT_REASON_SUCCESS;
        topics_p[idx].qos    =     mqttUtilPRNG(drbg, MQTT_QOS_2);
        topics_p[idx].sub_id = 1 + mqttUtilPRNG(drbg, 0xfe);
        topics_p[idx].alias  = 1 + mqttUtilPRNG(drbg, 0x7e);
    }
    return status;
} // end of mqttTestRandGenSubsTopics



static void mqttTestCleanSubsTopics(mqttTopic_t *topics , word16 topic_cnt)
{
    word32  idx = 0;
    if(topic_cnt == 0 || topics == NULL) { return; }
    for(idx=0; idx < topic_cnt; idx++) {
        mqttTopic_t *topic = &topics[idx];
        if(topic != NULL) {
            XMEMSET(topic->filter.data, 0x00, topic->filter.len);
            XMEMFREE((void *) topic->filter.data);
            topic->filter.data = NULL;
        }
    }
    XMEMSET(topics, 0x00, sizeof(mqttTopic_t) * topic_cnt);
    XMEMFREE((void *)topics);
} // end of mqttTestCleanSubsTopics



static void mqttTestRandSetupProp( mqttDRBG_t *drbg, mqttProp_t *curr_prop )
{
    uint8_t  rand_len_1     = 0; 
    uint8_t  rand_len_2     = 0;
    byte *   rand_str_dst_1 = NULL;
    byte *   rand_str_dst_2 = NULL;
    // for few property types, we must allocate space to store bytes string
    // before we pass it to testing function
    switch( curr_prop->type )
    {
        case MQTT_PROP_SESSION_EXPIRY_INTVL :
            curr_prop->body.u32 = 300 + mqttUtilPRNG(drbg, 900);
            break;
        case MQTT_PROP_RECV_MAX         :
            // TODO: test for concurrent publish messages with QoS=1 or QoS=2.
            curr_prop->body.u16 = 1;
            break;
        case MQTT_PROP_MAX_PKT_SIZE     :
            curr_prop->body.u32 = (MQTT_RECV_PKT_MAXBYTES >> 1) + mqttUtilPRNG(drbg, MQTT_RECV_PKT_MAXBYTES >> 2);
            break;
        case MQTT_PROP_TOPIC_ALIAS_MAX  :
            curr_prop->body.u16 = 1 + mqttUtilPRNG(drbg, 0x8);
            break;
        case MQTT_PROP_TOPIC_ALIAS      :
            curr_prop->body.u16 = 1 + mqttUtilPRNG(drbg, 0x8);
            break;
        case MQTT_PROP_REQ_RESP_INFO    :
        case MQTT_PROP_REQ_PROBLEM_INFO :
        case MQTT_PROP_PKT_FMT_INDICATOR : 
            curr_prop->body.u8 = mqttUtilPRNG(drbg, 0x1);
            break;
        case MQTT_PROP_MSG_EXPIRY_INTVL  : 
        case MQTT_PROP_WILL_DELAY_INTVL  :
            curr_prop->body.u32 = 5 + mqttUtilPRNG(drbg, 60);
            break;
        case MQTT_PROP_RESP_TOPIC        :
            rand_len_1     = mqttUtilPRNG(drbg, 16);
            curr_prop->body.str.len  = 13 + rand_len_1 + 2; // {resp_topic:[.....]}
            rand_str_dst_1 = (byte *) XMALLOC( sizeof(byte) * curr_prop->body.str.len );
            curr_prop->body.str.data = rand_str_dst_1;
            XMEMCPY( rand_str_dst_1, "{resp_topic:[", 13);
            rand_str_dst_1 += 13;
            mqttTestRandGenStr( drbg, rand_str_dst_1, rand_len_1 );
            rand_str_dst_1 += rand_len_1;
            rand_str_dst_1[0] = ']';
            rand_str_dst_1[1] = '}';
            break;
        case MQTT_PROP_CORRELATION_DATA  : 
        case MQTT_PROP_CONTENT_TYPE      :
            rand_len_1     = 10 + mqttUtilPRNG(drbg, 32);
            rand_str_dst_1 = (byte *) XMALLOC( sizeof(byte) * rand_len_1 );
            curr_prop->body.str.len  = rand_len_1;
            curr_prop->body.str.data = rand_str_dst_1;
            mqttTestRandGenStr( drbg, rand_str_dst_1, rand_len_1 );
            break;
        case MQTT_PROP_REASON_STR :
        {
            const byte *reason_str = (const byte *)&("normal disconnect without errors");
            rand_len_1     = XSTRLEN((const char *)reason_str);
            rand_str_dst_1 = (byte *) XMALLOC( sizeof(byte) * rand_len_1 );
            curr_prop->body.str.len  = rand_len_1;
            curr_prop->body.str.data = rand_str_dst_1;
            XMEMCPY( rand_str_dst_1, reason_str, rand_len_1 );
            break;
        }
        case MQTT_PROP_SUBSCRIBE_ID      :
            curr_prop->body.u32 = 1 + mqttUtilPRNG(drbg, 0xfffe);
            break;
        case MQTT_PROP_USER_PROPERTY    :
            rand_len_1     = mqttUtilPRNG(drbg, 5); 
            rand_len_2     = mqttUtilPRNG(drbg, 16);
            curr_prop->body.strpair[0].len = 9 + rand_len_1; // "userlabel" + random number
            curr_prop->body.strpair[1].len = 8 + rand_len_2; // "userdata" + random number
            rand_str_dst_1 = (byte *) XMALLOC( sizeof(byte) * curr_prop->body.strpair[0].len );
            rand_str_dst_2 = (byte *) XMALLOC( sizeof(byte) * curr_prop->body.strpair[1].len );
            XMEMCPY( rand_str_dst_1, "userlabel", 9);
            XMEMCPY( rand_str_dst_2, "userdata" , 8);
            mqttTestRandGenStr( drbg, &rand_str_dst_1[9], rand_len_1 );
            mqttTestRandGenStr( drbg, &rand_str_dst_2[8], rand_len_2 );
            curr_prop->body.strpair[0].data = rand_str_dst_1;
            curr_prop->body.strpair[1].data = rand_str_dst_2;
            break;
        default:
            break;
    } // end of switch-case statement
} // end of mqttTestRandSetupProp



static mqttRespStatus mqttTestRandSetupProps( mqttDRBG_t *drbg, mqttPropertyType  *given_arr, size_t list_size, mqttProp_t **head_prop )
{
    uint8_t  num_props  = 0;
    uint8_t  select_idx = 0;
    uint8_t idx     = 0;
    mqttRespStatus      status = MQTT_RESP_OK;
    mqttPropertyType    select_type ;
    mqttProp_t         *curr_prop ;

    num_props = mqttUtilPRNG(drbg, (word32)list_size);
    
    for(idx=0; idx<num_props; idx++) {
        // select a property that hasn't been chosen in current packet
        select_idx  = (uint8_t) mqttUtilPRNG(drbg, list_size - 1);
        // swap the chosen property with the latest one, decrease number of the available array item
        // so the available items become given_arr[0] ... given_arr[list_size - 2] in next iteration.
        select_type  = given_arr[select_idx];
        if(select_idx < (list_size - 1)) {
            given_arr[select_idx]    = given_arr[list_size - 1];
            given_arr[list_size - 1] = select_type;
        }
        list_size--;
        // start generating random data to each property structure
        curr_prop = NULL; 
        curr_prop = mqttPropertyCreate(head_prop, select_type);
        if(curr_prop == NULL){ status = MQTT_RESP_ERRMEM; break; }
        mqttTestRandSetupProp( drbg, curr_prop );
    } // end of for-loop
    return status;
} // end of mqttTestRandSetupProps



// -------- set up CONNECT packet --------
static mqttRespStatus  mqttTestGenPattConnect( mqttDRBG_t *drbg, mqttConn_t *mconn )
{
    mqttRespStatus  status          = MQTT_RESP_OK;
    mqttStr_t      *brokerUsername  = NULL;
    mqttStr_t      *brokerPasswd    = NULL;
    byte           *str_dst         = NULL;
    uint8_t         str_len         = 0;

    mconn->protocol_lvl    = MQTT_CONN_PROTOCOL_LEVEL;
    // if CLEAR flag is set, and if this client have session that is previously created on
    // the server before, then it will clean up this created session.
    mconn->flgs.clean_session   = mqttUtilPRNG(drbg, 1);
    mconn->keep_alive_sec  = MQTT_DEFAULT_KEEPALIVE_SEC + mqttUtilPRNG(drbg, 30);
    // allocate number of properties to CONNECT packet
    status = mqttTestRandSetupProps( drbg, (mqttPropertyType *)&connectPropTypeList,
                                     XGETARRAYSIZE(connectPropTypeList), &mconn->props );
    if(status < 0) { return status; }
    // last will testament
    mconn->flgs.will_enable = mqttUtilPRNG(drbg, 1);
    if(mconn->flgs.will_enable == 1) {
        mqttMsg_t  *lwtmsg  = &mconn->lwt_msg;
        lwtmsg->retain = 1;
        lwtmsg->qos    = mqttUtilPRNG(drbg, MQTT_QOS_2);
        status = mqttTestRandSetupProps(drbg, (mqttPropertyType *)&willPropTypeList,
                                         XGETARRAYSIZE(willPropTypeList), &lwtmsg->props );
        if(status < 0) { return status; }
        status = mqttTestRandGenTopic( drbg, &lwtmsg->topic );
        if(status < 0) { return status; }
        // total length of the application specific data 
        const char *default_lwt_str     = "connection is off on client, random number: ";
        word16      default_lwt_str_len = XSTRLEN(default_lwt_str);
        word16      lwt_payld_len       = default_lwt_str_len + mqttUtilPRNG(drbg, 20);
        byte       *lwt_payld_data      = (byte *)XMALLOC(sizeof(byte) * lwt_payld_len);
        XMEMCPY( &lwt_payld_data[0], default_lwt_str, default_lwt_str_len );
        mqttTestRandGenStr( drbg, &lwt_payld_data[default_lwt_str_len], (lwt_payld_len - default_lwt_str_len) );
        lwtmsg->buff         = lwt_payld_data;
        lwtmsg->app_data_len = lwt_payld_len;
    }
    else {
        mconn->lwt_msg.retain = 0;
        mconn->lwt_msg.qos = 0;
    }

    str_len = 8 + mqttUtilPRNG(drbg, 8);
    str_dst = (byte *) XMALLOC( sizeof(byte) * str_len );
    XMEMCPY( &str_dst[0], "MyClient", 8 );
    mqttTestRandGenStr( drbg, &str_dst[8], (str_len - 8) );
    mconn->client_id.len  = str_len;
    mconn->client_id.data = str_dst;

    mqttAuthGetBrokerLoginInfo( &brokerUsername, &brokerPasswd );

    str_len = brokerUsername->len;
    str_dst = (byte *) XMALLOC( sizeof(byte) * str_len );
    XMEMCPY( str_dst, brokerUsername->data, str_len );
    mconn->username.len  = str_len;
    mconn->username.data = str_dst;
    str_len = brokerPasswd->len;
    str_dst = (byte *) XMALLOC( sizeof(byte) * str_len );
    XMEMCPY( str_dst, brokerPasswd->data, str_len );
    mconn->password.len  = str_len;
    mconn->password.data = str_dst;
    return status;
} // end of mqttTestGenPattConnect




// -------- set up PUBLISH packet --------
static mqttRespStatus  mqttTestGenPattPublish( mqttDRBG_t *drbg, mqttMsg_t *pubmsg, word32 send_pkt_maxbytes )
{
    mqttRespStatus  status = MQTT_RESP_OK;
    word32   app_data_len = 0;
    byte    *app_data     = NULL;

    pubmsg->retain     = mqttUtilPRNG(drbg, 1);
    pubmsg->duplicate  = 0;
    pubmsg->qos        = mqttUtilPRNG(drbg, MQTT_QOS_2);
    // re-allocate number of properties
    status = mqttTestRandSetupProps(  drbg, (mqttPropertyType *)&publishPropTypeList,
                                      XGETARRAYSIZE(publishPropTypeList), &pubmsg->props );
    if(status < 0) { return status; }
    status = mqttTestRandGenTopic( drbg, &pubmsg->topic );
    if(status < 0) { return status; }

    // total length of the application specific data 
    app_data_len = (send_pkt_maxbytes >> 1) + mqttUtilPRNG(drbg, send_pkt_maxbytes >> 2);
    app_data     = (byte *)XMALLOC(sizeof(byte) * app_data_len);
    if(app_data == NULL){ return MQTT_RESP_ERRMEM; }
    XMEMCPY( app_data, "{ mockdata:[", 12);
    mqttTestRandGenStr(drbg, &app_data[12], (app_data_len - 12));
    app_data[app_data_len - 2] = ']';
    app_data[app_data_len - 1] = '}';
    pubmsg->app_data_len = app_data_len;
    pubmsg->buff         = app_data;
    return status;
} // end of mqttTestGenPattPublish




static mqttRespStatus  mqttTestGenPattSubscribe(mqttDRBG_t *drbg, mqttPktSubs_t *subs)
{
    mqttRespStatus  status = MQTT_RESP_OK;
    subs->topic_cnt = 1 + mqttUtilPRNG(drbg, 2);
    status = mqttTestRandSetupProps( drbg, (mqttPropertyType *)&subscribePropTypeList,
                                     XGETARRAYSIZE(subscribePropTypeList), &subs->props );
    if(status < 0) { return status; }
    status = mqttTestRandGenSubsTopics( drbg, &subs->topics, subs->topic_cnt);
    return status;
} // end of mqttTestGenPattSubscribe



static mqttRespStatus mqttTestGenPattUnsubscribe( mqttDRBG_t *drbg, mqttPktUnsubs_t *unsubs_out, const mqttPktSubs_t *subs_in )
{
    mqttRespStatus  status = MQTT_RESP_OK;
    mqttTopic_t    *topics_p;
    size_t          topics_len;
    word16          idx;

    status = mqttTestRandSetupProps( drbg, (mqttPropertyType *)&unsubscribePropTypeList,
                                     XGETARRAYSIZE(unsubscribePropTypeList), &unsubs_out->props );
    if(status < 0) { return status; }
    // copy topic filters from subs_in
    unsubs_out->topic_cnt = subs_in->topic_cnt ;
    topics_len = sizeof(mqttTopic_t) * unsubs_out->topic_cnt;
    topics_p   = (mqttTopic_t *)XMALLOC(topics_len);
    if(topics_p == NULL){ return MQTT_RESP_ERRMEM; }
    unsubs_out->topics = topics_p;

    XMEMCPY( unsubs_out->topics, subs_in->topics, topics_len );
    for(idx=0; idx < unsubs_out->topic_cnt; idx++) {
        unsubs_out->topics[idx].filter.data = (byte *)XMALLOC( sizeof(byte) * subs_in->topics[idx].filter.len );
        if(unsubs_out->topics[idx].filter.data == NULL){ return MQTT_RESP_ERRMEM; }
        XMEMCPY( unsubs_out->topics[idx].filter.data, subs_in->topics[idx].filter.data, subs_in->topics[idx].filter.len );
    }
    return status;
} // end of mqttTestGenPattUnsubscribe



static mqttRespStatus  mqttTestGenPattDisconnect(mqttDRBG_t *drbg, mqttPktDisconn_t *disconn)
{
    mqttRespStatus  status = MQTT_RESP_OK;
    disconn->reason_code = MQTT_REASON_NORMAL_DISCONNECTION;
    status = mqttTestRandSetupProps( drbg, (mqttPropertyType *)&disconnPropTypeList,
                                     XGETARRAYSIZE(disconnPropTypeList), &disconn->props );
    if(status < 0) { return status; }
    return status;
} // end of mqttTestGenPattDisconnect




mqttRespStatus  mqttTestCopyPatterns( mqttTestPatt *patt_in, mqttCtx_t *mctx, mqttCtrlPktType cmdtype )
{
    mqttRespStatus status = MQTT_RESP_OK;
    if(patt_in == NULL || mctx == NULL){
        return MQTT_RESP_ERRARGS;
    }
    mqttTestCleanupPatterns( patt_in, cmdtype );

    switch(cmdtype) {
        case MQTT_PACKET_TYPE_CONNECT       :
            status = mqttTestGenPattConnect( patt_in->drbg, &patt_in->conn );
            if(status == MQTT_RESP_OK) {
                XMEMCPY((void *)&mctx->send_pkt.conn, (void *)&patt_in->conn, sizeof(mqttConn_t) );
            }
            break;
        case MQTT_PACKET_TYPE_DISCONNECT    :
            status = mqttTestGenPattDisconnect( patt_in->drbg, &patt_in->disconn );
            if(status == MQTT_RESP_OK) {
                XMEMCPY((void *)&mctx->send_pkt.disconn, (void *)&patt_in->disconn, sizeof(mqttPktDisconn_t) );
            }
            break;
        case MQTT_PACKET_TYPE_PUBLISH       :
            patt_in->send_pkt_maxbytes = mctx->send_pkt_maxbytes;
            status =  mqttTestGenPattPublish( patt_in->drbg, &patt_in->pubmsg_send, patt_in->send_pkt_maxbytes );
            if(status == MQTT_RESP_OK) {
                XMEMCPY((void *)&mctx->send_pkt.pub_msg, (void *)&patt_in->pubmsg_send, sizeof(mqttMsg_t) );
            }
            break;
        case MQTT_PACKET_TYPE_SUBSCRIBE     :
            status =  mqttTestGenPattSubscribe( patt_in->drbg, &patt_in->subs );
            if(status == MQTT_RESP_OK) {
                XMEMCPY((void *)&mctx->send_pkt.subs, (void *)&patt_in->subs, sizeof(mqttPktSubs_t) );
            }
            break;
        case MQTT_PACKET_TYPE_UNSUBSCRIBE   :
            status =  mqttTestGenPattUnsubscribe( patt_in->drbg, &patt_in->unsubs, &patt_in->subs );
            if(status == MQTT_RESP_OK) {
                XMEMCPY((void *)&mctx->send_pkt.unsubs, (void *)&patt_in->unsubs, sizeof(mqttPktUnsubs_t) );
            }
            break;
        case MQTT_PACKET_TYPE_PINGREQ       :
        default:
            break;
    } // end of switch-case statement
    return status;
} // end of mqttTestCopyPatterns




mqttRespStatus  mqttTestCleanupPatterns( mqttTestPatt *patt_in, mqttCtrlPktType cmdtype )
{
    mqttRespStatus status = MQTT_RESP_OK;
    if(patt_in == NULL){ return MQTT_RESP_ERRARGS; }

    switch(cmdtype) {
        case MQTT_PACKET_TYPE_CONNECT       :
        {
            mqttConn_t *conn = &patt_in->conn ;
            mqttPropertyDel( conn->props );
            if( conn->client_id.data != NULL ) {
                XMEMFREE((void *)conn->client_id.data);
            }
            if( conn->username.data != NULL ) {
                XMEMFREE((void *)conn->username.data);
            }
            if( conn->password.data != NULL ) {
                XMEMFREE((void *)conn->password.data);
            }
            if( conn->flgs.will_enable == 1 ) { // TODO: build API to free memory allocated to the mqttMsg_t packet 
                mqttMsg_t  *lwtmsg  = &conn->lwt_msg;
                mqttPropertyDel( lwtmsg->props );
                if(lwtmsg->topic.data != NULL) {
                    XMEMFREE((void *)lwtmsg->topic.data);
                }
                if(lwtmsg->buff != NULL) {
                    XMEMFREE((void *)lwtmsg->buff);
                }
                XMEMSET(lwtmsg, 0x00, sizeof(mqttMsg_t));
            }
            XMEMSET(conn, 0x00, sizeof(mqttConn_t));
            break;
        }
        case MQTT_PACKET_TYPE_DISCONNECT    :
        {
            mqttPktDisconn_t  *disconn = &patt_in->disconn; 
            mqttPropertyDel( disconn->props );
            XMEMSET(disconn, 0x00, sizeof(mqttPktDisconn_t));
            break;
        }
        case MQTT_PACKET_TYPE_PUBLISH       :
        {
            mqttMsg_t  *pubmsg = &patt_in->pubmsg_send;
            mqttPropertyDel( pubmsg->props );
            if(pubmsg->topic.data != NULL) {
                XMEMFREE((void *)pubmsg->topic.data);
            }
            if(pubmsg->buff != NULL) {
                XMEMFREE((void *)pubmsg->buff);
            }
            XMEMSET(pubmsg , 0x00, sizeof(mqttMsg_t));
            break;
        }
        case MQTT_PACKET_TYPE_SUBSCRIBE     :
        {
            mqttPktSubs_t *subs = &patt_in->subs;
            mqttPropertyDel( subs->props );
            mqttTestCleanSubsTopics(subs->topics, subs->topic_cnt);
            XMEMSET(subs, 0x00, sizeof(mqttPktSubs_t));
            break;
        }
        case MQTT_PACKET_TYPE_UNSUBSCRIBE   :
        {
            mqttPktUnsubs_t *unsubs = &patt_in->unsubs;
            mqttPropertyDel( unsubs->props );
            mqttTestCleanSubsTopics(unsubs->topics, unsubs->topic_cnt);
            XMEMSET(unsubs, 0x00, sizeof(mqttPktUnsubs_t));
            break;
        }
        case MQTT_PACKET_TYPE_PINGREQ       :
        default:
            break;
    } // end of switch-case statement
    return status;
} // end of mqttTestCleanupPatterns



