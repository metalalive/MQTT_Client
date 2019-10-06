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




static void mqttTestRandGenStr( byte* dst, word32 len )
{
    word32 idx = 0;
    for(idx = 0; idx < len; idx++) {
        // write digit 0-9 , A-Z , a-z, other symbols
        if((idx%2) == 0) {
            dst[idx] = '0' + mqttSysRNG(0x49);
        }
        else{
            dst[idx] = dst[idx-1] + 1;
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


    
static mqttRespStatus mqttTestRandGenTopic( mqttStr_t *topic )
{
    mqttRespStatus  status = MQTT_RESP_OK;
    uint8_t   chosen_name_idx[MQTT_TEST_TOPIC_LVL_NAMES_ARRAY_LENGTH];
    uint8_t   num_seperator = 0;
    uint8_t   idx  = 0;
    byte     *dst  = NULL;
    if(topic == NULL) { return MQTT_RESP_ERRARGS; }
    // at most 3 seperators are written to the topic string
    num_seperator = 1 + mqttSysRNG(0x2);
    topic->len    = num_seperator;
    for (idx=0 ; idx <= num_seperator; idx++) {
        chosen_name_idx[idx] = mqttSysRNG( MQTT_TEST_TOPIC_LVL_NAMES_ARRAY_LENGTH - 1 );
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



static mqttRespStatus mqttTestRandGenSubsTopics(mqttTopic_t **topics , word16 topic_cnt)
{
    mqttRespStatus  status = MQTT_RESP_OK;
    word32        idx = 0;
    mqttTopic_t  *topics_p  = NULL;

    if(topic_cnt == 0 || topics == NULL) { return MQTT_RESP_ERRARGS; }
    topics_p = (mqttTopic_t *)XMALLOC(sizeof(mqttTopic_t) * topic_cnt) ;
    if(topics_p == NULL){ return MQTT_RESP_ERRMEM; }
    *topics = topics_p;

    for(idx=0; idx < topic_cnt; idx++) {
        status = mqttTestRandGenTopic( &topics_p[idx].filter );
        if(status < 0) { break; }
        topics_p[idx].reason_code = MQTT_REASON_SUCCESS;
        topics_p[idx].qos    = mqttSysRNG(MQTT_QOS_2);
        topics_p[idx].sub_id = 1 + mqttSysRNG(0xfe);
        topics_p[idx].alias  = 1 + mqttSysRNG(0x7e);
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



static void mqttTestRandSetupProp( mqttProp_t *curr_prop )
{
    uint8_t  rand_len_1     = 0; 
    uint8_t  rand_len_2     = 0;
    byte *   rand_str_dst_1 = NULL;
    byte *   rand_str_dst_2 = NULL;
    // for few property types, we must allocate space to store bytes string
    // before we pass it to testing function
    switch( curr_prop->type )
    { //  TODO: finish this test code
        case MQTT_PROP_SESSION_EXPIRY_INTVL :
            curr_prop->body.u32 = 300 + mqttSysRNG(900);
            break;
        case MQTT_PROP_RECV_MAX         :
            // TODO: test for concurrent publish messages with QoS=1 or QoS=2.
            curr_prop->body.u16 = 1;
            break;
        case MQTT_PROP_MAX_PKT_SIZE     :
            if(MQTT_RECV_PKT_MAXBYTES > 0x200) {
                curr_prop->body.u32 = 0x200 + mqttSysRNG(MQTT_RECV_PKT_MAXBYTES - 0x200);
            }
            else {
                curr_prop->body.u32 = 0x40 + mqttSysRNG(MQTT_RECV_PKT_MAXBYTES - 0x40);
            }
            break;
        case MQTT_PROP_TOPIC_ALIAS_MAX  :
            curr_prop->body.u16 = 1 + mqttSysRNG(0x8);
            break;
        case MQTT_PROP_TOPIC_ALIAS      :
            curr_prop->body.u16 = 1 + mqttSysRNG(0x8);
            break;
        case MQTT_PROP_REQ_RESP_INFO    :
        case MQTT_PROP_REQ_PROBLEM_INFO :
        case MQTT_PROP_PKT_FMT_INDICATOR : 
            curr_prop->body.u8 = mqttSysRNG(0x1);
            break;
        case MQTT_PROP_MSG_EXPIRY_INTVL  : 
            curr_prop->body.u32 = 5 + mqttSysRNG(60);
            break;
        case MQTT_PROP_RESP_TOPIC        :
            rand_len_1     = mqttSysRNG(16);
            curr_prop->body.str.len  = 13 + rand_len_1 + 2; // {resp_topic:[.....]}
            rand_str_dst_1 = (byte *) XMALLOC( sizeof(byte) * curr_prop->body.str.len );
            curr_prop->body.str.data = rand_str_dst_1;
            XMEMCPY( rand_str_dst_1, "{resp_topic:[", 13);
            rand_str_dst_1 += 13;
            mqttTestRandGenStr( rand_str_dst_1, rand_len_1 );
            rand_str_dst_1 += rand_len_1;
            rand_str_dst_1[0] = ']';
            rand_str_dst_1[1] = '}';
            break;
        case MQTT_PROP_CORRELATION_DATA  : 
        case MQTT_PROP_CONTENT_TYPE      :
            rand_len_1     = 10 + mqttSysRNG(32);
            rand_str_dst_1 = (byte *) XMALLOC( sizeof(byte) * rand_len_1 );
            curr_prop->body.str.len  = rand_len_1;
            curr_prop->body.str.data = rand_str_dst_1;
            mqttTestRandGenStr( rand_str_dst_1, rand_len_1 );
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
            curr_prop->body.u32 = 1 + mqttSysRNG(0xfffe);
            break;
        case MQTT_PROP_USER_PROPERTY    :
            rand_len_1     = mqttSysRNG(5); 
            rand_len_2     = mqttSysRNG(16);
            curr_prop->body.strpair[0].len = 9 + rand_len_1; // "userlabel" + random number
            curr_prop->body.strpair[1].len = 8 + rand_len_2; // "userdata" + random number
            rand_str_dst_1 = (byte *) XMALLOC( sizeof(byte) * curr_prop->body.strpair[0].len );
            rand_str_dst_2 = (byte *) XMALLOC( sizeof(byte) * curr_prop->body.strpair[1].len );
            XMEMCPY( rand_str_dst_1, "userlabel", 9);
            XMEMCPY( rand_str_dst_2, "userdata" , 8);
            mqttTestRandGenStr( &rand_str_dst_1[9], rand_len_1 );
            mqttTestRandGenStr( &rand_str_dst_2[8], rand_len_2 );
            curr_prop->body.strpair[0].data = rand_str_dst_1;
            curr_prop->body.strpair[1].data = rand_str_dst_2;
            break;
        default:
            break;
    } // end of switch-case statement
} // end of mqttTestRandSetupProp



static mqttRespStatus mqttTestRandSetupProps( mqttPropertyType  *given_arr, size_t list_size, mqttProp_t **head_prop )
{
    uint8_t  num_props  = 0;
    uint8_t  select_idx = 0;
    uint8_t idx     = 0;
    mqttRespStatus      status = MQTT_RESP_OK;
    mqttPropertyType    select_type ;
    mqttProp_t         *curr_prop ;

    num_props = mqttSysRNG((word32)list_size);
    
    for(idx=0; idx<num_props; idx++) {
        // select a property that hasn't been chosen in current packet
        select_idx  = (uint8_t) mqttSysRNG(list_size - 1);
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
        curr_prop = mqttPropertyCreate( head_prop );
        if(curr_prop == NULL){ status = MQTT_RESP_ERRMEM; break; }
        curr_prop->next = NULL; 
        curr_prop->type = select_type;
        mqttTestRandSetupProp( curr_prop );
    } // end of for-loop
    return status;
} // end of mqttTestRandSetupProps



// -------- set up CONNECT packet --------
static mqttRespStatus  mqttTestGenPattConnect( mqttConn_t *mconn )
{
    mqttRespStatus  status          = MQTT_RESP_OK;
    mqttStr_t      *brokerUsername  = NULL;
    mqttStr_t      *brokerPasswd    = NULL;
    byte           *str_dst         = NULL;
    uint8_t         str_len         = 0;

    mconn->protocol_lvl    = MQTT_CONN_PROTOCOL_LEVEL;
    // if CLEAR flag is set, and if this client have session that is previously created on
    // the server before, then it will clean up this created session.
    mconn->clean_session   = mqttSysRNG(1);
    mconn->keep_alive_sec  = MQTT_DEFAULT_KEEPALIVE_SEC + mqttSysRNG(30);
    // re-allocate number of properties
    status = mqttTestRandSetupProps((mqttPropertyType *)&connectPropTypeList,
                                     XGETARRAYSIZE(connectPropTypeList), &mconn->props );
    if(status < 0) { return status; }

    str_len = 8 + mqttSysRNG(8);
    str_dst = (byte *) XMALLOC( sizeof(byte) * str_len );
    XMEMCPY( &str_dst[0], "MyClient", 8 );
    mqttTestRandGenStr( &str_dst[8], (str_len - 8) );
    mconn->client_id.len  = str_len;
    mconn->client_id.data = str_dst;
    // TODO : implement & test will properties

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
static mqttRespStatus  mqttTestGenPattPublish( mqttMsg_t *pubmsg )
{
    mqttRespStatus  status = MQTT_RESP_OK;
    word32   app_data_len = 0;
    byte    *app_data     = NULL;

    pubmsg->retain     = mqttSysRNG(1);
    pubmsg->duplicate  = 0;
    pubmsg->qos        = mqttSysRNG(MQTT_QOS_2);
    // re-allocate number of properties
    status = mqttTestRandSetupProps( (mqttPropertyType *)&publishPropTypeList,
                                      XGETARRAYSIZE(publishPropTypeList), &pubmsg->props );
    if(status < 0) { return status; }
    status = mqttTestRandGenTopic( &pubmsg->topic );
    if(status < 0) { return status; }

    // total length of the application specific data 
    app_data_len = (MQTT_RECV_PKT_MAXBYTES >> 1) + mqttSysRNG(MQTT_RECV_PKT_MAXBYTES >> 2);
    app_data     = (byte *)XMALLOC(sizeof(byte) * app_data_len);
    if(app_data == NULL){ return MQTT_RESP_ERRMEM; }
    XMEMCPY( app_data, "{ mockdata:[", 12);
    mqttTestRandGenStr(&app_data[12], (app_data_len - 12));
    app_data[app_data_len - 2] = ']';
    app_data[app_data_len - 1] = '}';
    pubmsg->app_data_len = app_data_len;
    pubmsg->buff         = app_data;
    return status;
} // end of mqttTestGenPattPublish




static mqttRespStatus  mqttTestGenPattSubscribe(mqttPktSubs_t *subs)
{
    mqttRespStatus  status = MQTT_RESP_OK;
    subs->topic_cnt = 1 + mqttSysRNG( 2 );
    status = mqttTestRandSetupProps( (mqttPropertyType *)&subscribePropTypeList,
                                     XGETARRAYSIZE(subscribePropTypeList), &subs->props );
    if(status < 0) { return status; }
    status = mqttTestRandGenSubsTopics( &subs->topics, subs->topic_cnt);
    return status;
} // end of mqttTestGenPattSubscribe



static mqttRespStatus mqttTestGenPattUnsubscribe( mqttPktUnsubs_t *unsubs_out, const mqttPktSubs_t *subs_in )
{
    mqttRespStatus  status = MQTT_RESP_OK;
    mqttTopic_t    *topics_p;
    size_t          topics_len;
    word16          idx;

    status = mqttTestRandSetupProps( (mqttPropertyType *)&unsubscribePropTypeList,
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
    }
    return status;
} // end of mqttTestGenPattUnsubscribe



static mqttRespStatus  mqttTestGenPattDisconnect(mqttPktDisconn_t *disconn)
{
    mqttRespStatus  status = MQTT_RESP_OK;
    disconn->reason_code = MQTT_REASON_NORMAL_DISCONNECTION;
    status = mqttTestRandSetupProps( (mqttPropertyType *)&disconnPropTypeList,
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
            status = mqttTestGenPattConnect( &patt_in->conn );
            if(status == MQTT_RESP_OK) {
                XMEMCPY((void *)&mctx->send_pkt.conn, (void *)&patt_in->conn, sizeof(mqttConn_t) );
            }
            break;
        case MQTT_PACKET_TYPE_DISCONNECT    :
            status = mqttTestGenPattDisconnect( &patt_in->disconn );
            if(status == MQTT_RESP_OK) {
                XMEMCPY((void *)&mctx->send_pkt.disconn, (void *)&patt_in->disconn, sizeof(mqttPktDisconn_t) );
            }
            break;
        case MQTT_PACKET_TYPE_PUBLISH       :
            status =  mqttTestGenPattPublish( &patt_in->pubmsg_send );
            if(status == MQTT_RESP_OK) {
                XMEMCPY((void *)&mctx->send_pkt.pub_msg, (void *)&patt_in->pubmsg_send, sizeof(mqttMsg_t) );
            }
            break;
        case MQTT_PACKET_TYPE_SUBSCRIBE     :
            status =  mqttTestGenPattSubscribe( &patt_in->subs );
            if(status == MQTT_RESP_OK) {
                XMEMCPY((void *)&mctx->send_pkt.subs, (void *)&patt_in->subs, sizeof(mqttPktSubs_t) );
            }
            break;
        case MQTT_PACKET_TYPE_UNSUBSCRIBE   :
            status =  mqttTestGenPattUnsubscribe( &patt_in->unsubs, &patt_in->subs );
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



