#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

static mqttCtx_t     *unittest_mctx;
static mqttRespStatus mock_sysinit_return_val;
#if defined(MQTT_CFG_USE_TLS)
static tlsRespStatus  mock_tlsinit_return_val;
#endif // end of MQTT_CFG_USE_TLS

// ---------------- mock or dummy functions declaration ------------------
mqttRespStatus  mqttSysInit( void )
{
    return mock_sysinit_return_val;
}

#if defined(MQTT_CFG_USE_TLS)
tlsRespStatus  tlsModifyReadMsgTimeout(tlsSession_t *session, int new_val)
{
    return TLS_RESP_OK;
} // end of tlsModifyReadMsgTimeout

mqttRespStatus   tlsRespCvtToMqttResp(tlsRespStatus in)
{
    mqttRespStatus  out;
    switch(in) {
        case  TLS_RESP_OK:
        case  TLS_RESP_REQ_MOREDATA:
            out = MQTT_RESP_OK;    break;
        case  TLS_RESP_ERRARGS:
            out = MQTT_RESP_ERRARGS; break;
        case  TLS_RESP_ERRMEM:
            out = MQTT_RESP_ERRMEM; break;
        case TLS_RESP_TIMEOUT:
            out = MQTT_RESP_TIMEOUT;  break;
        case TLS_RESP_MALFORMED_PKT :
            out = MQTT_RESP_MALFORMED_DATA;  break;
        case TLS_RESP_ERR_ENCODE:
        case TLS_RESP_ERR_DECODE:
        case TLS_RESP_ERR_KEYGEN:
            out = MQTT_RESP_ERR_SECURE_CONN; break;
        case TLS_RESP_ERR_SYS_SEND_PKT:
        case TLS_RESP_ERR_SYS_RECV_PKT:
            out = MQTT_RESP_ERR_TRANSMIT; break;
        case TLS_RESP_ERR_EXCEED_MAX_REC_SZ: 
            out = MQTT_RESP_ERR_EXCEED_PKT_SZ; break;
        case TLS_RESP_ERR:
        default:
            out = MQTT_RESP_ERR;     break;
    } // end of switch-case statement
    return out;
} // end of tlsRespCvtToMqttResp

tlsRespStatus  tlsClientInit(mqttCtx_t *mctx)
{
    return mock_tlsinit_return_val;
}
#endif // end of MQTT_CFG_USE_TLS

static void  mock_mqttClientDeinit( mqttCtx_t *mctx )
{
    if(mctx == NULL){ return; }
    if(mctx->tx_buf != NULL) {
        XMEMFREE( mctx->tx_buf );
        mctx->tx_buf = NULL;
    }
    if(mctx->rx_buf != NULL) {
        XMEMFREE( mctx->rx_buf );
        mctx->rx_buf = NULL;
    }
    XMEMFREE( mctx );
}


// ------------------------- test framework set-up ---------------------------

TEST_GROUP(mqttClientInit);
TEST_GROUP(mqttPropertyCreate);
TEST_GROUP(mqttPropertyDel);
TEST_GROUP(mqttPropErrChk);

TEST_GROUP_RUNNER(mqttClientInit)
{
    RUN_TEST_CASE(mqttClientInit, mctx_null);
    RUN_TEST_CASE(mqttClientInit, zero_timeout);
    RUN_TEST_CASE(mqttClientInit, rand_timeout);
    RUN_TEST_CASE(mqttClientInit, sysinit_fail);
    RUN_TEST_CASE(mqttClientInit, tlsinit_fail);
}

TEST_GROUP_RUNNER(mqttPropertyCreate)
{
    RUN_TEST_CASE(mqttPropertyCreate, in_null);
    RUN_TEST_CASE(mqttPropertyCreate, take_one);
    RUN_TEST_CASE(mqttPropertyCreate, take_all);
}

TEST_GROUP_RUNNER(mqttPropertyDel)
{
    RUN_TEST_CASE(mqttPropertyDel, take_some_alloc_space);
}

TEST_GROUP_RUNNER(mqttPropErrChk)
{
    RUN_TEST_CASE(mqttPropErrChk, in_null);
    RUN_TEST_CASE(mqttPropErrChk, dup_user_prop);
    RUN_TEST_CASE(mqttPropErrChk, dup_sub_id_in_publish);
    RUN_TEST_CASE(mqttPropErrChk, dup_prop_cannot_repeat);
    RUN_TEST_CASE(mqttPropErrChk, strpair_integrity);
    RUN_TEST_CASE(mqttPropErrChk, var_int_limit);
    RUN_TEST_CASE(mqttPropErrChk, update_keepalive);
    RUN_TEST_CASE(mqttPropErrChk, update_topic_alias_max);
    RUN_TEST_CASE(mqttPropErrChk, chk_topic_alias_pubmsg);
    RUN_TEST_CASE(mqttPropErrChk, chk_max_pkt_sz);
}


TEST_SETUP(mqttClientInit)
{
    unittest_mctx = NULL;
    mock_sysinit_return_val = MQTT_RESP_OK;
#if defined(MQTT_CFG_USE_TLS)
    mock_tlsinit_return_val = TLS_RESP_OK;
#endif // end of MQTT_CFG_USE_TLS
}

TEST_SETUP(mqttPropertyCreate)
{
    int timeout = 100;
    unittest_mctx = NULL;
    mqttClientInit(&unittest_mctx, timeout);
}

TEST_SETUP(mqttPropertyDel)
{
    int timeout = 100;
    unittest_mctx = NULL;
    mqttClientInit(&unittest_mctx, timeout);
}

TEST_SETUP(mqttPropErrChk)
{
    int timeout = 100;
    unittest_mctx = NULL;
    mqttClientInit(&unittest_mctx, timeout);
}


TEST_TEAR_DOWN(mqttClientInit)
{
    mock_mqttClientDeinit( unittest_mctx );
    unittest_mctx = NULL;
    mock_sysinit_return_val = MQTT_RESP_OK;
#if defined(MQTT_CFG_USE_TLS)
    mock_tlsinit_return_val = TLS_RESP_OK;
#endif // end of MQTT_CFG_USE_TLS
}

TEST_TEAR_DOWN(mqttPropertyCreate)
{
    mqttPropertyDel( unittest_mctx->send_pkt.conn.props );
    mock_mqttClientDeinit( unittest_mctx );
    unittest_mctx = NULL;
}

TEST_TEAR_DOWN(mqttPropertyDel)
{
    mock_mqttClientDeinit( unittest_mctx );
    unittest_mctx = NULL;
}

TEST_TEAR_DOWN(mqttPropErrChk)
{
    mock_mqttClientDeinit( unittest_mctx );
    unittest_mctx = NULL;
}



// ------------------------------ start test body  ------------------------------
TEST(mqttClientInit, mctx_null)
{
    mqttRespStatus status = MQTT_RESP_OK;
    status = mqttClientInit(NULL, 0);
    TEST_ASSERT_EQUAL(MQTT_RESP_ERRARGS, status);
    status = mqttClientInit(NULL, 1);
    TEST_ASSERT_EQUAL(MQTT_RESP_ERRARGS, status);
}

TEST(mqttClientInit, zero_timeout)
{
    mqttRespStatus status = MQTT_RESP_OK;
    status = mqttClientInit(&unittest_mctx, 0);
    TEST_ASSERT_EQUAL(MQTT_RESP_ERRARGS, status);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx);
}

TEST(mqttClientInit, rand_timeout)
{
    int timeout = 23;
    mqttRespStatus status = MQTT_RESP_OK;
    status = mqttClientInit(&unittest_mctx, timeout);
    TEST_ASSERT_EQUAL(MQTT_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);
    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx->tx_buf);
    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx->rx_buf);
    TEST_ASSERT_EQUAL_INT(timeout, unittest_mctx->cmd_timeout_ms);
    TEST_ASSERT_EQUAL_INT(MQTT_QOS_2                , unittest_mctx->max_qos_server     );
    TEST_ASSERT_EQUAL_INT(MQTT_QOS_2                , unittest_mctx->max_qos_client     );
    TEST_ASSERT_EQUAL_INT(MQTT_RECV_PKT_MAXBYTES    , unittest_mctx->send_pkt_maxbytes  );
    TEST_ASSERT_EQUAL_INT(MQTT_DEFAULT_KEEPALIVE_SEC, unittest_mctx->keep_alive_sec     );
    TEST_ASSERT_EQUAL_INT(1, unittest_mctx->flgs.req_probm_info     );
    TEST_ASSERT_EQUAL_INT(1, unittest_mctx->flgs.retain_avail       );
    TEST_ASSERT_EQUAL_INT(1, unittest_mctx->flgs.subs_id_avail      );
    TEST_ASSERT_EQUAL_INT(1, unittest_mctx->flgs.shr_subs_avail     );
    TEST_ASSERT_EQUAL_INT(1, unittest_mctx->flgs.wildcard_subs_avail);
}

TEST(mqttClientInit, sysinit_fail)
{
    int timeout = 29;
    mqttRespStatus status = MQTT_RESP_OK;

    mock_sysinit_return_val = MQTT_RESP_ERR;
    status = mqttClientInit(&unittest_mctx, timeout);
    TEST_ASSERT_NOT_EQUAL(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL(MQTT_RESP_ERR, status);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx);

    mock_sysinit_return_val = MQTT_RESP_ERRMEM;
    status = mqttClientInit(&unittest_mctx, timeout);
    TEST_ASSERT_EQUAL(MQTT_RESP_ERRMEM, status);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx);
}

#if defined(MQTT_CFG_USE_TLS)
TEST(mqttClientInit, tlsinit_fail)
{
    int timeout = 29;
    mqttRespStatus status = MQTT_RESP_OK;

    mock_tlsinit_return_val = TLS_RESP_ERR;
    status = mqttClientInit(&unittest_mctx, timeout);
    TEST_ASSERT_NOT_EQUAL(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL(MQTT_RESP_ERR, status);
    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);
    mock_mqttClientDeinit( unittest_mctx );
    unittest_mctx = NULL;

    mock_tlsinit_return_val = TLS_RESP_ERR_KEYGEN;
    status = mqttClientInit(&unittest_mctx, timeout);
    TEST_ASSERT_EQUAL(MQTT_RESP_ERR_SECURE_CONN, status);
    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);
    mock_mqttClientDeinit( unittest_mctx );
    unittest_mctx = NULL;

    mock_tlsinit_return_val = TLS_RESP_ERRMEM;
    status = mqttClientInit(&unittest_mctx, timeout);
    TEST_ASSERT_EQUAL(MQTT_RESP_ERRMEM, status);
    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);
    mock_mqttClientDeinit( unittest_mctx );
    unittest_mctx = NULL;
}
#else
IGNORE_TEST(mqttClientInit, tlsinit_fail)
{
}
#endif // end of MQTT_CFG_USE_TLS


TEST(mqttPropertyCreate, in_null)
{
    mqttProp_t   *new_prop  = NULL;
    mqttProp_t  **prop_list = NULL;

    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);
    prop_list = &unittest_mctx->send_pkt.conn.props;
    new_prop = mqttPropertyCreate(NULL, MQTT_PROP_USER_PROPERTY);
    TEST_ASSERT_EQUAL_UINT(NULL, new_prop);
    new_prop = mqttPropertyCreate(prop_list, MQTT_PROP_NONE);
    TEST_ASSERT_EQUAL_UINT(NULL, *prop_list);
    TEST_ASSERT_EQUAL_UINT(NULL,  new_prop);
}

TEST(mqttPropertyCreate, take_one)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;

    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);
    prop_list = &unittest_mctx->send_pkt.conn.props;
    new_prop = mqttPropertyCreate(prop_list, MQTT_PROP_USER_PROPERTY);
    TEST_ASSERT_NOT_EQUAL(NULL, new_prop);
    TEST_ASSERT_EQUAL_UINT(new_prop, *prop_list);
}

TEST(mqttPropertyCreate, take_all)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttProp_t  *tmp_prop = NULL;
    word16 idx  = 0;

    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);
    prop_list = &unittest_mctx->send_pkt.conn.props;
    for (idx=0; idx<MQTT_MAX_NUM_PROPS; idx++) {
        tmp_prop = *prop_list;
        new_prop = mqttPropertyCreate(prop_list, MQTT_PROP_USER_PROPERTY);
        TEST_ASSERT_NOT_EQUAL(NULL,  new_prop);
        if(idx > 0) { // the production function always inserts new item to the tail of list
            TEST_ASSERT_EQUAL_UINT(tmp_prop, *prop_list);
        }
    } // take all available items from the internal property list

    tmp_prop = new_prop; // temp store last item
    // from here on, no item available in the internal property list
    new_prop = mqttPropertyCreate(prop_list, MQTT_PROP_TOPIC_ALIAS_MAX);
    TEST_ASSERT_EQUAL_UINT(NULL, new_prop);

    mqttPropertyDel(tmp_prop); // release the final item
    // there should be only one item available in the internal property list
    new_prop = mqttPropertyCreate(prop_list, MQTT_PROP_MAX_PKT_SIZE);
    TEST_ASSERT_NOT_EQUAL(NULL,  new_prop);
    new_prop = mqttPropertyCreate(prop_list, MQTT_PROP_SESSION_EXPIRY_INTVL);
    TEST_ASSERT_EQUAL_UINT(NULL, new_prop);
} // end of TEST(mqttPropertyCreate, take_all)


TEST(mqttPropertyDel, take_some_alloc_space)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    word16 nbytes_alloc    = 0x20;
    word16 idx  = 0;

    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);
    prop_list = &unittest_mctx->send_pkt.conn.props;
    for (idx=0; idx<MQTT_MAX_NUM_PROPS; idx++) {
        switch(idx % 3) {
           case 1:  ptype = MQTT_PROP_MSG_EXPIRY_INTVL;
               break;
           case 2:  ptype = MQTT_PROP_REASON_STR;
               break;
           case 0:
           default:  ptype = MQTT_PROP_USER_PROPERTY;
               break;
        } // end of switch-case statement
        new_prop = mqttPropertyCreate(prop_list, ptype);
        TEST_ASSERT_NOT_EQUAL(NULL,  new_prop);
        switch(ptype) {
           case MQTT_PROP_USER_PROPERTY:
               new_prop->body.strpair[0].len  = nbytes_alloc;
               new_prop->body.strpair[0].data = XMALLOC(sizeof(byte) * nbytes_alloc);
               new_prop->body.strpair[1].len  = nbytes_alloc;
               new_prop->body.strpair[1].data = XMALLOC(sizeof(byte) * nbytes_alloc);
               break;
           case MQTT_PROP_REASON_STR:
               new_prop->body.str.len  = nbytes_alloc;
               new_prop->body.str.data = XMALLOC(sizeof(byte) * nbytes_alloc);
               break;
           default:
               break;
        } // end of switch-case statement
    } // end of loop
    mqttPropertyDel(*prop_list);
    TEST_ASSERT_EQUAL_UINT(NULL,           (*prop_list)->next);
    TEST_ASSERT_EQUAL_UINT(MQTT_PROP_NONE, (*prop_list)->type);
} // end of TEST(mqttPropertyDel, take_some_alloc_space)


TEST(mqttPropErrChk, in_null)
{
    mqttRespStatus status = MQTT_RESP_OK;

    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);
    status = mqttPropErrChk(NULL, MQTT_PACKET_TYPE_RESERVED, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERRARGS, status);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_RESERVED, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status); // it's ok to give NULL property list
} // end of TEST(mqttPropErrChk, in_null)


TEST(mqttPropErrChk, dup_user_prop)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;
    word16 nbytes_alloc   = 0x20;

    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);

    prop_list = &unittest_mctx->send_pkt.conn.props;
    ptype = MQTT_PROP_USER_PROPERTY;
    {
        new_prop = mqttPropertyCreate(prop_list, ptype);
        new_prop->body.strpair[0].len  = nbytes_alloc;
        new_prop->body.strpair[0].data = XMALLOC(sizeof(byte) * nbytes_alloc);
        new_prop->body.strpair[1].len  = nbytes_alloc;
        new_prop->body.strpair[1].data = XMALLOC(sizeof(byte) * nbytes_alloc);
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    }
    {
        new_prop = mqttPropertyCreate(prop_list, ptype);
        new_prop->body.strpair[0].len  = nbytes_alloc;
        new_prop->body.strpair[0].data = XMALLOC(sizeof(byte) * nbytes_alloc);
        new_prop->body.strpair[1].len  = nbytes_alloc;
        new_prop->body.strpair[1].data = XMALLOC(sizeof(byte) * nbytes_alloc);
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    }
    mqttPropertyDel(*prop_list);
} // end of TEST_CASE(mqttPropErrChk, dup_user_prop)


TEST(mqttPropErrChk, dup_sub_id_in_publish)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);

    prop_list = &unittest_mctx->send_pkt.pub_msg.props;
    ptype = MQTT_PROP_SUBSCRIBE_ID;
    unittest_mctx->flgs.recv_mode = 1; // temporarily avoid property error, will test this later
    {
        new_prop = mqttPropertyCreate(prop_list, ptype);
        new_prop->body.u32 = 0x2;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    }
    {
        new_prop = mqttPropertyCreate(prop_list, ptype);
        new_prop->body.u32 = 0x5;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    }
    {
        new_prop = mqttPropertyCreate(prop_list, ptype);
        new_prop->body.u32 = 0x7;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    }
    mqttPropertyDel(*prop_list);
} // end of TEST(mqttPropErrChk, dup_sub_id_in_publish)


TEST(mqttPropErrChk, dup_prop_cannot_repeat)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;
    word16 nbytes_alloc   = 0x20;

    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);

    prop_list = &unittest_mctx->send_pkt.pub_msg.props;
    ptype = MQTT_PROP_CONTENT_TYPE;
    {
        new_prop = mqttPropertyCreate(prop_list, ptype);
        new_prop->body.str.len  = nbytes_alloc;
        new_prop->body.str.data = XMALLOC(sizeof(byte) * nbytes_alloc);
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_UINT(MQTT_RESP_OK, status);
    }
    ptype = MQTT_PROP_TOPIC_ALIAS;
    unittest_mctx->flgs.recv_mode = 0; // temporarily avoid property error, will test this later
    unittest_mctx->send_topic_alias_max = 13;
    {
        new_prop = mqttPropertyCreate(prop_list, ptype);
        new_prop->body.u16 = 11;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_UINT(MQTT_RESP_OK, status);
    }
    ptype = MQTT_PROP_CONTENT_TYPE;
    {
        new_prop = mqttPropertyCreate(prop_list, ptype);
        new_prop->body.str.len  = nbytes_alloc;
        new_prop->body.str.data = XMALLOC(sizeof(byte) * nbytes_alloc);
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP_REPEAT, status);
        TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_PROTOCOL_ERR, unittest_mctx->err_info.reason_code);
        TEST_ASSERT_EQUAL_UINT8(ptype, unittest_mctx->err_info.prop_id);
    }
    mqttPropertyDel(*prop_list);
} // end of TEST(mqttPropErrChk, dup_prop_cannot_repeat)


TEST(mqttPropErrChk, strpair_integrity)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;
    word16 nbytes_alloc   = 0x20;

    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);

    prop_list = &unittest_mctx->send_pkt.conn.props;
    ptype = MQTT_PROP_USER_PROPERTY;
    {
        new_prop = mqttPropertyCreate(prop_list, ptype);
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_INTEGRITY, status);

        new_prop->body.strpair[0].len  = nbytes_alloc;
        new_prop->body.strpair[0].data = XMALLOC(sizeof(byte) * nbytes_alloc);
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_INTEGRITY, status);

        new_prop->body.strpair[1].len  = nbytes_alloc;
        new_prop->body.strpair[1].data = XMALLOC(sizeof(byte) * nbytes_alloc);
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    }
    mqttPropertyDel(*prop_list);
} // end of TEST(mqttPropErrChk, strpair_integrity)


TEST(mqttPropErrChk, var_int_limit)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    prop_list = &unittest_mctx->send_pkt.pub_msg.props;
    ptype = MQTT_PROP_SUBSCRIBE_ID;
    unittest_mctx->flgs.recv_mode = 1; // temporarily avoid property error, will test this later
    {
        new_prop = mqttPropertyCreate(prop_list, ptype);
        new_prop->body.u32 = 0x2;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
        new_prop->body.u32  = (0x1 << 28);
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
        TEST_ASSERT_EQUAL_UINT8(ptype, unittest_mctx->err_info.prop_id);
        new_prop->body.u32 -= 1;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    }
    mqttPropertyDel(*prop_list);
} // end of TEST(mqttPropErrChk, var_int_limit)


TEST(mqttPropErrChk, update_keepalive)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    prop_list = &unittest_mctx->recv_pkt.connack.props;
    ptype = MQTT_PROP_SERVER_KEEP_ALIVE;
    unittest_mctx->flgs.recv_mode = 1;
    {
        new_prop = mqttPropertyCreate(prop_list, ptype);
        new_prop->body.u16 = 0xfffe;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
        TEST_ASSERT_EQUAL_UINT16(new_prop->body.u16, unittest_mctx->keep_alive_sec);
    }
    mqttPropertyDel(*prop_list);
} // end of TEST(mqttPropErrChk, update_keepalive)


TEST(mqttPropErrChk, update_topic_alias_max)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    ptype = MQTT_PROP_TOPIC_ALIAS_MAX;
    prop_list = &unittest_mctx->recv_pkt.connack.props;
    unittest_mctx->flgs.recv_mode = 1;
    new_prop = mqttPropertyCreate(prop_list, ptype);
    new_prop->body.u16 = 0x4fd;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(new_prop->body.u16, unittest_mctx->send_topic_alias_max);

    new_prop->body.u16 = 0x2f7;
    unittest_mctx->flgs.recv_mode = 0;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT16(new_prop->body.u16, unittest_mctx->recv_topic_alias_max);

    mqttPropertyDel(*prop_list);
} // end of TEST(mqttPropErrChk, update_topic_alias_max)


TEST(mqttPropErrChk, chk_topic_alias_pubmsg)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    unittest_mctx->send_topic_alias_max = 0x1;
    unittest_mctx->recv_topic_alias_max = 0x2;
    prop_list = &unittest_mctx->send_pkt.pub_msg.props;
    ptype = MQTT_PROP_TOPIC_ALIAS;
    new_prop = mqttPropertyCreate(prop_list, ptype);
    { // assume the client gets this property in the PUBLISH command that is ready to send out
        unittest_mctx->flgs.recv_mode = 0;
        new_prop->body.u16 = 0;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
        TEST_ASSERT_EQUAL_UINT8(ptype, unittest_mctx->err_info.prop_id);
        TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_TOPIC_ALIAS_INVALID, unittest_mctx->err_info.reason_code);
        new_prop->body.u16 = 1 + unittest_mctx->send_topic_alias_max;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
        TEST_ASSERT_EQUAL_UINT8(ptype, unittest_mctx->err_info.prop_id);
        TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_TOPIC_ALIAS_INVALID, unittest_mctx->err_info.reason_code);
        new_prop->body.u16 -= 1;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    }
    { // assume the client gets this property from received PUBLISH command
        unittest_mctx->flgs.recv_mode = 1;
        new_prop->body.u16 = 1 + unittest_mctx->recv_topic_alias_max;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
        TEST_ASSERT_EQUAL_UINT8(ptype, unittest_mctx->err_info.prop_id);
        TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_TOPIC_ALIAS_INVALID, unittest_mctx->err_info.reason_code);
        new_prop->body.u16 -= 1;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    }
    mqttPropertyDel(*prop_list);
} // end of TEST(mqttPropErrChk, chk_topic_alias_pubmsg)


TEST(mqttPropErrChk, chk_max_pkt_sz)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    ptype = MQTT_PROP_MAX_PKT_SIZE;
    {
        prop_list = &unittest_mctx->send_pkt.conn.props;
        unittest_mctx->flgs.recv_mode = 0;
        new_prop = mqttPropertyCreate(prop_list, ptype);
        new_prop->body.u32 = 0;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
        TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_PROTOCOL_ERR, unittest_mctx->err_info.reason_code);
        new_prop->body.u32 = MQTT_RECV_PKT_MAXBYTES + 1;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
        TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_RX_MAX_EXCEEDED, unittest_mctx->err_info.reason_code);
        new_prop->body.u32 -= 1;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK , status);
    }
    {
        prop_list = &unittest_mctx->recv_pkt.connack.props;
        unittest_mctx->flgs.recv_mode = 1;
        new_prop = mqttPropertyCreate(prop_list, ptype);
        new_prop->body.u32 = MQTT_PROTOCOL_PKT_MAXBYTES + 1;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
        TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_PROTOCOL_ERR, unittest_mctx->err_info.reason_code);
        new_prop->body.u32 -= 1;
        status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
        TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK , status);
        TEST_ASSERT_EQUAL_UINT(new_prop->body.u32, unittest_mctx->send_pkt_maxbytes);
    }
    mqttPropertyDel(unittest_mctx->send_pkt.conn.props);
    mqttPropertyDel(unittest_mctx->recv_pkt.connack.props);
} // end of TEST(mqttPropErrChk, chk_max_pkt_sz)





static void RunAllTestGroups(void)
{
    RUN_TEST_GROUP(mqttClientInit);
    RUN_TEST_GROUP(mqttPropertyCreate);
    RUN_TEST_GROUP(mqttPropertyDel);
    RUN_TEST_GROUP(mqttPropErrChk);
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


