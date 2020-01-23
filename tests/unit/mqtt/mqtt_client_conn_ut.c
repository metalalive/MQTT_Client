#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

static mqttCtx_t      *unittest_mctx;
static mqttRespStatus  mock_sysinit_return_val;
static mqttRespStatus  mock_net_pktread_return_val;
static mqttRespStatus  mock_net_pktwrite_return_val;
static mqttRespStatus  mock_decode_pkt_return_val;
static int             mock_get_pktlen_return_val;
static int             mock_encode_pkt_return_val;
static word32          mock_nbytes_pktread;
static const byte     *mock_rawbytes_pktread;
static word16          mock_mqtt_pkt_id;
#if defined(MQTT_CFG_USE_TLS)
static tlsRespStatus  mock_tlsinit_return_val;
#endif // end of MQTT_CFG_USE_TLS

static byte mock_rawbytes_connack[0x4]  = {0x20, 0x02, 0x00, 0x00};
static byte mock_rawbytes_puback[0x5]   = {0x40, 0x03, 0x00, 0x01, 0x10};
static byte mock_rawbytes_pubrel[0x5]   = {0x62, 0x03, 0x00, 0x01, 0x00};
static byte mock_rawbytes_pubcomp[0x5]  = {0x70, 0x03, 0x00, 0x01, 0x00};
static byte mock_rawbytes_suback[0x7]   = {0x90, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00};
static byte mock_rawbytes_unsuback[0x7] = {0xb0, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00};
static byte mock_rawbytes_pingresp[0x2] = {0xd0, 0x00};
static byte mock_rawbytes_auth[0xe]     = {0xf0, 0x0c , 0x18,  0x0a, // packet ID & length field of property
                                           MQTT_PROP_AUTH_METHOD, 0x00, 0x02, 0x5e, 0xe4,   // fake auth method property
                                           MQTT_PROP_AUTH_DATA  , 0x00, 0x02, 0xbe, 0xef }; // fake auth data property
static byte mock_rawbytes_invalid_cmd[0x4] = {0x00, 0x02, 0xde, 0xad};
static byte mock_rawbytes_pub_qos0[0xc] = { 0x30, 0x0a,
                                            0x00, 0x03, 0x62, 0x63, 0x64, // topic : bcd
                                            0x00, // no property included
                                            0x42, 0x31, 0x38, 0x32 // message : B182
                                          };

// ---------------- mock or dummy functions declaration ------------------
mqttRespStatus  mqttSysInit( void )
{
    return mock_sysinit_return_val;
}

mqttRespStatus  mqttSysDeInit( void )
{
    return MQTT_RESP_OK;
}

mqttRespStatus  mqttPktRead( struct __mqttCtx *mctx, byte *buf, word32 buf_max_len, word32 *copied_len )
{
    if(mock_net_pktread_return_val == MQTT_RESP_OK) {
        mock_nbytes_pktread = XMIN(mock_nbytes_pktread, buf_max_len);
        XMEMCPY(buf, mock_rawbytes_pktread, mock_nbytes_pktread);
        *copied_len = mock_nbytes_pktread;
    }
    return mock_net_pktread_return_val;
} // end of mqttPktRead


mqttRespStatus mqttPktWrite( struct __mqttCtx *mctx, byte *buf, word32 buf_len )
{
    return  mock_net_pktwrite_return_val;
} // end of mqttPktWrite


mqttRespStatus  mqttDecodePkt( struct __mqttCtx *mctx, byte *buf, word32 buf_len,  mqttCtrlPktType  cmdtype, void **p_decode, word16 *recv_pkt_id )
{
    switch (cmdtype)
    {
        case MQTT_PACKET_TYPE_CONNACK:
            break;
        case MQTT_PACKET_TYPE_PUBACK :
        case MQTT_PACKET_TYPE_PUBRECV:
        case MQTT_PACKET_TYPE_PUBREL :
        case MQTT_PACKET_TYPE_PUBCOMP:
            (*(mqttPktPubResp_t **)p_decode)->packet_id = mock_mqtt_pkt_id;
            *recv_pkt_id = mock_mqtt_pkt_id;
            if((cmdtype==MQTT_PACKET_TYPE_PUBRECV) || (cmdtype==MQTT_PACKET_TYPE_PUBREL)) {
                // send next publish response packet.
                mqttPktPubResp_t *pub_resp = &mctx->send_pkt_qos2.pub_resp ;
                pub_resp->props       = NULL; // don't send extra properties in response packet for simplicity
                pub_resp->packet_id   = *recv_pkt_id ;
                pub_resp->reason_code =  MQTT_REASON_SUCCESS;
                mock_decode_pkt_return_val = mqttSendPubResp( mctx, (cmdtype + 1), (mqttPktPubResp_t **)p_decode );
            }
            break;
        case MQTT_PACKET_TYPE_SUBACK  :
            (*(mqttPktSuback_t **)p_decode)->packet_id = mock_mqtt_pkt_id;
            (*(mqttPktSuback_t **)p_decode)->return_codes = XMALLOC(sizeof(byte) * 0x10);
            (*(mqttPktSuback_t **)p_decode)->return_codes[0] = mock_rawbytes_suback[5];
            (*(mqttPktSuback_t **)p_decode)->return_codes[1] = mock_rawbytes_suback[6];
            *recv_pkt_id = mock_mqtt_pkt_id;
            break;
        case MQTT_PACKET_TYPE_UNSUBACK:
            (*(mqttPktUnsuback_t **)p_decode)->packet_id = mock_mqtt_pkt_id;
            (*(mqttPktUnsuback_t **)p_decode)->return_codes = XMALLOC(sizeof(byte) * 0x10);
            (*(mqttPktUnsuback_t **)p_decode)->return_codes[0] = mock_rawbytes_unsuback[5];
            (*(mqttPktUnsuback_t **)p_decode)->return_codes[1] = mock_rawbytes_unsuback[6];
            *recv_pkt_id = mock_mqtt_pkt_id;
            break;
        case MQTT_PACKET_TYPE_PINGRESP:
        default:
            break;
    } // end of switch case
    return  mock_decode_pkt_return_val;
} // end of mock mqttDecodePkt()

int  mqttGetPktLenConnect ( mqttConn_t *conn, word32 max_pkt_sz )
{
    return  mock_get_pktlen_return_val;
}

int  mqttGetPktLenAuth ( mqttAuth_t *auth, word32 max_pkt_sz )
{
    return  mock_get_pktlen_return_val;
}

int  mqttGetPktLenDisconn ( mqttPktDisconn_t *disconn, word32 max_pkt_sz )
{
    return  mock_get_pktlen_return_val;
}

int  mqttGetPktLenPublish( mqttMsg_t *msg, word32 max_pkt_sz )
{
    return  mock_get_pktlen_return_val;
}
int  mqttGetPktLenPubResp ( mqttPktPubResp_t *resp, word32 max_pkt_sz )
{
    return  mock_get_pktlen_return_val;
}

int  mqttGetPktLenSubscribe ( mqttPktSubs_t *subs, word32 max_pkt_sz )
{
    return  mock_get_pktlen_return_val;
}

int  mqttGetPktLenUnsubscribe ( mqttPktUnsubs_t *unsubs, word32 max_pkt_sz )
{
    return  mock_get_pktlen_return_val;
}

int  mqttEncodePktConnect( byte *tx_buf, word32 tx_buf_len, mqttConn_t *conn )
{
    return  mock_encode_pkt_return_val;
}

int  mqttEncodePktAuth( byte *tx_buf, word32 tx_buf_len, mqttAuth_t *auth )
{
    return  mock_encode_pkt_return_val;
}

int  mqttEncodePktDisconn( byte *tx_buf, word32 tx_buf_len, mqttPktDisconn_t *disconn )
{
    return  mock_encode_pkt_return_val;
}

int  mqttEncodePktPublish( byte *tx_buf, word32 tx_buf_len, struct __mqttMsg  *msg )
{
    return  mock_encode_pkt_return_val;
}

int  mqttEncodePktPubResp( byte *tx_buf, word32 tx_buf_len, mqttPktPubResp_t *resp, mqttCtrlPktType cmdtype )
{
    return  mock_encode_pkt_return_val;
}

int  mqttEncodePktSubscribe( byte *tx_buf, word32 tx_buf_len, mqttPktSubs_t *subs )
{
    return  mock_encode_pkt_return_val;
}

int  mqttEncodePktUnsubscribe( byte *tx_buf, word32 tx_buf_len, mqttPktUnsubs_t *unsubs )
{
    return  mock_encode_pkt_return_val;
}

int  mqttEncodePktPing( byte *tx_buf, word32 tx_buf_len )
{
    return  mock_encode_pkt_return_val;
}

mqttProp_t*  mqttGetPropByType( mqttProp_t* head, mqttPropertyType type )
{
    if(type == MQTT_PROP_NONE) { return NULL; }
    mqttProp_t *curr_node = NULL;

    for(curr_node = head; curr_node != NULL; curr_node = curr_node->next ) 
    {
        if(curr_node->type == type) { break; }
    } // end of for-loop
    return curr_node;
} // end of mqttGetPropByType

word16  mqttGetPktID( void )
{
    return mock_mqtt_pkt_id;
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

void  tlsClientDeInit(mqttCtx_t *mctx) {}

#endif // end of MQTT_CFG_USE_TLS


static mqttRespStatus mock_mqttAuthSetupCallback(const mqttStr_t *auth_data_in,  mqttStr_t *auth_data_out, mqttStr_t *reason_str_out )
{
    mqttRespStatus status = MQTT_RESP_OK;
    const byte nbytes_alloc = 0x20;
    if(auth_data_out != NULL) {
        if(auth_data_out->data == NULL) {
            auth_data_out->len  = nbytes_alloc;
            auth_data_out->data = XMALLOC(sizeof(byte) * nbytes_alloc);
        }
    }
    if(reason_str_out != NULL) {
        if(reason_str_out->data == NULL) {
            reason_str_out->len  = nbytes_alloc;
            reason_str_out->data = XMALLOC(sizeof(byte) * nbytes_alloc);
        }
    }
    return status;
} // end of mock_mqttAuthSetupCallback

static mqttRespStatus mock_mqttAuthFinalCallback(mqttStr_t *auth_data_sent,  mqttStr_t *auth_reason_out)
{
    return MQTT_RESP_OK;
} // end of mock_mqttAuthFinalCallback


// ------------------------- test framework set-up ---------------------------

TEST_GROUP(mqttClientInit);
TEST_GROUP(mqttPropertyCreate);
TEST_GROUP(mqttPropertyDel);
TEST_GROUP(mqttPropErrChk);
TEST_GROUP(mqttSendConnect);
TEST_GROUP(mqttSendAuth);
TEST_GROUP(mqttSendDisconnect);
TEST_GROUP(mqttSendPublish);
TEST_GROUP(mqttSendPubResp);
TEST_GROUP(mqttSendSubscribe);
TEST_GROUP(mqttSendUnsubscribe);
TEST_GROUP(mqttSendPingReq);
TEST_GROUP(mqttClientWaitPkt);

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
    RUN_TEST_CASE(mqttPropErrChk, update_retain_avail);
    RUN_TEST_CASE(mqttPropErrChk, update_wildcard_subs_avail);
    RUN_TEST_CASE(mqttPropErrChk, update_subs_id_avail);
    RUN_TEST_CASE(mqttPropErrChk, update_shr_subs_avail);
    RUN_TEST_CASE(mqttPropErrChk, update_max_qos_server);
    RUN_TEST_CASE(mqttPropErrChk, update_req_resp_info);
    RUN_TEST_CASE(mqttPropErrChk, update_req_probm_info);
    RUN_TEST_CASE(mqttPropErrChk, chk_reason_str);
    RUN_TEST_CASE(mqttPropErrChk, chk_subs_id);
    RUN_TEST_CASE(mqttPropErrChk, chk_resp_topic);
    RUN_TEST_CASE(mqttPropErrChk, unknown_prop_id);
    RUN_TEST_CASE(mqttPropErrChk, auth_integrity);
}

TEST_GROUP_RUNNER(mqttSendConnect)
{
    RUN_TEST_CASE(mqttSendConnect, in_null);
    RUN_TEST_CASE(mqttSendConnect, wrong_prop);
    RUN_TEST_CASE(mqttSendConnect, wrong_prop_lwt);
    RUN_TEST_CASE(mqttSendConnect, err_cal_pktlen);
    RUN_TEST_CASE(mqttSendConnect, err_net_pkt_send);
    RUN_TEST_CASE(mqttSendConnect, err_net_pkt_recv);
    RUN_TEST_CASE(mqttSendConnect, recv_decode_connack_ok);
}

TEST_GROUP_RUNNER(mqttSendAuth)
{
    RUN_TEST_CASE(mqttSendAuth, in_null);
    RUN_TEST_CASE(mqttSendAuth, next_auth_sent);
}

TEST_GROUP_RUNNER(mqttSendDisconnect)
{
    RUN_TEST_CASE(mqttSendDisconnect, err_chk);
}

TEST_GROUP_RUNNER(mqttSendPublish)
{
    RUN_TEST_CASE(mqttSendPublish, wrong_args);
    RUN_TEST_CASE(mqttSendPublish, qos1_sent_ok);
}


TEST_GROUP_RUNNER(mqttSendPubResp)
{
    RUN_TEST_CASE(mqttSendPubResp, wrong_args);
    RUN_TEST_CASE(mqttSendPubResp, qos2_pubrecv_sent);
    RUN_TEST_CASE(mqttSendPubResp, qos2_pubrel_sent);
}

TEST_GROUP_RUNNER(mqttSendSubscribe)
{
    RUN_TEST_CASE(mqttSendSubscribe, invalid_topics);
    RUN_TEST_CASE(mqttSendSubscribe, topics_sent);
}

TEST_GROUP_RUNNER(mqttSendUnsubscribe)
{
    RUN_TEST_CASE(mqttSendUnsubscribe, topics_sent);
}

TEST_GROUP_RUNNER(mqttSendPingReq)
{
    RUN_TEST_CASE(mqttSendPingReq, ping_sent);
}

TEST_GROUP_RUNNER(mqttClientWaitPkt)
{
    RUN_TEST_CASE(mqttClientWaitPkt, auth_in_recv);
    RUN_TEST_CASE(mqttClientWaitPkt, invalid_cmd);
    RUN_TEST_CASE(mqttClientWaitPkt, pubmsg_recv);
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
}

TEST_SETUP(mqttPropertyDel)
{
}

TEST_SETUP(mqttPropErrChk)
{
}

TEST_SETUP(mqttSendConnect)
{
}

TEST_SETUP(mqttSendAuth)
{
}

TEST_SETUP(mqttSendDisconnect)
{
}

TEST_SETUP(mqttSendPublish)
{
}

TEST_SETUP(mqttSendPubResp)
{
}

TEST_SETUP(mqttSendSubscribe)
{
}

TEST_SETUP(mqttSendUnsubscribe)
{
}

TEST_SETUP(mqttSendPingReq)
{
}

TEST_SETUP(mqttClientWaitPkt)
{
}



TEST_TEAR_DOWN(mqttClientInit)
{
    mqttClientDeinit( unittest_mctx );
    unittest_mctx = NULL;
    mock_sysinit_return_val = MQTT_RESP_OK;
#if defined(MQTT_CFG_USE_TLS)
    mock_tlsinit_return_val = TLS_RESP_OK;
#endif // end of MQTT_CFG_USE_TLS
}

TEST_TEAR_DOWN(mqttPropertyCreate)
{
    mqttPropertyDel( unittest_mctx->send_pkt.conn.props );
    unittest_mctx->send_pkt.conn.props = NULL;
}

TEST_TEAR_DOWN(mqttPropertyDel)
{
}

TEST_TEAR_DOWN(mqttPropErrChk)
{
}

TEST_TEAR_DOWN(mqttSendConnect)
{
    mqttConn_t  *conn = NULL;
    conn = &unittest_mctx->send_pkt.conn;
    mqttPropertyDel(conn->props);
    conn->props = NULL;
    mqttPropertyDel(conn->lwt_msg.props);
    conn->lwt_msg.props = NULL;
}


TEST_TEAR_DOWN(mqttSendAuth)
{
    mqttAuth_t  *auth_recv = &unittest_mctx->recv_pkt.auth;
    mqttAuth_t  *auth_send = &unittest_mctx->send_pkt.auth;
    mqttPropertyDel(auth_send->props);
    auth_send->props = NULL;
    mqttPropertyDel(auth_recv->props);
    auth_recv->props = NULL;
}

TEST_TEAR_DOWN(mqttSendDisconnect)
{
    mqttPktDisconn_t *disconn = NULL;
    disconn = &unittest_mctx->send_pkt.disconn;
    mqttPropertyDel(disconn->props);
    disconn->props = NULL;
}

TEST_TEAR_DOWN(mqttSendPublish)
{
    mqttMsg_t         *msg  = NULL;
    mqttPktPubResp_t  *resp = NULL;

    msg = &unittest_mctx->send_pkt.pub_msg;
    mqttPropertyDel(msg->props);
    msg->props = NULL;

    resp = &unittest_mctx->recv_pkt.pub_resp;
    mqttPropertyDel(resp->props);
    resp->props = NULL;
}


TEST_TEAR_DOWN(mqttSendPubResp)
{
    mqttPktPubResp_t  *resp = NULL;

    resp = &unittest_mctx->recv_pkt.pub_resp;
    mqttPropertyDel(resp->props);
    resp->props = NULL;

    resp = &unittest_mctx->send_pkt.pub_resp;
    mqttPropertyDel(resp->props);
    resp->props = NULL;
}

TEST_TEAR_DOWN(mqttSendSubscribe)
{
}

TEST_TEAR_DOWN(mqttSendUnsubscribe)
{
}

TEST_TEAR_DOWN(mqttSendPingReq)
{
}

TEST_TEAR_DOWN(mqttClientWaitPkt)
{
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
    mqttClientDeinit( unittest_mctx );
    unittest_mctx = NULL;

    mock_tlsinit_return_val = TLS_RESP_ERR_KEYGEN;
    status = mqttClientInit(&unittest_mctx, timeout);
    TEST_ASSERT_EQUAL(MQTT_RESP_ERR_SECURE_CONN, status);
    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);
    mqttClientDeinit( unittest_mctx );
    unittest_mctx = NULL;

    mock_tlsinit_return_val = TLS_RESP_ERRMEM;
    status = mqttClientInit(&unittest_mctx, timeout);
    TEST_ASSERT_EQUAL(MQTT_RESP_ERRMEM, status);
    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx);
    mqttClientDeinit( unittest_mctx );
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
    *prop_list = NULL;
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
    *prop_list = NULL;
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
    *prop_list = NULL;
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
    *prop_list = NULL;
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
    *prop_list = NULL;
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
    *prop_list = NULL;
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
    *prop_list = NULL;
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
    *prop_list = NULL;
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
    *prop_list = NULL;
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
    unittest_mctx->send_pkt.conn.props    = NULL;
    unittest_mctx->recv_pkt.connack.props = NULL;
} // end of TEST(mqttPropErrChk, chk_max_pkt_sz)


TEST(mqttPropErrChk, update_retain_avail)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    prop_list = &unittest_mctx->recv_pkt.connack.props;
    unittest_mctx->flgs.recv_mode = 1;
    ptype = MQTT_PROP_RETAIN_AVAILABLE;
    new_prop = mqttPropertyCreate(prop_list, ptype);

    new_prop->body.u8 = 2;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_PROTOCOL_ERR, unittest_mctx->err_info.reason_code);

    new_prop->body.u8 = 1;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(new_prop->body.u8, unittest_mctx->flgs.retain_avail);

    new_prop->body.u8 = 0;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(new_prop->body.u8, unittest_mctx->flgs.retain_avail);

    mqttPropertyDel(*prop_list);
    *prop_list = NULL;
} // end of TEST(mqttPropErrChk, update_retain_avail)


TEST(mqttPropErrChk, update_wildcard_subs_avail)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    prop_list = &unittest_mctx->recv_pkt.connack.props;
    unittest_mctx->flgs.recv_mode = 1;
    ptype = MQTT_PROP_WILDCARD_SUBS_AVAIL;
    new_prop = mqttPropertyCreate(prop_list, ptype);

    new_prop->body.u8 = 2;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_PROTOCOL_ERR, unittest_mctx->err_info.reason_code);

    new_prop->body.u8 = 1;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(new_prop->body.u8, unittest_mctx->flgs.wildcard_subs_avail);

    new_prop->body.u8 = 0;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(new_prop->body.u8, unittest_mctx->flgs.wildcard_subs_avail);

    mqttPropertyDel(*prop_list);
    *prop_list = NULL;
} // end of TEST(mqttPropErrChk, update_wildcard_subs_avail)


TEST(mqttPropErrChk, update_subs_id_avail)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    prop_list = &unittest_mctx->recv_pkt.connack.props;
    unittest_mctx->flgs.recv_mode = 1;
    ptype = MQTT_PROP_SUBSCRIBE_ID_AVAIL;
    new_prop = mqttPropertyCreate(prop_list, ptype);

    new_prop->body.u8 = 1;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(new_prop->body.u8, unittest_mctx->flgs.subs_id_avail);

    new_prop->body.u8 = 0;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(new_prop->body.u8, unittest_mctx->flgs.subs_id_avail);

    mqttPropertyDel(*prop_list);
    *prop_list = NULL;
} // end of TEST(mqttPropErrChk, update_subs_id_avail)


TEST(mqttPropErrChk, update_shr_subs_avail)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    prop_list = &unittest_mctx->recv_pkt.connack.props;
    unittest_mctx->flgs.recv_mode = 1;
    ptype = MQTT_PROP_SHARE_SUBSCRIBE_AVAIL;
    new_prop = mqttPropertyCreate(prop_list, ptype);

    new_prop->body.u8 = 1;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(new_prop->body.u8, unittest_mctx->flgs.shr_subs_avail);

    new_prop->body.u8 = 0;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(new_prop->body.u8, unittest_mctx->flgs.shr_subs_avail);

    mqttPropertyDel(*prop_list);
    *prop_list = NULL;
} // end of TEST(mqttPropErrChk, update_shr_subs_avail)


TEST(mqttPropErrChk, update_max_qos_server)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    prop_list = &unittest_mctx->recv_pkt.connack.props;
    unittest_mctx->flgs.recv_mode = 1;
    ptype = MQTT_PROP_MAX_QOS;
    new_prop = mqttPropertyCreate(prop_list, ptype);

    new_prop->body.u8 = MQTT_QOS_1;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_QOS_1, unittest_mctx->max_qos_server);

    new_prop->body.u8 = MQTT_QOS_0;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_QOS_0, unittest_mctx->max_qos_server);

    mqttPropertyDel(*prop_list);
    *prop_list = NULL;
} // end of TEST(mqttPropErrChk, update_max_qos_server)


TEST(mqttPropErrChk, update_req_resp_info)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    prop_list = &unittest_mctx->send_pkt.conn.props;
    unittest_mctx->flgs.recv_mode = 0;
    ptype = MQTT_PROP_REQ_RESP_INFO;
    new_prop = mqttPropertyCreate(prop_list, ptype);

    new_prop->body.u8 = 1;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(1, unittest_mctx->flgs.req_resp_info);

    new_prop->body.u8 = 0;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(0, unittest_mctx->flgs.req_resp_info);

    mqttPropertyDel(*prop_list);
    *prop_list = NULL;
} // end of TEST(mqttPropErrChk, update_req_resp_info)


TEST(mqttPropErrChk, update_req_probm_info)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    prop_list = &unittest_mctx->send_pkt.conn.props;
    unittest_mctx->flgs.recv_mode = 0;
    ptype = MQTT_PROP_REQ_PROBLEM_INFO;
    new_prop = mqttPropertyCreate(prop_list, ptype);

    new_prop->body.u8 = 1;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(1, unittest_mctx->flgs.req_probm_info);

    new_prop->body.u8 = 0;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(0, unittest_mctx->flgs.req_probm_info);

    mqttPropertyDel(*prop_list);
    *prop_list = NULL;
} // end of TEST(mqttPropErrChk, update_req_probm_info)


TEST(mqttPropErrChk, chk_reason_str)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;
    word16 nbytes_alloc    = 0x20;

    prop_list = &unittest_mctx->recv_pkt.connack.props;
    unittest_mctx->flgs.req_probm_info = 0;
    ptype = MQTT_PROP_REASON_STR;
    new_prop = mqttPropertyCreate(prop_list, ptype);

    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_INTEGRITY, status);
    new_prop->body.str.len  = nbytes_alloc;
    new_prop->body.str.data = XMALLOC(sizeof(byte) * nbytes_alloc);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_DISCONNECT, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT , *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PROP_REASON_STR, unittest_mctx->err_info.prop_id);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_SUBSCRIBE, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBCOMP, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_SUBACK , *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);

    unittest_mctx->flgs.req_probm_info = 1;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_DISCONNECT, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT , *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PROP_REASON_STR, unittest_mctx->err_info.prop_id);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_SUBSCRIBE, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBCOMP, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_SUBACK , *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    mqttPropertyDel(*prop_list);
    *prop_list = NULL;
} // end of TEST_CASE(mqttPropErrChk, chk_reason_str)


TEST(mqttPropErrChk, chk_subs_id)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    prop_list = &unittest_mctx->recv_pkt.connack.props;
    unittest_mctx->flgs.recv_mode = 1;
    ptype = MQTT_PROP_SUBSCRIBE_ID_AVAIL;
    new_prop = mqttPropertyCreate(prop_list, ptype);
    new_prop->body.u8 = 0;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    prop_list = &unittest_mctx->send_pkt.pub_msg.props;
    unittest_mctx->flgs.recv_mode = 0;
    ptype = MQTT_PROP_SUBSCRIBE_ID;
    new_prop = mqttPropertyCreate(prop_list, ptype);
    new_prop->body.u32  = 0x0;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_SUB_ID_NOT_SUP, unittest_mctx->err_info.reason_code);

    prop_list = &unittest_mctx->recv_pkt.connack.props;
    unittest_mctx->flgs.recv_mode = 1;
    (*prop_list)->body.u8 = 1;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNACK, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    prop_list = &unittest_mctx->send_pkt.pub_msg.props;
    unittest_mctx->flgs.recv_mode = 0;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status); // root cause: sending PUBLISH with SUBSCRIBE_ID property
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_PROTOCOL_ERR, unittest_mctx->err_info.reason_code);

    unittest_mctx->flgs.recv_mode = 1;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status); // root cause: subscription ID = 0
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_PROTOCOL_ERR, unittest_mctx->err_info.reason_code);

    (*prop_list)->body.u32 = (1 << 28) - 1;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    mqttPropertyDel(unittest_mctx->send_pkt.pub_msg.props);
    mqttPropertyDel(unittest_mctx->recv_pkt.connack.props);
    unittest_mctx->send_pkt.pub_msg.props = NULL;
    unittest_mctx->recv_pkt.connack.props = NULL;
} // end of TEST(mqttPropErrChk, chk_subs_id)


TEST(mqttPropErrChk, chk_resp_topic)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    unittest_mctx->flgs.recv_mode = 0;
    prop_list = &unittest_mctx->send_pkt.pub_msg.props;
    ptype = MQTT_PROP_RESP_TOPIC;
    new_prop = mqttPropertyCreate(prop_list, ptype);
    new_prop->body.str.data = XMALLOC(sizeof(byte) * 0x10);

    new_prop->body.str.len = 1;

    new_prop->body.str.data[0] = MQTT_TOPIC_LEVEL_MULTI;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_INVALID_TOPIC, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_WILDCARD_SUB_NOT_SUP, unittest_mctx->err_info.reason_code);

    new_prop->body.str.data[0] = 'a';
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    new_prop->body.str.data[0] = MQTT_TOPIC_LEVEL_SINGLE;
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_INVALID_TOPIC, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_WILDCARD_SUB_NOT_SUP, unittest_mctx->err_info.reason_code);

    new_prop->body.str.data[0] = '0';
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    new_prop->body.str.len = 3;
    new_prop->body.str.data[1] = MQTT_TOPIC_LEVEL_MULTI;
    new_prop->body.str.data[2] = 'B';
    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_INVALID_TOPIC, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_WILDCARD_SUB_NOT_SUP, unittest_mctx->err_info.reason_code);

    mqttPropertyDel(*prop_list);
    *prop_list = NULL;
} // end of TEST(mqttPropErrChk, chk_resp_topic)


TEST(mqttPropErrChk, unknown_prop_id)
{
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status = MQTT_RESP_OK;

    prop_list = &unittest_mctx->send_pkt.conn.props;
    ptype = 0x04; // given unknown ID, the property check function should report error.
    mqttPropertyCreate(prop_list, ptype);

    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_MALFORMED_PACKET, unittest_mctx->err_info.reason_code);

    mqttPropertyDel(*prop_list);
    *prop_list = NULL;
} // end of TEST(mqttPropErrChk, unknown_prop_id)


TEST(mqttPropErrChk, auth_integrity)
{
    mqttProp_t  *new_prop  = NULL;
    mqttProp_t **prop_list = NULL;
    mqttPropertyType ptype = MQTT_PROP_NONE;
    mqttRespStatus status  = MQTT_RESP_OK;
    word16 nbytes_alloc    = 0x20;

    prop_list = &unittest_mctx->send_pkt.conn.props;
    ptype = MQTT_PROP_AUTH_METHOD;
    new_prop = mqttPropertyCreate(prop_list, ptype);
    new_prop->body.str.len  = nbytes_alloc;
    new_prop->body.str.data = XMALLOC(sizeof(byte) * nbytes_alloc);

    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_PROTOCOL_ERR, unittest_mctx->err_info.reason_code);

    ptype = MQTT_PROP_AUTH_DATA;
    new_prop = mqttPropertyCreate(prop_list, ptype);
    new_prop->body.str.len  = nbytes_alloc;
    new_prop->body.str.data = XMALLOC(sizeof(byte) * nbytes_alloc);

    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_INTEGRITY, status);

    unittest_mctx->eauth_setup_cb = mock_mqttAuthSetupCallback;
    unittest_mctx->eauth_final_cb = mock_mqttAuthFinalCallback;

    status = mqttPropErrChk(unittest_mctx, MQTT_PACKET_TYPE_CONNECT, *prop_list);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    mqttPropertyDel(*prop_list);
    *prop_list = NULL;
} // end of TEST(mqttPropErrChk, auth_integrity)


TEST(mqttSendConnect, in_null)
{
    mqttRespStatus status  = MQTT_RESP_OK;
    status = mqttSendConnect(NULL, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERRARGS, status);
} // end of TEST(mqttSendConnect, in_null)


TEST(mqttSendConnect, wrong_prop)
{
    mqttConn_t  *conn = NULL;
    mqttRespStatus status  = MQTT_RESP_OK;

    conn = &unittest_mctx->send_pkt.conn;
    mqttPropertyCreate(&conn->props , MQTT_PROP_MAX_PKT_SIZE);
    conn->props->body.u32 = 1 + MQTT_RECV_PKT_MAXBYTES;
    status = mqttSendConnect(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_RX_MAX_EXCEEDED, unittest_mctx->err_info.reason_code);
} // end of TEST(mqttSendConnect, wrong_prop)


TEST(mqttSendConnect, wrong_prop_lwt)
{
    mqttConn_t  *conn = NULL;
    mqttRespStatus status  = MQTT_RESP_OK;

    conn = &unittest_mctx->send_pkt.conn;
    conn->flgs.will_enable = 1;
    mqttPropertyCreate(&conn->lwt_msg.props , MQTT_PROP_MAX_PKT_SIZE);
    conn->lwt_msg.props->body.u32 = 1 + MQTT_RECV_PKT_MAXBYTES;
    status = mqttSendConnect(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_RX_MAX_EXCEEDED, unittest_mctx->err_info.reason_code);
} // end of TEST(mqttSendConnect, wrong_prop_lwt)


TEST(mqttSendConnect, err_cal_pktlen)
{
    mqttRespStatus status  = MQTT_RESP_OK;
    mock_get_pktlen_return_val = (int) MQTT_RESP_ERRARGS;
    status = mqttSendConnect(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERRARGS, status);

    mock_get_pktlen_return_val = (int) MQTT_RESP_ERR_EXCEED_PKT_SZ;
    status = mqttSendConnect(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_EXCEED_PKT_SZ, status);

    mock_get_pktlen_return_val = (int) 0x0;
    status = mqttSendConnect(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_MALFORMED_DATA, status);
} // end of TEST(mqttSendConnect, err_cal_pktlen)


TEST(mqttSendConnect, err_net_pkt_send)
{
    mqttRespStatus status  = MQTT_RESP_OK;
    // assume the function successfully computes total length of the CONNECT packet and encodes them 
    mock_get_pktlen_return_val = unittest_mctx->tx_buf_len + 1;
    mock_encode_pkt_return_val = unittest_mctx->tx_buf_len + 1;
    unittest_mctx->last_send_cmdtype = MQTT_PACKET_TYPE_RESERVED;
    // but gets error when sending the encoded packet
    mock_net_pktwrite_return_val = MQTT_RESP_NO_NET_DEV;
    status = mqttSendConnect(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_NO_NET_DEV, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_CONNECT, unittest_mctx->last_send_cmdtype);

    mock_net_pktwrite_return_val = MQTT_RESP_ERR_CONN;
    status = mqttSendConnect(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_CONN, status);

    mock_net_pktwrite_return_val = MQTT_RESP_ERR_SECURE_CONN;
    status = mqttSendConnect(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_SECURE_CONN, status);
} // end of TEST(mqttSendConnect, err_net_pkt_send)


TEST(mqttSendConnect, err_net_pkt_recv)
{
    mqttRespStatus status  = MQTT_RESP_OK;
    // assume the function successfully computes total length of the CONNECT packet and encodes them 
    mock_get_pktlen_return_val = unittest_mctx->tx_buf_len + 1;
    mock_encode_pkt_return_val = unittest_mctx->tx_buf_len + 1;
    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    // but receiving & decoding packet function goes wrong
    mock_net_pktread_return_val = MQTT_RESP_TIMEOUT;
    status = mqttSendConnect(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_TIMEOUT, status);

    mock_net_pktread_return_val = MQTT_RESP_MALFORMED_DATA;
    status = mqttSendConnect(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_MALFORMED_DATA, status);

    mock_net_pktread_return_val = MQTT_RESP_ERR_EXCEED_PKT_SZ;
    status = mqttSendConnect(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_EXCEED_PKT_SZ, status);
} // end of TEST(mqttSendConnect, err_net_pkt_recv)


TEST(mqttSendConnect, recv_decode_connack_ok)
{
    mqttPktHeadConnack_t *connack = NULL;
    mqttRespStatus status  = MQTT_RESP_OK;

    mock_get_pktlen_return_val = unittest_mctx->tx_buf_len + 1;
    mock_encode_pkt_return_val = unittest_mctx->tx_buf_len + 1;
    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    mock_net_pktread_return_val  = MQTT_RESP_OK;
    mock_decode_pkt_return_val   = MQTT_RESP_OK;

    mock_nbytes_pktread   = sizeof(mock_rawbytes_connack);
    mock_rawbytes_pktread = &mock_rawbytes_connack[0];
    unittest_mctx->last_send_cmdtype = MQTT_PACKET_TYPE_RESERVED;

    status = mqttSendConnect(unittest_mctx, &connack);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_CONNECT, unittest_mctx->last_send_cmdtype);
    TEST_ASSERT_EQUAL_UINT(&unittest_mctx->recv_pkt.connack, connack);
} // end of TEST(mqttSendConnect, recv_decode_connack_ok)


TEST(mqttSendAuth, in_null)
{
    mqttRespStatus status  = MQTT_RESP_OK;

    status = mqttSendAuth(NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERRARGS, status);

    unittest_mctx->eauth_final_cb = NULL;
    unittest_mctx->eauth_setup_cb = NULL;
    status = mqttSendAuth(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERRARGS, status);

    unittest_mctx->eauth_final_cb = mock_mqttAuthFinalCallback;
    unittest_mctx->eauth_setup_cb = mock_mqttAuthSetupCallback;
    status = mqttSendAuth(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_PROP, status);
} // end of TEST(mqttSendAuth, in_null)


TEST(mqttSendAuth, next_auth_sent)
{
    mqttAuth_t  *auth_recv = NULL;
    mqttProp_t  *tmp_prop  = NULL;
    mqttRespStatus status  = MQTT_RESP_OK;
    byte nbytes_alloc = 0x20;

    unittest_mctx->last_send_cmdtype = MQTT_PACKET_TYPE_RESERVED;
    unittest_mctx->eauth_final_cb = mock_mqttAuthFinalCallback;
    unittest_mctx->eauth_setup_cb = mock_mqttAuthSetupCallback;
    // assume server sends AUTH command back after CONNECT sent by client
    auth_recv  = &unittest_mctx->recv_pkt.auth;
    auth_recv->props = NULL;
    tmp_prop  = mqttPropertyCreate(&auth_recv->props, MQTT_PROP_AUTH_METHOD);
    tmp_prop->body.str.len  = nbytes_alloc;
    tmp_prop->body.str.data = XMALLOC(sizeof(byte) * nbytes_alloc);
    tmp_prop  = mqttPropertyCreate(&auth_recv->props, MQTT_PROP_AUTH_DATA);
    tmp_prop->body.str.len  = nbytes_alloc;
    tmp_prop->body.str.data = XMALLOC(sizeof(byte) * nbytes_alloc);
    // delibarately take all available property items, mqttSendAuth() should return error due
    // to lack of available property items
    tmp_prop = mqttPropertyCreate(&auth_recv->props, MQTT_PROP_USER_PROPERTY);
    while(mqttPropertyCreate(&auth_recv->props, MQTT_PROP_USER_PROPERTY) != NULL);
    status = mqttSendAuth(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERRMEM, status);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->send_pkt.auth.props);
    // release property items allocated and pointed by tmp_prop
    mqttPropertyDel(tmp_prop);
    TEST_ASSERT_EQUAL_UINT(tmp_prop, auth_recv->props->next->next);
    auth_recv->props->next->next = NULL; // TODO: find better way to deallocate property list item

    mock_get_pktlen_return_val = (int) MQTT_RESP_ERR_EXCEED_PKT_SZ;
    status = mqttSendAuth(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_EXCEED_PKT_SZ, status);

    mock_get_pktlen_return_val = (int) 0x0;
    status = mqttSendAuth(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_MALFORMED_DATA, status);
    // assume everything in mqttSendAuth() works well
    mock_get_pktlen_return_val = unittest_mctx->tx_buf_len + 1;
    mock_encode_pkt_return_val = unittest_mctx->tx_buf_len + 1;
    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    mock_net_pktread_return_val  = MQTT_RESP_OK;
    mock_decode_pkt_return_val   = MQTT_RESP_OK;
    status = mqttSendAuth(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_AUTH, unittest_mctx->last_send_cmdtype);
} // end of TEST(mqttSendAuth, next_auth_sent)


TEST(mqttSendDisconnect, err_chk)
{
    mqttRespStatus status  = MQTT_RESP_OK;

    mock_get_pktlen_return_val = (int) MQTT_RESP_ERR_EXCEED_PKT_SZ;
    status = mqttSendDisconnect(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_EXCEED_PKT_SZ, status);

    mock_get_pktlen_return_val = (int) 0x0;
    status = mqttSendDisconnect(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_MALFORMED_DATA, status);

    // assume everything in mqttSendDisconnect() works well
    mock_get_pktlen_return_val = unittest_mctx->tx_buf_len + 1;
    mock_encode_pkt_return_val = unittest_mctx->tx_buf_len + 1;
    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    mock_net_pktread_return_val  = MQTT_RESP_OK;
    mock_decode_pkt_return_val   = MQTT_RESP_OK;
    status = mqttSendDisconnect(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_DISCONNECT, unittest_mctx->last_send_cmdtype);
} // end of TEST(mqttSendDisconnect, err_chk)


TEST(mqttSendPublish, wrong_args)
{
    mqttMsg_t        *msg  = NULL;
    mqttRespStatus status  = MQTT_RESP_OK;

    msg = &unittest_mctx->send_pkt.pub_msg;

    msg->qos = MQTT_QOS_2;
    unittest_mctx->max_qos_server = MQTT_QOS_1;
    status = mqttSendPublish(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERRARGS, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_QOS_NOT_SUPPORTED, unittest_mctx->err_info.reason_code);

    msg->qos = MQTT_QOS_0;
    msg->retain = 1;
    unittest_mctx->flgs.retain_avail = 0;
    status = mqttSendPublish(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERRARGS, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_RETAIN_NOT_SUPPORTED, unittest_mctx->err_info.reason_code);

    unittest_mctx->flgs.retain_avail = 1;
    msg->topic.data = NULL;
    msg->topic.len  = 0;
    status = mqttSendPublish(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_INTEGRITY, status);

    msg->topic.data = XMALLOC(sizeof(byte) * 0x20);
    msg->topic.len  = 7;
    XMEMCPY(msg->topic.data, (byte *)&("$share/"), 7);
    unittest_mctx->flgs.shr_subs_avail = 0;
    status = mqttSendPublish(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_INVALID_TOPIC, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_SS_NOT_SUPPORTED, unittest_mctx->err_info.reason_code);

    unittest_mctx->flgs.shr_subs_avail = 1;
    status = mqttSendPublish(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_INVALID_TOPIC, status);

    msg->topic.len  += 10;
    XMEMCPY(&msg->topic.data[7], (byte *)&("hier/topic"), 10);
    msg->props = NULL;
    mock_get_pktlen_return_val = (int) MQTT_RESP_ERR_EXCEED_PKT_SZ;
    status = mqttSendPublish(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_EXCEED_PKT_SZ, status);

    XMEMFREE(msg->topic.data);
    msg->topic.data = NULL;
} // end of TEST(mqttSendPublish, wrong_args)


TEST(mqttSendPublish, qos1_sent_ok)
{
    mqttPktPubResp_t *resp = NULL;
    mqttMsg_t        *msg  = NULL;
    mqttRespStatus status  = MQTT_RESP_OK;

    msg = &unittest_mctx->send_pkt.pub_msg;

    unittest_mctx->max_qos_server = MQTT_QOS_2;
    unittest_mctx->flgs.retain_avail = 1;
    unittest_mctx->flgs.shr_subs_avail = 1;

    msg->qos = MQTT_QOS_1;
    msg->retain = 0;
    msg->topic.data = XMALLOC(sizeof(byte) * 0x20);
    msg->topic.len  = 7;
    XMEMCPY(msg->topic.data, (byte *)&("qos1_ok"), 7);
    msg->props = NULL;

    mock_get_pktlen_return_val = unittest_mctx->tx_buf_len + 1;
    mock_encode_pkt_return_val = unittest_mctx->tx_buf_len + 1;
    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    mock_net_pktread_return_val  = MQTT_RESP_TIMEOUT;

    status = mqttSendPublish(unittest_mctx, &resp);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_TIMEOUT, status);
    TEST_ASSERT_EQUAL_UINT8( 1, msg->duplicate );

    mock_net_pktread_return_val  = MQTT_RESP_OK;
    mock_decode_pkt_return_val   = MQTT_RESP_OK;
    mock_mqtt_pkt_id = 0x010b; // TODO: randomly give non-zero packet ID
    mock_rawbytes_puback[2] = mock_mqtt_pkt_id >> 0x8;
    mock_rawbytes_puback[3] = mock_mqtt_pkt_id & 0xff;
    mock_nbytes_pktread   = sizeof(mock_rawbytes_puback);
    mock_rawbytes_pktread = &mock_rawbytes_puback[0];
    unittest_mctx->last_send_cmdtype = MQTT_PACKET_TYPE_RESERVED;

    status = mqttSendPublish(unittest_mctx, &resp);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_PUBACK , unittest_mctx->last_recv_cmdtype);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_PUBLISH, unittest_mctx->last_send_cmdtype);
    TEST_ASSERT_EQUAL_UINT(&unittest_mctx->recv_pkt.pub_resp, resp);
    TEST_ASSERT_EQUAL_UINT16(mock_mqtt_pkt_id, resp->packet_id);
    TEST_ASSERT_LESS_THAN_UINT8(MQTT_REASON_UNSPECIFIED_ERR, resp->reason_code);

    XMEMFREE(msg->topic.data);
    msg->topic.data = NULL;
} // end of TEST(mqttSendPublish, qos1_sent_ok)


TEST(mqttSendPubResp, wrong_args)
{
    mqttPktPubResp_t *resp_in  = NULL;
    mqttRespStatus  status = MQTT_RESP_OK;

    resp_in = &unittest_mctx->send_pkt.pub_resp;
    status  = mqttSendPubResp(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERRARGS, status);

    resp_in->props = NULL;
    mock_get_pktlen_return_val = (int) MQTT_RESP_ERR_EXCEED_PKT_SZ;
    status  = mqttSendPubResp(unittest_mctx, MQTT_PACKET_TYPE_PUBRECV, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_EXCEED_PKT_SZ, status);

    mock_get_pktlen_return_val = (int) 0x0;
    status = mqttSendPubResp(unittest_mctx, MQTT_PACKET_TYPE_PUBRECV, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_MALFORMED_DATA, status);
} // end of TEST(mqttSendPubResp, wrong_args)


TEST(mqttSendPubResp, qos2_pubrecv_sent)
{
    mqttPktPubResp_t *resp_out = NULL;
    mqttPktPubResp_t *resp_in  = NULL;
    mqttRespStatus  status = MQTT_RESP_OK;

    resp_in = &unittest_mctx->send_pkt.pub_resp;
    resp_in->props = NULL;

    mock_get_pktlen_return_val = unittest_mctx->tx_buf_len + 1;
    mock_encode_pkt_return_val = unittest_mctx->tx_buf_len + 1;
    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    mock_net_pktread_return_val  = MQTT_RESP_OK;
    mock_decode_pkt_return_val   = MQTT_RESP_OK;

    mock_mqtt_pkt_id   = 0x012c; // TODO: randomly give non-zero packet ID
    resp_in->packet_id = mock_mqtt_pkt_id;
    mock_rawbytes_pubrel[2] = mock_mqtt_pkt_id >> 0x8;
    mock_rawbytes_pubrel[3] = mock_mqtt_pkt_id & 0xff;
    mock_nbytes_pktread   =  sizeof(mock_rawbytes_pubrel);
    mock_rawbytes_pktread = &mock_rawbytes_pubrel[0];
    status  = mqttSendPubResp(unittest_mctx, MQTT_PACKET_TYPE_PUBRECV, &resp_out);

    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_PUBREL , unittest_mctx->last_recv_cmdtype);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_PUBCOMP, unittest_mctx->last_send_cmdtype);
    TEST_ASSERT_EQUAL_UINT(&unittest_mctx->recv_pkt_qos2.pub_resp, resp_out);
    TEST_ASSERT_EQUAL_UINT16(mock_mqtt_pkt_id, resp_out->packet_id);
    TEST_ASSERT_LESS_THAN_UINT8(MQTT_REASON_UNSPECIFIED_ERR, resp_out->reason_code);
} // end of TEST(mqttSendPubResp, qos2_pubrecv_sent)


TEST(mqttSendPubResp, qos2_pubrel_sent)
{
    mqttPktPubResp_t *resp_out = NULL;
    mqttPktPubResp_t *resp_in  = NULL;
    mqttRespStatus  status = MQTT_RESP_OK;

    resp_in = &unittest_mctx->send_pkt_qos2.pub_resp;
    resp_in->props = NULL;

    mock_get_pktlen_return_val = unittest_mctx->tx_buf_len + 1;
    mock_encode_pkt_return_val = unittest_mctx->tx_buf_len + 1;
    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    mock_net_pktread_return_val  = MQTT_RESP_OK;
    mock_decode_pkt_return_val   = MQTT_RESP_OK;

    mock_mqtt_pkt_id   = 0x023d; // TODO: randomly give non-zero packet ID
    resp_in->packet_id = mock_mqtt_pkt_id;
    mock_rawbytes_pubcomp[2] = mock_mqtt_pkt_id >> 0x8;
    mock_rawbytes_pubcomp[3] = mock_mqtt_pkt_id & 0xff;
    mock_nbytes_pktread   =  sizeof(mock_rawbytes_pubcomp);
    mock_rawbytes_pktread = &mock_rawbytes_pubcomp[0];
    status  = mqttSendPubResp(unittest_mctx, MQTT_PACKET_TYPE_PUBREL, &resp_out);

    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_PUBCOMP, unittest_mctx->last_recv_cmdtype);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_PUBREL , unittest_mctx->last_send_cmdtype);
    TEST_ASSERT_EQUAL_UINT(&unittest_mctx->recv_pkt_qos2.pub_resp, resp_out);
    TEST_ASSERT_EQUAL_UINT16(mock_mqtt_pkt_id, resp_out->packet_id);
} // end of TEST(mqttSendPubResp, qos2_pubrel_sent)


TEST(mqttSendSubscribe, invalid_topics)
{
    mqttPktSubs_t   *subs = NULL;
    mqttRespStatus status = MQTT_RESP_OK;

    subs = &unittest_mctx->send_pkt.subs;

    subs->topics = NULL;
    subs->topic_cnt = 0;
    status = mqttSendSubscribe(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_UINT8(MQTT_REASON_PROTOCOL_ERR, unittest_mctx->err_info.reason_code);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_INVALID_TOPIC, status);

    subs->props = NULL;
    subs->topic_cnt = 2;
    subs->topics = (mqttTopic_t *)XMALLOC(sizeof(mqttTopic_t) * subs->topic_cnt);
    subs->topics[0].filter.len  = 0;
    subs->topics[0].filter.data = NULL;
    subs->topics[1].filter.len  = 0;
    subs->topics[1].filter.data = NULL;
    status = mqttSendSubscribe(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_INTEGRITY, status);

    unittest_mctx->flgs.wildcard_subs_avail = 0x1;
    subs->topics[0].filter.data = (byte *) XMALLOC(sizeof(byte) * 0x20);
    subs->topics[1].filter.data = (byte *) XMALLOC(sizeof(byte) * 0x20);

    XMEMCPY(subs->topics[0].filter.data, (byte *)&("multilvl/#sep"), 13);
    subs->topics[0].filter.len  = 13;
    status = mqttSendSubscribe(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_INVALID_TOPIC, status);

    XMEMCPY(subs->topics[0].filter.data, (byte *)&("multilvl/sep#"), 13);
    subs->topics[0].filter.len  = 13;
    status = mqttSendSubscribe(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_INVALID_TOPIC, status);

    XMEMCPY(subs->topics[0].filter.data, (byte *)&("multilvl/sep/#"), 14);
    subs->topics[0].filter.len  = 14;
    XMEMCPY(subs->topics[1].filter.data, (byte *)&("singlelvl/s+ep"), 14);
    subs->topics[1].filter.len  = 0;
    status = mqttSendSubscribe(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_INTEGRITY, status);

    subs->topics[1].filter.len  = 14;
    status = mqttSendSubscribe(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_INVALID_TOPIC, status);

    XMEMCPY(subs->topics[1].filter.data, (byte *)&("singlelvl/+sep"), 14);
    subs->topics[1].filter.len = 14;
    status = mqttSendSubscribe(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_INVALID_TOPIC, status);

    XMEMCPY(subs->topics[1].filter.data, (byte *)&("singlelvl/+/sep"), 15);
    subs->topics[1].filter.len = 15;
    mock_get_pktlen_return_val = (int) MQTT_RESP_ERR_EXCEED_PKT_SZ;
    status = mqttSendSubscribe(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_EXCEED_PKT_SZ, status);

    XMEMFREE(subs->topics[0].filter.data);
    XMEMFREE(subs->topics[1].filter.data);
    subs->topics[0].filter.data = NULL;
    subs->topics[1].filter.data = NULL;
    XMEMFREE(subs->topics);
    subs->topics = NULL;
} // end of TEST(mqttSendSubscribe, invalid_topics)


TEST(mqttSendSubscribe, topics_sent)
{
    mqttPktSubs_t   *subs   = NULL;
    mqttPktSuback_t *suback = NULL;
    mqttRespStatus status = MQTT_RESP_OK;

    subs = &unittest_mctx->send_pkt.subs;

    unittest_mctx->flgs.wildcard_subs_avail = 0x1;
    subs->topic_cnt = 2;
    subs->topics = (mqttTopic_t *)XMALLOC(sizeof(mqttTopic_t) * subs->topic_cnt);
    subs->topics[0].filter.data = (byte *) XMALLOC(sizeof(byte) * 0x20);
    subs->topics[1].filter.data = (byte *) XMALLOC(sizeof(byte) * 0x20);
    XMEMCPY(subs->topics[0].filter.data, (byte *)&("multilvl/sep/#"), 14);
    subs->topics[0].filter.len = 14;
    XMEMCPY(subs->topics[1].filter.data, (byte *)&("singlelvl/+/sep"), 15);
    subs->topics[1].filter.len = 15;
    subs->topics[0].qos = MQTT_QOS_2;
    subs->topics[1].qos = MQTT_QOS_1;

    mock_get_pktlen_return_val = unittest_mctx->tx_buf_len + 1;
    mock_encode_pkt_return_val = unittest_mctx->tx_buf_len + 1;
    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    mock_net_pktread_return_val  = MQTT_RESP_OK;
    mock_decode_pkt_return_val   = MQTT_RESP_OK;

    mock_mqtt_pkt_id   = 0x046f; // TODO: randomly give non-zero packet ID
    mock_rawbytes_suback[2] = mock_mqtt_pkt_id >> 0x8;
    mock_rawbytes_suback[3] = mock_mqtt_pkt_id & 0xff;
    mock_rawbytes_suback[5] = subs->topics[0].qos; // reason code: granted QoS fot 1st topic
    mock_rawbytes_suback[6] = subs->topics[1].qos; // reason code: granted QoS fot 2nd topic
    mock_nbytes_pktread   =  sizeof(mock_rawbytes_suback);
    mock_rawbytes_pktread = &mock_rawbytes_suback[0];

    status = mqttSendSubscribe(unittest_mctx, &suback);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_SUBSCRIBE, unittest_mctx->last_send_cmdtype);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_SUBACK   , unittest_mctx->last_recv_cmdtype);
    TEST_ASSERT_EQUAL_UINT(&unittest_mctx->recv_pkt.suback, suback);
    TEST_ASSERT_EQUAL_UINT16(mock_mqtt_pkt_id, suback->packet_id);
    TEST_ASSERT_NOT_EQUAL(NULL, suback->return_codes);
    TEST_ASSERT_EQUAL_UINT8(MQTT_QOS_2, suback->return_codes[0]);
    TEST_ASSERT_EQUAL_UINT8(MQTT_QOS_1, suback->return_codes[1]);

    XMEMFREE(subs->topics[0].filter.data);
    XMEMFREE(subs->topics[1].filter.data);
    subs->topics[0].filter.data = NULL;
    subs->topics[1].filter.data = NULL;
    XMEMFREE(subs->topics);
    subs->topics = NULL;
    if(suback != NULL) {
        if(suback->return_codes != NULL) {
            XMEMFREE(suback->return_codes);
            suback->return_codes = NULL;
        }
    }
} // end of TEST(mqttSendSubscribe, topics_sent)



TEST(mqttSendUnsubscribe, topics_sent)
{
    mqttPktUnsubs_t   *unsubs   = NULL;
    mqttPktUnsuback_t *unsuback = NULL;
    mqttRespStatus status = MQTT_RESP_OK;

    unsubs = &unittest_mctx->send_pkt.unsubs;

    unsubs->topic_cnt = 0;
    unsubs->topics    = NULL;
    status = mqttSendUnsubscribe(unittest_mctx, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_INVALID_TOPIC, status);

    unittest_mctx->flgs.wildcard_subs_avail = 0x1;
    unsubs->topic_cnt = 2;
    unsubs->topics = (mqttTopic_t *)XMALLOC(sizeof(mqttTopic_t) * unsubs->topic_cnt);
    unsubs->topics[0].filter.data = (byte *) XMALLOC(sizeof(byte) * 0x20);
    unsubs->topics[1].filter.data = (byte *) XMALLOC(sizeof(byte) * 0x20);
    XMEMCPY(unsubs->topics[0].filter.data, (byte *)&("unsubscribe/#"), 13);
    unsubs->topics[0].filter.len = 13;
    XMEMCPY(unsubs->topics[1].filter.data, (byte *)&("undo/+/sep"), 10);
    unsubs->topics[1].filter.len = 10;
    unsubs->topics[0].qos = MQTT_QOS_2;
    unsubs->topics[1].qos = MQTT_QOS_1;

    mock_get_pktlen_return_val = unittest_mctx->tx_buf_len + 1;
    mock_encode_pkt_return_val = unittest_mctx->tx_buf_len + 1;
    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    mock_net_pktread_return_val  = MQTT_RESP_OK;
    mock_decode_pkt_return_val   = MQTT_RESP_OK;

    mock_mqtt_pkt_id   = 0x0571; // TODO: randomly give non-zero packet ID
    mock_rawbytes_unsuback[2] = mock_mqtt_pkt_id >> 0x8;
    mock_rawbytes_unsuback[3] = mock_mqtt_pkt_id & 0xff;
    mock_rawbytes_unsuback[5] = unsubs->topics[0].qos; // reason code: granted QoS fot 1st topic
    mock_rawbytes_unsuback[6] = unsubs->topics[1].qos; // reason code: granted QoS fot 2nd topic
    mock_nbytes_pktread   =  sizeof(mock_rawbytes_unsuback);
    mock_rawbytes_pktread = &mock_rawbytes_unsuback[0];

    status = mqttSendUnsubscribe(unittest_mctx, &unsuback);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_UNSUBSCRIBE, unittest_mctx->last_send_cmdtype);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_UNSUBACK   , unittest_mctx->last_recv_cmdtype);
    TEST_ASSERT_EQUAL_UINT(&unittest_mctx->recv_pkt.unsuback, unsuback);
    TEST_ASSERT_EQUAL_UINT16(mock_mqtt_pkt_id, unsuback->packet_id);
    TEST_ASSERT_NOT_EQUAL(NULL, unsuback->return_codes);
    TEST_ASSERT_EQUAL_UINT8(MQTT_QOS_2, unsuback->return_codes[0]);
    TEST_ASSERT_EQUAL_UINT8(MQTT_QOS_1, unsuback->return_codes[1]);

    XMEMFREE(unsubs->topics[0].filter.data);
    XMEMFREE(unsubs->topics[1].filter.data);
    unsubs->topics[0].filter.data = NULL;
    unsubs->topics[1].filter.data = NULL;
    XMEMFREE(unsubs->topics);
    unsubs->topics = NULL;
    if(unsuback != NULL) {
        if(unsuback->return_codes != NULL) {
            XMEMFREE(unsuback->return_codes);
            unsuback->return_codes = NULL;
        }
    }
} // end of TEST(mqttSendUnsubscribe, topics_sent)


TEST(mqttSendPingReq, ping_sent)
{
    mqttRespStatus status = MQTT_RESP_OK;
    mock_encode_pkt_return_val   = 2;
    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    mock_net_pktread_return_val  = MQTT_RESP_OK;
    mock_decode_pkt_return_val   = MQTT_RESP_OK;
    mock_nbytes_pktread   =  sizeof(mock_rawbytes_pingresp);
    mock_rawbytes_pktread = &mock_rawbytes_pingresp[0];

    status = mqttSendPingReq(unittest_mctx);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_PINGREQ , unittest_mctx->last_send_cmdtype);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_PINGRESP, unittest_mctx->last_recv_cmdtype);
} // end of TEST(mqttSendPingReq, ping_sent)


TEST(mqttClientWaitPkt, auth_in_recv)
{
    mqttRespStatus status = MQTT_RESP_OK;

    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    mock_net_pktread_return_val  = MQTT_RESP_OK;
    mock_decode_pkt_return_val   = MQTT_RESP_OK;
    mock_nbytes_pktread   =  sizeof(mock_rawbytes_auth);
    mock_rawbytes_pktread = &mock_rawbytes_auth[0];

    status = mqttClientWaitPkt(unittest_mctx, MQTT_PACKET_TYPE_AUTH, 0x0, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_AUTH, unittest_mctx->last_recv_cmdtype);
} // end of TEST(mqttClientWaitPkt, auth_in_recv)


TEST(mqttClientWaitPkt, invalid_cmd)
{
    mqttRespStatus status = MQTT_RESP_OK;

    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    mock_net_pktread_return_val  = MQTT_RESP_OK;
    mock_decode_pkt_return_val   = MQTT_RESP_OK;
    mock_nbytes_pktread   =  sizeof(mock_rawbytes_invalid_cmd);
    mock_rawbytes_pktread = &mock_rawbytes_invalid_cmd[0];

    status = mqttClientWaitPkt(unittest_mctx, MQTT_PACKET_TYPE_PINGREQ, 0x0, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_CTRL_PKT_TYPE, status);
} // end of TEST(mqttClientWaitPkt, invalid_cmd)


TEST(mqttClientWaitPkt, pubmsg_recv)
{
    mqttRespStatus status = MQTT_RESP_OK;

    mock_net_pktwrite_return_val = MQTT_RESP_OK;
    mock_net_pktread_return_val  = MQTT_RESP_OK;
    mock_decode_pkt_return_val   = MQTT_RESP_OK;
    mock_nbytes_pktread   =  sizeof(mock_rawbytes_pub_qos0);
    mock_rawbytes_pktread = &mock_rawbytes_pub_qos0[0];

    status = mqttClientWaitPkt(unittest_mctx, MQTT_PACKET_TYPE_PUBLISH, 0x0, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_PUBLISH, unittest_mctx->last_recv_cmdtype);

    mock_nbytes_pktread   =  sizeof(mock_rawbytes_pingresp);
    mock_rawbytes_pktread = &mock_rawbytes_pingresp[0];
    // receive PINGRESP, then deallocate space for previously received PUBLISH
    status = mqttClientWaitPkt(unittest_mctx, MQTT_PACKET_TYPE_PINGRESP, 0x0, NULL);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PACKET_TYPE_PINGRESP, unittest_mctx->last_recv_cmdtype);
} // end of TEST(mqttClientWaitPkt, pubmsg_recv)




static void RunAllTestGroups(void)
{
    RUN_TEST_GROUP(mqttClientInit);
    // no need to re-init new mqtt client when running new test group
    unittest_mctx = NULL;
    mqttClientInit(&unittest_mctx, 0x100);
    RUN_TEST_GROUP(mqttPropertyCreate);
    RUN_TEST_GROUP(mqttPropertyDel);
    RUN_TEST_GROUP(mqttPropErrChk);
    RUN_TEST_GROUP(mqttSendConnect);
    RUN_TEST_GROUP(mqttSendAuth);
    RUN_TEST_GROUP(mqttSendDisconnect);
    RUN_TEST_GROUP(mqttSendPublish);
    RUN_TEST_GROUP(mqttSendPubResp);
    RUN_TEST_GROUP(mqttSendSubscribe);
    RUN_TEST_GROUP(mqttSendUnsubscribe);
    RUN_TEST_GROUP(mqttSendPingReq);
    RUN_TEST_GROUP(mqttClientWaitPkt);
    mqttClientDeinit( unittest_mctx );
    unittest_mctx = NULL;
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


