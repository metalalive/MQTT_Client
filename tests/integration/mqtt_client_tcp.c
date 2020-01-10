#include "mqtt_include.h"
#include "pattern_generator.h"

// wait 10 seconds after MQTT command is sent to broker
#define  MQTT_TEST_CMD_TIMEOUT_MS          6000
#define  MQTT_TEST_THREAD_STACK_SIZE       ((uint16_t) 0x13e)

static mqttTestPatt testPatternSet;
static mqttCtx_t *m_client;



static mqttRespStatus mqttTestRunPatterns( mqttTestPatt *patt_in, mqttCtx_t *mctx )
{
    mqttRespStatus status =  MQTT_RESP_OK;
    uint8_t  num_pub_msg_sent =  2 + mqttUtilPRNG(patt_in->drbg, 3);
    uint8_t  num_pub_msg_recv =  2 + mqttUtilPRNG(patt_in->drbg, 3);
    uint8_t  num_ping_sent    =  1 + mqttUtilPRNG(patt_in->drbg, 2);
    patt_in->connack       = NULL; 
    patt_in->suback        = NULL;
    patt_in->unsuback      = NULL;

    // -------- send CONNECT packet to broker --------
    mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_CONNECT );
    status = mqttSendConnect( mctx, &patt_in->connack );
    mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_CONNECT);
    if((status < 0) || (patt_in->connack == NULL)) { goto disconnect_server; }
    status = mqttChkReasonCode(patt_in->connack->reason_code);
    if( status != MQTT_RESP_OK ){
        mctx->err_info.reason_code = patt_in->connack->reason_code;
        goto disconnect_server;
    }
    // -------- send PUBLISH packet to broker --------
    while(num_pub_msg_sent > 0) {
        num_pub_msg_sent--;
        patt_in->pubresp = NULL;
        mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_PUBLISH );
        status = mqttSendPublish( mctx, &patt_in->pubresp );
        mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_PUBLISH );
        if(status < 0) { goto disconnect_server; }
        if(patt_in->pubmsg_send.qos == MQTT_QOS_0) {
            continue; // skip checking publish response, prepare for next PUBLISH packet
        }
        else {
            if(patt_in->pubresp == NULL) { goto disconnect_server;  }
        }
        status = mqttChkReasonCode(patt_in->pubresp->reason_code);
        if( status != MQTT_RESP_OK ){
            mctx->err_info.reason_code = patt_in->pubresp->reason_code;
            goto disconnect_server;
        }
    } // end of while-loop
    // -------- send SUBSCRIBE packet, and wait for incoming PUBLISH packet (from broker) --------
    mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_SUBSCRIBE );
    status = mqttSendSubscribe( mctx, &patt_in->suback );
    if((status < 0) || (patt_in->suback==NULL)) {
        mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_SUBSCRIBE );
        goto disconnect_server;
    }
    status = mqttChkReasonCode(patt_in->suback->return_codes[0]);
    if( status != MQTT_RESP_OK ){
        mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_SUBSCRIBE );
        mctx->err_info.reason_code = patt_in->suback->return_codes[0];
        goto disconnect_server;
    }
    // --------- wait for incoming PUBLISH packet ---------
    mqttModifyReadMsgTimeout(mctx, 0xdbba0); // wait 15 minutes = 1000 * 60 * 15 milliseconds
    // TODO: write script to mock another client sending PUBLISH packet to this subsriber...
    while(num_pub_msg_recv > 0) {
        patt_in->pubmsg_recv = NULL;
        status = mqttClientWaitPkt( mctx, MQTT_PACKET_TYPE_PUBLISH, 0, (void **)&patt_in->pubmsg_recv );
        if((status < 0) || (patt_in->pubmsg_recv==NULL)) { break; }
        num_pub_msg_recv--;
    } // end of while-loop
    mqttModifyReadMsgTimeout(mctx, MQTT_TEST_CMD_TIMEOUT_MS);
    // -------- send UNSUBSCRIBE packet to broker --------
    mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_UNSUBSCRIBE );
    status = mqttSendUnsubscribe( mctx, &patt_in->unsuback );
    mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_UNSUBSCRIBE );
    mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_SUBSCRIBE );
    if((status < 0) || (patt_in->unsuback==NULL)) { goto disconnect_server; }
    status = mqttChkReasonCode(patt_in->unsuback->return_codes[0]);
    if( status != MQTT_RESP_OK ){
        mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_SUBSCRIBE );
        mctx->err_info.reason_code = patt_in->unsuback->return_codes[0];
        goto disconnect_server;
    }
    // -------- send optional PING packet to broker --------
    while(num_ping_sent > 0) {
        status = mqttSendPingReq( mctx );
        if(status < 0) { break; }
        num_ping_sent--;
    } // end of while-loop
    // -------- send DISCONNET packet to broker --------
disconnect_server :
    mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_DISCONNECT );
    mqttSendDisconnect( mctx );
    mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_DISCONNECT );
    return status;
} // end of mqttTestRunPatterns





static void mqttTestStartFn(void *params) 
{
    mqttRespStatus status   = MQTT_RESP_ERR;
    uint8_t        num_iter = 0;

    if(m_client->drbg == NULL) {
        status = mqttDRBGinit(&m_client->drbg);
        if(status != MQTT_RESP_OK) { goto end_of_main_test; }
    }
    XMEMSET( &testPatternSet, 0x00, sizeof(mqttTestPatt)) ;
    testPatternSet.drbg = m_client->drbg;
    num_iter = 3 + (uint8_t) mqttUtilPRNG(m_client->drbg, 3);
    while(num_iter > 0)
    {
        status =  mqttNetconnStart( m_client );
        if( status == MQTT_RESP_OK ) {
            mqttTestRunPatterns( &testPatternSet, m_client );
        }
        status =  mqttNetconnStop( m_client );
        if( status != MQTT_RESP_OK ) { break; }
        num_iter--;
    } // end of while-loop
end_of_main_test:
    if(m_client->drbg != NULL) {
        mqttDRBGdeinit(m_client->drbg);
        m_client->drbg = NULL;
    }
    mqttClientDeinit( m_client ); // TODO: should we de-init system before terminating this thread ?
    m_client = NULL;
#ifdef MQTT_CFG_RUN_TEST_THREAD
    mqttSysThreadDelete( NULL );
#endif
} // end of mqttTestStartFn




int main (int argc, char** argv)
{
    mqttRespStatus status = MQTT_RESP_ERR;
    m_client = NULL;
    status =  mqttClientInit( &m_client, MQTT_TEST_CMD_TIMEOUT_MS );
    if( status == MQTT_RESP_OK ) {
#ifdef MQTT_CFG_RUN_TEST_THREAD
        uint8_t isPrivileged = 0x1;
        mqttSysThre_t  new_thread;
        mqttSysThreadCreate( "mqttTestStartFn", (mqttSysThreFn)mqttTestStartFn, NULL ,
                              MQTT_TEST_THREAD_STACK_SIZE, MQTT_APPS_THREAD_PRIO_MIN 
                              , isPrivileged, &new_thread );
        mqttSysThreadWaitUntilExit(&new_thread, NULL);
#else
        mqttTestStartFn( NULL );
#endif
    }
    return 0;
} // end of main()


