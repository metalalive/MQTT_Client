#include "mqtt_include.h"
#include "pattern_generator.h"

// wait 10 seconds after MQTT command is sent to broker
#define  MQTT_TEST_CMD_TIMEOUT_MS          6000
#define  MQTT_TEST_THREAD_STACK_SIZE       ((uint16_t) 0x13e)

static mqttTestPatt testPatternSet;
static mqttCtx_t *m_client;



static mqttRespStatus mqttTestRunPatterns( mqttTestPatt *patt_in, mqttCtx_t *mctx )
{ // this test acting as client only send CONNECT and DISCONNECT to its peer MQTT broker.
    mqttRespStatus status =  MQTT_RESP_OK;
    uint8_t  num_pub_msg_recv = 0;
    patt_in->connack  = NULL; 
    patt_in->suback   = NULL;
    patt_in->unsuback = NULL;
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
    // -------- send SUBSCRIBE packet, and wait for incoming PUBLISH packet (from broker) --------
    mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_SUBSCRIBE );
    status = mqttSendSubscribe( mctx, &patt_in->suback );
    if((status < 0) || (patt_in->suback==NULL)) {
        goto cleanup_subscribe_testdata;
    }
    status = mqttChkReasonCode(patt_in->suback->return_codes[0]);
    if( status != MQTT_RESP_OK ){
        mctx->err_info.reason_code = patt_in->suback->return_codes[0];
        goto cleanup_subscribe_testdata;
    }
    // --------- wait for incoming PUBLISH packet ---------
    mqttModifyReadMsgTimeout(mctx, 0xdbba0); // wait 15 minutes = 1000 * 60 * 15 milliseconds
    for(num_pub_msg_recv = 3; num_pub_msg_recv > 0; num_pub_msg_recv--) {
        patt_in->pubmsg_recv = NULL;
        status = mqttClientWaitPkt( mctx, MQTT_PACKET_TYPE_PUBLISH, 0, (void **)&patt_in->pubmsg_recv );
        if((status < 0) || (patt_in->pubmsg_recv==NULL)) { break; }
    } // end of while-loop
    mqttModifyReadMsgTimeout(mctx, MQTT_TEST_CMD_TIMEOUT_MS);
    // -------- send UNSUBSCRIBE packet to broker --------
    mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_UNSUBSCRIBE );
    status = mqttSendUnsubscribe( mctx, &patt_in->unsuback );
    if((status < 0) || (patt_in->unsuback==NULL)) { goto cleanup_subscribe_testdata; }
    status = mqttChkReasonCode(patt_in->unsuback->return_codes[0]);
    if( status != MQTT_RESP_OK ){
        mctx->err_info.reason_code = patt_in->unsuback->return_codes[0];
    }
cleanup_subscribe_testdata:
    mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_UNSUBSCRIBE );
    mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_SUBSCRIBE );
disconnect_server :
    // -------- send DISCONNET packet to broker --------
    mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_DISCONNECT );
    mqttSendDisconnect( mctx );
    mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_DISCONNECT );
    return status;
} // end of mqttTestRunPatterns



static void mqttTestStartFn(void *params) 
{
    mqttRespStatus status   = MQTT_RESP_ERR;
    uint8_t  num_iter = 0;

    if(m_client->drbg == NULL) {
        status = mqttDRBGinit(&m_client->drbg);
        if(status != MQTT_RESP_OK) { goto end_of_main_test; }
    }
    XMEMSET( &testPatternSet, 0x00, sizeof(mqttTestPatt)) ;
    testPatternSet.drbg = m_client->drbg;
    for (num_iter = 1; num_iter > 0; num_iter--) {
        status =  mqttNetconnStart(m_client);
        if( status == MQTT_RESP_OK ) {
            mqttTestRunPatterns(&testPatternSet, m_client);
        }
        status =  mqttNetconnStop(m_client);
        if( status != MQTT_RESP_OK ) { break; }
    } // end of while-loop
end_of_main_test:
    if(m_client->drbg != NULL) {
        mqttDRBGdeinit(m_client->drbg);
        m_client->drbg = NULL;
    }
    mqttClientDeinit( m_client );
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
    } else { // terminate immediately on initialization failure
        mqttClientDeinit( m_client );
    }
    return 0;
} // end of main()


