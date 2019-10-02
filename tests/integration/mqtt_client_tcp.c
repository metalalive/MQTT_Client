#include "mqtt_client_tcp.h"
#include "pattern_generator.h"

static mqttTestPatt testPatternSet;
static mqttCtx_t *m_client;


static void mqttTestRunPatterns( mqttTestPatt *patt_in, mqttCtx_t *mctx )
{
    mqttRespStatus status =  MQTT_RESP_OK;
    uint8_t  num_pub_msg_sent =  4 + mqttSysRNG(5);
    uint8_t  num_pub_msg_recv =  4 + mqttSysRNG(5);
    uint8_t  num_ping_sent    =  0 + mqttSysRNG(2);

    // -------- send CONNECT packet to broker --------
    mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_CONNECT );
    status = mqttSendConnect( mctx, &patt_in->connack );
    mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_CONNECT);
    if((status < 0) || (patt_in->connack == NULL)) { return; }
    // do something after we get connack_out, check reason code, or any property sent by MQTT broker
    mqttSysDelay(200);
    // -------- send PUBLISH packet to broker --------
    while(num_pub_msg_sent > 0) {
        mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_PUBLISH );
        status = mqttSendPublish( mctx, &patt_in->pubresp );
        mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_PUBLISH );
        if((status < 0) || (patt_in->pubresp == NULL)) { return; }
        mqttSysDelay(2000);
        num_pub_msg_sent--;
    } // end of while-loop
    // -------- send SUBSCRIBE packet, and wait for incoming PUBLISH packet (from broker) --------
    mqttSysDelay(200);
    mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_SUBSCRIBE );
    status = mqttSendSubscribe( mctx, &patt_in->suback );
    if((status < 0) || (patt_in->suback==NULL)) { return; }
    // wait for incoming PUBLISH packet
    mctx->cmd_timeout_ms = MQTT_SYS_MAX_TIMEOUT;
    // TODO: write script to mock another client sending PUBLISH packet to this subsriber...
    while(num_pub_msg_recv > 0) {
        patt_in->pubmsg_recv = NULL;
        status = mqttClientWaitPkt( mctx, MQTT_PACKET_TYPE_PUBLISH, 0, (void **)&patt_in->pubmsg_recv );
        if((status < 0) || (patt_in->pubmsg_recv==NULL)) { break; }
        num_pub_msg_recv--;
    } // end of while-loop
    // -------- send UNSUBSCRIBE packet to broker --------
    mqttSysDelay(200);
    mctx->cmd_timeout_ms = MQTT_TEST_CMD_TIMEOUT_MS;
    mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_UNSUBSCRIBE );
    status = mqttSendUnsubscribe( mctx, &patt_in->unsuback );
    if((status < 0) || (patt_in->unsuback==NULL)) { return; }
    mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_UNSUBSCRIBE );
    mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_SUBSCRIBE );
    // -------- send optional PING packet to broker --------
    mqttSysDelay(200);
    while(num_ping_sent > 0) {
        mqttSysDelay(3000); // TODO: implenment & test PING / PINGRESP packets
        num_ping_sent--;
    } // end of while-loop
    // -------- send DISCONNET packet to broker --------
    mqttSysDelay(200);
    mqttTestCopyPatterns( patt_in, mctx, MQTT_PACKET_TYPE_DISCONNECT );
    mqttSendDisconnect( mctx );
    mqttTestCleanupPatterns( patt_in, MQTT_PACKET_TYPE_DISCONNECT );
    mqttSysDelay(1000);
} // end of mqttTestRunPatterns





static void mqttTestStartFn(void *params) 
{
    mqttRespStatus status   = MQTT_RESP_ERR;
    uint8_t        num_iter = 3 + (uint8_t) mqttSysRNG(3);
    XMEMSET( &testPatternSet, 0x00, sizeof(mqttTestPatt)) ;
    while(num_iter > 0)
    {
        status =  mqttSysNetconnStart( m_client );
        if( status == MQTT_RESP_OK ) {
            mqttTestRunPatterns( &testPatternSet, m_client );
        }
        status =  mqttSysNetconnStop( m_client );
        if( status != MQTT_RESP_OK ) { break; }
        num_iter--;
    } // end of while-loop
    mqttClientDeinit( m_client ); // TODO: should we de-init system before terminating this thread ?
    m_client = NULL;
#ifdef MQTT_CFG_RUN_TEST_THREAD
    mqttSysThreadDelete( NULL );
#endif
} // end of mqttTestStartFn




int main (int argc, char** argv)
{
    mqttRespStatus status =  MQTT_RESP_ERR;

    m_client = NULL;
    status =  mqttClientInit( &m_client, MQTT_TEST_CMD_TIMEOUT_MS );
    if( status == MQTT_RESP_OK ) {
#ifdef MQTT_CFG_RUN_TEST_THREAD
        uint8_t isPrivileged = 0x1;
        // TODO: stack size of a thread should be determined in each system port, NOT in test code.
        mqttSysThreadCreate( "mqttTestStartFn", (mqttSysThreFn)mqttTestStartFn, NULL ,
                              MQTT_TEST_THREAD_STACK_SIZE, MQTT_APPS_THREAD_PRIO_MIN 
                              , isPrivileged,  NULL );
#else
        mqttTestStartFn( NULL );
#endif
    }
    return 0;
} // end of main()


