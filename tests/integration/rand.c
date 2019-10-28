#include "mqtt_include.h"

// wait 6 seconds after MQTT command is sent to broker
#define  MQTT_TEST_CMD_TIMEOUT_MS          6000
#define  MQTT_TEST_THREAD_STACK_SIZE       ((uint16_t) 0xbe)
#define  MQTT_TEST_RND_HISTO_LIST_LEN      8
#define  MQTT_TEST_RND_BYTE_SEQ_MAXLEN     0xff

static mqttCtx_t *m_client;
static volatile       word32 rand_history_list[MQTT_TEST_RND_HISTO_LIST_LEN];
static volatile const word32 rand_maxval_list[MQTT_TEST_RND_HISTO_LIST_LEN] = {0x5, 0xff, 0x100, 0xffff, 0x10000, 0xffffff, 0x1000000, 0xfffffffe};
static volatile       byte   rand_byte_seq[MQTT_TEST_RND_BYTE_SEQ_MAXLEN];


static void mqttTestStartFn(void *params) 
{
    mqttRespStatus status  = MQTT_RESP_ERR;
    word16        rand_byte_seq_len = 0;
    word16        num_iter = 0;
    word16        idx      = 0;

    status = mqttDRBGinit(&m_client->drbg);
    if(status != MQTT_RESP_OK) { goto end_of_main_test; }
    num_iter  = MQTT_TEST_RND_HISTO_LIST_LEN << 3;
    num_iter += (uint8_t) mqttUtilPRNG(m_client->drbg, num_iter);
    while(num_iter > 0)
    {   // part I : generate random number
        rand_history_list[idx] = mqttUtilPRNG(m_client->drbg, rand_maxval_list[idx] );
        // part II : generate random byte sequence.
        XMEMSET( (void *)&rand_byte_seq[0], 0x00, sizeof(byte) * MQTT_TEST_RND_BYTE_SEQ_MAXLEN);
        rand_byte_seq_len = mqttUtilPRNG( m_client->drbg, MQTT_TEST_RND_BYTE_SEQ_MAXLEN);
        mqttUtilRandByteSeq( m_client->drbg, (byte *)&rand_byte_seq[0], rand_byte_seq_len );
        idx = (idx + 1) % MQTT_TEST_RND_HISTO_LIST_LEN;
        num_iter--;
    } // end of while-loop
end_of_main_test:
    mqttDRBGdeinit(m_client->drbg);
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
