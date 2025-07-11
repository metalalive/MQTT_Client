#include "mqtt_include.h"
#include "pattern_generator.h"

// wait 10 seconds after MQTT command is sent to broker
#define MQTT_TEST_CMD_TIMEOUT_MS    6000
#define MQTT_TEST_THREAD_STACK_SIZE ((uint16_t)0x13e)

static mqttTestPatt testPatternSet;

static mqttRespStatus mqttTestRunPatterns(
    mqttTestPatt *patt_in, mqttCtx_t *mctx
) { // this test acting as client only send CONNECT and DISCONNECT to its peer MQTT broker.
    uint8_t        num_pub_msg_sent = 0;
    mqttRespStatus status = MQTT_RESP_OK;
    patt_in->connack = NULL;
    // -------- send CONNECT packet to broker --------
    mqttTestCopyPatterns(patt_in, mctx, MQTT_PACKET_TYPE_CONNECT);
    status = mqttSendConnect(mctx, &patt_in->connack);
    mqttTestCleanupPatterns(patt_in, MQTT_PACKET_TYPE_CONNECT);
    if ((status < 0) || (patt_in->connack == NULL)) {
        goto disconnect_server;
    }
    status = mqttChkReasonCode(patt_in->connack->reason_code);
    if (status != MQTT_RESP_OK) {
        mctx->err_info.reason_code = patt_in->connack->reason_code;
        goto disconnect_server;
    }
    // -------- send PUBLISH packet to broker --------
    for (num_pub_msg_sent = 3; num_pub_msg_sent > 0; num_pub_msg_sent--) {
        patt_in->pubresp = NULL;
        mqttTestCopyPatterns(patt_in, mctx, MQTT_PACKET_TYPE_PUBLISH);
        status = mqttSendPublish(mctx, &patt_in->pubresp);
        mqttTestCleanupPatterns(patt_in, MQTT_PACKET_TYPE_PUBLISH);
        if (status < 0) {
            break;
        }
        if (patt_in->pubmsg_send.qos > MQTT_QOS_0) {
            if (patt_in->pubresp == NULL) {
                break;
            }
            status = mqttChkReasonCode(patt_in->pubresp->reason_code);
            if (status != MQTT_RESP_OK) {
                mctx->err_info.reason_code = patt_in->pubresp->reason_code;
                break;
            }
        }
    } // end of for loop
disconnect_server:
    // -------- send DISCONNET packet to broker --------
    mqttTestCopyPatterns(patt_in, mctx, MQTT_PACKET_TYPE_DISCONNECT);
    mqttSendDisconnect(mctx);
    mqttTestCleanupPatterns(patt_in, MQTT_PACKET_TYPE_DISCONNECT);
    return status;
} // end of mqttTestRunPatterns

static void mqttTestStartFn(void *params) {
    mqttCtx_t     *m_client = params;
    mqttRespStatus status = mqttSysNetInit();
    if (status != MQTT_RESP_OK) {
        goto end_of_main_test;
    }
    uint8_t num_iter = 0;
    if (m_client->drbg == NULL) {
        status = mqttDRBGinit(&m_client->drbg);
        if (status != MQTT_RESP_OK) {
            goto end_of_main_test;
        }
    }
    XMEMSET(&testPatternSet, 0x00, sizeof(mqttTestPatt));
    testPatternSet.drbg = m_client->drbg;
    for (num_iter = 2; num_iter > 0; num_iter--) {
        status = mqttNetconnStart(m_client);
        if (status == MQTT_RESP_OK) {
            mqttTestRunPatterns(&testPatternSet, m_client);
        }
        status = mqttNetconnStop(m_client);
        if (status != MQTT_RESP_OK) {
            break;
        }
    } // end of while-loop
end_of_main_test:
    if (m_client->drbg != NULL) {
        mqttDRBGdeinit(m_client->drbg);
        m_client->drbg = NULL;
    }
    status = mqttSysNetDeInit();
    mqttClientDeinit(m_client);
    m_client = NULL;
#ifdef MQTT_CFG_RUN_TEST_THREAD
    mqttSysThreadDelete(NULL);
#endif
} // end of mqttTestStartFn

int main(int argc, char **argv) {
    mqttCtx_t     *m_client = NULL;
    mqttRespStatus status = mqttClientInit(&m_client, MQTT_TEST_CMD_TIMEOUT_MS);
    if (status == MQTT_RESP_OK) {
#ifdef MQTT_CFG_RUN_TEST_THREAD
        uint8_t       isPrivileged = 0x1;
        mqttSysThre_t new_thread;
        mqttSysThreadCreate(
            "mqttTestStartFn", (mqttSysThreFn)mqttTestStartFn, m_client,
            MQTT_TEST_THREAD_STACK_SIZE, MQTT_APPS_THREAD_PRIO_MIN, isPrivileged, &new_thread
        );
        mqttSysThreadWaitUntilExit(&new_thread, NULL);
#else
        mqttTestStartFn(NULL);
#endif
    } else { // terminate immediately on initialization failure
        mqttClientDeinit(m_client);
    }
    return 0;
} // end of main()
