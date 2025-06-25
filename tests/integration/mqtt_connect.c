#include "mqtt_include.h"
#include "pattern_generator.h"

// wait 10 seconds after MQTT command is sent to broker
#define MQTT_TEST_CMD_TIMEOUT_MS    6000
#define MQTT_TEST_THREAD_STACK_SIZE ((uint16_t)0x13e)

static mqttTestPatt testPatternSet;
static mqttCtx_t   *m_client;

static mqttRespStatus mqttTestRunPatterns(
    mqttTestPatt *patt_in, mqttCtx_t *mctx
) { // this test acting as client only send CONNECT and DISCONNECT to its peer MQTT broker.
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
    // -------- send optional PING packet to broker --------
    status = mqttSendPingReq(mctx);
    // -------- send DISCONNET packet to broker --------
disconnect_server:
    mqttTestCopyPatterns(patt_in, mctx, MQTT_PACKET_TYPE_DISCONNECT);
    mqttSendDisconnect(mctx);
    mqttTestCleanupPatterns(patt_in, MQTT_PACKET_TYPE_DISCONNECT);
    return status;
} // end of mqttTestRunPatterns

static void mqttTestStartFn(void *params) {
    mqttRespStatus status = MQTT_RESP_ERR;
    uint8_t        num_iter = 4;

    if (m_client->drbg == NULL) {
        status = mqttDRBGinit(&m_client->drbg);
        if (status != MQTT_RESP_OK) {
            goto end_of_main_test;
        }
    }
    XMEMSET(&testPatternSet, 0x00, sizeof(mqttTestPatt));
    testPatternSet.drbg = m_client->drbg;
    while (num_iter > 0) {
        status = mqttNetconnStart(m_client);
        if (status == MQTT_RESP_OK) {
            mqttTestRunPatterns(&testPatternSet, m_client);
        }
        status = mqttNetconnStop(m_client);
        if (status != MQTT_RESP_OK) {
            break;
        }
        num_iter--;
    } // end of while-loop
end_of_main_test:
    if (m_client->drbg != NULL) {
        mqttDRBGdeinit(m_client->drbg);
        m_client->drbg = NULL;
    }
    mqttClientDeinit(m_client);
    m_client = NULL;
#ifdef MQTT_CFG_RUN_TEST_THREAD
    mqttSysThreadDelete(NULL);
#endif
} // end of mqttTestStartFn

int main(int argc, char **argv) {
    mqttRespStatus status = MQTT_RESP_ERR;
    m_client = NULL;
    status = mqttClientInit(&m_client, MQTT_TEST_CMD_TIMEOUT_MS);
    if (status == MQTT_RESP_OK) {
#ifdef MQTT_CFG_RUN_TEST_THREAD
        uint8_t       isPrivileged = 0x1;
        mqttSysThre_t new_thread;
        mqttSysThreadCreate(
            "mqttTestStartFn", (mqttSysThreFn)mqttTestStartFn, NULL, MQTT_TEST_THREAD_STACK_SIZE,
            MQTT_APPS_THREAD_PRIO_MIN, isPrivileged, &new_thread
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
