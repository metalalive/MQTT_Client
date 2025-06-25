#include "mqtt_include.h"

#define MAX_RAWBYTE_READ_BUF_SZ \
    0x100 // internal parameter for read buffer, DO NOT modify this value

static mqttCtx_t     *unittest_mctx;
static mqttRespStatus mock_sys_get_entropy_return_val;
static int            mock_hash_init_return_val;
static int            mock_hash_update_return_val;
static int            mock_hash_done_return_val;

mqttRespStatus mqttSysGetEntropy(mqttStr_t *entropy_out) {
    return mock_sys_get_entropy_return_val;
} // end of mqttSysGetEntropy

word16 mqttHashGetOutlenBytes(mqttHashLenType type) { return 32; }

// leave these mocked hash functions empty since it is NOT essential for this unit test file
static int mock_mqttHashInitFn(mqttHash_t *md) { return mock_hash_init_return_val; }

static int mock_mqttHashUpdateFn(mqttHash_t *md, const byte *in, unsigned long inlen) {
    return mock_hash_update_return_val;
}

static int mock_mqttHashDoneFn(mqttHash_t *md, byte *out) { return mock_hash_done_return_val; }

word32 mqttEncodeWord32(byte *buf, word32 value) {
    if (buf != NULL) {
        buf[0] = value >> 24;
        buf[1] = (value >> 16) & 0xff;
        buf[2] = (value >> 8) & 0xff;
        buf[3] = value & 0xff;
    }
    // return number of bytes used to store the encoded value
    return (word32)4;
} // end of mqttEncodeWord32

void *mqttHashFnSelect(mqttHashOpsType ops, mqttHashLenType type) {
    void *out = NULL;
    switch (ops) {
    case MQTT_HASH_OPERATION_INIT:
        out = (void *)mock_mqttHashInitFn;
        break;
    case MQTT_HASH_OPERATION_UPDATE:
        out = (void *)mock_mqttHashUpdateFn;
        break;
    case MQTT_HASH_OPERATION_DONE:
        out = (void *)mock_mqttHashDoneFn;
        break;
    default:
        break;
    } // end of switch-case statement
    return out;
} // end of mqttHashFnSelect

mqttRespStatus mqttUtilMultiByteUAdd(mqttStr_t *out, mqttStr_t *in1, mqttStr_t *in2) {
    return MQTT_RESP_OK;
}

mqttRespStatus mqttUtilMultiByteUAddDG(mqttStr_t *out, mqttStr_t *in1, word32 in2) {
    return MQTT_RESP_OK;
}

// --------------------------------------------------
TEST_GROUP(mqttDRBGinit);
TEST_GROUP(mqttDRBGops);

TEST_GROUP_RUNNER(mqttDRBGinit) {
    RUN_TEST_CASE(mqttDRBGinit, init_err);
    RUN_TEST_CASE(mqttDRBGinit, init_ok);
}

TEST_GROUP_RUNNER(mqttDRBGops) {
    RUN_TEST_CASE(mqttDRBGops, reseed);
    RUN_TEST_CASE(mqttDRBGops, gen_drbg);
}

TEST_SETUP(mqttDRBGinit) {}

TEST_TEAR_DOWN(mqttDRBGinit) {}

TEST_SETUP(mqttDRBGops) {}

TEST_TEAR_DOWN(mqttDRBGops) {}

TEST(mqttDRBGinit, init_err) {
    mqttRespStatus status = MQTT_RESP_OK;
    mock_sys_get_entropy_return_val = MQTT_RESP_BUSY;
    mock_hash_init_return_val = 0;
    mock_hash_update_return_val = 0;
    mock_hash_done_return_val = 0;
    status = mqttDRBGinit(&unittest_mctx->drbg);
    TEST_ASSERT_EQUAL_INT(mock_sys_get_entropy_return_val, status);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->drbg);

    mock_sys_get_entropy_return_val = MQTT_RESP_OK;
    mock_hash_update_return_val = 1;
    status = mqttDRBGinit(&unittest_mctx->drbg);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR, status);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->drbg);

    mock_hash_update_return_val = 0;
    mock_hash_done_return_val = 1;
    status = mqttDRBGinit(&unittest_mctx->drbg);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR, status);
    TEST_ASSERT_EQUAL_UINT(NULL, unittest_mctx->drbg);
} // end of TEST(mqttDRBGinit, init_err)

TEST(mqttDRBGinit, init_ok) {
    mqttRespStatus status = MQTT_RESP_OK;
    mock_sys_get_entropy_return_val = MQTT_RESP_OK;
    mock_hash_init_return_val = 0;
    mock_hash_update_return_val = 0;
    mock_hash_done_return_val = 0;

    status = mqttDRBGinit(&unittest_mctx->drbg);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, unittest_mctx->drbg);
    TEST_ASSERT_EQUAL_UINT8(1, unittest_mctx->drbg->reseed_cnt);
} // end of TEST(mqttDRBGinit, init_ok)

TEST(mqttDRBGops, reseed) {
    mqttStr_t extra_in = {0, NULL};
    extra_in.data = (byte *)&("add_extra_salt");
    extra_in.len = 14;
    mqttRespStatus status = MQTT_RESP_OK;
    status = mqttDRBGreseed(unittest_mctx->drbg, &extra_in);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(1, unittest_mctx->drbg->reseed_cnt);
} // end of TEST(mqttDRBGops, reseed)

TEST(mqttDRBGops, gen_drbg) {
    mqttStr_t      extra_in = {0, NULL};
    mqttStr_t      out = {0, NULL};
    mqttRespStatus status = MQTT_RESP_OK;

    extra_in.data = (byte *)&("add_extra_salt");
    extra_in.len = 14;
    out.len = 0x27;
    out.data = XMALLOC(sizeof(byte) * out.len);

    status = mqttDRBGgen(unittest_mctx->drbg, &out, &extra_in);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(2, unittest_mctx->drbg->reseed_cnt);

    status = mqttDRBGgen(unittest_mctx->drbg, &out, &extra_in);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(3, unittest_mctx->drbg->reseed_cnt);

    unittest_mctx->drbg->reseed_cnt = 1 + unittest_mctx->drbg->reseed_intvl;
    status = mqttDRBGgen(unittest_mctx->drbg, &out, &extra_in);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(2, unittest_mctx->drbg->reseed_cnt);

    XMEMFREE(out.data);
} // end of TEST(mqttDRBGops, gen_drbg)

static void RunAllTestGroups(void) {
    unittest_mctx = XMALLOC(sizeof(mqttCtx_t));
    XMEMSET(unittest_mctx, 0x00, sizeof(mqttCtx_t));
    // be aware of encoding / decoding message may require more buffer space
    unittest_mctx->tx_buf = XMALLOC(sizeof(byte) * MAX_RAWBYTE_READ_BUF_SZ);
    unittest_mctx->tx_buf_len = MAX_RAWBYTE_READ_BUF_SZ;
    unittest_mctx->rx_buf = XMALLOC(sizeof(byte) * MAX_RAWBYTE_READ_BUF_SZ);
    unittest_mctx->rx_buf_len = MAX_RAWBYTE_READ_BUF_SZ;

    RUN_TEST_GROUP(mqttDRBGinit);
    RUN_TEST_GROUP(mqttDRBGops);

    if (unittest_mctx->drbg != NULL) {
        mqttDRBGdeinit(unittest_mctx->drbg);
        unittest_mctx->drbg = NULL;
    }
    XMEMFREE(unittest_mctx->tx_buf);
    XMEMFREE(unittest_mctx->rx_buf);
    XMEMFREE(unittest_mctx);
    unittest_mctx = NULL;
} // end of RunAllTestGroups

int main(int argc, const char *argv[]) {
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main
