#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

static int mock_mp_add_return_val;
static size_t mock_mp_ubin_sz_val;

mqttRespStatus  mqttDRBGgen(mqttDRBG_t *drbg, mqttStr_t *out, mqttStr_t *extra_in)
{ // produce sequence number as fake random number only for the unit test
    byte idx = 0;
    if(out != NULL && out->data != NULL && out->len > 0) {
        for(idx = 1; idx < out->len; idx++) {
            out->data[idx] += out->data[idx - 1] + 1;
        }
    }
    return MQTT_RESP_OK;
}


int sha256_init(mqttHash_t *md)
{ return 0; }

int sha384_init(mqttHash_t *md)
{ return 0; }

int sha256_process(mqttHash_t *md, const byte *in, unsigned long inlen)
{ return 0; }

int sha512_process(mqttHash_t *md, const byte *in, unsigned long inlen)
{ return 0; }

int sha256_done(mqttHash_t *md, byte *out)
{ return 0; }

int sha384_done(mqttHash_t *md, byte *out)
{ return 0; }

int mp_init(multiBint_t *a)
{ return 0; }

int mp_from_ubin(multiBint_t *out, const byte *buf, size_t size)
{ return 0; }

int mp_add(const multiBint_t *a, const multiBint_t *b, multiBint_t *c)
{ return mock_mp_add_return_val; }

// mp_digit
int mp_add_d(const multiBint_t *a, uint64_t b, multiBint_t *c)
{ return mock_mp_add_return_val; }

size_t mp_ubin_size(const multiBint_t *a)
{ return mock_mp_ubin_sz_val; }

int  mp_to_ubin(const multiBint_t *a, byte *buf, size_t maxlen, size_t *written)
{ return 0; }

void mp_clear(multiBint_t *a)
{ return; }


// -------------------------------------------------------------------------

TEST_GROUP(mqttUtilMisc);
TEST_GROUP(mqttUtilRand);
TEST_GROUP(mqttUtilMathWrapper);


TEST_GROUP_RUNNER(mqttUtilMisc)
{
    RUN_TEST_CASE(mqttUtilMisc, mqttGetInterval);
    RUN_TEST_CASE(mqttUtilMisc, mqttChkReasonCode);
    RUN_TEST_CASE(mqttUtilMisc, mqttGetPropByType);
    RUN_TEST_CASE(mqttUtilMisc, mqttHashFnSelect);
    RUN_TEST_CASE(mqttUtilMisc, mqttHashGetOutlenBytes);
    RUN_TEST_CASE(mqttUtilMisc, mqttCvtDecimalToBCDbyte);
}

TEST_GROUP_RUNNER(mqttUtilRand)
{ // TODO: improve test cases
    RUN_TEST_CASE(mqttUtilRand, gen_uint);
    RUN_TEST_CASE(mqttUtilRand, gen_byte_seq);
}

TEST_GROUP_RUNNER(mqttUtilMathWrapper)
{ // TODO: improve test cases
    RUN_TEST_CASE(mqttUtilMathWrapper, mqttUtilMultiByteUAdd);
    RUN_TEST_CASE(mqttUtilMathWrapper, mqttUtilMultiByteUAddDG);
}

TEST_SETUP(mqttUtilMisc)
{}

TEST_SETUP(mqttUtilRand)
{}

TEST_SETUP(mqttUtilMathWrapper)
{}

TEST_TEAR_DOWN(mqttUtilMisc)
{}

TEST_TEAR_DOWN(mqttUtilRand)
{}

TEST_TEAR_DOWN(mqttUtilMathWrapper)
{}


TEST(mqttUtilMisc, mqttGetInterval)
{
    word32 diff = 0;
    word32 now  = 0;
    word32 then = 0;

    now  = 4;
    then = 3;
    diff = mqttGetInterval(now, then);
    TEST_ASSERT_EQUAL_UINT32(0x1, diff);
    now  = 3;
    then = 4;
    diff = mqttGetInterval(now, then);
    TEST_ASSERT_EQUAL_UINT32(0xffffffff, diff);
} // end of TEST(mqttUtilMisc, mqttGetInterval)


TEST(mqttUtilMisc, mqttChkReasonCode)
{
    mqttRespStatus status = MQTT_RESP_OK;
    mqttReasonCode reason_code = MQTT_GREATEST_NORMAL_REASON_CODE;
    status = mqttChkReasonCode(reason_code);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    reason_code = MQTT_GREATEST_NORMAL_REASON_CODE + 1;
    status = mqttChkReasonCode(reason_code);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR, status);

    reason_code = MQTT_REASON_REAUTH;
    status = mqttChkReasonCode(reason_code);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    reason_code = MQTT_REASON_UNSPECIFIED_ERR;
    status = mqttChkReasonCode(reason_code);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR, status);
} // end of TEST(mqttUtilMisc, mqttChkReasonCode)


TEST(mqttUtilMisc, mqttGetPropByType)
{
    mqttProp_t* head   = NULL;
    mqttProp_t* middle = NULL;
    mqttProp_t* tail   = NULL;
    mqttProp_t* tmp    = NULL;

    head   = (mqttProp_t *) XMALLOC(sizeof(mqttProp_t));
    middle = (mqttProp_t *) XMALLOC(sizeof(mqttProp_t));
    tail   = (mqttProp_t *) XMALLOC(sizeof(mqttProp_t));
    head->type = MQTT_PROP_SERVER_KEEP_ALIVE;
    middle->type = MQTT_PROP_TOPIC_ALIAS_MAX;
    tail->type = MQTT_PROP_WILDCARD_SUBS_AVAIL;
    head->next = middle;
    middle->next = tail;
    tail->next = NULL;

    tmp = mqttGetPropByType(head, MQTT_PROP_NONE);
    TEST_ASSERT_EQUAL_UINT(NULL, tmp);

    tmp = mqttGetPropByType(head, head->type);
    TEST_ASSERT_EQUAL_UINT(head, tmp);

    tmp = mqttGetPropByType(head, middle->type);
    TEST_ASSERT_EQUAL_UINT(middle, tmp);

    tmp = mqttGetPropByType(head, tail->type);
    TEST_ASSERT_EQUAL_UINT(tail, tmp);

    tmp = mqttGetPropByType(head,MQTT_PROP_PKT_FMT_INDICATOR);
    TEST_ASSERT_EQUAL_UINT(NULL, tmp);

    XMEMFREE(head  );
    XMEMFREE(middle);
    XMEMFREE(tail  );
} // end of TEST(mqttUtilMisc, mqttGetPropByType)


TEST(mqttUtilMisc, mqttHashFnSelect)
{
    void* fp = NULL;
    fp = mqttHashFnSelect(MQTT_HASH_OPERATION_INIT  , MQTT_HASH_SHA256);
    TEST_ASSERT_EQUAL_UINT(sha256_init, fp);
    fp = mqttHashFnSelect(MQTT_HASH_OPERATION_UPDATE, MQTT_HASH_SHA256);
    TEST_ASSERT_EQUAL_UINT(sha256_process, fp);
    fp = mqttHashFnSelect(MQTT_HASH_OPERATION_DONE  , MQTT_HASH_SHA256);
    TEST_ASSERT_EQUAL_UINT(sha256_done, fp);
    fp = mqttHashFnSelect(MQTT_HASH_OPERATION_INIT  , MQTT_HASH_SHA384);
    TEST_ASSERT_EQUAL_UINT(sha384_init, fp);
    fp = mqttHashFnSelect(MQTT_HASH_OPERATION_UPDATE, MQTT_HASH_SHA384);
    TEST_ASSERT_EQUAL_UINT(sha512_process, fp);
    fp = mqttHashFnSelect(MQTT_HASH_OPERATION_DONE  , MQTT_HASH_SHA384);
    TEST_ASSERT_EQUAL_UINT(sha384_done, fp);
} // end of TEST(mqttUtilMisc, mqttHashFnSelect)


TEST(mqttUtilMisc, mqttHashGetOutlenBytes)
{
    word16 out = 0;
    out = mqttHashGetOutlenBytes(MQTT_HASH_SHA256);
    TEST_ASSERT_EQUAL_UINT16(32, out);
    out = mqttHashGetOutlenBytes(MQTT_HASH_SHA384);
    TEST_ASSERT_EQUAL_UINT16(48, out);
    out = mqttHashGetOutlenBytes(0x0);
    TEST_ASSERT_EQUAL_UINT16(0, out);
} // end of mqttHashGetOutlenBytes


TEST(mqttUtilMisc, mqttCvtDecimalToBCDbyte)
{
    TEST_ASSERT_EQUAL_UINT8(0x09, mqttCvtDecimalToBCDbyte( 9, 10));
    TEST_ASSERT_EQUAL_UINT8(0x10, mqttCvtDecimalToBCDbyte(10, 10));
    TEST_ASSERT_EQUAL_UINT8(0x19, mqttCvtDecimalToBCDbyte(19, 10));
    TEST_ASSERT_EQUAL_UINT8(0x20, mqttCvtDecimalToBCDbyte(20, 10));
} // end of TEST(mqttUtilMisc, mqttCvtDecimalToBCDbyte)


TEST(mqttUtilRand, gen_uint)
{
    mqttDRBG_t *drbg = NULL;
    word32 out = 0;
    word32 range = 0;

    drbg = XMALLOC(sizeof(mqttDRBG_t));
    XMEMSET(drbg, 0x00, sizeof(mqttDRBG_t));
    drbg->cache.len  = mqttHashGetOutlenBytes(MQTT_HASH_SHA256);
    drbg->cache.data = XMALLOC(sizeof(byte) * drbg->cache.len);
    drbg->cache_rd_ptr = drbg->cache.len;

    out  = mqttUtilPRNG(drbg, range);
    TEST_ASSERT_EQUAL_UINT(0x0, out);
    TEST_ASSERT_EQUAL_UINT(drbg->cache.len, drbg->cache_rd_ptr);

    range = 0xff;
    out  = mqttUtilPRNG(drbg, range);
    TEST_ASSERT_EQUAL_UINT(0x1, drbg->cache_rd_ptr);

    range = 0x100;
    out  = mqttUtilPRNG(drbg, range);
    TEST_ASSERT_EQUAL_UINT(0x3, drbg->cache_rd_ptr);

    range = 0xffff;
    out  = mqttUtilPRNG(drbg, range);
    TEST_ASSERT_EQUAL_UINT(0x5, drbg->cache_rd_ptr);

    range = 0xffffff;
    out  = mqttUtilPRNG(drbg, range);
    TEST_ASSERT_EQUAL_UINT(0x8, drbg->cache_rd_ptr);

    range = 0x1000000;
    out  = mqttUtilPRNG(drbg, range);
    TEST_ASSERT_EQUAL_UINT(0xc, drbg->cache_rd_ptr);

    range = 0xffffffff;
    out  = mqttUtilPRNG(drbg, range);
    TEST_ASSERT_EQUAL_UINT(0x10, drbg->cache_rd_ptr);

    range = 0x100;
    out  = mqttUtilPRNG(drbg, range);
    TEST_ASSERT_EQUAL_UINT(0x12, drbg->cache_rd_ptr);

    drbg->cache_rd_ptr = drbg->cache.len - 2;
    range = 0xe2345678;
    out  = mqttUtilPRNG(drbg, range);
    TEST_ASSERT_EQUAL_UINT(2, drbg->cache_rd_ptr);

    XMEMFREE(drbg->cache.data);
    XMEMFREE(drbg);
} // end of TEST(mqttUtilRand, gen_uint)


TEST(mqttUtilRand, gen_byte_seq)
{
    mqttDRBG_t *drbg = NULL;
    byte   rand_seq[0x30];
    mqttRespStatus status = MQTT_RESP_OK;

    drbg = XMALLOC(sizeof(mqttDRBG_t));
    XMEMSET(drbg, 0x00, sizeof(mqttDRBG_t));
    drbg->cache.len  = mqttHashGetOutlenBytes(MQTT_HASH_SHA256);
    drbg->cache.data = XMALLOC(sizeof(byte) * drbg->cache.len);
    drbg->cache_rd_ptr = drbg->cache.len;

    status = mqttUtilRandByteSeq(drbg, &rand_seq[0], 0x1);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x1, drbg->cache_rd_ptr);

    status = mqttUtilRandByteSeq(drbg, &rand_seq[0], 0x3);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x4, drbg->cache_rd_ptr);

    status = mqttUtilRandByteSeq(drbg, &rand_seq[0], (drbg->cache.len - 1));
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT(0x3, drbg->cache_rd_ptr);

    XMEMFREE(drbg->cache.data);
    XMEMFREE(drbg);
} // end of TEST(mqttUtilRand, gen_byte_seq)


TEST(mqttUtilMathWrapper, mqttUtilMultiByteUAdd)
{
    mqttStr_t out;
    mqttStr_t in1;
    mqttStr_t in2;
    mqttRespStatus status = MQTT_RESP_OK;

    out.len = 0x10;
    in1.len = 0x10;
    in2.len = 0x10;
    out.data = XMALLOC(sizeof(byte) * 0x30);
    in1.data = &out.data[0x10];
    in2.data = &out.data[0x20];

    mock_mp_add_return_val = 1;
    status = mqttUtilMultiByteUAdd(&out, &in1, &in2);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR, status);

    mock_mp_add_return_val = 0;
    mock_mp_ubin_sz_val = 0;
    status = mqttUtilMultiByteUAdd(&out, &in1, &in2);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    mock_mp_ubin_sz_val = out.len + 1;
    status = mqttUtilMultiByteUAdd(&out, &in1, &in2);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    XMEMFREE(out.data);
} // end of TEST(mqttUtilMathWrapper, mqttUtilMultiByteUAdd)


TEST(mqttUtilMathWrapper, mqttUtilMultiByteUAddDG)
{
    mqttStr_t out;
    mqttStr_t in1;
    word32    in2 = 0;
    mqttRespStatus status = MQTT_RESP_OK;

    out.len = 0x10;
    in1.len = 0x10;
    out.data = XMALLOC(sizeof(byte) * 0x20);
    in1.data = &out.data[0x10];
    status = mqttUtilMultiByteUAddDG(&out, &in1, in2);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);
    TEST_ASSERT_EQUAL_STRING_LEN(in1.data, out.data, out.len);

    in2 = 3;
    mock_mp_ubin_sz_val = 0;
    status = mqttUtilMultiByteUAddDG(&out, &in1, in2);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    mock_mp_ubin_sz_val = out.len + 1;
    status = mqttUtilMultiByteUAddDG(&out, &in1, in2);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_OK, status);

    XMEMFREE(out.data);
} // end of TEST(mqttUtilMathWrapper, mqttUtilMultiByteUAddDG)




static void RunAllTestGroups(void)
{
    RUN_TEST_GROUP(mqttUtilMisc);
    RUN_TEST_GROUP(mqttUtilRand);
    RUN_TEST_GROUP(mqttUtilMathWrapper);
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


