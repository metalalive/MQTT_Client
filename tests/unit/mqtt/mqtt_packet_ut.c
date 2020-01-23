#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

static mqttCtx_t *unittest_mctx;

TEST_GROUP(mqttEncodeElement);
TEST_GROUP(mqttDecodeElement);


TEST_GROUP_RUNNER(mqttEncodeElement)
{
    RUN_TEST_CASE(mqttEncodeElement, mqttEncodeVarBytes);
    RUN_TEST_CASE(mqttEncodeElement, mqttEncodeWord16);
    RUN_TEST_CASE(mqttEncodeElement, mqttEncodeWord32);
    RUN_TEST_CASE(mqttEncodeElement, mqttEncodeStr);
}

TEST_GROUP_RUNNER(mqttDecodeElement)
{
    RUN_TEST_CASE(mqttDecodeElement, mqttDecodeVarBytes);
    RUN_TEST_CASE(mqttDecodeElement, mqttDecodeWord16);
    RUN_TEST_CASE(mqttDecodeElement, mqttDecodeWord32);
    RUN_TEST_CASE(mqttDecodeElement, mqttDecodeStr);
}


TEST_SETUP(mqttEncodeElement)
{}

TEST_TEAR_DOWN(mqttEncodeElement)
{}

TEST_SETUP(mqttDecodeElement)
{}

TEST_TEAR_DOWN(mqttDecodeElement)
{}



TEST(mqttEncodeElement, mqttEncodeVarBytes)
{
    word32 value = 0;
    word32 nbytes_encoded = 0;

    value = 0x7f;
    nbytes_encoded = mqttEncodeVarBytes(&unittest_mctx->tx_buf[0], value);
    TEST_ASSERT_EQUAL_UINT32(0x1, nbytes_encoded);
    TEST_ASSERT_EQUAL_UINT8(0x7f , unittest_mctx->tx_buf[0]);

    value = 0x80;
    nbytes_encoded = mqttEncodeVarBytes(&unittest_mctx->tx_buf[0], value);
    TEST_ASSERT_EQUAL_UINT32(0x2, nbytes_encoded);
    TEST_ASSERT_EQUAL_UINT8(0x80 , unittest_mctx->tx_buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0x01 , unittest_mctx->tx_buf[1]);

    value = 0x3fff;
    nbytes_encoded = mqttEncodeVarBytes(&unittest_mctx->tx_buf[0], value);
    TEST_ASSERT_EQUAL_UINT32(0x2, nbytes_encoded);
    TEST_ASSERT_EQUAL_UINT8(0xff , unittest_mctx->tx_buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0x7f , unittest_mctx->tx_buf[1]);

    value = 0x4000;
    nbytes_encoded = mqttEncodeVarBytes(&unittest_mctx->tx_buf[0], value);
    TEST_ASSERT_EQUAL_UINT32(0x3, nbytes_encoded);
    TEST_ASSERT_EQUAL_UINT8(0x80 , unittest_mctx->tx_buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0x80 , unittest_mctx->tx_buf[1]);
    TEST_ASSERT_EQUAL_UINT8(0x01 , unittest_mctx->tx_buf[2]);

    value = 0x1fffff;
    nbytes_encoded = mqttEncodeVarBytes(&unittest_mctx->tx_buf[0], value);
    TEST_ASSERT_EQUAL_UINT32(0x3, nbytes_encoded);
    TEST_ASSERT_EQUAL_UINT8(0xff , unittest_mctx->tx_buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0xff , unittest_mctx->tx_buf[1]);
    TEST_ASSERT_EQUAL_UINT8(0x7f , unittest_mctx->tx_buf[2]);

    value = 0x200000;
    nbytes_encoded = mqttEncodeVarBytes(&unittest_mctx->tx_buf[0], value);
    TEST_ASSERT_EQUAL_UINT32(0x4, nbytes_encoded);
    TEST_ASSERT_EQUAL_UINT8(0x80 , unittest_mctx->tx_buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0x80 , unittest_mctx->tx_buf[1]);
    TEST_ASSERT_EQUAL_UINT8(0x80 , unittest_mctx->tx_buf[2]);
    TEST_ASSERT_EQUAL_UINT8(0x01 , unittest_mctx->tx_buf[3]);
} // end of TEST(mqttEncodeElement, mqttEncodeVarBytes)


TEST(mqttEncodeElement, mqttEncodeWord16)
{
    word32 nbytes_encoded = 0;
    nbytes_encoded = mqttEncodeWord16(&unittest_mctx->tx_buf[0], (word16)0xba98);
    TEST_ASSERT_EQUAL_UINT32(0x2, nbytes_encoded);
    TEST_ASSERT_EQUAL_UINT8(0xba, unittest_mctx->tx_buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0x98, unittest_mctx->tx_buf[1]);
} // end of TEST(mqttEncodeElement, mqttEncodeWord16)


TEST(mqttEncodeElement, mqttEncodeWord32)
{
    word32 nbytes_encoded = 0;
    nbytes_encoded = mqttEncodeWord32(&unittest_mctx->tx_buf[0], (word32)0x876ba98d);
    TEST_ASSERT_EQUAL_UINT32(0x4, nbytes_encoded);
    TEST_ASSERT_EQUAL_UINT8(0x87, unittest_mctx->tx_buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0x6b, unittest_mctx->tx_buf[1]);
    TEST_ASSERT_EQUAL_UINT8(0xa9, unittest_mctx->tx_buf[2]);
    TEST_ASSERT_EQUAL_UINT8(0x8d, unittest_mctx->tx_buf[3]);
} // end of TEST(mqttEncodeElement, mqttEncodeWord32)


TEST(mqttEncodeElement, mqttEncodeStr)
{
    const byte *str_to_encode = "ready to encode";
    word32  nbytes_encoded = 0;
    word16  str_len = 15;

    nbytes_encoded = mqttEncodeStr(&unittest_mctx->tx_buf[0], (const byte *)str_to_encode, str_len);
    TEST_ASSERT_EQUAL_UINT32((0x2 + str_len), nbytes_encoded);
    TEST_ASSERT_EQUAL_UINT8(0x00   , unittest_mctx->tx_buf[0]);
    TEST_ASSERT_EQUAL_UINT8(str_len, unittest_mctx->tx_buf[1]);

    nbytes_encoded = XSTRNCMP((const char *)str_to_encode, (const char *)&unittest_mctx->tx_buf[2], (size_t)str_len);
    TEST_ASSERT_EQUAL_UINT32(0x0, nbytes_encoded);
} // end of TEST(mqttEncodeElement, mqttEncodeStr)




TEST(mqttDecodeElement, mqttDecodeVarBytes)
{
    word32 value = 0;
    word32 nbytes_decoded = 0;

    unittest_mctx->rx_buf[0] = 0x7f;
    nbytes_decoded = mqttDecodeVarBytes((const byte *)&unittest_mctx->rx_buf[0], (word32 *)&value);
    TEST_ASSERT_EQUAL_UINT32(0x1, nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT32(0x7f, value);

    unittest_mctx->rx_buf[0] = 0x80;
    unittest_mctx->rx_buf[1] = 0x01;
    nbytes_decoded = mqttDecodeVarBytes((const byte *)&unittest_mctx->rx_buf[0], (word32 *)&value);
    TEST_ASSERT_EQUAL_UINT32(0x2, nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT32(0x80, value);

    unittest_mctx->rx_buf[0] = 0xff;
    unittest_mctx->rx_buf[1] = 0x7f;
    nbytes_decoded = mqttDecodeVarBytes((const byte *)&unittest_mctx->rx_buf[0], (word32 *)&value);
    TEST_ASSERT_EQUAL_UINT32(0x2, nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT32(0x3fff, value);

    unittest_mctx->rx_buf[0] = 0x80;
    unittest_mctx->rx_buf[1] = 0x80;
    unittest_mctx->rx_buf[2] = 0x01;
    nbytes_decoded = mqttDecodeVarBytes((const byte *)&unittest_mctx->rx_buf[0], (word32 *)&value);
    TEST_ASSERT_EQUAL_UINT32(0x3, nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT32(0x4000, value);

    unittest_mctx->rx_buf[0] = 0xff;
    unittest_mctx->rx_buf[1] = 0xff;
    unittest_mctx->rx_buf[2] = 0x7f;
    nbytes_decoded = mqttDecodeVarBytes((const byte *)&unittest_mctx->rx_buf[0], (word32 *)&value);
    TEST_ASSERT_EQUAL_UINT32(0x3, nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT32(0x1fffff, value);

    unittest_mctx->rx_buf[0] = 0x80;
    unittest_mctx->rx_buf[1] = 0x80;
    unittest_mctx->rx_buf[2] = 0x80;
    unittest_mctx->rx_buf[3] = 0x01;
    nbytes_decoded = mqttDecodeVarBytes((const byte *)&unittest_mctx->rx_buf[0], (word32 *)&value);
    TEST_ASSERT_EQUAL_UINT32(0x4, nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT32(0x200000, value);

    unittest_mctx->rx_buf[0] = 0xff;
    unittest_mctx->rx_buf[1] = 0xff;
    unittest_mctx->rx_buf[2] = 0xff;
    unittest_mctx->rx_buf[3] = 0x7f;
    nbytes_decoded = mqttDecodeVarBytes((const byte *)&unittest_mctx->rx_buf[0], (word32 *)&value);
    TEST_ASSERT_EQUAL_UINT32(0x4, nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT32(0xfffffff, value);
} // end of TEST(mqttDecodeElement, mqttDecodeVarBytes)


TEST(mqttDecodeElement, mqttDecodeWord16)
{
    word16 value = 0;
    word32 nbytes_decoded = 0;

    unittest_mctx->rx_buf[0] = 0xe2;
    unittest_mctx->rx_buf[1] = 0x34;
    nbytes_decoded = mqttDecodeWord16(&unittest_mctx->rx_buf[0], &value);
    TEST_ASSERT_EQUAL_UINT32(0x2, nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT16(0xe234, value);
} // end of TEST(mqttDecodeElement, mqttDecodeWord16)


TEST(mqttDecodeElement, mqttDecodeWord32)
{
    word32 value = 0;
    word32 nbytes_decoded = 0;

    unittest_mctx->rx_buf[0] = 0xde;
    unittest_mctx->rx_buf[1] = 0xad;
    unittest_mctx->rx_buf[2] = 0xb0;
    unittest_mctx->rx_buf[3] = 0x55;
    nbytes_decoded = mqttDecodeWord32(&unittest_mctx->rx_buf[0], &value);
    TEST_ASSERT_EQUAL_UINT32(0x4, nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT16(0xdeadb055, value);
} // end of TEST(mqttDecodeElement, mqttDecodeWord32)


TEST(mqttDecodeElement, mqttDecodeStr)
{
    const byte *encoded_str = "this_is_encoded_string";
    word16  str_len = sizeof("this_is_encoded_string") - 1;

    byte  *out    = XMALLOC(sizeof(byte) * 0x40);
    word16 outlen = 0;
    word32 nbytes_decoded  = 0;

    unittest_mctx->rx_buf[0] = 0x00;
    unittest_mctx->rx_buf[1] = str_len;
    XMEMCPY(&unittest_mctx->rx_buf[2], encoded_str, str_len);

    nbytes_decoded = mqttDecodeStr(&unittest_mctx->rx_buf[0], out, &outlen);
    TEST_ASSERT_EQUAL_UINT32((2 + str_len) , nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT16(str_len , outlen);
    TEST_ASSERT_EQUAL_STRING(encoded_str , out);
    XMEMFREE(out);
} // end of TEST(mqttDecodeElement, mqttDecodeStr)






static void RunAllTestGroups(void)
{
    unittest_mctx = XMALLOC(sizeof(mqttCtx_t));
    unittest_mctx->tx_buf     = XMALLOC(sizeof(byte) * 0x40);
    unittest_mctx->tx_buf_len = 0x40;
    unittest_mctx->rx_buf     = XMALLOC(sizeof(byte) * 0x40);
    unittest_mctx->rx_buf_len = 0x40;

    RUN_TEST_GROUP(mqttEncodeElement);
    RUN_TEST_GROUP(mqttDecodeElement);

    XMEMFREE(unittest_mctx->tx_buf);
    XMEMFREE(unittest_mctx->rx_buf);
    XMEMFREE(unittest_mctx);
    unittest_mctx = NULL;
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


