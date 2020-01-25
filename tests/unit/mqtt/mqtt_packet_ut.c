#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

static mqttCtx_t *unittest_mctx;

// ------------------- global variables that are accessed by implementation files -------------------
// find appropriate data type for each property defined in MQTT protocol
const mqttDataType mqttQueryPropDataType [] = 
{
    MQTT_DATA_TYPE_NONE, // MQTT_PROP_NONE = 0x00,
    MQTT_DATA_TYPE_BYTE, // MQTT_PROP_PKT_FMT_INDICATOR = 0x01,
    MQTT_DATA_TYPE_INT , // MQTT_PROP_MSG_EXPIRY_INTVL  = 0x02,
    MQTT_DATA_TYPE_STRING, // MQTT_PROP_CONTENT_TYPE      = 0x03,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_STRING,  // MQTT_PROP_RESP_TOPIC        = 0x08,
    MQTT_DATA_TYPE_BINARY,  // MQTT_PROP_CORRELATION_DATA  = 0x09,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_VAR_INT, // MQTT_PROP_SUBSCRIBE_ID      = 0x0b,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_INT ,   // MQTT_PROP_SESSION_EXPIRY_INTVL = 0x11,
    MQTT_DATA_TYPE_STRING, // MQTT_PROP_ASSIGNED_CLIENT_ID   = 0x12,
    MQTT_DATA_TYPE_SHORT,  // MQTT_PROP_SERVER_KEEP_ALIVE    = 0x13,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_STRING, // MQTT_PROP_AUTH_METHOD       = 0x15,
    MQTT_DATA_TYPE_BINARY, // MQTT_PROP_AUTH_DATA         = 0x16,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_REQ_PROBLEM_INFO  = 0x17,
    MQTT_DATA_TYPE_INT ,   // MQTT_PROP_WILL_DELAY_INTVL  = 0x18,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_REQ_RESP_INFO     = 0x19,
    MQTT_DATA_TYPE_STRING, // MQTT_PROP_RESP_INFO         = 0x1a,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_STRING, // MQTT_PROP_SERVER_REF        = 0x1c,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_STRING, // MQTT_PROP_REASON_STR        = 0x1f,
    MQTT_DATA_TYPE_NONE,
    MQTT_DATA_TYPE_SHORT,  // MQTT_PROP_RECV_MAX          = 0x21,
    MQTT_DATA_TYPE_SHORT,  // MQTT_PROP_TOPIC_ALIAS_MAX   = 0x22,
    MQTT_DATA_TYPE_SHORT,  // MQTT_PROP_TOPIC_ALIAS       = 0x23,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_MAX_QOS           = 0x24,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_RETAIN_AVAILABLE  = 0x25,
    MQTT_DATA_TYPE_STRING_PAIR, // MQTT_PROP_USER_PROPERTY     = 0x26,
    MQTT_DATA_TYPE_INT ,   // MQTT_PROP_MAX_PKT_SIZE      = 0x27,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_WILDCARD_SUBS_AVAIL = 0x28,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_SUBSCRIBE_ID_AVAIL  = 0x29,
    MQTT_DATA_TYPE_BYTE,   // MQTT_PROP_SHARE_SUBSCRIBE_AVAIL = 0x2a,
}; // end of mqttGetPropLength


mqttProp_t*  mqttPropertyCreate(mqttProp_t **head , mqttPropertyType type)
{
    mqttProp_t*  curr_node = NULL;
    mqttProp_t*  prev_node = NULL;
    curr_node = *head;
    while((curr_node != NULL) && (curr_node->type != MQTT_PROP_NONE)) {
        prev_node = curr_node;
        curr_node = curr_node->next;
    }
    curr_node = (mqttProp_t *) XMALLOC(sizeof(mqttProp_t));
    curr_node->next = NULL;
    curr_node->type = type;
    if(prev_node == NULL) { *head = curr_node; }
    else{ prev_node->next = curr_node; }
    return curr_node;
} // end of mqttPropertyCreate


void   mqttPropertyDel( mqttProp_t *head )
{
    mqttProp_t*  curr_prop = head;
    mqttProp_t*  next_prop = NULL;
    while( curr_prop != NULL ){
        switch( mqttQueryPropDataType[curr_prop->type] )
        {
            case MQTT_DATA_TYPE_BINARY       : 
            case MQTT_DATA_TYPE_STRING       :
                if(curr_prop->body.str.data != NULL) {
                    XMEMFREE((void *)curr_prop->body.str.data);
                    curr_prop->body.str.data = NULL;
                }
                curr_prop->body.str.len = 0;
                break;
            case MQTT_DATA_TYPE_STRING_PAIR  :
                if(curr_prop->body.strpair[0].data != NULL) {
                    XMEMFREE((void *)curr_prop->body.strpair[0].data);
                    curr_prop->body.strpair[0].data = NULL; 
                }
                if(curr_prop->body.strpair[1].data != NULL) {
                    XMEMFREE((void *)curr_prop->body.strpair[1].data);
                    curr_prop->body.strpair[1].data = NULL;
                }
                curr_prop->body.strpair[0].len = 0; 
                curr_prop->body.strpair[1].len = 0;
                break;
            default:
                curr_prop->body.u32 = 0; 
                break;
        } // end of switch-case statement
        next_prop = curr_prop->next;
        curr_prop->next = NULL;
        XMEMFREE(curr_prop);
        curr_prop = next_prop;
    } // end of loop
} // end of mqttPropertyDel


// --------------------------------------------------------------------------------------

TEST_GROUP(mqttEncodeElement);
TEST_GROUP(mqttDecodeElement);
TEST_GROUP(mqttGetPktID);
TEST_GROUP(mqttCalEncodePktLen);


TEST_GROUP_RUNNER(mqttEncodeElement)
{
    RUN_TEST_CASE(mqttEncodeElement, mqttEncodeVarBytes);
    RUN_TEST_CASE(mqttEncodeElement, mqttEncodeWord16);
    RUN_TEST_CASE(mqttEncodeElement, mqttEncodeWord32);
    RUN_TEST_CASE(mqttEncodeElement, mqttEncodeStr);
    RUN_TEST_CASE(mqttEncodeElement, mqttEncodeProps);
}

TEST_GROUP_RUNNER(mqttDecodeElement)
{
    RUN_TEST_CASE(mqttDecodeElement, mqttDecodeVarBytes);
    RUN_TEST_CASE(mqttDecodeElement, mqttDecodeWord16);
    RUN_TEST_CASE(mqttDecodeElement, mqttDecodeWord32);
    RUN_TEST_CASE(mqttDecodeElement, mqttDecodeStr);
    RUN_TEST_CASE(mqttDecodeElement, mqttDecodeProps);
}

TEST_GROUP_RUNNER(mqttGetPktID)
{
    RUN_TEST_CASE(mqttGetPktID, increment_packet_id);
}

TEST_GROUP_RUNNER(mqttCalEncodePktLen)
{
    RUN_TEST_CASE(mqttCalEncodePktLen, mqttGetPktLenConnect);
    RUN_TEST_CASE(mqttCalEncodePktLen, mqttGetPktLenPublish);
    RUN_TEST_CASE(mqttCalEncodePktLen, mqttGetPktLenPubResp);
}


TEST_SETUP(mqttEncodeElement)
{}

TEST_SETUP(mqttDecodeElement)
{}

TEST_SETUP(mqttGetPktID)
{}

TEST_SETUP(mqttCalEncodePktLen)
{}

TEST_TEAR_DOWN(mqttEncodeElement)
{}

TEST_TEAR_DOWN(mqttDecodeElement)
{}

TEST_TEAR_DOWN(mqttGetPktID)
{}

TEST_TEAR_DOWN(mqttCalEncodePktLen)
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
    const byte *str_to_encode = (const byte *)&("ready to encode");
    word32  nbytes_encoded = 0;
    word16  str_len = 15;

    nbytes_encoded = mqttEncodeStr(&unittest_mctx->tx_buf[0], (const byte *)str_to_encode, str_len);
    TEST_ASSERT_EQUAL_UINT32((MQTT_DSIZE_STR_LEN + str_len), nbytes_encoded);
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
    const byte *encoded_str = (const byte *)&("this_is_encoded_string");
    word16  str_len = sizeof("this_is_encoded_string") - 1;

    byte  *out    = XMALLOC(sizeof(byte) * 0x40);
    word16 outlen = 0;
    word32 nbytes_decoded  = 0;

    unittest_mctx->rx_buf[0] = 0x00;
    unittest_mctx->rx_buf[1] = str_len;
    XMEMCPY(&unittest_mctx->rx_buf[2], encoded_str, str_len);

    nbytes_decoded = mqttDecodeStr(&unittest_mctx->rx_buf[0], out, &outlen);
    TEST_ASSERT_EQUAL_UINT32((MQTT_DSIZE_STR_LEN + str_len) , nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT16(str_len , outlen);
    TEST_ASSERT_EQUAL_STRING_LEN(encoded_str, out, outlen);
    XMEMFREE(out);
} // end of TEST(mqttDecodeElement, mqttDecodeStr)


TEST(mqttEncodeElement, mqttEncodeProps)
{
    mqttProp_t  *props = NULL;
    mqttProp_t  *tmp_prop = NULL;
    byte        *buf = NULL;
    int expected_nbytes_encoded = 0;
    int actual_nbytes_encoded   = 0;
    // different data type of properties tested at here : MQTT_DATA_TYPE_BYTE, MQTT_DATA_TYPE_SHORT, MQTT_DATA_TYPE_INT,
    // MQTT_DATA_TYPE_VAR_INT,  MQTT_DATA_TYPE_BINARY,  MQTT_DATA_TYPE_STRING,  MQTT_DATA_TYPE_STRING_PAIR,
    const mqttPropertyType  prop_types[6] = {
        MQTT_PROP_RETAIN_AVAILABLE,   // MQTT_DATA_TYPE_BYTE
        MQTT_PROP_SERVER_KEEP_ALIVE,  // MQTT_DATA_TYPE_SHORT
        MQTT_PROP_SESSION_EXPIRY_INTVL,  // MQTT_DATA_TYPE_INT
        MQTT_PROP_REASON_STR ,     // MQTT_DATA_TYPE_STRING
        MQTT_PROP_USER_PROPERTY,   // MQTT_DATA_TYPE_STRING_PAIR
        MQTT_PROP_SUBSCRIBE_ID,    // MQTT_DATA_TYPE_VAR_INT
    }; // NOTE: the list is ONLY for this unit test, it's practically impossible to have all these properties
       // in any single MQTT command packet
    const byte nproptypes = sizeof(prop_types) / sizeof(prop_types[0]);
    byte  idx = 0;

    actual_nbytes_encoded = mqttEncodeProps(NULL, props);
    TEST_ASSERT_EQUAL_INT32(0, actual_nbytes_encoded);

    props = (mqttProp_t *) XMALLOC(sizeof(mqttProp_t));
    tmp_prop = props;
    for(idx = 0; idx < (nproptypes - 1); idx++) {
        tmp_prop->next = (mqttProp_t *) XMALLOC(sizeof(mqttProp_t));
        tmp_prop = tmp_prop->next;
    } // end of for loop
    tmp_prop->next = NULL;

    expected_nbytes_encoded = 0;
    for (tmp_prop = props, idx = 0; tmp_prop != NULL; tmp_prop = tmp_prop->next, idx++) {
         tmp_prop->type = prop_types[idx];
          switch( mqttQueryPropDataType[tmp_prop->type] ){
              case MQTT_DATA_TYPE_BYTE :
                  tmp_prop->body.u8 = 0xe4;
                  expected_nbytes_encoded += 1 + 1;
                  break;
              case MQTT_DATA_TYPE_SHORT:
                  tmp_prop->body.u16 = 0xb08b;
                  expected_nbytes_encoded += 1 + 2;
                  break;
              case MQTT_DATA_TYPE_INT:
                  tmp_prop->body.u32 = 0x886525a;
                  expected_nbytes_encoded += 1 + 4;
                  break;
              case MQTT_DATA_TYPE_VAR_INT:
                  tmp_prop->body.u32 = 0xffff8;
                  expected_nbytes_encoded += 1 + 3;
                  break;
              case MQTT_DATA_TYPE_STRING:
                  tmp_prop->body.str.data = (byte *)&("Do-Mi-Sol");
                  tmp_prop->body.str.len  = 9;
                  expected_nbytes_encoded += 1 + MQTT_DSIZE_STR_LEN + 9;
                  break;
              case MQTT_DATA_TYPE_STRING_PAIR:
                  tmp_prop->body.strpair[0].data = (byte *)&("Si-Ray-Sol");
                  tmp_prop->body.strpair[0].len  = 10;
                  tmp_prop->body.strpair[1].data = (byte *)&("speedup");
                  tmp_prop->body.strpair[1].len  = 7;
                  expected_nbytes_encoded += 1 + MQTT_DSIZE_STR_LEN + 10 + MQTT_DSIZE_STR_LEN + 7;
                  break;
              default: break;
          } // end of switch case statement
    } // end of for loop

    actual_nbytes_encoded = mqttEncodeProps(&unittest_mctx->tx_buf[0], props);
    buf = &unittest_mctx->tx_buf[0];

    TEST_ASSERT_EQUAL_INT32(expected_nbytes_encoded, actual_nbytes_encoded);
    TEST_ASSERT_EQUAL_UINT8(MQTT_PROP_RETAIN_AVAILABLE, buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0xe4, buf[1]);
    buf += 1 + 1;
    TEST_ASSERT_EQUAL_UINT8(MQTT_PROP_SERVER_KEEP_ALIVE, buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0xb0, buf[1]);
    TEST_ASSERT_EQUAL_UINT8(0x8b, buf[2]);
    buf += 1 + 2;
    TEST_ASSERT_EQUAL_UINT8(MQTT_PROP_SESSION_EXPIRY_INTVL, buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0x08, buf[1]);
    TEST_ASSERT_EQUAL_UINT8(0x86, buf[2]);
    TEST_ASSERT_EQUAL_UINT8(0x52, buf[3]);
    TEST_ASSERT_EQUAL_UINT8(0x5a, buf[4]);
    buf += 1 + 4;
    TEST_ASSERT_EQUAL_UINT8(MQTT_PROP_REASON_STR, buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0x00, buf[1]);
    TEST_ASSERT_EQUAL_UINT8(0x09, buf[2]);
    TEST_ASSERT_EQUAL_STRING_LEN(&("Do-Mi-Sol"), &buf[3], 9);

    for (tmp_prop = props; tmp_prop != NULL; tmp_prop = tmp_prop->next) {
        XMEMFREE(tmp_prop);
    } // end of for loop
} // end of TEST(mqttEncodeElement, mqttEncodeProps)


TEST(mqttDecodeElement, mqttDecodeProps)
{
    mqttProp_t  *props = NULL;
    mqttProp_t  *tmp_prop = NULL;
    byte        *buf = NULL;
    int expected_nbytes_decoded = 0;
    int actual_nbytes_decoded   = 0;

    const byte *reason_str = (const byte *)&("decoded reason string");
    const byte *user_label_str = (const byte *)&("user label");
    const byte *user_data_str  = (const byte *)&("user data");
    word16  reason_str_len = 21;
    word16  user_label_len = 10;
    word16  user_data_len  = 9;

    buf  = &unittest_mctx->rx_buf[0];
    buf += mqttEncodeVarBytes(buf, MQTT_PROP_REASON_STR);
    buf += mqttEncodeStr(buf, reason_str, reason_str_len);
    buf += mqttEncodeVarBytes(buf, MQTT_PROP_USER_PROPERTY);
    buf += mqttEncodeStr(buf, user_label_str, user_label_len);
    buf += mqttEncodeStr(buf, user_data_str , user_data_len );
    buf += mqttEncodeVarBytes(buf, MQTT_PROP_RETAIN_AVAILABLE);
    *buf++ = 0x1b;
    buf += mqttEncodeVarBytes(buf, MQTT_PROP_SERVER_KEEP_ALIVE);
    buf += mqttEncodeWord16(buf , 0x2345);
    buf += mqttEncodeVarBytes(buf, MQTT_PROP_SESSION_EXPIRY_INTVL);
    buf += mqttEncodeWord32(buf , 0xfee1bad);
    buf += mqttEncodeVarBytes(buf, MQTT_PROP_SUBSCRIBE_ID);
    buf += mqttEncodeVarBytes(buf, 0x81);

    expected_nbytes_decoded = (int)(buf - &unittest_mctx->rx_buf[0]);
    actual_nbytes_decoded = mqttDecodeProps(&unittest_mctx->rx_buf[0], &props, (word32)expected_nbytes_decoded);
    TEST_ASSERT_EQUAL_INT32(expected_nbytes_decoded, actual_nbytes_decoded);
    TEST_ASSERT_NOT_EQUAL(NULL, props);

    tmp_prop = props;
    TEST_ASSERT_EQUAL_UINT8(MQTT_PROP_REASON_STR, tmp_prop->type);
    TEST_ASSERT_EQUAL_UINT16(reason_str_len, tmp_prop->body.str.len);
    TEST_ASSERT_EQUAL_STRING_LEN(reason_str, tmp_prop->body.str.data, reason_str_len);

    tmp_prop = tmp_prop->next;
    TEST_ASSERT_EQUAL_UINT8(MQTT_PROP_USER_PROPERTY, tmp_prop->type);
    TEST_ASSERT_EQUAL_UINT16(user_label_len, tmp_prop->body.strpair[0].len);
    TEST_ASSERT_EQUAL_UINT16(user_data_len , tmp_prop->body.strpair[1].len);
    TEST_ASSERT_EQUAL_STRING_LEN(user_label_str, tmp_prop->body.strpair[0].data, user_label_len);
    TEST_ASSERT_EQUAL_STRING_LEN(user_data_str , tmp_prop->body.strpair[1].data, user_data_len );

    tmp_prop = tmp_prop->next;
    TEST_ASSERT_EQUAL_UINT8(MQTT_PROP_RETAIN_AVAILABLE, tmp_prop->type);
    TEST_ASSERT_EQUAL_UINT8(0x1b, tmp_prop->body.u8);

    tmp_prop = tmp_prop->next;
    TEST_ASSERT_EQUAL_UINT8(MQTT_PROP_SERVER_KEEP_ALIVE, tmp_prop->type);
    TEST_ASSERT_EQUAL_UINT16(0x2345, tmp_prop->body.u16);

    tmp_prop = tmp_prop->next;
    TEST_ASSERT_EQUAL_UINT8(MQTT_PROP_SESSION_EXPIRY_INTVL, tmp_prop->type);
    TEST_ASSERT_EQUAL_UINT32(0xfee1bad, tmp_prop->body.u32);

    tmp_prop = tmp_prop->next;
    TEST_ASSERT_EQUAL_UINT8(MQTT_PROP_SUBSCRIBE_ID, tmp_prop->type);
    TEST_ASSERT_EQUAL_UINT32(0x81, tmp_prop->body.u32);

    // free up all space allocated inside mqttPropertyCreate()
    mqttPropertyDel(props);
} // end of TEST(mqttDecodeElement, mqttDecodeProps)


TEST(mqttGetPktID, increment_packet_id)
{
    TEST_ASSERT_EQUAL_UINT16(0x1, mqttGetPktID());
    TEST_ASSERT_EQUAL_UINT16(0x2, mqttGetPktID());
    TEST_ASSERT_EQUAL_UINT16(0x3, mqttGetPktID());
    TEST_ASSERT_EQUAL_UINT16(0x4, mqttGetPktID());
} // end of TEST(mqttGetPktID, increment_packet_id)


TEST(mqttCalEncodePktLen, mqttGetPktLenConnect)
{
    mqttProp_t  *tmp_prop = NULL;
    mqttConn_t  *conn     = NULL;
    int expected_nbytes_decoded = 10; // for first 10 bytes of variable header in CONNECT
    int actual_nbytes_decoded   = 0;
    word32   remain_len  = 0;
    word32   props_len   = 0;

    conn = &unittest_mctx->send_pkt.conn;

    conn->props = NULL;
    tmp_prop = mqttPropertyCreate(&conn->props, MQTT_PROP_RECV_MAX);
    tmp_prop->body.u16 = 0x321;
    tmp_prop = mqttPropertyCreate(&conn->props, MQTT_PROP_TOPIC_ALIAS_MAX);
    tmp_prop->body.u16 = 0x14;
    props_len = 1 + 2 + 1 + 2;
    expected_nbytes_decoded += 1 + props_len; // #bytes of property for CONNECT command

    conn->client_id.data = (byte *)&("test_identifier");
    conn->client_id.len  = 15;
    conn->username.data  = (byte *)&("testuser543");
    conn->username.len   = 11;
    conn->password.data  = (byte *)&("passwd2user");
    conn->password.len   = 11;
    expected_nbytes_decoded += MQTT_DSIZE_STR_LEN + conn->client_id.len;
    expected_nbytes_decoded += MQTT_DSIZE_STR_LEN + conn->username.len;
    expected_nbytes_decoded += MQTT_DSIZE_STR_LEN + conn->password.len;

    conn->flgs.will_enable = 1;
    {
        conn->lwt_msg.props = NULL;
        tmp_prop = mqttPropertyCreate(&conn->lwt_msg.props, MQTT_PROP_WILL_DELAY_INTVL);
        tmp_prop->body.u32 = 0x38600;
        expected_nbytes_decoded += 1 + 1 + 4;
        conn->lwt_msg.topic.data   = (byte *)&("here/is/it");
        conn->lwt_msg.topic.len    = 10;
        conn->lwt_msg.app_data_len = 20;
        expected_nbytes_decoded += MQTT_DSIZE_STR_LEN + conn->lwt_msg.topic.len;
        expected_nbytes_decoded += MQTT_DSIZE_STR_LEN + conn->lwt_msg.app_data_len;
    }

    actual_nbytes_decoded = mqttGetPktLenConnect(conn, expected_nbytes_decoded);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_EXCEED_PKT_SZ, actual_nbytes_decoded);

    remain_len = expected_nbytes_decoded;
    expected_nbytes_decoded += 1 + 1; // 1-byte header and 1-byte length field of entire CONNECT command
    actual_nbytes_decoded = mqttGetPktLenConnect(conn, expected_nbytes_decoded);
    TEST_ASSERT_EQUAL_INT(expected_nbytes_decoded, actual_nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT32(remain_len, conn->pkt_len_set.remain_len);
    TEST_ASSERT_EQUAL_UINT32(props_len , conn->pkt_len_set.props_len );

    mqttPropertyDel(conn->props);
    mqttPropertyDel(conn->lwt_msg.props);
    XMEMSET(conn, 0x00, sizeof(mqttConn_t));
} // end of TEST(mqttCalEncodePktLen, mqttGetPktLenConnect)


TEST(mqttCalEncodePktLen, mqttGetPktLenPublish)
{
    mqttMsg_t *msg = NULL;
    int expected_nbytes_decoded = 0;
    int actual_nbytes_decoded   = 0;
    word32   remain_len  = 0;

    msg = &unittest_mctx->send_pkt.pub_msg;

    msg->props = NULL;
    expected_nbytes_decoded += 1; // no property in this test
    msg->topic.data = NULL;
    msg->topic.len  = 0;

    actual_nbytes_decoded = mqttGetPktLenPublish(msg, 0x0);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERRARGS, actual_nbytes_decoded);

    msg->topic.data = (byte *)&("mqttGetPktLenPublish");
    msg->topic.len  = 20;
    msg->qos = MQTT_QOS_2;
    msg->packet_id = 0;
    expected_nbytes_decoded += 2; // 2-byte packet ID

    actual_nbytes_decoded = mqttGetPktLenPublish(msg, 0x0);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_CTRL_PKT_ID, actual_nbytes_decoded);

    msg->packet_id = mqttGetPktID();
    msg->topic.len = 17;
    msg->app_data_len = 50;
    expected_nbytes_decoded += MQTT_DSIZE_STR_LEN + msg->topic.len + msg->app_data_len;

    actual_nbytes_decoded = mqttGetPktLenPublish(msg, expected_nbytes_decoded);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_EXCEED_PKT_SZ, actual_nbytes_decoded);

    remain_len = expected_nbytes_decoded;
    expected_nbytes_decoded += 1 + 1; // 1-byte header and 1-byte length field of entire CONNECT command

    actual_nbytes_decoded = mqttGetPktLenPublish(msg, expected_nbytes_decoded);
    TEST_ASSERT_EQUAL_INT(expected_nbytes_decoded, actual_nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT32(remain_len, msg->pkt_len_set.remain_len);
    TEST_ASSERT_EQUAL_UINT32(0x0,        msg->pkt_len_set.props_len);

    XMEMSET(msg, 0x00, sizeof(mqttMsg_t));
} // end of TEST(mqttCalEncodePktLen, mqttGetPktLenPublish)


TEST(mqttCalEncodePktLen, mqttGetPktLenPubResp)
{
    mqttPktPubResp_t *resp = NULL;
    int expected_nbytes_decoded = 0;
    int actual_nbytes_decoded   = 0;
    word32   remain_len  = 0;

    resp = &unittest_mctx->send_pkt.pub_resp;

    resp->props = NULL;
    resp->reason_code = MQTT_REASON_NO_MATCH_SUBS;
    resp->packet_id   = mqttGetPktID();
    expected_nbytes_decoded += 1 + 2;
    actual_nbytes_decoded = mqttGetPktLenPubResp(resp, expected_nbytes_decoded);
    TEST_ASSERT_EQUAL_INT(MQTT_RESP_ERR_EXCEED_PKT_SZ, actual_nbytes_decoded);

    remain_len = expected_nbytes_decoded;
    expected_nbytes_decoded += 1 + 1; // 1-byte header and 1-byte length field of entire CONNECT command
    actual_nbytes_decoded = mqttGetPktLenPubResp(resp, expected_nbytes_decoded);
    TEST_ASSERT_EQUAL_INT(expected_nbytes_decoded, actual_nbytes_decoded);
    TEST_ASSERT_EQUAL_UINT32(remain_len, resp->pkt_len_set.remain_len);
    TEST_ASSERT_EQUAL_UINT32(0x0,        resp->pkt_len_set.props_len);

    XMEMSET(resp, 0x00, sizeof(mqttPktPubResp_t));
} // end of TEST(mqttCalEncodePktLen, mqttGetPktLenPubResp)





static void RunAllTestGroups(void)
{
    unittest_mctx = XMALLOC(sizeof(mqttCtx_t));
    unittest_mctx->tx_buf     = XMALLOC(sizeof(byte) * 0x40);
    unittest_mctx->tx_buf_len = 0x40;
    unittest_mctx->rx_buf     = XMALLOC(sizeof(byte) * 0x40);
    unittest_mctx->rx_buf_len = 0x40;

    RUN_TEST_GROUP(mqttEncodeElement);
    RUN_TEST_GROUP(mqttDecodeElement);
    RUN_TEST_GROUP(mqttGetPktID);
    RUN_TEST_GROUP(mqttCalEncodePktLen);

    XMEMFREE(unittest_mctx->tx_buf);
    XMEMFREE(unittest_mctx->rx_buf);
    XMEMFREE(unittest_mctx);
    unittest_mctx = NULL;
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


