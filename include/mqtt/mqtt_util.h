#ifndef MQTT_UTIL_H
#define MQTT_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

// indicate number of bytes used in 4-bytes integer
#define MQTT_DSIZE_INT  4

// indicate number of bytes to represent number of characters in a UTF-8 string
#define MQTT_DSIZE_STR_LEN  2

// In MQTT specification, remaining length is stored as variable bytes
// in a MQTT packet, it can be at most 4 bytes.
#define  MQTT_PKT_MAX_BYTES_REMAIN_LEN   4

#define  MQTT_DEFAULT_KEEPALIVE_SEC      60 

// max number of properties used in this MQTT client
#define  MQTT_MAX_NUM_PROPS              32

// greatest normal reason code 
#define  MQTT_GREATEST_NORMAL_REASON_CODE  0x79

// max. number of extensive objects that assist in working with underlying system/platform
#define  MQTT_MAX_NUM_EXT_SYSOBJS          0x2

// ------- topic naming rule --------
// use English letters / numbers for each level of topic string, forward slashes for levels separator.
// Do not start name with forward slash (/) or $ (reserved for broker)
// Example: "register/event/evt_id" */
/* The forward slash is used to define levels of topic matching */
#define MQTT_TOPIC_LEVEL_SEPERATOR   '/'

// available for Topic Filters on Subscribe only,  used to match on a single level */
// Example: "userid/home/+/cam/yesterday" 
#define MQTT_TOPIC_LEVEL_SINGLE      '+'

// used to match on a multiple levels
// Example: "userid/home/#" 
#define MQTT_TOPIC_LEVEL_MULTI       '#'



// ----------------- defined macro -----------------
// Get/Set packet types : located in first byte of fixed header in bits 4-7 
#define MQTT_CTRL_PKT_TYPE_GET(b)       (((b) >> 4) & 0xF)

#define MQTT_CTRL_PKT_TYPE_SET(b, x)    b =  (((x) & 0xF) << 4) | ((b) & 0xF)

#define XMIN(x, y)          ((x) < (y) ? (x) : (y))

#define XMAX(x, y)          ((x) > (y) ? (x) : (y))

#define XGETARRAYSIZE(x)    (sizeof((x)) / sizeof((x)[0]))

// extract "rd_len" number of bits, starting from "offset" of the variable "bitmap", write it to "out"
#define XBIT_READ(bitmap, offset, rd_len, out) \
{                                              \
    word32 mask = (0x1 << (rd_len)) - 0x1;     \
    (out) = ((bitmap) >> (offset)) & mask;     \
}


#define XBIT_SET( bitmap, offset, len )  \
{                                        \
    word32 wr_b = (0x1 << (len)) - 0x1;  \
    (bitmap)   |= wr_b << (offset);      \
}


#define XBIT_CLEAR( bitmap, offset, len ) \
{                                         \
    word32 wr_b = (0x1 << (len)) - 0x1;   \
    (bitmap)   &= ~(wr_b << (offset));    \
}


#define XGET_BITMASK( len )   ((0x1 << (len)) - 0x1)


// find property structure with given type, by looking for a given linked list, 
// return the property item whenever it is found.
mqttProp_t*  mqttGetPropByType( mqttProp_t* head, mqttPropertyType type );

mqttRespStatus mqttChkReasonCode( mqttReasonCode reason_code );

// generate a number that ranges from 0 to some positive integer as given input
word32  mqttUtilPRNG(mqttDRBG_t *drbg, word32 range);
// generate random byte sequence & store it to given output buffer
mqttRespStatus  mqttUtilRandByteSeq(mqttDRBG_t *drbg, byte *out, word16 outlen);

// -------- hash operations, will be integrated with third-party crypto library --------
// hash function selection, based on hash output length, and operations
void*   mqttHashFnSelect(mqttHashOpsType ops, mqttHashLenType type);

word16  mqttHashGetOutlenBytes(mqttHashLenType type);

// -------- multi-bytes integer arithmetic operations, will be integrated with third-party math library --------

// add operation on multi-bytes unsigned integer operands
mqttRespStatus  mqttUtilMultiByteUAdd( mqttStr_t *out, mqttStr_t *in1, mqttStr_t *in2 );

// add operation on multi-bytes unsigned integer operand, the 2nd operand is digit.
mqttRespStatus  mqttUtilMultiByteUAddDG( mqttStr_t *out, mqttStr_t *in1, word32 in2 );


#ifdef __cplusplus
}
#endif
#endif // end of  MQTT_UTIL_H
