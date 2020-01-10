#include "mqtt_include.h"


mqttProp_t*  mqttGetPropByType( mqttProp_t* head, mqttPropertyType type )
{
    if(type == MQTT_PROP_NONE) { return NULL; }
    mqttProp_t *curr_node = NULL;

    for(curr_node = head; curr_node != NULL; curr_node = curr_node->next ) 
    {
        if(curr_node->type == type) { break; }
    } // end of for-loop
    return curr_node;
} // end of mqttGetPropByType



mqttRespStatus mqttChkReasonCode( mqttReasonCode reason_code )
{
    return  (reason_code <= MQTT_GREATEST_NORMAL_REASON_CODE ? MQTT_RESP_OK : MQTT_RESP_ERR);
} // end of mqttChkReasonCode


word32  mqttGetInterval(word32 now, word32 then)
{
    word32 out = 0;
    if(now < then) {
        out = 0xffffffff - then + now;
    }
    else{
        out = now - then;
    }
    return out;
} // end of mqttGetInterval


byte  mqttCvtDecimalToBCDbyte(byte in, byte base)
{
    return  ((in/base) << 4) | (in%base);
} // mqttCvtDecimalToBCDbyte


// the return value below means minimum number of bytes to store a given integer
// Note: currently I only consider 32-bit CPU platform, so the possible return value
//       will range from 1 to 4.
static  uint8_t mqttUtilNbytesCoverInt(word32 range) {
    uint8_t num = 0;
    uint8_t out = 0;
    while(range > 0){
        num++;
        range = range >> 1;
    }
    out = num >> 3;
    if((num % 8) != 0){ out++; }
    return out ;
} // end of mqttUtilNbytesCoverInt



word32  mqttUtilPRNG(mqttDRBG_t *drbg, word32 range)
{
    word32 out = 0;
    if((range == 0) || (drbg == NULL)) {return out;}
    byte        buf[4]    = {0};
    byte       *bufp      = &buf[0];
    // TODO: add mutex operation for multi-tasking cases
    mqttStr_t  *drbgcache = &drbg->cache;
    word16      rd_ptr    =  drbg->cache_rd_ptr;
    // estimate number of bytes we need to retrieve from the (previously generated) random byte sequence.
    uint8_t nbytes_need = mqttUtilNbytesCoverInt(range);
    uint8_t nbytes_cpy  = XMIN(nbytes_need, drbgcache->len - rd_ptr);

    if( nbytes_cpy != 0 ) {
        XMEMCPY((void *)bufp, (void *)&drbgcache->data[rd_ptr], nbytes_cpy);
        bufp   += nbytes_cpy;
        rd_ptr += nbytes_cpy;
    }
    if( nbytes_cpy < nbytes_need ) { // if no sufficient random bytes from drbg->cache
        nbytes_cpy = nbytes_need - nbytes_cpy;
        mqttRespStatus status = mqttDRBGgen(drbg, drbgcache, NULL);
        if(status != MQTT_RESP_OK) { return out; }
        XMEMCPY((void *)bufp, (void *)&drbgcache->data[0], nbytes_cpy);
        rd_ptr = (word16)nbytes_cpy;
    }
    drbg->cache_rd_ptr = rd_ptr;
    // treat the random bytes (buf) as 32-bit integer, perform modulo operation to get return value
    out = (*(word32 *)&buf[0]) % (range + 1);
    return  out;
} // end of mqttUtilPRNG



mqttRespStatus  mqttUtilRandByteSeq(mqttDRBG_t *drbg, byte *out, word16 outlen)
{
    if((out == NULL) || (drbg == NULL) || (outlen == 0)) {
        return MQTT_RESP_ERRARGS;
    }
    mqttRespStatus status = MQTT_RESP_OK;
    // TODO: add mutex operation for multi-tasking cases
    mqttStr_t  *drbgcache  = &drbg->cache;
    word16      rd_ptr     =  drbg->cache_rd_ptr;
    word16      nbytes_cpy =  0;
    while(1) {
        nbytes_cpy = XMIN(outlen, drbgcache->len - rd_ptr);
        if( nbytes_cpy != 0 ) {
            XMEMCPY(out, &drbgcache->data[rd_ptr], nbytes_cpy);
            out    += nbytes_cpy;
            outlen -= nbytes_cpy;
            rd_ptr += nbytes_cpy;
        }
        if( outlen > 0 ) { // if no sufficient random bytes from drbg->cache
            status = mqttDRBGgen(drbg, drbgcache, NULL);
            if(status != MQTT_RESP_OK) { break; }
            rd_ptr = 0;
        }
        else { break; } // outlen == 0
    } // end of while-loop
    drbg->cache_rd_ptr = rd_ptr;
    return status;
} // end of mqttUtilRandByteSeq


// ----------------- Hash function integration with third-party crypto library -------------------------
extern int MGTT_CFG_HASH_SHA256_FN_INIT(mqttHash_t *md);

extern int MGTT_CFG_HASH_SHA384_FN_INIT(mqttHash_t *md);

extern int MGTT_CFG_HASH_SHA256_FN_UPDATE(mqttHash_t *md, const byte *in, unsigned long inlen);

extern int MGTT_CFG_HASH_SHA384_FN_UPDATE(mqttHash_t *md, const byte *in, unsigned long inlen);

extern int MGTT_CFG_HASH_SHA256_FN_DONE(mqttHash_t *md, byte *out);

extern int MGTT_CFG_HASH_SHA384_FN_DONE(mqttHash_t *md, byte *out);



#define  MQTT_HASH_SELECT_FN_BY_OPS( fp, opname, htype )  \
static  fp  mqttHash##opname##fnSelect(mqttHashLenType htype) \
{                                                   \
    fp  out = NULL;                                 \
    switch(htype) {                                 \
        case MQTT_HASH_SHA256:                      \
            out = MGTT_CFG_HASH_SHA256_FN_##opname; \
            break;                                  \
        case MQTT_HASH_SHA384:                      \
            out = MGTT_CFG_HASH_SHA384_FN_##opname; \
            break;                                  \
        default:                                    \
            break;                                  \
    }                                               \
    return out;                                     \
}
// end of MQTT_HASH_SELECT_FN_BY_OPS


MQTT_HASH_SELECT_FN_BY_OPS( mqttHashInitFp  , INIT,   type );

MQTT_HASH_SELECT_FN_BY_OPS( mqttHashUpdateFp, UPDATE, type );

MQTT_HASH_SELECT_FN_BY_OPS( mqttHashDoneFp  , DONE,   type );


void*   mqttHashFnSelect(mqttHashOpsType ops, mqttHashLenType type)
{
    void *out = NULL;
    switch(ops) {
        case MQTT_HASH_OPERATION_INIT:
            out = (void *) mqttHashINITfnSelect(type);
            break;
        case MQTT_HASH_OPERATION_UPDATE:
            out = (void *) mqttHashUPDATEfnSelect(type);
            break;
        case MQTT_HASH_OPERATION_DONE:
            out = (void *) mqttHashDONEfnSelect(type);
            break;
        default:
            break;
    } // end of switch-case statement
    return out;
} // end of mqttHashFnSelect



word16  mqttHashGetOutlenBytes(mqttHashLenType type)
{
    word16 out = 0;
    switch(type) {
        case MQTT_HASH_SHA256:
            out = 256; // unit: bit(s)
            break;
        case MQTT_HASH_SHA384:
            out = 384; // unit: bit(s)
            break;
        default:
            break;
    }
    out = out >> 3;
    return out;
} // end of mqttHashGetOutlenBits



mqttRespStatus  mqttUtilMultiByteUAdd( mqttStr_t *out, mqttStr_t *in1, mqttStr_t *in2 )
{
    if((out == NULL) || (in1 == NULL) || (in2 == NULL)) {
        return MQTT_RESP_ERRARGS;
    }
    if((out->data == NULL) || (in1->data == NULL) || (in2->data == NULL)) {
        return MQTT_RESP_ERRARGS;
    }
    int           mp_status = 0;
    multiBint_t   mp_in1;
    multiBint_t   mp_in2;
    multiBint_t   mp_out;
    byte         *outbias = NULL;
    size_t        outlenbias = 0;
    size_t        written = 0;
    // TODO: find better way to init/deinit the multi-byte integer structure, since
    //       these operations will be performed a lot of times.
    mp_status  = MQTT_CFG_MPBINT_FN_INIT( &mp_in1 );
    mp_status |= MQTT_CFG_MPBINT_FN_INIT( &mp_in2 );
    mp_status |= MQTT_CFG_MPBINT_FN_INIT( &mp_out );
    if(mp_status != 0) { goto end_of_mb_math_ops; }

    mp_status = MQTT_CFG_MPBINT_FN_BIN2MPINT(&mp_in1, (const byte *)&in1->data[0], (size_t)in1->len);
    if(mp_status != 0) { goto end_of_mb_math_ops; }

    mp_status = MQTT_CFG_MPBINT_FN_BIN2MPINT(&mp_in2, (const byte *)&in2->data[0], (size_t)in2->len);
    if(mp_status != 0) { goto end_of_mb_math_ops; }

    mp_status = MQTT_CFG_MPBINT_FN_ADD((const multiBint_t *)&mp_in1,
                                            (const multiBint_t *)&mp_in2,
                                            (multiBint_t *)&mp_out );
    if(mp_status != 0) { goto end_of_mb_math_ops; }

    if(MQTT_CFG_MPBINT_FN_CAL_UBINSIZE(&mp_out) > out->len) {
         outbias    = &out->data[-1];
         outlenbias = (size_t)out->len + 1;
    }
    else{
         outbias    = &out->data[0];
         outlenbias = (size_t)out->len;
    }
    mp_status = MQTT_CFG_MPBINT_FN_MPINT2BIN((const multiBint_t *)&mp_out,
                                              outbias, outlenbias, &written );
end_of_mb_math_ops:
    MQTT_CFG_MPBINT_FN_CLEAR( &mp_in1 );
    MQTT_CFG_MPBINT_FN_CLEAR( &mp_in2 );
    MQTT_CFG_MPBINT_FN_CLEAR( &mp_out );
    return (mp_status == 0 ? MQTT_RESP_OK: MQTT_RESP_ERR);
} // end of mqttUtilMultiByteUAdd



mqttRespStatus  mqttUtilMultiByteUAddDG( mqttStr_t *out, mqttStr_t *in1, word32 in2 )
{
    if((out == NULL) || (in1 == NULL)) {
        return MQTT_RESP_ERRARGS;
    }
    if((out->data == NULL) || (in1->data == NULL)) {
        return MQTT_RESP_ERRARGS;
    }
    if(in2 == 0) {
        if(out != in1) {
            word16  minlen = XMIN( out->len, in1->len );
            word16  maxlen = XMAX( out->len, in1->len );
            XMEMCPY( &out->data[0], &in1->data[0], minlen );
            if(maxlen > minlen) {
                XMEMSET( &out->data[minlen], 0x00, (maxlen - minlen));
            }
        }
        return MQTT_RESP_OK;
    }
    int           mp_status = 0;
    size_t        written   = 0;
    multiBint_t   mp_in1;
    multiBint_t   mp_out;
    byte         *outbias = NULL;
    size_t        outlenbias = 0;
    // TODO: find better way to init/deinit the multi-byte integer structure, since
    //       these operations will be performed a lot of times.
    mp_status  = MQTT_CFG_MPBINT_FN_INIT( &mp_in1 );
    mp_status |= MQTT_CFG_MPBINT_FN_INIT( &mp_out );
    if(mp_status != 0) { goto end_of_mb_math_ops; }

    mp_status = MQTT_CFG_MPBINT_FN_BIN2MPINT(&mp_in1, (const byte *)&in1->data[0], (size_t)in1->len);
    if(mp_status != 0) { goto end_of_mb_math_ops; }

    mp_status = MQTT_CFG_MPBINT_FN_ADDDG((const multiBint_t *)&mp_in1, in2, &mp_out);
    if(mp_status != 0) { goto end_of_mb_math_ops; }

    if(MQTT_CFG_MPBINT_FN_CAL_UBINSIZE(&mp_out) > out->len) {
         outbias    = &out->data[-1];
         outlenbias = (size_t)out->len + 1;
    }
    else{
         outbias    = &out->data[0];
         outlenbias = (size_t)out->len;
    }
    mp_status = MQTT_CFG_MPBINT_FN_MPINT2BIN((const multiBint_t *)&mp_out,
                                               outbias, outlenbias, &written );
end_of_mb_math_ops:
    MQTT_CFG_MPBINT_FN_CLEAR( &mp_in1 );
    MQTT_CFG_MPBINT_FN_CLEAR( &mp_out );
    return (mp_status == 0 ? MQTT_RESP_OK: MQTT_RESP_ERR);
} // end of mqttUtilMultiByteUAddDG



