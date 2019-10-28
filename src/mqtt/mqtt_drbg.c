#include "mqtt_include.h"

static const byte  mqtt_drbg_ignore_first_seq_byte = 0xff;

// the hash derivation function below comes from the Hash_df algorithm in section 10.3.1 SP800-90Ar1,
// "in" must be present, "in2", "in3" are optional
static mqttRespStatus  mqttDRBGhashDerivation(mqttDrbgHash_t *hash, mqttStr_t *out, byte firstbyte,
                                              mqttStr_t *in, mqttStr_t *in2, mqttStr_t *in3)
{
    if((hash == NULL) || (out == NULL) || (in == NULL)) {  return MQTT_RESP_ERRARGS; }
    if((out->data == NULL) || (in->data == NULL)) {  return MQTT_RESP_ERRARGS;  }
    int      hash_status  = 0;
    int      nbits_return = (int)out->len << 3;
    if(nbits_return < 0) { return MQTT_RESP_ERR; } // overflow

    byte    *outdata      = &out->data[0];
    word16   nbytes_hashed_len = hash->nbytes_outlen;
    word16   tmp_sz = 0; // the size will be either 5 or 6
    byte     tmp[1 + 4 + 1];
    // Step 3: counter = 1
    tmp[tmp_sz++]  = 1;
    tmp_sz += mqttEncodeWord32( &tmp[1], nbits_return );
    if (firstbyte != mqtt_drbg_ignore_first_seq_byte) {
        tmp[tmp_sz++] = firstbyte;
    }
    // Step 4: start looping running hash function
    while( nbits_return > 0 )
    {
        hash_status = hash->mthd.init(&hash->md);
        if(hash_status != 0) { goto end_of_hash; }
        // Step 4.1: temp = temp || Hash(counter || no_of_bits_to_return)
        hash_status = hash->mthd.update(&hash->md, &tmp[0], tmp_sz);
        if(hash_status != 0) { goto end_of_hash; }
        // Step 4.1: temp = temp || Hash(input_string)
        hash_status = hash->mthd.update(&hash->md, in->data, in->len);
        if(hash_status != 0) { goto end_of_hash; }
        if((in2 != NULL) && (in2->data != NULL)) {
            hash_status = hash->mthd.update(&hash->md, in2->data, in2->len);
            if(hash_status != 0) { goto end_of_hash; }
        }
        if((in3 != NULL) && (in3->data != NULL)) {
            hash_status = hash->mthd.update(&hash->md, in3->data, in3->len);
            if(hash_status != 0) { goto end_of_hash; }
        }
end_of_hash:
        hash_status = hash->mthd.done(&hash->md, outdata);
        if(hash_status != 0) { break; }
        outdata      += nbytes_hashed_len;
        nbits_return -= nbytes_hashed_len << 3;
        tmp[0] += 1;
    } // end of loop
    return (hash_status != 0) ? MQTT_RESP_ERR: MQTT_RESP_OK;
} // end of mqttDRBGhashDerivation



static mqttRespStatus  mqttDRBGhashSeq2(mqttDrbgHash_t *hash, mqttStr_t *out, byte firstbyte,
                                              mqttStr_t *in, mqttStr_t *extra_in)
{
    if((hash == NULL) || (out == NULL) || (in == NULL)) {  return MQTT_RESP_ERRARGS; }
    if((out->data == NULL) || (in->data == NULL)) {  return MQTT_RESP_ERRARGS;  }
    int      hash_status  = 0;

    hash_status = hash->mthd.init(&hash->md);
    if(hash_status != 0) { goto end_of_hash; }
    if (firstbyte != mqtt_drbg_ignore_first_seq_byte) {
        hash_status = hash->mthd.update(&hash->md, &firstbyte, 0x1);
        if(hash_status != 0) { goto end_of_hash; }
    }
    hash_status = hash->mthd.update(&hash->md, in->data, in->len);
    if(hash_status != 0) { goto end_of_hash; }
    if((extra_in != NULL) && (extra_in->data != NULL)) {
        hash_status = hash->mthd.update(&hash->md, extra_in->data, extra_in->len);
        if(hash_status != 0) { goto end_of_hash; }
    }
end_of_hash:
    hash_status = hash->mthd.done(&hash->md, &out->data[0]);
    return (hash_status != 0)? MQTT_RESP_ERR: MQTT_RESP_OK;
} // end of mqttDRBGhashSeq2



// Hashgen algorithm  in section 10.1.1.4, SP800-90Ar1
static mqttRespStatus  mqttDRBGhashgen(mqttDrbgHash_t *hash, mqttStr_t *out)
{
    if((hash == NULL) || (out == NULL)) { return MQTT_RESP_ERRARGS; }
    if(out->data == NULL){  return MQTT_RESP_ERRARGS; }
    mqttRespStatus status = MQTT_RESP_OK;
    int      hash_status  = 0;
    int      nbits_return = (int)out->len << 3;
    if(nbits_return < 0) { return MQTT_RESP_ERR; } // overflow
    byte    *outdata      = &out->data[0];
    word16   nbytes_hashed_len = hash->nbytes_outlen;
    // Step 2 : Vtmp = V
    XMEMCPY( &hash->Vtmp.data[0], &hash->V.data[0], hash->V.len );
    for(;;) {
        hash_status = hash->mthd.init(&hash->md);
        if(hash_status != 0) { break; }
        // Step 4.1 : w = Hash(Vtmp)
        hash_status = hash->mthd.update(&hash->md, &hash->Vtmp.data[0], hash->Vtmp.len);
        if(hash_status != 0) { break; }
        // Step 4.2 : out = out || w , append the hashed bit sequence to output
        hash_status = hash->mthd.done(&hash->md, outdata);
        if(hash_status != 0) { break; }
        outdata      += nbytes_hashed_len;
        nbits_return -= nbytes_hashed_len << 3;
        if(nbits_return <= 0) { break; }
        // Step 4.3 : Vtmp = (Vtmp + 1) mod (2^seedlen)
        // since Vtmp.len = seedlen, that will ignore overflow bits (if happened) ,
        // which easily achieves modulo operation with divisor (2 ^ seedlen)
        status = mqttUtilMultiByteUAddDG( &hash->Vtmp, &hash->Vtmp, 0x1 );
    } // end of loop
    return status;
} // end of mqttDRBGhashgen


static mqttRespStatus  mqttDRBGinstantiate(mqttDRBG_t *drbg, mqttStr_t *nonce)
{
    mqttRespStatus status = MQTT_RESP_OK;
    mqttStr_t *entropy    = &drbg->entropy;
    status = mqttSysGetEntropy(entropy);
    if(status != MQTT_RESP_OK) { return status; }
    status = mqttSysGetEntropy(nonce);
    if(status != MQTT_RESP_OK) { return status; }
    // start Hash_DRBG instantiate process (section 10.1.1.2 , SP800-90Ar1)
    status = mqttDRBGhashDerivation(&drbg->hash, &drbg->hash.V,
               mqtt_drbg_ignore_first_seq_byte, entropy, nonce, NULL);
    if(status != MQTT_RESP_OK) { return status; }
    status = mqttDRBGhashDerivation(&drbg->hash, &drbg->hash.C, 0x00, &drbg->hash.V, NULL, NULL);
    drbg->reseed_cnt = 1;
    return status;
} // end of mqttDRBGinstantiate


static word16  mqttDRBGgetSeedlenBytes(mqttHashLenType type)
{
    word16 out = 0;
    switch(type) {
        case MQTT_HASH_SHA256:
            out = MQTT_MIN_BYTES_SEED ; // unit: bit(s)
            break;
        case MQTT_HASH_SHA384:
            out = MQTT_MAX_BYTES_SEED ; // unit: bit(s)
            break;
        default:
            break;
    }
    return out;
} // end of mqttDRBGgetSeedlenBytes


mqttRespStatus  mqttDRBGinit(mqttDRBG_t **drbg)
{
    if(drbg == NULL) { return MQTT_RESP_ERRARGS; }
    mqttStr_t      nonce;
    mqttRespStatus status = MQTT_RESP_OK;
    mqttDRBG_t   *d = NULL;
    word16    seed_len = 0;
    word16    hash_outlen = 0;

    d = (mqttDRBG_t *) XMALLOC(sizeof(mqttDRBG_t));
    XASSERT(d != NULL);
    XMEMSET(d, 0x00, sizeof(mqttDRBG_t));
    d->entropy.len  = MQTT_MIN_BYTES_ENTROPY;
    d->entropy.data = (byte *) XMALLOC(sizeof(byte) * d->entropy.len);
    XASSERT(d->entropy.data != NULL);
    nonce.len   = MQTT_MIN_BYTES_ENTROPY >> 1;
    nonce.data  = (byte *) XMALLOC(sizeof(byte) * nonce.len);
    XASSERT(nonce.data != NULL);
    d->reseed_intvl= MQTT_CFG_DRBG_RESEED_INTERVAL;
    // This DRBG impd->lementation only supports Hash_DRBG with SHA-256 , not HMAC_DRBG
    d->hash.nbytes_outlen = mqttHashGetOutlenBytes( MQTT_HASH_SHA256 );
    // function pointers to hashing function integration
    d->hash.mthd.init   = (mqttHashInitFp)   mqttHashFnSelect( MQTT_HASH_OPERATION_INIT,   MQTT_HASH_SHA256 );
    d->hash.mthd.update = (mqttHashUpdateFp) mqttHashFnSelect( MQTT_HASH_OPERATION_UPDATE, MQTT_HASH_SHA256 );
    d->hash.mthd.done   = (mqttHashDoneFp)   mqttHashFnSelect( MQTT_HASH_OPERATION_DONE,   MQTT_HASH_SHA256 );
    // the length of output random byte sequence should be the power of 2 that is greater then seedlen
    seed_len   = mqttDRBGgetSeedlenBytes( MQTT_HASH_SHA256 );
    while(seed_len > hash_outlen) {
       hash_outlen += d->hash.nbytes_outlen;
    }
    // note that one more byte is allocated to V, C, Vtmp elements of the hash DRBG function
    // for  storing the extra (overflow) byte whenever users convert multi-byte integer to a given byte
    // sequence  (because some math libraries do NOT allow smaller byte sequence to store large value of
    //  multi-byte integer structure ), the overflow byte  can be simply ignored when performing
    // modulo operation with the divisor = 2 ^ MQTT_MIN_BYTES_SEED
    d->hash.V.len   = hash_outlen;
    d->hash.V.data  = (byte *) XMALLOC(sizeof(byte) * hash_outlen+1);
    d->hash.C.len   = hash_outlen;
    d->hash.C.data  = (byte *) XMALLOC(sizeof(byte) * hash_outlen+1);
    d->hash.Vtmp.len   = hash_outlen;
    d->hash.Vtmp.data  = (byte *) XMALLOC(sizeof(byte) * hash_outlen+1);
    XASSERT(d->hash.V.data != NULL);
    XASSERT(d->hash.C.data != NULL);
    XASSERT(d->hash.Vtmp.data != NULL);
    // move pointers of V, C, Vtmp to data[1]
    // always used V.data[1...hash_outlen] to store hashed value or arithmetic result,
    // use V.data[0] to store overflow byte as described above.
    d->hash.V.data += 1;
    d->hash.C.data += 1;
    d->hash.Vtmp.data += 1;
    d->cache_rd_ptr = hash_outlen;
    d->cache.len  = hash_outlen;
    d->cache.data = (byte *) XMALLOC(sizeof(byte) * hash_outlen);
    XASSERT(d->cache.data != NULL);
    status = mqttDRBGinstantiate(d, &nonce);
    if(status == MQTT_RESP_OK) {
        *drbg = d;
    }
    else {
         mqttDRBGdeinit(d);
        *drbg = NULL;
    }
    if(nonce.data != NULL) {
        XMEMFREE((void *)nonce.data);
        nonce.data = NULL;
    }
    return status;
} // end of mqttDRBGinit



mqttRespStatus  mqttDRBGdeinit(mqttDRBG_t *drbg)
{
    mqttRespStatus status =  MQTT_RESP_OK;
    if(drbg == NULL) { return MQTT_RESP_ERRARGS; }
    if(drbg->entropy.data != NULL) {
        XMEMFREE((void *)drbg->entropy.data);
        drbg->entropy.data = NULL;
    }
    if(drbg->hash.V.data != NULL) {
        // the point was moved to V.data[1] while it was allocated,
        // now it should be moved back to V.data[0]
        drbg->hash.V.data -= 1;
        XMEMFREE((void *)drbg->hash.V.data);
        drbg->hash.V.data = NULL;
    }
    if(drbg->hash.C.data != NULL) {
        drbg->hash.C.data -= 1;
        XMEMFREE((void *)drbg->hash.C.data);
        drbg->hash.C.data = NULL;
    }
    if(drbg->hash.Vtmp.data != NULL) {
        drbg->hash.Vtmp.data -= 1;
        XMEMFREE((void *)drbg->hash.Vtmp.data);
        drbg->hash.Vtmp.data = NULL;
    }
    if(drbg->cache.data != NULL) {
        XMEMFREE((void *)drbg->cache.data);
        drbg->cache.data = NULL;
    }
    XMEMFREE((void *)drbg);
    return status;
} // end of mqttDRBGdeinit



mqttRespStatus  mqttDRBGreseed(mqttDRBG_t *drbg, mqttStr_t *extra_in)
{
    if(drbg == NULL) {return MQTT_RESP_ERRARGS;}
    mqttRespStatus status =  MQTT_RESP_OK;
    // firstly get entropy from underlying system / platform
    mqttStr_t *entropy = &drbg->entropy;
    mqttSysGetEntropy(entropy);
    // start Hash_DRBG reseed process (section 10.1.1.3 , SP800-90Ar1)
    // Step 1 : seed_material = 0x01 || V || entropy_input || additional_input
    // Step 2 : Vtmp = Hash_df (seed_material, seedlen)
    status = mqttDRBGhashDerivation(&drbg->hash, &drbg->hash.Vtmp, 0x01, &drbg->hash.V, entropy, extra_in);
    if(status != MQTT_RESP_OK) { return status; }
    // Step 3 : V = Vtmp
    XMEMCPY( &drbg->hash.V.data[0], &drbg->hash.Vtmp.data[0], drbg->hash.Vtmp.len );
    // Step 4 : C = Hash_df ((0x00 || Vtmp), seedlen)
    status = mqttDRBGhashDerivation(&drbg->hash, &drbg->hash.C, 0x00, &drbg->hash.Vtmp, NULL, NULL);
    if(status != MQTT_RESP_OK) { return status; }
    drbg->reseed_cnt = 1;
    return status;
} // end of mqttDRBGreseed


mqttRespStatus  mqttDRBGgen(mqttDRBG_t *drbg, mqttStr_t *out, mqttStr_t *extra_in)
{
    if((out == NULL) || (drbg == NULL)) {return MQTT_RESP_ERRARGS;}
    mqttRespStatus status =  MQTT_RESP_OK;
    // Step 1: periodically run reseeding function when the previous seed
    //  has been used for certain number of times to generate random bit sequence.
    if(drbg->reseed_cnt > drbg->reseed_intvl) {
        status = mqttDRBGreseed(drbg, extra_in);
        if(status != MQTT_RESP_OK) { return status; }
    }
    if((extra_in != NULL) && (extra_in->data != NULL)) { // Step 2
        // Step 2.1 : Vtmp = Hash (0x02 || V || additional_input)
        status = mqttDRBGhashSeq2(&drbg->hash, &drbg->hash.Vtmp, 0x02, &drbg->hash.V, extra_in);
        if(status != MQTT_RESP_OK) { return status; }
        // Step 2.2: V = (V + Vtmp) mod (2^seedlen)
        // note that drbg->hash.V.len is equal to seedlen, the maximum value of drbg->hash.V.data is (2^seedlen) - 1
        // this means it already provides easier way to perform modulo operation with divisor = 2^seedlen .
        // (by simply ignoring the overflow bits after V = V + Vtmp)
        status = mqttUtilMultiByteUAdd( &drbg->hash.V, &drbg->hash.V, &drbg->hash.Vtmp );
        if(status != MQTT_RESP_OK) { return status; }
    }
    // Step 3: (returned_bits) = Hashgen (requested_number_of_bits, V)
    status = mqttDRBGhashgen(&drbg->hash, out);
    if(status != MQTT_RESP_OK) { return status; }
    // Step 4: Vtmp = Hash (0x03 || V)
    status = mqttDRBGhashSeq2(&drbg->hash, &drbg->hash.Vtmp, 0x03, &drbg->hash.V, NULL);
    if(status != MQTT_RESP_OK) { return status; }
    // Step 5: V = (V + Vtmp + C + reseed_counter) mod (2^seedlen)
    //     breakdown step 5-1 : V = (V + Vtmp)    mod (2^seedlen)
    status = mqttUtilMultiByteUAdd( &drbg->hash.V, &drbg->hash.V, &drbg->hash.Vtmp );
    if(status != MQTT_RESP_OK) { return status; }
    //     breakdown step 5-2 : V = (V + C)       mod (2^seedlen)
    status = mqttUtilMultiByteUAdd( &drbg->hash.V, &drbg->hash.V, &drbg->hash.C );
    if(status != MQTT_RESP_OK) { return status; }
    //     breakdown step 5-3 : V = (V + reseed_cnt)  mod (2^seedlen)
    status = mqttUtilMultiByteUAddDG( &drbg->hash.V, &drbg->hash.V, (word32)drbg->reseed_cnt );
    if(status != MQTT_RESP_OK) { return status; }
    // Step 6 : reseed_counter = reseed_counter + 1
    drbg->reseed_cnt++;
    return status;
} // end of mqttDRBGgen


