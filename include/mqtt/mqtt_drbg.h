#ifndef MQTT_DRBG_H
#define MQTT_DRBG_H

#ifdef __cplusplus
extern "C" {
#endif

// ------------- Deterministic Random Bit Generator -------------
// Accoring to Table 2, section 10-1, NIST SP800-90Ar1
// seed length (seedlen) for Hash_DRBG is 440 bits (for SHA-256) or 888 bits (for SHA-384).
// In this MQTT implementation, if the selected system platform doesn't include hardware hash
// function accelerator, then the software hashing function will be called as default,
// and we only suppport SHA-256 and SHA-384 functions for DRBG
#define MQTT_MIN_BYTES_SEED (440 >> 3) // for SHA-256
#define MQTT_MAX_BYTES_SEED (888 >> 3) // for SHA-384
// Accoring to Table 3, section 5-6-1, NIST SP800-57 Pt.1  Rev.4 , and the description above,
// SHA-256 can provide 128 bits of security strength, so the entropy should be at least 128 bits
#define MQTT_MIN_BYTES_ENTROPY (128 >> 3)
// note that we simply set twice MQTT_MIN_BYTES_ENTROPY to maximum number of bytes of entropy.
#define MQTT_MAX_BYTES_ENTROPY (MQTT_MIN_BYTES_ENTROPY << 2)
// number of times users can perform DRBG generate operations, between 2 DRBG reseeding operations
#ifndef MQTT_CFG_DRBG_RESEED_INTERVAL
    #define MQTT_CFG_DRBG_RESEED_INTERVAL 16
#endif // end of MQTT_CFG_DRBG_RESEED_INTERVAL
// TODO: find better way to provide the parameters above

// --------- interfaces for deterministic random bit generator ---------
// note that  this DRBG implementation only supports HASH_DRBG,
// HMAC_DRBG is not implemented at here

mqttRespStatus mqttDRBGinit(mqttDRBG_t **drbg);

mqttRespStatus mqttDRBGdeinit(mqttDRBG_t *drbg);

mqttRespStatus mqttDRBGreseed(mqttDRBG_t *drbg, mqttStr_t *extra_in);

mqttRespStatus mqttDRBGgen(mqttDRBG_t *drbg, mqttStr_t *out, mqttStr_t *extra_in);

#ifdef __cplusplus
}
#endif
#endif // end of  MQTT_DRBG_H
