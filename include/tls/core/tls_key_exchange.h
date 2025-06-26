#ifndef TLS_KEY_EXCHANGE_H
#define TLS_KEY_EXCHANGE_H

#ifdef __cplusplus
extern "C" {
#endif

tlsRespStatus tlsGenEphemeralKeyPairs(mqttDRBG_t *, tlsKeyEx_t *);

void tlsFreeEphemeralKeyPairs(tlsKeyEx_t *);

tlsRespStatus tlsFreeEphemeralKeyPairByGrp(void *keyout, tlsNamedGrp grp_id);

tlsRespStatus
tlsImportPubValKeyShare(byte *in, word16 inlen, tlsNamedGrp grp_id, void **chosen_key);

tlsRespStatus
tlsExportPubValKeyShare(byte *out, tlsNamedGrp grp_id, void *chosen_key, word16 chosen_key_sz);

tlsRespStatus tlsECDHEgenSharedSecret(tlsSession_t *, tlsOpaque8b_t *out);

word16 tlsKeyExGetKeySize(tlsNamedGrp grp_id);

word16 tlsKeyExGetExportKeySize(tlsNamedGrp grp_id);

tlsRespStatus tlsEstimatePSKbinders(tlsSession_t *, tlsOpaque8b_t *out); // TODO

tlsRespStatus tlsVerifyPSKbinders(tlsSession_t *); // TODO

#ifdef __cplusplus
}
#endif
#endif // end of  TLS_KEY_EXCHANGE_H
