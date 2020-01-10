#ifndef TLS_KEY_SCHEDULE_H
#define TLS_KEY_SCHEDULE_H

#ifdef __cplusplus
extern "C" {
#endif

tlsRespStatus  tlsGenEarlySecret(const tlsCipherSpec_t *cs, tlsPSK_t *pskin, tlsOpaque8b_t *out);

// This function is called when :
// (1) encoding ClientHello with pre-shared key extension entry
// (2) decoding ServerHello with pre-shared key extension entry
// then this function generates PSK binder secret & binder keys for further verification on
// binder section of the pre-shared key extension entry.
// Note that this function will NOT check correctness of early_secret input, applications must run
// tlsGenEarlySecret() with pre-shared key before calling this function.
//// tlsRespStatus  tlsDerivePSKbinderSecret( tlsPSK_t *pskin, tlsOpaque8b_t *earlysecret_in, tlsOpaque8b_t *binder_out );

// derive handshake traffic secret for both client & server
tlsRespStatus  tlsDeriveHStrafficSecret(tlsSession_t *session,  tlsOpaque8b_t* earlysecret_in);

tlsRespStatus  tlsDeriveAPPtrafficSecret(tlsSession_t *session);

// derive encrypt/decrypt keys for both client & server, during handshake process, or application data transmission
tlsRespStatus  tlsDeriveTraffickey(tlsSecurityElements_t *sec, tlsOpaque8b_t  *in_rd_secret, tlsOpaque8b_t  *in_wr_secret);

tlsRespStatus  tlsActivateReadKey(tlsSecurityElements_t *sec);

tlsRespStatus  tlsActivateWriteKey(tlsSecurityElements_t *sec);


#ifdef __cplusplus
}
#endif
#endif // end of  TLS_KEY_SCHEDULE_H
