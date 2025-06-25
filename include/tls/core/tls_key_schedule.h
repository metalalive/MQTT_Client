#ifndef TLS_KEY_SCHEDULE_H
#define TLS_KEY_SCHEDULE_H

#ifdef __cplusplus
extern "C" {
#endif

tlsRespStatus tlsGenEarlySecret(const tlsCipherSpec_t *, tlsPSK_t *pskin, tlsOpaque8b_t *out);

tlsRespStatus tlsDerivePSKbinderKey(tlsPSK_t *pskin, tlsOpaque8b_t *out);

// derive handshake traffic secret for both client & server
tlsRespStatus tlsDeriveHStrafficSecret(tlsSession_t *, tlsOpaque8b_t *earlysecret_in);

tlsRespStatus tlsDeriveAPPtrafficSecret(tlsSession_t *);

// derive encrypt/decrypt keys for both client & server, during handshake process, or application
// data transmission
tlsRespStatus tlsDeriveTraffickey(
    tlsSecurityElements_t *, tlsOpaque8b_t *in_rd_secret, tlsOpaque8b_t *in_wr_secret
);

tlsRespStatus tlsActivateReadKey(tlsSecurityElements_t *);

tlsRespStatus tlsActivateWriteKey(tlsSecurityElements_t *);

#ifdef __cplusplus
}
#endif
#endif // end of  TLS_KEY_SCHEDULE_H
