#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#ifdef __cplusplus
extern "C" {
#endif

tlsHandshakeType tlsGetHSexpectedState(tlsSession_t *);

void tlsHSstateTransition(tlsSession_t *);

tlsRespStatus tlsClientStartHandshake(tlsSession_t *);

void tlsCleanSpaceOnClientCertSent(tlsSession_t *);

tlsRespStatus tlsChkHSfinished(tlsSession_t *);

#ifdef __cplusplus
}
#endif
#endif // end of TLS_HANDSHAKE_H
