#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#ifdef __cplusplus
extern "C" {
#endif


tlsHandshakeType  tlsGetHSexpectedState(tlsSession_t *session);

void   tlsHSstateTransition(tlsSession_t *session);

tlsRespStatus  tlsClientStartHandshake(tlsSession_t *session);

void tlsCleanSpaceOnClientCertSent(tlsSession_t *session);

tlsRespStatus  tlsChkHSfinished(tlsSession_t  *session);


#ifdef __cplusplus
}
#endif
#endif // end of TLS_HANDSHAKE_H
