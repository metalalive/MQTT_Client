#ifndef TLS_PKT_TRANSMIT_H
#define TLS_PKT_TRANSMIT_H

#ifdef __cplusplus
extern "C" {
#endif


tlsRespStatus tlsPktSendToPeer(tlsSession_t *session, byte flush_flg);

tlsRespStatus tlsPktRecvFromPeer(tlsSession_t *session);

// helper functions for sending message if there are multiple fragments of it
tlsRespStatus  tlsChkFragStateOutMsg(tlsSession_t *session);

void  tlsInitFragNumOutMsg(tlsSession_t *session);

void  tlsIncrementFragNumOutMsg(tlsSession_t *session);

void  tlsDecrementFragNumOutMsg(tlsSession_t *session);

// helper functions for receiving message if there are multiple fragments of it
tlsRespStatus  tlsChkFragStateInMsg(tlsSession_t *session);

void  tlsInitFragNumInMsg(tlsSession_t *session);

void  tlsIncrementFragNumInMsg(tlsSession_t *session);

void  tlsDecrementFragNumInMsg(tlsSession_t *session);





#ifdef __cplusplus
}
#endif
#endif // end of TLS_PKT_TRANSMIT_H
