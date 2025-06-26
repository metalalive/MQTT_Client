#ifndef TLS_PKT_TRANSMIT_H
#define TLS_PKT_TRANSMIT_H

#ifdef __cplusplus
extern "C" {
#endif

tlsRespStatus tlsPktSendToPeer(tlsSession_t *, byte flush_flg);

tlsRespStatus tlsPktRecvFromPeer(tlsSession_t *);

// helper functions for sending message if there are multiple fragments of it
tlsRespStatus tlsChkFragStateOutMsg(tlsSession_t *);

void tlsInitFragNumOutMsg(tlsSession_t *);

void tlsIncrementFragNumOutMsg(tlsSession_t *);

void tlsDecrementFragNumOutMsg(tlsSession_t *);

// helper functions for receiving message if there are multiple fragments of it
tlsRespStatus tlsChkFragStateInMsg(tlsSession_t *);

void tlsInitFragNumInMsg(tlsSession_t *);

void tlsIncrementFragNumInMsg(tlsSession_t *);

void tlsDecrementFragNumInMsg(tlsSession_t *);

#ifdef __cplusplus
}
#endif
#endif // end of TLS_PKT_TRANSMIT_H
