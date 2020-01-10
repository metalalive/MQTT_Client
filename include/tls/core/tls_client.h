#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

// run this intialization code only in the beginning of application
tlsRespStatus    tlsClientInit(mqttCtx_t *mctx);
// run this de-intialization code only in the end of application
void             tlsClientDeInit(mqttCtx_t *mctx);

// the entry point, the integrated functions below are used to communicate between
// application-lever MQTT implementation and TLS implementation
mqttRespStatus   mqttSecureNetconnStart(mqttCtx_t *mctx);

mqttRespStatus   mqttSecureNetconnStop(mqttCtx_t *mctx);

int  mqttSecurePktSend(mqttCtx_t *mctx, byte *buf, word32 buf_len);

int  mqttSecurePktRecv(mqttCtx_t *mctx, byte *buf, word32 buf_len);


#ifdef __cplusplus
}
#endif
#endif // end of TLS_CLIENT_H
