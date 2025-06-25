#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

// run this intialization code only in the beginning of application
tlsRespStatus tlsClientInit(mqttCtx_t *);
// run this de-intialization code only in the end of application
void tlsClientDeInit(mqttCtx_t *);

// the entry point, the integrated functions below are used to communicate between
// application-lever MQTT implementation and TLS implementation
mqttRespStatus mqttSecureNetconnStart(mqttCtx_t *);

mqttRespStatus mqttSecureNetconnStop(mqttCtx_t *);

int mqttSecurePktSend(mqttCtx_t *, byte *buf, word32 buf_len);

int mqttSecurePktRecv(mqttCtx_t *, byte *buf, word32 buf_len);

#ifdef __cplusplus
}
#endif
#endif // end of TLS_CLIENT_H
