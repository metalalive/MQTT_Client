#ifndef TLS_ENCRYPT_H
#define TLS_ENCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif



tlsRespStatus  tlsEncryptRecordMsg(tlsSession_t *session);

tlsRespStatus  tlsDecryptRecordMsg(tlsSession_t *session);


#ifdef __cplusplus
}
#endif
#endif // end of TLS_ENCRYPT_H
