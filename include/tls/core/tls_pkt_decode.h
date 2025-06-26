#ifndef TLS_PKT_DECODE_H
#define TLS_PKT_DECODE_H

#ifdef __cplusplus
extern "C" {
#endif

tlsRespStatus tlsDecodeRecordLayer(tlsSession_t *);

tlsRespStatus tlsVerifyDecodeRecordType(tlsContentType rec_type);

tlsRespStatus tlsVerifyDecodeVersionCode(const byte *ver_in);

word16 tlsGetUndecodedNumBytes(tlsSession_t *);

#ifdef __cplusplus
}
#endif
#endif // end of TLS_PKT_DECODE_H
