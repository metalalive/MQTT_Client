#ifndef TLS_UTIL_H
#define TLS_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MQTT_CFG_ENABLE_TLS_V1_3
    #define  TLS_HKDF_LABEL_PREFIX_V1_3  "tls13 "
#else
    #error  "must speecify TLS version for HHDF-Expand-Label function"
#endif // end of MQTT_CFG_ENABLE_TLS_V1_3

#define  TLS_HKDF_LABEL_PREFIX  TLS_HKDF_LABEL_PREFIX_V1_3


// reuse few decoding/encoding funcitons from MQTT implementation
#define  tlsEncodeWord16(buf, value)  mqttEncodeWord16((buf), (value))
#define  tlsDecodeWord16(buf, value)  mqttDecodeWord16((buf), (value))
#define  tlsEncodeWord32(buf, value)  mqttEncodeWord32((buf), (value))
#define  tlsDecodeWord32(buf, value)  mqttDecodeWord32((buf), (value))

// 24-bit (3 bytes) integer coding is used only in TLS implementation.
word32  tlsEncodeWord24( byte *buf , word32  value );
word32  tlsDecodeWord24( byte *buf , word32 *value );

tlsRespStatus  tlsAddItemToList(tlsListItem_t **list, tlsListItem_t *item, uint8_t insert_to_back);

tlsRespStatus  tlsRemoveItemFromList(tlsListItem_t **list, tlsListItem_t *removing_item );

tlsListItem_t*  tlsGetFinalItemFromList(tlsListItem_t *list);

word32          tlsGetListItemSz(tlsListItem_t *list);

mqttRespStatus   tlsRespCvtToMqttResp(tlsRespStatus in);

tlsRespStatus    tlsRespCvtFromMqttResp(mqttRespStatus in);

tlsRespStatus    tlsAlertTypeCvtToTlsResp(tlsAlertType in);

tlsHashAlgoID    tlsGetHashAlgoIDBySize(word16 len);

tlsRespStatus  tlsFreePSKentry(tlsPSK_t *in);

tlsRespStatus  tlsFreeExtEntry(tlsExtEntry_t *in);

tlsRespStatus  tlsValidateHashAlgoID(tlsHashAlgoID in);

tlsRespStatus  tlsModifyReadMsgTimeout(tlsSession_t *session, int new_val);

byte  tlsGetSupportedKeyExGrpSize( void );

byte  tlsGetSupportedVersionListSize( void );

byte  tlsGetSupportedSignSchemeListSize( void );


#ifdef __cplusplus
}
#endif
#endif // end of TLS_UTIL_H
