#include "mqtt_include.h"

extern  mqttStr_t  mqttAuthBrokerHostname ; 
extern  word16     mqttAuthBrokerPort     ; 
extern  mqttStr_t  mqttAuthWifiSSID       ; 
extern  mqttStr_t  mqttAuthWifiPasswd     ; 
extern  mqttStr_t  mqttAuthBrokerUsername ; 
extern  mqttStr_t  mqttAuthBrokerPasswd   ; 

#if defined(MQTT_CFG_USE_TLS)
extern  const  byte  mqtt_auth_ca_cert_rawbyte[];
extern  unsigned int mqtt_auth_ca_cert_rawbyte_len;
extern  const  byte  mqtt_auth_ca_priv_key_rawbyte[];
extern  unsigned int mqtt_auth_ca_priv_key_rawbyte_len;
#endif // end of MQTT_CFG_USE_TLS



mqttRespStatus  mqttAuthGetWifiLoginInfo( mqttStr_t **ssid, mqttStr_t **passwd )
{
    if( ssid==NULL || passwd==NULL ) { return MQTT_RESP_ERRARGS; }
    *ssid   = &mqttAuthWifiSSID;
    *passwd = &mqttAuthWifiPasswd;
    return MQTT_RESP_OK;
} // end of mqttAuthGetWifiLoginInfo



mqttRespStatus  mqttAuthGetBrokerHost( mqttStr_t **hostname, word16 *port )
{
    if( hostname==NULL || port==NULL ) { return MQTT_RESP_ERRARGS; }
    *hostname =  &mqttAuthBrokerHostname;
    *port     =  mqttAuthBrokerPort;
    return MQTT_RESP_OK;
} // end of mqttAuthGetBrokerHost



mqttRespStatus  mqttAuthGetBrokerLoginInfo( mqttStr_t **username, mqttStr_t **passwd )
{
    if( username==NULL || passwd==NULL ) { return MQTT_RESP_ERRARGS; }
    *username = &mqttAuthBrokerUsername;
    *passwd   = &mqttAuthBrokerPasswd;
    return MQTT_RESP_OK;
} // end of mqttAuthGetBrokerLoginInfo


#if defined(MQTT_CFG_USE_TLS)
mqttRespStatus  mqttAuthGetCertRawBytes( byte **out, word16 *len )
{
    if(out==NULL || len==NULL) { return MQTT_RESP_ERRARGS; }
    *out = (const byte *) &mqtt_auth_ca_cert_rawbyte[0];
    *len = (word16)mqtt_auth_ca_cert_rawbyte_len;
    return MQTT_RESP_OK;
} // end of mqttAuthGetCertRawBytes


mqttRespStatus  mqttAuthGetCAprivKeyRawBytes( const byte **out, word16 *len )
{
    if(out==NULL || len==NULL) { return MQTT_RESP_ERRARGS; }
    *out = (const byte *) &mqtt_auth_ca_priv_key_rawbyte[0];
    *len = (word16)mqtt_auth_ca_priv_key_rawbyte_len;
    return MQTT_RESP_OK;
} // end of mqttAuthGetCAprivKeyRawBytes
#endif // end of MQTT_CFG_USE_TLS



