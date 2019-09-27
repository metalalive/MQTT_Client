#include "mqtt_include.h"

extern  mqttStr_t  mqttAuthBrokerHostname ; 
extern  word16     mqttAuthBrokerPort     ; 
extern  mqttStr_t  mqttAuthWifiSSID       ; 
extern  mqttStr_t  mqttAuthWifiPasswd     ; 
extern  mqttStr_t  mqttAuthBrokerUsername ; 
extern  mqttStr_t  mqttAuthBrokerPasswd   ; 



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



