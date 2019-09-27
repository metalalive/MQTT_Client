#ifndef MQTT_AUTH_H
#define MQTT_AUTH_H

#ifdef __cplusplus
extern "C" {
#endif


mqttRespStatus  mqttAuthGetWifiLoginInfo( mqttStr_t **ssid, mqttStr_t **passwd );

mqttRespStatus  mqttAuthGetBrokerHost( mqttStr_t **hostname, word16 *port );

mqttRespStatus  mqttAuthGetBrokerLoginInfo( mqttStr_t **username, mqttStr_t **passwd );



#ifdef __cplusplus
}
#endif
#endif // end of MQTT_AUTH_H

