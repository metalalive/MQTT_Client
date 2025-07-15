#include "mqtt_include.h"

extern mqttHost_t mqttAuthBrokerHostname;
extern word16     mqttAuthBrokerPort;
extern mqttStr_t  mqttAuthWifiSSID;
extern mqttStr_t  mqttAuthWifiPasswd;
extern mqttStr_t  mqttAuthBrokerUsername;
extern mqttStr_t  mqttAuthBrokerPasswd;

#if defined(MQTT_CFG_USE_TLS)
extern const byte   mqtt_auth_cacert4broker_rawbyte[];
extern unsigned int mqtt_auth_cacert4broker_nbytes;
extern const byte   mqtt_auth_client_privkey_rawbyte[];
extern unsigned int mqtt_auth_client_privkey_nbytes;
extern const byte   mqtt_auth_clientcert_rawbyte[];
extern unsigned int mqtt_auth_clientcert_nbytes;
#endif

mqttRespStatus mqttAuthGetWifiLoginInfo(mqttStr_t **ssid, mqttStr_t **passwd) {
    if (ssid == NULL || passwd == NULL) {
        return MQTT_RESP_ERRARGS;
    }
    *ssid = &mqttAuthWifiSSID;
    *passwd = &mqttAuthWifiPasswd;
    return MQTT_RESP_OK;
}

mqttRespStatus mqttAuthGetBrokerHost(mqttHost_t **host, word16 *port) {
    if (host == NULL || port == NULL) {
        return MQTT_RESP_ERRARGS;
    }
    *host = &mqttAuthBrokerHostname;
    *port = mqttAuthBrokerPort;
    return MQTT_RESP_OK;
}

mqttRespStatus mqttAuthGetBrokerLoginInfo(mqttStr_t **username, mqttStr_t **passwd) {
    if (username == NULL || passwd == NULL) {
        return MQTT_RESP_ERRARGS;
    }
    *username = &mqttAuthBrokerUsername;
    *passwd = &mqttAuthBrokerPasswd;
    return MQTT_RESP_OK;
}

#if defined(MQTT_CFG_USE_TLS)
mqttRespStatus mqttAuthCACertBrokerRaw(byte **out, word16 *len) {
    if (out == NULL || len == NULL) {
        return MQTT_RESP_ERRARGS;
    }
    *out = (const byte *)&mqtt_auth_cacert4broker_rawbyte[0];
    *len = (word16)mqtt_auth_cacert4broker_nbytes;
    return MQTT_RESP_OK;
}

mqttRespStatus mqttAuthClientPrivKeyRaw(const byte **out, word16 *len) {
    if (out == NULL || len == NULL) {
        return MQTT_RESP_ERRARGS;
    }
    *out = (const byte *)&mqtt_auth_client_privkey_rawbyte[0];
    *len = (word16)mqtt_auth_client_privkey_nbytes;
    return MQTT_RESP_OK;
}

mqttRespStatus mqttAuthClientCertRaw(byte **out, word16 *len) {
    if (out == NULL || len == NULL) {
        return MQTT_RESP_ERRARGS;
    }
    *out = (const byte *)&mqtt_auth_clientcert_rawbyte[0];
    *len = (word16)mqtt_auth_clientcert_nbytes;
    return MQTT_RESP_OK;
}
#endif // end of MQTT_CFG_USE_TLS
