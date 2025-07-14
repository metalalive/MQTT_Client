// header which collects all include files of common third-party libraries
#include "mqtt_third_party_include.h"
#include "mqtt/mqtt_types.h"

mqttStr_t  mqttAuthBrokerHostname = { {{{ brokeraddr.value@strlen }}},       (byte *)&({{{ brokeraddr.value@wrapQuote }}}) };
word16     mqttAuthBrokerPort     =   {{{ brokerport.value@numToStr }}}; // or default port 1883 if TLS feature is NOT enabled
mqttStr_t  mqttAuthWifiSSID       = { {{{ wifiusername.value@strlen }}},     (byte *)&({{{ wifiusername.value@wrapQuote   }}}) };
mqttStr_t  mqttAuthWifiPasswd     = { {{{ wifiuserpasswd.value@strlen }}},   (byte *)&({{{ wifiuserpasswd.value@wrapQuote }}}) };
mqttStr_t  mqttAuthBrokerUsername = { {{{ brokerusername.value@strlen }}},   (byte *)&({{{ brokerusername.value@wrapQuote  }}}) };
mqttStr_t  mqttAuthBrokerPasswd   = { {{{ brokeruserpasswd.value@strlen }}}, (byte *)&({{{ brokeruserpasswd.value@wrapQuote }}}) };

const byte   mqttAuthInitHour    = {{{sysinithour.value@numToStr@convertBCD }}};
const byte   mqttAuthInitMinutes = {{{sysinitminutes.value@numToStr@convertBCD }}};
const byte   mqttAuthInitSeconds = {{{sysinitseconds.value@numToStr@convertBCD }}};
const byte   mqttAuthInitMonth   = {{{sysinitmonth.value@numToStr@convertBCD  }}};
const byte   mqttAuthInitDate    = {{{sysinitdate.value@numToStr@convertBCD   }}};
const word16 mqttAuthInitYear    = {{{ sysinityear.value@numToStr@convertBCD  }}};
 
#ifdef    MQTT_CFG_USE_TLS
const byte   mqtt_auth_cacert4broker_rawbyte[] = {
    {{{ path_cacert_broker.value@filedumphex@genCcharArray }}}
};

unsigned int mqtt_auth_cacert4broker_nbytes = {{{ path_cacert_broker.value@filelen }}};

const byte   mqtt_auth_clientcert_rawbyte[] = {
    {{{ path_client_cert.value@filedumphex@genCcharArray }}}
};

unsigned int mqtt_auth_clientcert_nbytes = {{{ path_client_cert.value@filelen }}};

const byte   mqtt_auth_client_privkey_rawbyte[] = {
    {{{ path_client_privkey.value@filedumphex@genCcharArray }}}
};

unsigned int mqtt_auth_client_privkey_nbytes = {{{ path_client_privkey.value@filelen }}};

#endif // end of MQTT_CFG_USE_TLS
