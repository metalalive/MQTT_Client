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
const byte   mqtt_auth_ca_cert_rawbyte[] = {
{{{ pathcert.value@filedumphex@genCcharArray }}}
}; // end of mqtt_auth_ca_cert_rawbyte

unsigned int mqtt_auth_ca_cert_rawbyte_len = {{{ pathcert.value@filelen }}};

const byte   mqtt_auth_ca_priv_key_rawbyte[] = {
 {{{ pathprivkey.value@filedumphex@genCcharArray }}}
}; // end of mqtt_auth_ca_priv_key_rawbyte

unsigned int mqtt_auth_ca_priv_key_rawbyte_len = {{{ pathprivkey.value@filelen }}};

#endif // end of MQTT_CFG_USE_TLS
