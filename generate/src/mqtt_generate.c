// [TODO]: 
//
// this file will be automatically generated in the future by script,
// then users can dynamically change their :
//
// * ssid & password, when connecting to wifi Access Point
// * username & password, when connecting to MQTT broker
// * certificate beffer on client side, 
//   this is used when established secure connection like TLS
//   (in embedded application, try not to use certificate chain, this would
//   largely take memory space )
// * private key buffer, client certificate buffer (if TLS secure connection is enabled)
//

// header which collects all include files of common third-party libraries
#include "mqtt_third_party_include.h"
#include "mqtt/mqtt_types.h"

mqttStr_t  mqttAuthBrokerHostname = { 10, (byte *)&("123.45.6.7") };
word16     mqttAuthBrokerPort     = 1883;
mqttStr_t  mqttAuthWifiSSID       = { 10, (byte *)&("MY_AP_SSID") };
mqttStr_t  mqttAuthWifiPasswd     = { 14, (byte *)&("YOUR_PASS_WORD") };
mqttStr_t  mqttAuthBrokerUsername = { 11, (byte *)&("areYouBroke") };
mqttStr_t  mqttAuthBrokerPasswd   = { 8,  (byte *)&("IamBroke") };


