#ifndef MQTT_THIRD_PARTY_INCLUDE_H
#define MQTT_THIRD_PARTY_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

// ------ user configuations for this MQTT implementation ------
{{{ tls.c_define@genCdefine }}}

{{{ cryptolib.metadata.path.include.c_headers@getCinclude }}}

#if defined(MQTT_UNIT_TEST_MODE)
{{{ unitestlib.metadata.path.include.c_headers@getCinclude }}}
#endif // end of MQTT_UNIT_TEST_MODE

#ifdef __cplusplus
}
#endif
#endif // end of MQTT_THIRD_PARTY_INCLUDE_H
