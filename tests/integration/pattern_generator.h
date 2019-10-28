#ifndef __INTEGRATION_TEST_PATTERN_GENERATOR_H
#define __INTEGRATION_TEST_PATTERN_GENERATOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mqtt_include.h"

typedef struct {
    word32                   send_pkt_maxbytes;
    mqttDRBG_t              *drbg;
    // buffers for each type of packet test
    mqttConn_t               conn;
    mqttPktHeadConnack_t    *connack;
    mqttMsg_t                pubmsg_send;
    mqttMsg_t               *pubmsg_recv;
    mqttPktPubResp_t        *pubresp;
    mqttPktSubs_t            subs;
    mqttPktSuback_t         *suback;
    mqttPktUnsubs_t          unsubs;
    mqttPktUnsuback_t       *unsuback;
    mqttPktDisconn_t         disconn;
} mqttTestPatt;



mqttRespStatus  mqttTestGenPatterns( mqttTestPatt *patt_in ); 

mqttRespStatus  mqttTestCopyPatterns( mqttTestPatt *patt_in, mqttCtx_t *mctx, mqttCtrlPktType cmdtype );

mqttRespStatus  mqttTestCleanupPatterns( mqttTestPatt *patt_in, mqttCtrlPktType cmdtype );



#ifdef __cplusplus
}
#endif
#endif // end of __INTEGRATION_TEST_PATTERN_GENERATOR_H 

