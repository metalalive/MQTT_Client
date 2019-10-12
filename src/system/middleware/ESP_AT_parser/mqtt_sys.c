#include "mqtt_include.h"

// [Note]
// The low-level implementation should depend on what kind of underlying hardware / operating system applied to your application, this file only shows API integration with our ESP AT parser, used with ESP8266 wifi device. 
// For other OS users, you will need to implement your own socket functions.

#define  MAX_NUM_AP_FOUND            15

// In some use cases, users might call this read function multiple times only for fetching few bytes of packet data. so we need to reserve the packet data that hasn't been completed reading (from user applications)
static espPbuf_t   *unfinish_rd_pktbuf      = NULL;
static espPbuf_t   *unfinish_rd_pktbuf_head = NULL;

// data structure to record IP, MAC address on current connection
static espIp_t      curr_ip;
static espMac_t     curr_mac;

// temporarily store the Access-Points (AP) found by this ESP device
static espAP_t      foundAPs[ MAX_NUM_AP_FOUND ];

// network connection object that is internally used in ESP AT parser
static espNetConnPtr   espNetconn ;

// used for Linear congruential generator to generate random bits,
// TODO: will change implemention for cryptographic purpose.
static word32  mqtt_sys_rng__coeff[2] ;
static word32  mqtt_sys_rng__x[2] ;
static word32  mqtt_sys_rng__modular ;
// it's time to refresh division variables above every time when this countdown timer reaches zero
static byte    mqtt_sys_rng__cntdown_timer;
// this value is fed to the countdown timer above as the next reset value , when the countdown timer reaches zero
static byte    mqtt_sys_rng__timer_nxt_rst;


static espRes_t  eESPdefaultEvtCallBack( espEvt_t*  evt )
{
    espRes_t    response = espOK;
    espConn_t  *conn   = NULL; 

    switch( evt->type )
    {
        case ESP_EVT_INIT_FINISH :
            // library initialized OK!
            break;

        case ESP_EVT_RESET_DETECTED:
            // Device reset detected 
            break;

        case ESP_EVT_RESET:
            if(evt->body.reset.res == espOK) {
                // ESP reset sequence finished with success
            }
            else {
                // ESP reset sequence error
            }
            break;

        case ESP_EVT_WIFI_CONNECTED:
            // Wifi connected to access point
            break;

        case ESP_EVT_WIFI_DISCONNECTED:
            // wifi disconnected from access point
            break;

        case ESP_EVT_CONN_RECV:
            conn   = evt->body.connDataRecv.conn ;
            // put pointer of the new IPD data to message-box of the server,
            if( espNetconn != NULL ){
                response = eESPnetconnRecvPkt( espNetconn, conn->pbuf );
            }
            else {
                response = espERRMEM;
            }
            break;

        case ESP_EVT_CONN_SEND:
            break;

        default:
            break;
    } // end of switch statement
    return  response;
} // end of  eESPdefaultEvtCallBack



static mqttRespStatus mqttSysRespCvtFromESPresp(espRes_t in)
{
    mqttRespStatus out = MQTT_RESP_OK;
    switch(in) {
        case espERRNOAP:
        case espERRNODEVICE:
            out = MQTT_RESP_NO_NET_DEV;    break;
        case espOK:
        case espOKIGNOREMORE:
            out = MQTT_RESP_OK;            break;
        case espERRMEM:
            out = MQTT_RESP_ERRMEM;        break;
        case espERRARGS:
            out = MQTT_RESP_ERRARGS;       break;
        case espBUSY:
            out = MQTT_RESP_BUSY;          break;
        case espTIMEOUT:
            out = MQTT_RESP_TIMEOUT;       break;
        case espERRCONNFAIL :
        case espERRWIFINOTCONNECTED:
            out = MQTT_RESP_ERR_CONN;      break;
        default:
            out = MQTT_RESP_ERR;           break;
    }
    return out;
} // end of mqttSysRespCvtFromESPresp



static espRes_t  mqttSysRespCvtToESPresp(mqttRespStatus in)
{
    espRes_t out ;
    switch(in) {
        case MQTT_RESP_NO_NET_DEV :
            out = espERRNODEVICE;    break;
        case MQTT_RESP_OK :
            out = espOK;             break;
        case MQTT_RESP_ERRMEM:
            out = espERRMEM ;        break;
        case MQTT_RESP_ERRARGS:
            out = espERRARGS;        break;
        case MQTT_RESP_BUSY:
            out = espBUSY;           break;
        case MQTT_RESP_TIMEOUT:
            out = espTIMEOUT ;       break;
        case MQTT_RESP_ERR_CONN:
            out = espERRCONNFAIL;    break;
        default:
            out = espERR;            break;
    }
    return out;
} // end of  mqttSysRespCvtToESPresp



static espRes_t  mqttSysConnectToAP( espIp_t *out_ip, espMac_t *out_mac )
{ // we better determine maximum number of times to rescan APs or reconnect to the preferred AP
#define  MQTT_SYS_MAXTIMES_RECONNECT_AP    2
#define  MQTT_SYS_MAXTIMES_RESCAN_APS      3
    mqttStr_t  *wifiSSID   = NULL;
    mqttStr_t  *wifiPasswd = NULL;
    espIp_t     dummy_ip  ;
    espMac_t    dummy_mac ;
    espRes_t    response = espOK ;
    uint16_t    num_ap_found  = 0;
    uint8_t     ap_connected  = 0;
    uint8_t     tried_conn    = 0;
    uint8_t     num_times_reconnect_ap  = 0;
    uint8_t     num_times_rescan_aps    = 0;
    uint8_t     idx ;

    mqttAuthGetWifiLoginInfo( &wifiSSID, &wifiPasswd);

    do {
        num_ap_found = 0;
        ESP_MEMSET( &foundAPs[0], 0x00, sizeof(espAP_t) * MAX_NUM_AP_FOUND );
        // scan all available APs around this ESP device , it's not practical to feed
        // MAC address & channel number to narrow down the search result to minimum.
        // (for some sophisticated Wi-fi Access Points (AP), channel number could be
        // changed each  time when the AP is launched )
        response = eESPstaListAP( NULL, 0, &foundAPs[0], ESP_ARRAYSIZE(foundAPs), &num_ap_found, 
                                  NULL, NULL, ESP_AT_CMD_BLOCKING );
        if((response == espOK) || (response == espOKIGNOREMORE)) {
            tried_conn  = 0;
            for (idx = 0; idx < num_ap_found; idx++) {
                if( strncmp( foundAPs[idx].ssid, (const char *)wifiSSID->data, wifiSSID->len ) == 0 )
                {
                    tried_conn = 1;
                    response =  eESPstaJoin((const char *)wifiSSID->data,   wifiSSID->len, 
                                            (const char *)wifiPasswd->data, wifiPasswd->len, 
                                            NULL,  ESP_SETVALUE_NOT_SAVE , NULL, NULL, 
                                            ESP_AT_CMD_BLOCKING );
                    if (response == espOK) {
                        eESPgetLocalIPmac( out_ip, out_mac, &dummy_ip, &dummy_mac,
                                           NULL, NULL, ESP_AT_CMD_BLOCKING );
                        ap_connected = 0x1;
                    }
                    else { // Connection error
                        if(num_times_reconnect_ap < MQTT_SYS_MAXTIMES_RECONNECT_AP) {
                            num_times_reconnect_ap++;
                            vESPsysDelay(5000);
                        }
                        else {
                            ap_connected = 0x2; // stop tying to reconnect & return error instead
                            response = espERRCONNFAIL; 
                        }
                    }
                    break;
                } // end of if-statment (SSID comparison)
            } // end of for-loop
        }
        else if (response == espERRNODEVICE) {
            break; // Device is not present!
        }
        if(tried_conn == 0) { // if we cannot find preferred AP from the list of APs we scanned.
            if(num_times_rescan_aps < MQTT_SYS_MAXTIMES_RESCAN_APS) {
                num_times_rescan_aps++;
                vESPsysDelay(5000); // for other errors, scan the APs again 
            }
            else{
                response = espERRNOAP; 
                break; // the preferred AP cannot be found after scanning specified number of times
            }
        }
    } while( ap_connected == 0 );  // end of outer (infinite) loop
    return response;
#undef  MQTT_SYS_MAXTIMES_RECONNECT_AP
#undef  MQTT_SYS_MAXTIMES_RESCAN_APS  
} // end of mqttSysConnectToAP




static espRes_t  mqttSysCreateTCPconn(mqttCtx_t *mctx)
{
    espRes_t  response = espOK;
    espConn_t*    conn =  NULL;

    conn =  pxESPgetNxtAvailConn();
    // reach maximum number of TCP connection, not available now
    if(conn == NULL) { return espERRMEM; }
    // get broker hostname & port
    mqttAuthGetBrokerHost( &mctx->broker_host, &mctx->broker_port );
    // establish new TCP connection between ESP device and remote peer (MQTT broker) 
    response = eESPconnClientStart( conn, ESP_CONN_TYPE_TCP, 
                      (const char* const)mctx->broker_host->data,  mctx->broker_host->len,
                      mctx->broker_port,  eESPdefaultEvtCallBack,  NULL, NULL, ESP_AT_CMD_BLOCKING );
    if(response == espOK) {
        espNetconn = pxESPnetconnCreate( ESP_NETCONN_TYPE_TCP );
        if(espNetconn == NULL) { return espERRMEM; }
        mctx->ext_sysobjs[0] = (void *) espNetconn;
        mctx->ext_sysobjs[1] = (void *) conn;
    }
    return response;
} // end of mqttSysCreateTCPconn 



espRes_t   eESPlowLvlRecvStartFn( void )
{
    mqttRespStatus response  = mqttPlatformPktRecvEnable();
    return  mqttSysRespCvtToESPresp(response);
} // end of  eESPlowLvlRecvStartFn 



void    vESPlowLvlRecvStopFn( void )
{
    mqttPlatformPktRecvDisable();
} // end of vESPlowLvlRecvStopFn



// the low-level functions that will be called when ESP AT parser (running on
// host MCU board) sends raw bytes out .
espRes_t   eESPlowLvlSendFn( void* data, size_t len, uint32_t timeout )
{
    mqttRespStatus response  = mqttPlatformPktSend( data, len, timeout );
    return  mqttSysRespCvtToESPresp(response);
} // end of eESPlowLvlSendFn



// the low-level functions that will be called when MCU board reset (the hardware state) 
// of the ESP wifi module through hardware reset pin.
espRes_t   eESPlowLvlRstFn( uint8_t state )
{
    mqttRespStatus response  = mqttPlatformNetworkModRst( state );
    return  mqttSysRespCvtToESPresp(response);
} // end of eESPlowLvlRstFn



espRes_t  eESPlowLvlDevInit(void *params)
{
    mqttRespStatus response  = mqttPlatformInit();
    return  mqttSysRespCvtToESPresp(response);
}


void  mqttSysDelay(uint32_t ms) {
    vESPsysDelay( ms ); 
} // end of mqttSysDelay




mqttRespStatus  mqttSysPktRecvHandler( uint8_t* data, uint16_t data_len )
{
    espRes_t  response = eESPappendRecvRespISR( data, data_len );
    return  mqttSysRespCvtFromESPresp(response);
} // end of mqttSysPktRecvHandler



mqttRespStatus  mqttSysThreadCreate( const char* name, mqttSysThreFn thread_fn, 
                                     void* const arg,  size_t stack_size,
                                     uint32_t prio, uint8_t isPrivileged,
                                     mqttSysThre_t *out_thread_ptr )
{
    espRes_t  response ;
    response = eESPsysThreadCreate( (espSysThread_t *)out_thread_ptr, name, thread_fn, arg,
                                    stack_size, (espSysThreadPrio_t)prio, isPrivileged );
    ESP_ASSERT( response == espOK ); 
    // in this system port, if thread scheduler hasn't been running,
    // then we launch thread scheduler at here immediately after the first thread is created
    if(eESPsysGetTskSchedulerState() == ESP_SYS_TASK_SCHEDULER_NOT_STARTED) {
        eESPsysTskSchedulerStart();
    }
    // in some system port e.g. FreeRTOS, 
    // CPU might never arrive in here after thread scheduler  is running
    return  mqttSysRespCvtFromESPresp(response);
} // end of mqttSysThreadCreate



mqttRespStatus  mqttSysThreadDelete( mqttSysThre_t *thre_in )
{
    espRes_t  response ;
    response = eESPsysThreadDelete( (espSysThread_t *)thre_in );
    return  mqttSysRespCvtFromESPresp(response);
} // end of mqttSysThreadDelete



mqttRespStatus  mqttSysThreadWaitUntilExit( mqttSysThre_t *thre_in, void **return_p )
{   // dummy function
    return MQTT_RESP_OK;
} // end of mqttSysThreadWaitUntilExit



mqttRespStatus  mqttSysNetconnStart( mqttCtx_t *mctx )
{
    espRes_t  response = espOK;

    if(mctx == NULL) { return MQTT_RESP_ERRARGS; }
#if (ESP_CFG_RST_ON_INIT == 0)
    // reset & configure the ESP device.
    response =  eESPresetWithDelay( 1, NULL, NULL );
#endif // end of ESP_CFG_RST_ON_INIT
    if(response == espOK) {
        // scan all available APs , connect to the AP specified by user if found
        response = mqttSysConnectToAP( &curr_ip, &curr_mac );
    }
    if(response == espOK) {
        // set up a TCP connection to remote peer (MQTT broker, in this case)
        response = mqttSysCreateTCPconn( mctx );
    }
    return  mqttSysRespCvtFromESPresp( response );
} // end of mqttSysNetconnStart



mqttRespStatus  mqttSysNetconnStop( mqttCtx_t *mctx )
{
    espRes_t   response = espOK;
    if(mctx == NULL) { return MQTT_RESP_ERRARGS; }
    // close TCP connection
    eESPconnClientClose( (espConn_t *)mctx->ext_sysobjs[1],
                         NULL, NULL, ESP_AT_CMD_BLOCKING );
    // quit from AP, reset ESP device again
    eESPcloseDevice( );
    // de-initialize network connection object used in ESP parser.
    eESPnetconnDelete( espNetconn );
    // in this system port, ext_sysobjs[0] should always point to espNetconn and never modified.
    if(espNetconn != NULL && (void *)mctx->ext_sysobjs[0] != (void *)espNetconn) {
        response = espERRMEM;
    }
    // release espConn_t back to connection pool in ESP library.
    if((void *)mctx->ext_sysobjs[1] != NULL) {
        espConn_t *conn =  (espConn_t *) mctx->ext_sysobjs[1];
        if(conn->pbuf != NULL) {
            //TODO: figure out why there is missing memory checks here that cause hardware fault
            vESPpktBufChainDelete( conn->pbuf ); 
        } // release packet buffer list that hasn't been freed.
        XMEMSET(conn, 0x00, sizeof(espConn_t)); 
    }
    espNetconn = NULL;
    mctx->ext_sysobjs[0] = NULL;
    mctx->ext_sysobjs[1] = NULL;
    return  mqttSysRespCvtFromESPresp( response );
} // end of mqttSysNetconnStop



mqttRespStatus  mqttSysInit( void )
{
    espRes_t  response = eESPinit( eESPdefaultEvtCallBack );
    XASSERT( response == espOK );
    mqtt_sys_rng__coeff[0] = 13 ;
    mqtt_sys_rng__coeff[1] = 17 ;
    mqtt_sys_rng__x[0]     = 31 ;
    mqtt_sys_rng__cntdown_timer = 0;
    mqtt_sys_rng__timer_nxt_rst = 0;
    return  MQTT_RESP_OK ;
} // end of mqttSysInit




mqttRespStatus  mqttSysDeInit( void )
{
    espRes_t  response = eESPdeinit();
    XASSERT( response == espOK );
    return  mqttPlatformDeInit();
} // end of mqttSysDeInit



word32  mqttSysRNG( word32 maxnum )
{
    word32  update_flg = 0;

    update_flg = mqtt_sys_rng__cntdown_timer % 0x60;
    switch( update_flg ) {
        case 0x0:
            mqtt_sys_rng__modular  = (mqttPlatformRNG(0xff0000) + 0xffff)  | 0x1 ;
            mqtt_sys_rng__x[0]     = 0xf + mqttPlatformRNG(mqtt_sys_rng__modular - 0xf) ;
            break;
        case 0x20:
            mqtt_sys_rng__coeff[0] = 0xf + mqttPlatformRNG(mqtt_sys_rng__modular - 0xf) ;
            break;
        case 0x40:
            mqtt_sys_rng__coeff[1] = (0xf + mqttPlatformRNG(mqtt_sys_rng__modular - 0xf)) | 0x1 ;
            break;
        default: break;
    }  // end of switch-case
    if(mqtt_sys_rng__cntdown_timer > 0) {
        mqtt_sys_rng__cntdown_timer--;
    }
    else{
        mqtt_sys_rng__timer_nxt_rst  = 0x60 + mqttPlatformRNG(0x60);
        mqtt_sys_rng__cntdown_timer = mqtt_sys_rng__timer_nxt_rst ;
    }
    mqtt_sys_rng__x[1] = (mqtt_sys_rng__coeff[1] * mqtt_sys_rng__x[0] + mqtt_sys_rng__coeff[0]) % mqtt_sys_rng__modular ;
    mqtt_sys_rng__x[0] = mqtt_sys_rng__x[1] ;
    return  (mqtt_sys_rng__x[1] % (maxnum + 1));
} // end of mqttUtilPRNG




int  mqttSysPktRead( mqttCtx_t *mctx, byte *buf, word32 buf_len )
{
    espNetConnPtr   espconn = NULL; 
    espRes_t        response ;
    byte           *curr_src_p ;
    byte           *curr_dst_p ;
    size_t          rd_ptr;
    size_t          copied_len_total = 0; // total length of copied data
    size_t          copied_len_iter  = 0; // length of copied data in each iteration
    size_t          remain_payld_len = 0;
 
    if((mctx == NULL) || (buf == NULL) || (buf_len == 0)) {
        return MQTT_RESP_ERRARGS;
    }
    espconn = (espNetConnPtr) mctx->ext_sysobjs[0];
    if(espconn == NULL) { return MQTT_RESP_ERRMEM; }

    while(buf_len > 0) 
    {
        if(unfinish_rd_pktbuf == NULL) {
            // implement non-blocking packet read function.
            response = eESPnetconnGrabNextPkt( espconn, &unfinish_rd_pktbuf,  mctx->cmd_timeout_ms );
            if( response != espOK ){
                unfinish_rd_pktbuf = NULL;
                return ( copied_len_total > 0 ? copied_len_total : MQTT_RESP_TIMEOUT);
            }
            unfinish_rd_pktbuf_head = unfinish_rd_pktbuf;
        }
        rd_ptr       = unfinish_rd_pktbuf->rd_ptr ;
        curr_src_p   = & unfinish_rd_pktbuf->payload[rd_ptr] ;
        curr_dst_p   = & buf[ copied_len_total ];
        remain_payld_len  = unfinish_rd_pktbuf->payload_len - rd_ptr ;
        copied_len_iter   = ESP_MIN( buf_len, remain_payld_len );
        copied_len_total += copied_len_iter;
        ESP_MEMCPY( curr_dst_p, curr_src_p, copied_len_iter );
        buf_len     -= copied_len_iter;
        rd_ptr      += copied_len_iter;
        unfinish_rd_pktbuf->rd_ptr =  rd_ptr ;
        if(rd_ptr >= unfinish_rd_pktbuf->payload_len) {
            unfinish_rd_pktbuf = unfinish_rd_pktbuf->next;
            if(unfinish_rd_pktbuf == NULL) {
                // free the allocated space to the last packet we read
                vESPpktBufChainDelete( unfinish_rd_pktbuf_head );
                unfinish_rd_pktbuf_head = NULL;
            }
        }
    } // end of while-loop

    return  copied_len_total;
} // end of mqttSysPktRead





int  mqttSysPktWrite( mqttCtx_t *mctx, byte *buf, word32 buf_len )
{
    if((mctx == NULL) || (buf == NULL) || (buf_len == 0)) {
        return MQTT_RESP_ERRARGS ;
    }
    espConn_t  *espconn = (espConn_t *) mctx->ext_sysobjs[1] ;
    espRes_t    response ; 
    if(espconn == NULL) {
        return MQTT_RESP_ERRMEM;
    }
    response = eESPconnClientSend( espconn,  buf,  buf_len, NULL, NULL, ESP_AT_CMD_BLOCKING );
    return  (response == espOK ? buf_len : mqttSysRespCvtFromESPresp(response));
} // end of mqttSysPktWrite





