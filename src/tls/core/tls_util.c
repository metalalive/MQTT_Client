#include "mqtt_include.h"

// note that we only support TLS v1.3 and its future version in this implementation
// currently we use static array instead because number of supported versions will not grow that fast
// the size of this array MUST NOT exceeds TLS_MAX_BYTES_SUPPORTED_VERSIONS
const tlsVersionCode  tls_supported_versions[] = {
    TLS_VERSION_ENCODE_1_3,
};

// in this implementation, we only support of allowable named groups defined in TLS v1.3
// the size of this array MUST NOT exceeds TLS_MAX_BYTES_NAMED_GRPS
const tlsNamedGrp  tls_supported_named_groups[] = {
    TLS_NAMED_GRP_SECP256R1, TLS_NAMED_GRP_X25519,
    TLS_NAMED_GRP_SECP384R1, TLS_NAMED_GRP_SECP521R1,
};

// This implementation only supports signature schemes that are mandatory to implement e.g. PSS and PKCS1
const tlsSignScheme  tls_supported_sign_scheme[] = {
    TLS_SIGNATURE_RSA_PKCS1_SHA256 ,
    TLS_SIGNATURE_RSA_PKCS1_SHA384 ,
    TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    TLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
};

// a ready list of PSKs contains :
// * a preserved pre-shared key from NewSessionTicket of previous secure connection (if exists), 
// * PSKs that are explicitly established by user applications.
// Note that PSK is useful to make future connection more effecient, see section 2-2 in RFC8446.
tlsPSK_t  *tls_PSKs_rdy_list;

// CA certificate for this TLS client
// in this MQTT/TLS implementation, we don't exepct to consume huge space to store long CA (root) certificate chain
// ,since this implementation also considers of running on microcontroller-based platform (with very limited memory),
// , so we only store a single CA certificate. User applications SHOULD avoid long CA (root) certificate chain.
tlsCert_t *tls_CA_cert;

// private key corresponding to CA certificate above
// used only when server requests client authentication via Certificate, in that case, client has to send
// certificate (in Certificate message), and signature (in CertificateVerify) to server.
void *tls_CA_priv_key;


word32  tlsEncodeWord24( byte *buf , word32  value )
{
    if(buf != NULL){
        buf[0] = (value >> 16) & 0xff;
        buf[1] = (value >> 8 ) & 0xff;
        buf[2] = value & 0xff;
    }
    // return number of bytes used to store the encoded value
    return  (word32)3;
} // end of tlsEncodeWord24


word32  tlsDecodeWord24( byte *buf , word32 *value )
{
    if((buf != NULL) && (value != NULL)) {
        *value  = buf[2];
        *value |= buf[1] << 8 ;
        *value |= buf[0] << 16 ;
    }
    return  (word32)3;
} // end of tlsDecodeWord24



// user application can call this function to add on specific PSK
tlsRespStatus tlsAddItemToList(tlsListItem_t **list, tlsListItem_t *item, byte insert_to_front)
{
    if((list==NULL) || (item==NULL)) {
        return TLS_RESP_ERRARGS;
    }
    if(insert_to_front != 0) {
        item->next = *list;
        *list = item; // always change head item
    }
    else {
        tlsListItem_t  *final = NULL;
        final = tlsGetFinalItemFromList(*list);
        if(final == NULL) { *list = item; }
        else { final->next = item; }
    }
    return TLS_RESP_OK;
} // tlsAddItemToList


tlsListItem_t*  tlsGetFinalItemFromList(tlsListItem_t *list)
{
    tlsListItem_t  *idx  = NULL;
    tlsListItem_t  *prev = NULL;
    for(idx=list; idx!=NULL; idx=idx->next) {
        prev = idx;
    }
    return prev;
} // end of tlsGetFinalItemFromList


word32  tlsGetListItemSz(tlsListItem_t *list)
{
    tlsListItem_t  *idx  = NULL;
    word32  out = 0;
    for(idx=list; idx!=NULL; idx=idx->next) {
        out++;
    }
    return out;
} // end of tlsGetListItemSz


tlsRespStatus tlsRemoveItemFromList(tlsListItem_t **list, tlsListItem_t *removing_item )
{
    if((list == NULL) && (removing_item == NULL)) { return TLS_RESP_ERRARGS; }
    tlsListItem_t  *idx  = NULL;
    tlsListItem_t  *prev = NULL;
    for(idx=*list; idx!=NULL; idx=idx->next) {
        if(removing_item == idx) {
            if(prev != NULL) {
                prev->next = removing_item->next;
            }
            else {
               *list = removing_item->next;
            }
            break;
        }
        prev = idx;
    } // end of for-loop
    return TLS_RESP_OK;
} // end of tlsRemoveItemFromList



tlsRespStatus  tlsFreeExtEntry(tlsExtEntry_t *in) {
    if(in == NULL) { return TLS_RESP_ERRARGS; }
    XMEMFREE((void *)in->content.data);
    in->content.data  = NULL;
    in->next = NULL;
    XMEMFREE((void *)in);
    return TLS_RESP_OK;
} // end of tlsFreeExtEntry


// Note: in this implementation,
// every PSK entry nust be created ONLY in tlsDecodeNewSessnTkt()
tlsRespStatus  tlsFreePSKentry(tlsPSK_t *in) {
    if(in == NULL) { return TLS_RESP_ERRARGS; }
    if(in->key.data != NULL) {
        XMEMFREE((void *)in->key.data);
        in->key.data = NULL;
        in->id.data  = NULL;
    }
    in->next     = NULL;
    XMEMFREE((void *)in);
    return TLS_RESP_OK;
} // end of tlsFreePSKentry


mqttRespStatus   tlsRespCvtToMqttResp(tlsRespStatus in)
{
    mqttRespStatus  out;
    switch(in) {
        case  TLS_RESP_OK:
        case  TLS_RESP_REQ_MOREDATA:
            out = MQTT_RESP_OK;    break;
        case  TLS_RESP_ERRARGS:
            out = MQTT_RESP_ERRARGS; break;
        case  TLS_RESP_ERRMEM:
            out = MQTT_RESP_ERRMEM; break;
        case TLS_RESP_TIMEOUT:
            out = MQTT_RESP_TIMEOUT;  break;
        case TLS_RESP_MALFORMED_PKT :
            out = MQTT_RESP_MALFORMED_DATA;  break;
        case TLS_RESP_ILLEGAL_PARAMS:
        case TLS_RESP_ERR_ENCODE:
        case TLS_RESP_ERR_DECODE:
        case TLS_RESP_ERR_NO_KEYEX_MTHD_AVAIL:
        case TLS_RESP_ERR_KEYGEN :
        case TLS_RESP_ERR_HASH   :
        case TLS_RESP_ERR_ENCRYPT:
        case TLS_RESP_ERR_ENAUTH_FAIL:
        case TLS_RESP_CERT_AUTH_FAIL :
        case TLS_RESP_HS_AUTH_FAIL:
        case TLS_RESP_PEER_CONN_FAIL:
            out = MQTT_RESP_ERR_SECURE_CONN; break;
        case TLS_RESP_ERR_SYS_SEND_PKT:
        case TLS_RESP_ERR_SYS_RECV_PKT:
            out = MQTT_RESP_ERR_TRANSMIT; break;
        case TLS_RESP_ERR_EXCEED_MAX_REC_SZ: 
            out = MQTT_RESP_ERR_EXCEED_PKT_SZ; break;
        case TLS_RESP_ERR:
        default:
            out = MQTT_RESP_ERR;     break;
    } // end of switch-case statement
    return out;
} // end of tlsRespCvtToMqttResp


tlsRespStatus  tlsRespCvtFromMqttResp(mqttRespStatus in)
{
    tlsRespStatus  out;
    switch(in) {
        case MQTT_RESP_OK:
            out = TLS_RESP_OK;    break;
        case MQTT_RESP_ERRARGS:
            out = TLS_RESP_ERRARGS; break;
        case MQTT_RESP_ERRMEM:
            out = TLS_RESP_ERRMEM; break;
        case MQTT_RESP_TIMEOUT:
            out = TLS_RESP_TIMEOUT;   break;
        case MQTT_RESP_ERR_SECURE_CONN:
            out = TLS_RESP_PEER_CONN_FAIL; break;
        case MQTT_RESP_MALFORMED_DATA :
            out = TLS_RESP_MALFORMED_PKT; break;
        case MQTT_RESP_ERR_TRANSMIT:
            out = TLS_RESP_ERR_SYS_SEND_PKT; break;
        case MQTT_RESP_ERR_EXCEED_PKT_SZ:
            out = TLS_RESP_ERR_EXCEED_MAX_REC_SZ; break;
        case MQTT_RESP_ERR:
        default:
            out = TLS_RESP_ERR;  break;
    } // end of switch-case statement
    return out;
} // end of tlsRespCvtToMqttResp


tlsRespStatus  tlsAlertTypeCvtToTlsResp(tlsAlertType in)
{
    tlsRespStatus  out = TLS_RESP_OK;
    switch(in) {
        case TLS_ALERT_TYPE_CLOSE_NOTIFY :
        case TLS_ALERT_TYPE_USER_CANCELED:
            out = TLS_RESP_PEER_CONN_FAIL; break;
        case TLS_ALERT_TYPE_UNEXPECTED_MESSAGE:
            out = TLS_RESP_MALFORMED_PKT; break;
        case TLS_ALERT_TYPE_BAD_RECORD_MAC    :
            out = TLS_RESP_ERR_ENAUTH_FAIL; break;
        case TLS_ALERT_TYPE_RECORD_OVERFLOW   :
            out = TLS_RESP_ERR_EXCEED_MAX_REC_SZ; break;
        case TLS_ALERT_TYPE_HANDSHAKE_FAILURE :
        case TLS_ALERT_TYPE_INSUFFICIENT_SECURITY  :
            out = TLS_RESP_ERR_NO_KEYEX_MTHD_AVAIL; break;
        case TLS_ALERT_TYPE_BAD_CERTIFICATE   :
        case TLS_ALERT_TYPE_UNSUPPORTED_CERTIFICATE:
        case TLS_ALERT_TYPE_CERTIFICATE_REVOKED    :
        case TLS_ALERT_TYPE_CERTIFICATE_EXPIRED    :
        case TLS_ALERT_TYPE_CERTIFICATE_UNKNOWN    :
        case TLS_ALERT_TYPE_UNKNOWN_CA             :
        case TLS_ALERT_TYPE_BAD_CERTIFICATE_STATUS_RESPONSE:
            out = TLS_RESP_CERT_AUTH_FAIL; break;
        case TLS_ALERT_TYPE_ILLEGAL_PARAMETER      :
            out = TLS_RESP_ILLEGAL_PARAMS; break;
        case TLS_ALERT_TYPE_DECODE_ERROR     :
        case TLS_ALERT_TYPE_MISSING_EXTENSION:
            out = TLS_RESP_ERR_DECODE; break;
        case TLS_ALERT_TYPE_DECRYPT_ERROR          :
        case TLS_ALERT_TYPE_UNKNOWN_PSK_IDENTITY   :
            out = TLS_RESP_ERR_ENCRYPT; break;
        case TLS_ALERT_TYPE_PROTOCOL_VERSION       :
        case TLS_ALERT_TYPE_INAPPROPRIATE_FALLBACK :
        case TLS_ALERT_TYPE_UNSUPPORTED_EXTENSION  :
            out = TLS_RESP_ERR_NOT_SUPPORT; break;
        case TLS_ALERT_TYPE_UNRECOGNIZED_NAME :
            out = TLS_RESP_ERR_SERVER_NAME; break;
        case TLS_ALERT_TYPE_NO_APPLICATION_PROTOCOL :
        case TLS_ALERT_TYPE_ACCESS_DENIED :
        case TLS_ALERT_TYPE_INTERNAL_ERROR:
        default:
            out = TLS_RESP_ERR;  break;
    } // end of switch-case statement
    return out;
} // end of tlsAlertTypeCvtToTlsResp


tlsHashAlgoID    tlsGetHashAlgoIDBySize(word16 in)
{
    tlsHashAlgoID  out = TLS_HASH_ALGO_UNKNOWN;
    // this implementation currently only supports SHA256, SHA384, the input must be equal
    // to the hash output of either  SHA256 or SHA384
    word16  hash_sz = 0;
    hash_sz = mqttHashGetOutlenBytes((mqttHashLenType)TLS_HASH_ALGO_SHA256);
    if(hash_sz == in) { out = TLS_HASH_ALGO_SHA256; }
    hash_sz = mqttHashGetOutlenBytes((mqttHashLenType)TLS_HASH_ALGO_SHA384);
    if(hash_sz == in) { out = TLS_HASH_ALGO_SHA384; }
    return  out;
} // end of tlsGetHashAlgoIDBySize


tlsRespStatus  tlsValidateHashAlgoID(tlsHashAlgoID in)
{
    switch(in) {
        case TLS_HASH_ALGO_SHA256:
        case TLS_HASH_ALGO_SHA384:
            return TLS_RESP_OK;
        default:
            return TLS_RESP_ERR;
    } // end of switch case
} // end of tlsValidateHashAlgoID


tlsRespStatus  tlsModifyReadMsgTimeout(tlsSession_t *session, int new_val)
{
    if(session != NULL) {
        session->cmd_timeout_ms = new_val;
    }
    return TLS_RESP_OK;
} // end of tlsModifyReadMsgTimeout


byte  tlsGetSupportedKeyExGrpSize( void )
{
    byte  out = XGETARRAYSIZE(tls_supported_named_groups);
    return out;
} // end of tlsGetSupportedKeyExGrpSize


byte  tlsGetSupportedVersionListSize( void )
{
    return XGETARRAYSIZE(tls_supported_versions);
} // end of tlsGetSupportedVersionListSize


byte  tlsGetSupportedSignSchemeListSize( void )
{
    return XGETARRAYSIZE(tls_supported_sign_scheme);
} // end of tlsGetSupportedSignSchemeListSize


