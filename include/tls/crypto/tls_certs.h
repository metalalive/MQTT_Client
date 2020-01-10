#ifndef TLS_CERTS_H
#define TLS_CERTS_H

#ifdef __cplusplus
extern "C" {
#endif


// Note final_item_rdy indicates the entire cert chain is ready to decode, or fianl cert item is NOT ready,
// it is used when multiple fragments of the cert chain are transmitting from the peer
tlsRespStatus  tlsVerifyCertChain(tlsCert_t  *issuer_cert, tlsCert_t  *subject_cert);


// free some/all members of a cert chain at differnt phase of application execution
void  tlsFreeCertChain(tlsCert_t *in, tlsFreeCertEntryFlag ctrl_flg);

// this function is called when :
// (1) decoding certificate (chain) received from peer
// (2) decoding CA certificate at TLS initialization
// 
// Note final_item_rdy indicates the entire cert chain is ready to decode, or fianl cert item is NOT ready,
// it is used when multiple fragments of the cert chain are transmitting from the peer
tlsRespStatus  tlsDecodeCerts(tlsCert_t *cert, byte final_item_rdy);


// in TLS v1.3, default certificate type is DER-encoded X.509 unless negotiated through
// the entension entry "server_certificate_type" or "client_certificate_type".
// This implementation ONLY supports DER-encoded X.509 certificate , raw public key is
// NOT supported .
tlsRespStatus  tlsCopyCertRawData(tlsSession_t *session);


// this function can be reused for checking signature in CertificateVerify handshake message,
// verify signature of a subject cert, decrypt signature using given public key, then compare with
// hashed cert holder information.
tlsRespStatus tlsVerifyCertSignature(void *pubkey, tlsOpaque16b_t *sig, tlsAlgoOID sign_algo, tlsOpaque16b_t *ref, tlsRSApss_t *rsapssextra );


tlsRespStatus tlsSignCertSignature(void *privkey,  mqttDRBG_t *drbg, tlsOpaque16b_t *in, tlsOpaque16b_t *out, tlsAlgoOID sign_algo, tlsRSApss_t *rsapssextra);

// (RFC 8446, section 4.4.3 , Certificate Verify)
// Generate reference data -- hash output value of a digital signature, concatenated by :
// * A string that consists of octet 0x20 , repeated 64 times
// * Context string, for CertificateVerify from server, it should be "TLS 1.3, server CertificateVerify"
// * A single byte 0x0 which serves as the seperator.
// * the content to be signed, the tranacript hash from ClientHello to Certificate
// Then hash the concatenated string above , copy to output
tlsRespStatus  tlsCertVerifyGenDigitalSig(tlsSecurityElements_t *sec, const tlsRSApss_t *rsapss_attri, tlsOpaque16b_t *out, const byte is_server);

#ifdef __cplusplus
}
#endif
#endif // end of TLS_CERTS_H
