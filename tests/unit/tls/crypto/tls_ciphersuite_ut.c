#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

#define  MAX_RAWBYTE_BUF_SZ  0x80

static tlsSession_t *tls_session;

extern const tlsCipherSpec_t  tls_supported_cipher_suites[];

extern unsigned char  *mock_aes_gcm_process_pt_start;
extern unsigned char  *mock_aes_gcm_process_ct_start;
extern unsigned int    mock_aes_gcm_process_ct_len;
extern unsigned char  *mock_aes_gcm_mac_data;



// ------------------------------------------------------------
TEST_GROUP(tlsCipherSuite);

TEST_SETUP(tlsCipherSuite)
{}

TEST_TEAR_DOWN(tlsCipherSuite)
{}

TEST_GROUP_RUNNER(tlsCipherSuite)
{
    RUN_TEST_CASE(tlsCipherSuite, aes_encryption);
    RUN_TEST_CASE(tlsCipherSuite, aes_decryption);
    RUN_TEST_CASE(tlsCipherSuite, tlsGetCipherSuiteByID);
    RUN_TEST_CASE(tlsCipherSuite, TLScipherSuiteGetHashID);
}


TEST(tlsCipherSuite, aes_encryption)
{
    tlsSecurityElements_t  *sec = NULL;
    byte   *ct_start = NULL;
    word32  ct_len = 0;
    tlsRespStatus status = TLS_RESP_OK;
    const byte isDecrypt = 0;

    sec = &tls_session->sec;
    sec->chosen_ciphersuite = &tls_supported_cipher_suites[1];
    status = sec->chosen_ciphersuite->init_fn(sec, isDecrypt);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->encrypt_ctx);
    // the first fragment
    sec->flgs.ct_first_frag = 1;
    sec->flgs.ct_final_frag = 0;
    tls_session->curr_outmsg_start = 0;
    // .... the message will be split into 3 fragments to send.
    tls_session->curr_outmsg_len   = (tls_session->outbuf.len << 1) + sec->chosen_ciphersuite->tagSize;
    tls_session->curr_outmsg_len  -= (tls_session->outbuf.len - TLS_RECORD_LAYER_HEADER_NBYTES) % AES_PROCESSING_BLOCK_BYTES;
    tls_session->outlen_encoded    = tls_session->outbuf.len;
    tls_session->outlen_encrypted  = tls_session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES;
    ct_start = &tls_session->outbuf.data[tls_session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES];
    ct_len   =  tls_session->outlen_encoded - tls_session->curr_outmsg_start - TLS_RECORD_LAYER_HEADER_NBYTES;
    status = sec->chosen_ciphersuite->encrypt_fn(sec, ct_start, ct_start, &ct_len);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_LESS_THAN_UINT32(tls_session->outbuf.len, ct_len);
    TEST_ASSERT_EQUAL_UINT32(mock_aes_gcm_process_ct_len, ct_len);
    TEST_ASSERT_EQUAL_UINT(ct_start, mock_aes_gcm_process_pt_start);
    TEST_ASSERT_EQUAL_UINT(ct_start, mock_aes_gcm_process_ct_start);
    // the second fragment
    sec->flgs.ct_first_frag = 0;
    sec->flgs.ct_final_frag = 0;
    tls_session->curr_outmsg_start = 0;
    tls_session->outlen_encoded    = tls_session->outbuf.len;
    tls_session->outlen_encrypted  = tls_session->curr_outmsg_start;
    ct_start = &tls_session->outbuf.data[tls_session->curr_outmsg_start];
    ct_len   =  tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    status = sec->chosen_ciphersuite->encrypt_fn(sec, ct_start, ct_start, &ct_len);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT32(tls_session->outbuf.len, ct_len);
    TEST_ASSERT_EQUAL_UINT32(mock_aes_gcm_process_ct_len, ct_len);
    TEST_ASSERT_EQUAL_UINT(ct_start, mock_aes_gcm_process_pt_start);
    TEST_ASSERT_EQUAL_UINT(ct_start, mock_aes_gcm_process_ct_start);
    // the third fragment
    sec->flgs.ct_first_frag = 0;
    sec->flgs.ct_final_frag = 1;
    tls_session->curr_outmsg_start = 0;
    tls_session->outlen_encoded    = sec->chosen_ciphersuite->tagSize;
    tls_session->outlen_encrypted  = tls_session->curr_outmsg_start;
    ct_start = &tls_session->outbuf.data[tls_session->curr_outmsg_start];
    ct_len   =  tls_session->outlen_encoded - tls_session->curr_outmsg_start;
    mock_aes_gcm_process_pt_start = NULL;
    mock_aes_gcm_process_ct_start = NULL;
    mock_aes_gcm_process_ct_len   = 0;
    mock_aes_gcm_mac_data = NULL;
    status = sec->chosen_ciphersuite->encrypt_fn(sec, ct_start, ct_start, &ct_len);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT32(sec->chosen_ciphersuite->tagSize, ct_len);
    TEST_ASSERT_EQUAL_UINT32(0, mock_aes_gcm_process_ct_len);
    TEST_ASSERT_EQUAL_UINT(NULL, mock_aes_gcm_process_pt_start);
    TEST_ASSERT_EQUAL_UINT(NULL, mock_aes_gcm_process_ct_start);

    sec->chosen_ciphersuite->done_fn(sec);
    sec->chosen_ciphersuite = NULL;
    TEST_ASSERT_EQUAL_UINT(NULL, sec->encrypt_ctx);
} // end of TEST(tlsCipherSuite, aes_encryption)


TEST(tlsCipherSuite, aes_decryption)
{
    const byte *expect_gcm_mac = (const byte *)&("Message Authentication Code");
    tlsSecurityElements_t  *sec = NULL;
    byte   *ct_start = NULL;
    word32  ct_len = 0;
    tlsRespStatus status = TLS_RESP_OK;
    const byte isDecrypt = 1;

    sec = &tls_session->sec;
    sec->chosen_ciphersuite = &tls_supported_cipher_suites[1];
    status = sec->chosen_ciphersuite->init_fn(sec, isDecrypt);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_NOT_EQUAL(NULL, sec->decrypt_ctx);
    // the first fragment
    sec->flgs.ct_first_frag = 1;
    sec->flgs.ct_final_frag = 0;
    // .... the message will be split into 3 fragments to send.
    tls_session->inlen_total   = (tls_session->inbuf.len << 1) + sec->chosen_ciphersuite->tagSize;
    tls_session->inlen_total  -= (tls_session->inbuf.len - TLS_RECORD_LAYER_HEADER_NBYTES) % AES_PROCESSING_BLOCK_BYTES;
    tls_session->inlen_unprocessed = tls_session->inbuf.len;
    tls_session->inlen_decrypted   = TLS_RECORD_LAYER_HEADER_NBYTES;
    ct_start = &tls_session->inbuf.data[TLS_RECORD_LAYER_HEADER_NBYTES];
    ct_len   =  tls_session->inlen_unprocessed - TLS_RECORD_LAYER_HEADER_NBYTES;
    status = sec->chosen_ciphersuite->decrypt_fn(sec, ct_start, ct_start, &ct_len);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_LESS_THAN_UINT32(tls_session->inbuf.len, ct_len);
    TEST_ASSERT_EQUAL_UINT32(mock_aes_gcm_process_ct_len, ct_len);
    TEST_ASSERT_EQUAL_UINT(ct_start, mock_aes_gcm_process_pt_start);
    TEST_ASSERT_EQUAL_UINT(ct_start, mock_aes_gcm_process_ct_start);
    // the second fragment
    sec->flgs.ct_first_frag = 0;
    sec->flgs.ct_final_frag = 0;
    tls_session->inlen_unprocessed = tls_session->inbuf.len;
    tls_session->inlen_decrypted   = 0;
    ct_start = &tls_session->inbuf.data[0];
    ct_len   =  tls_session->inlen_unprocessed;
    status = sec->chosen_ciphersuite->decrypt_fn(sec, ct_start, ct_start, &ct_len);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT32(tls_session->inbuf.len, ct_len);
    TEST_ASSERT_EQUAL_UINT32(mock_aes_gcm_process_ct_len, ct_len);
    TEST_ASSERT_EQUAL_UINT(ct_start, mock_aes_gcm_process_pt_start);
    TEST_ASSERT_EQUAL_UINT(ct_start, mock_aes_gcm_process_ct_start);
    // the third fragment
    sec->flgs.ct_first_frag = 0;
    sec->flgs.ct_final_frag = 1;
    tls_session->inlen_unprocessed = sec->chosen_ciphersuite->tagSize;
    tls_session->inlen_decrypted   = 0;
    ct_start = &tls_session->inbuf.data[0];
    ct_len   =  tls_session->inlen_unprocessed;
    mock_aes_gcm_process_pt_start = NULL;
    mock_aes_gcm_process_ct_start = NULL;
    mock_aes_gcm_process_ct_len   = 0;
    // ... assume incorrect length of ciphertext is fed to decrypt function
    ct_len   =  tls_session->inlen_unprocessed - 1;
    status = sec->chosen_ciphersuite->decrypt_fn(sec, ct_start, ct_start, &ct_len);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERRMEM, status);
    // ... assume incorrect MAC code was received
    ct_len   =  tls_session->inlen_unprocessed;
    status = sec->chosen_ciphersuite->decrypt_fn(sec, ct_start, ct_start, &ct_len);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_ENAUTH_FAIL, status);
    // ... assume correct MAC code was received
    mock_aes_gcm_mac_data = expect_gcm_mac;
    XMEMCPY(&tls_session->inbuf.data[0], expect_gcm_mac, sec->chosen_ciphersuite->tagSize);
    status = sec->chosen_ciphersuite->decrypt_fn(sec, ct_start, ct_start, &ct_len);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT32(sec->chosen_ciphersuite->tagSize, ct_len);
    TEST_ASSERT_EQUAL_UINT32(0, mock_aes_gcm_process_ct_len);
    TEST_ASSERT_EQUAL_UINT(NULL, mock_aes_gcm_process_pt_start);
    TEST_ASSERT_EQUAL_UINT(NULL, mock_aes_gcm_process_ct_start);

    sec->chosen_ciphersuite->done_fn(sec);
    sec->chosen_ciphersuite = NULL;
    TEST_ASSERT_EQUAL_UINT(NULL, sec->decrypt_ctx);
    mock_aes_gcm_mac_data = NULL;
} // end of TEST(tlsCipherSuite, aes_decryption)


TEST(tlsCipherSuite, tlsGetCipherSuiteByID)
{
    const tlsCipherSpec_t* actual_cs = NULL;

    actual_cs = tlsGetCipherSuiteByID(TLS_CIPHERSUITE_ID_AES_128_CCM_8_SHA256);
    TEST_ASSERT_EQUAL_UINT(NULL, actual_cs);
    actual_cs = tlsGetCipherSuiteByID(TLS_CIPHERSUITE_ID_AES_128_GCM_SHA256);
    TEST_ASSERT_EQUAL_UINT(&tls_supported_cipher_suites[0], actual_cs);
    actual_cs = tlsGetCipherSuiteByID(TLS_CIPHERSUITE_ID_AES_256_GCM_SHA384);
    TEST_ASSERT_EQUAL_UINT(&tls_supported_cipher_suites[1], actual_cs);
    actual_cs = tlsGetCipherSuiteByID(TLS_CIPHERSUITE_ID_CHACHA20_POLY1305_SHA256);
    TEST_ASSERT_EQUAL_UINT(&tls_supported_cipher_suites[2], actual_cs);
} // end of TEST(tlsCipherSuite, tlsGetCipherSuiteByID)


TEST(tlsCipherSuite, TLScipherSuiteGetHashID)
{
    tlsCipherSpec_t   mock_cs;
    mock_cs.flags = 0;
    TEST_ASSERT_EQUAL_UINT16(TLS_HASH_ALGO_NOT_NEGO , TLScipherSuiteGetHashID(NULL));
    TEST_ASSERT_EQUAL_UINT16(TLS_HASH_ALGO_UNKNOWN, TLScipherSuiteGetHashID((const tlsCipherSpec_t *)&mock_cs));
    TEST_ASSERT_EQUAL_UINT16(TLS_HASH_ALGO_SHA256 , TLScipherSuiteGetHashID(&tls_supported_cipher_suites[0]));
    TEST_ASSERT_EQUAL_UINT16(TLS_HASH_ALGO_SHA384 , TLScipherSuiteGetHashID(&tls_supported_cipher_suites[1]));
    TEST_ASSERT_EQUAL_UINT16(TLS_HASH_ALGO_SHA256 , TLScipherSuiteGetHashID(&tls_supported_cipher_suites[2]));
} // end of TEST(tlsCipherSuite, TLScipherSuiteGetHashID)


static void RunAllTestGroups(void)
{
    tls_session = (tlsSession_t *) XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->inbuf.len  = MAX_RAWBYTE_BUF_SZ;
    tls_session->inbuf.data = (byte *) XCALLOC(sizeof(byte), MAX_RAWBYTE_BUF_SZ);
    tls_session->outbuf.len  = MAX_RAWBYTE_BUF_SZ;
    tls_session->outbuf.data = (byte *) XCALLOC(sizeof(byte), MAX_RAWBYTE_BUF_SZ);

    RUN_TEST_GROUP(tlsCipherSuite);

    XMEMFREE(tls_session->inbuf.data);
    XMEMFREE(tls_session->outbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


