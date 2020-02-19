#include "mqtt_include.h"
#include "unity.h"
#include "unity_fixture.h"

#define  MAX_RAWBYTE_BUF_SZ  0x80

static tlsSession_t *tls_session;
static byte    *mock_encrypt_data_start;
 // record number of bytes encrypted in the last encrypt/decrypt function call, excluding length of auth tag
static word32   mock_encrypt_len;

static tlsRespStatus  mock_tlsAESGCMinit (tlsSecurityElements_t *sec, byte isDecrypt)
{ return TLS_RESP_OK; }

static tlsRespStatus  mock_tlsAESGCMencrypt (tlsSecurityElements_t *sec, byte *pt, byte *ct, word32 *len)
{
    word32  ptlen = *len;
    if(sec->flgs.ct_final_frag != 0) { // for the final fragment, we only exclude tag length from plaintext length
        ptlen -= sec->chosen_ciphersuite->tagSize;
    } else { // otherwise, find maximal number of blocks that can be processed in current fragment of TLSInnerPlainText at once
        ptlen -= ptlen % AES_PROCESSING_BLOCK_BYTES;
    }
    if(ptlen > 0) {
        mock_encrypt_data_start = pt;
        mock_encrypt_len = ptlen;
        if(sec->flgs.ct_final_frag != 0) {
            *len = ptlen + sec->chosen_ciphersuite->tagSize;
        } else {
            *len = ptlen;
        }
    }
    return TLS_RESP_OK;
}

static tlsRespStatus  mock_tlsAESGCMdecrypt (tlsSecurityElements_t *sec, byte *ct, byte *pt, word32 *len)
{
    word32  ptlen = *len;
    if(sec->flgs.ct_final_frag != 0) { // for the final fragment, we only exclude tag length from plaintext length
        ptlen -= sec->chosen_ciphersuite->tagSize;
    } else { // otherwise, find maximal number of blocks that can be processed in current fragment of TLSCiphertext at once
        ptlen -= ptlen % AES_PROCESSING_BLOCK_BYTES;
    }
    if(ptlen > 0) {
        if(sec->flgs.ct_final_frag != 0) {
            *len = ptlen + sec->chosen_ciphersuite->tagSize;
        } else {
            *len = ptlen;
        }
    }
    return TLS_RESP_OK;
}

static tlsRespStatus  mock_tlsSymEncryptCommonDone(tlsSecurityElements_t *sec)
{ return TLS_RESP_OK; }

const tlsCipherSpec_t  tls_supported_cipher_suites[] = {
    { // TLS_AES_128_GCM_SHA256, 0x1301
        TLS_CIPHERSUITE_ID_AES_128_GCM_SHA256   ,// ident
        (1 << TLS_ENCRYPT_ALGO_AES128) | (1 << TLS_ENC_CHAINMODE_GCM) | (1 << TLS_HASH_ALGO_SHA256)      ,// flags
        16        ,// tagSize
        16        ,// keySize
        12        ,// ivSize
        mock_tlsAESGCMinit          ,// init_fn
        mock_tlsAESGCMencrypt       ,// encrypt_fn
        mock_tlsAESGCMdecrypt       ,// decrypt_fn
        mock_tlsSymEncryptCommonDone,// done_fn
    },
    { // TLS_AES_256_GCM_SHA384, 0x1302
        TLS_CIPHERSUITE_ID_AES_256_GCM_SHA384   ,// ident
        (1 << TLS_ENCRYPT_ALGO_AES256) | (1 << TLS_ENC_CHAINMODE_GCM) | (1 << TLS_HASH_ALGO_SHA384)      ,// flags
        16        ,// tagSize
        32        ,// keySize
        12        ,// ivSize
        mock_tlsAESGCMinit          ,// init_fn
        mock_tlsAESGCMencrypt       ,// encrypt_fn
        mock_tlsAESGCMdecrypt       ,// decrypt_fn
        mock_tlsSymEncryptCommonDone,// done_fn
    },
}; // end of tls_supported_cipher_suites

tlsRespStatus  tlsChkFragStateOutMsg(tlsSession_t *session)
{
    tlsRespStatus status = TLS_RESP_OK;
    if(session == NULL) { status = TLS_RESP_ERRARGS; }
    else {
        if(session->num_frags_out == 0) {
            status = TLS_RESP_REQ_REINIT;
        }
        else { // when num_frags_out > 0 , that means it is working & currently encoding message hasn't been sent yet
            if(session->remain_frags_out == session->num_frags_out) {
                status  = TLS_RESP_FIRST_FRAG;
            }
            if(session->remain_frags_out == 1) {
                status |= TLS_RESP_FINAL_FRAG;
            }
        }
    }
    return  status;
} // end of tlsChkFragStateOutMsg

tlsRespStatus  tlsChkFragStateInMsg(tlsSession_t *session)
{
    tlsRespStatus status = TLS_RESP_OK;
    if(session == NULL) { status = TLS_RESP_ERRARGS; }
    else {
        if(session->num_frags_in == 0) {
            status = TLS_RESP_REQ_REINIT;
        }
        else { // when num_frags_in > 0 , that means this client received bytes & should be decoding them
            if(session->remain_frags_in == session->num_frags_in) {
                status  = TLS_RESP_FIRST_FRAG;
            }
            if(session->remain_frags_in == 1) {
                status |= TLS_RESP_FINAL_FRAG;
            } // ignore those fragments which are not first one and last one
        }
    }
    return  status;
} // end of tlsChkFragStateInMsg



// ------------------------------------------------------------
TEST_GROUP(tlsEncryptRecordMsg);
TEST_GROUP(tlsDecryptRecordMsg);

TEST_SETUP(tlsEncryptRecordMsg)
{}

TEST_SETUP(tlsDecryptRecordMsg)
{}

TEST_TEAR_DOWN(tlsEncryptRecordMsg)
{}

TEST_TEAR_DOWN(tlsDecryptRecordMsg)
{}

TEST_GROUP_RUNNER(tlsEncryptRecordMsg)
{
    RUN_TEST_CASE(tlsEncryptRecordMsg, one_frag_multi_msgs);
}

TEST_GROUP_RUNNER(tlsDecryptRecordMsg)
{
    RUN_TEST_CASE(tlsDecryptRecordMsg, one_msg_multi_frags);
}


TEST(tlsEncryptRecordMsg, one_frag_multi_msgs)
{
    byte   *buf = NULL;
    word32  len = 0;
    tlsRespStatus status = TLS_RESP_OK;

    tls_session->sec.chosen_ciphersuite = NULL;
    status = tlsEncryptRecordMsg(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERRARGS, status);

    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[0];
    tls_session->outlen_encrypted = tls_session->outbuf.len >> 1;
    tls_session->outlen_encoded   = tls_session->outlen_encrypted - 1;
    status = tlsEncryptRecordMsg(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR, status);
    // the first record message
    tls_session->log.num_enc_recmsg_sent = 1;
    tls_session->remain_frags_out = 0;
    tls_session->num_frags_out = 0;
    tls_session->curr_outmsg_start = 0;
    tls_session->curr_outmsg_len  = tls_session->outbuf.len >> 1;
    tls_session->outlen_encoded   = tls_session->outbuf.len >> 1;
    tls_session->outlen_encrypted = 0;
    tls_session->log.last_encode_result = TLS_RESP_OK;
    status = tlsEncryptRecordMsg(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->sec.flgs.ct_first_frag);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->sec.flgs.ct_final_frag);
    TEST_ASSERT_EQUAL_UINT8(2, tls_session->log.num_enc_recmsg_sent);
    TEST_ASSERT_EQUAL_UINT16(tls_session->outlen_encoded, tls_session->outlen_encrypted);
    buf = tls_session->outbuf.data + tls_session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES;
    len = tls_session->curr_outmsg_len - TLS_RECORD_LAYER_HEADER_NBYTES - tls_session->sec.chosen_ciphersuite->tagSize;
    TEST_ASSERT_EQUAL_UINT(buf, mock_encrypt_data_start);
    TEST_ASSERT_EQUAL_UINT32(len, mock_encrypt_len);

    // the second record message, part of data bytes are encrypted & sent in this fragment,
    // while rest of them will be encrypted & sent in the next fragment.
    tls_session->remain_frags_out = 0;
    tls_session->num_frags_out = 0;
    tls_session->curr_outmsg_start = tls_session->outlen_encoded;
    tls_session->curr_outmsg_len  = (tls_session->outbuf.len >> 1) + tls_session->sec.chosen_ciphersuite->tagSize;
    tls_session->outlen_encoded  += (tls_session->outbuf.len >> 1); // assume all data bytes are encoded except auth tag
    tls_session->log.last_encode_result = TLS_RESP_REQ_MOREDATA;
    status = tlsEncryptRecordMsg(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->sec.flgs.ct_first_frag);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->sec.flgs.ct_final_frag);
    TEST_ASSERT_EQUAL_UINT8(2, tls_session->log.num_enc_recmsg_sent);
    buf = tls_session->outbuf.data + tls_session->curr_outmsg_start + TLS_RECORD_LAYER_HEADER_NBYTES;
    len = tls_session->outlen_encrypted - tls_session->curr_outmsg_start - TLS_RECORD_LAYER_HEADER_NBYTES;
    TEST_ASSERT_EQUAL_UINT(buf, mock_encrypt_data_start);
    TEST_ASSERT_EQUAL_UINT32(len, mock_encrypt_len);
    // calculate the bytes encoded but not encrypted in current fragment.
    len =  ((tls_session->outbuf.len >> 1) - TLS_RECORD_LAYER_HEADER_NBYTES) % tls_session->sec.chosen_ciphersuite->tagSize; //
    TEST_ASSERT_EQUAL_UINT16(tls_session->outlen_encoded, (tls_session->outlen_encrypted + len));

    // rest of data bytes in the second record message, previously encoded, and encrypted, sent in this fragment.
    tls_session->remain_frags_out = 1;
    tls_session->num_frags_out = 2;
    tls_session->curr_outmsg_start = 0;
    // "len" conatains number of the data bytes previously encoded, but not encrypted, sent in previous fragment.
    tls_session->outlen_encoded  = len + tls_session->sec.chosen_ciphersuite->tagSize;
    tls_session->outlen_encrypted = 0;
    tls_session->log.last_encode_result = TLS_RESP_OK;
    status = tlsEncryptRecordMsg(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->sec.flgs.ct_first_frag);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->sec.flgs.ct_final_frag);
    TEST_ASSERT_EQUAL_UINT8(3, tls_session->log.num_enc_recmsg_sent);
    TEST_ASSERT_EQUAL_UINT16(tls_session->outlen_encoded, tls_session->outlen_encrypted);
    buf = tls_session->outbuf.data + tls_session->curr_outmsg_start;
    len = tls_session->outlen_encrypted - tls_session->curr_outmsg_start - tls_session->sec.chosen_ciphersuite->tagSize;
    TEST_ASSERT_EQUAL_UINT(buf, mock_encrypt_data_start);
    TEST_ASSERT_EQUAL_UINT32(len, mock_encrypt_len);
} // end of TEST(tlsEncryptRecordMsg, one_frag_multi_msgs)


TEST(tlsDecryptRecordMsg, one_msg_multi_frags)
{
    word32  len = 0;
    tlsRespStatus status = TLS_RESP_OK;

    tls_session->sec.chosen_ciphersuite = &tls_supported_cipher_suites[1];
    tls_session->remain_frags_in = 0;
    tls_session->num_frags_in = 0;
    status = tlsDecryptRecordMsg(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR, status);

    len = (tls_session->inbuf.len - TLS_RECORD_LAYER_HEADER_NBYTES) % tls_session->sec.chosen_ciphersuite->tagSize;
    // the first fragment
    tls_session->log.num_enc_recmsg_recv = 1;
    tls_session->remain_frags_in = 2;
    tls_session->num_frags_in = 2;
    tls_session->inlen_total = tls_session->inbuf.len - len - 2 + tls_session->sec.chosen_ciphersuite->tagSize;
    tls_session->inlen_unprocessed = tls_session->inbuf.len;
    status = tlsDecryptRecordMsg(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->sec.flgs.ct_first_frag);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->sec.flgs.ct_final_frag);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->log.num_enc_recmsg_recv);
    TEST_ASSERT_EQUAL_UINT16(len, tls_session->inlen_unprocessed);
    TEST_ASSERT_EQUAL_UINT16((tls_session->inbuf.len - len), tls_session->inlen_decrypted);
    // the second fragment
    tls_session->remain_frags_in = 2;
    tls_session->num_frags_in = 3;
    tls_session->inlen_total = -2 + tls_session->sec.chosen_ciphersuite->tagSize;
    tls_session->inlen_unprocessed += tls_session->inbuf.len - len;
    status = tlsDecryptRecordMsg(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->sec.flgs.ct_first_frag);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->sec.flgs.ct_final_frag);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->log.num_enc_recmsg_recv);
    TEST_ASSERT_EQUAL_UINT16(tls_session->sec.chosen_ciphersuite->tagSize, tls_session->inlen_unprocessed);
    TEST_ASSERT_EQUAL_UINT16((tls_session->inbuf.len - tls_session->sec.chosen_ciphersuite->tagSize), tls_session->inlen_decrypted);

    // the third fragment
    tls_session->remain_frags_in = 1;
    tls_session->num_frags_in = 3;
    tls_session->inlen_total = 0;
    tls_session->inlen_unprocessed += -2 + tls_session->sec.chosen_ciphersuite->tagSize;
    status = tlsDecryptRecordMsg(tls_session);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT8(0, tls_session->sec.flgs.ct_first_frag);
    TEST_ASSERT_EQUAL_UINT8(1, tls_session->sec.flgs.ct_final_frag);
    TEST_ASSERT_EQUAL_UINT8(2, tls_session->log.num_enc_recmsg_recv);
    TEST_ASSERT_EQUAL_UINT16(0, tls_session->inlen_unprocessed);
    TEST_ASSERT_EQUAL_UINT16((tls_session->sec.chosen_ciphersuite->tagSize * 2 - 2) , tls_session->inlen_decrypted);
} // end of TEST(tlsDecryptRecordMsg, one_msg_multi_frags)


static void RunAllTestGroups(void)
{
    tls_session = (tlsSession_t *) XMALLOC(sizeof(tlsSession_t));
    XMEMSET(tls_session, 0x00, sizeof(tlsSession_t));
    tls_session->inbuf.len  = MAX_RAWBYTE_BUF_SZ;
    tls_session->inbuf.data = (byte *) XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);
    tls_session->outbuf.len  = MAX_RAWBYTE_BUF_SZ;
    tls_session->outbuf.data = (byte *) XMALLOC(sizeof(byte) * MAX_RAWBYTE_BUF_SZ);

    RUN_TEST_GROUP(tlsEncryptRecordMsg);
    RUN_TEST_GROUP(tlsDecryptRecordMsg);

    XMEMFREE(tls_session->inbuf.data);
    XMEMFREE(tls_session->outbuf.data);
    XMEMFREE(tls_session);
    tls_session = NULL;
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


