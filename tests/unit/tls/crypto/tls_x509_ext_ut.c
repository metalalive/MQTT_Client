#include "mqtt_include.h"

static byte  mock_x509_ext_rawbytes_data[] = {
    0xa3, 0x42,
    0x30, 0x40, // ID-length header bytes
    0x30, 0x0c,  0x06, 0x03, 0x55, 0x1d, 0x13,  // X509_EXT_TYPE_BASIC_CONSTRAINT
        0x04, 0x05, 0x30, 0x03,   0x1, 0x1, 0x1,
    0x30, 0x12,  0x06, 0x03, 0x55, 0x1d, 0x23,  // X509_EXT_TYPE_AUTH_ID
        0x04, 0x0b, 0x30, 0x09, 0x80, 0x07,   0xbe, 0xef, 0xde, 0xad, 0xb0, 0x0b, 0x1e,
    0x30, 0x0b,  0x06, 0x03, 0x55, 0x1d, 0x0f, // X509_EXT_TYPE_KEY_UASGE
        0x04, 0x04, 0x03, 0x02, 0x05, 0xe0, 
    0x30, 0x0f,  0x06, 0x03, 0x55, 0x1d, 0x0e, // X509_EXT_TYPE_SUBJ_ID
        0x04, 0x08, 0x04, 0x06,   0x5e, 0xe7, 0x33, 0xa3, 0x91, 0x2f,
};

static word16  mock_x509_ext_rawbytes_len = 0x44;

tlsRespStatus  tlsASN1GetIDlen(const byte *in, word32 *inlen, byte expected_idtag, word32 *datalen)
{
    if(in == NULL || inlen == NULL || datalen == NULL) {
        return TLS_RESP_ERRARGS;
    }
    word32    remain_len = 0;
    tlsRespStatus status = TLS_RESP_OK;

    if(expected_idtag != *in++) {
        status = TLS_RESP_ERR_NOT_SUPPORT;
    } else {
        remain_len = *inlen - 1;
        TLS_CFG_ASN1_GET_LEN_FN(status, in, &remain_len, datalen);
        *inlen = 1 + remain_len;
        if(*datalen > TLS_MAX_BYTES_CERT_CHAIN) {
            status = TLS_RESP_ERR_CERT_OVFL;
        }
    }
    return status;
} // end of tlsASN1GetIDlen


// ------------------------------------------------------------
TEST_GROUP(tlsX509getExtensions);

TEST_SETUP(tlsX509getExtensions)
{}

TEST_TEAR_DOWN(tlsX509getExtensions)
{}

TEST_GROUP_RUNNER(tlsX509getExtensions)
{
    RUN_TEST_CASE(tlsX509getExtensions, test_ok);
}


TEST(tlsX509getExtensions, test_ok)
{
    tlsX509v3ext_t *x509ext_obj = NULL;
    byte   *buf   = NULL;
    word32  inlen = 0;
    word32  datalen = 0;
    tlsRespStatus status = TLS_RESP_OK;

    buf   = &mock_x509_ext_rawbytes_data[0];
    inlen = mock_x509_ext_rawbytes_len;
    status = tlsX509getExtensions(buf, &inlen, &x509ext_obj, &datalen);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT32(2, inlen);
    TEST_ASSERT_EQUAL_UINT32(mock_x509_ext_rawbytes_len - 2, datalen);

    TEST_ASSERT_NOT_EQUAL(NULL, x509ext_obj);
    TEST_ASSERT_NOT_EQUAL(NULL, x509ext_obj->subjKeyID.data);
    TEST_ASSERT_NOT_EQUAL(NULL, x509ext_obj->authKeyID.data);
    TEST_ASSERT_EQUAL_UINT8(6, x509ext_obj->subjKeyID.len);
    TEST_ASSERT_EQUAL_UINT8(7, x509ext_obj->authKeyID.len);
    TEST_ASSERT_EQUAL_STRING_LEN("\x5e\xe7\x33\xa3\x91\x2f", x509ext_obj->subjKeyID.data, x509ext_obj->subjKeyID.len);
    TEST_ASSERT_EQUAL_STRING_LEN("\xbe\xef\xde\xad\xb0\x0b\x1e", x509ext_obj->authKeyID.data, x509ext_obj->authKeyID.len);

    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.is_ca);
    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.key_usage.digital_signature);
    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.key_usage.non_repudiation  );
    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.key_usage.key_encipher     );
    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.key_usage.data_encipher    );
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.key_agreement    );
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.key_cert_sign    );
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.crl_sign         );
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.encipher_only    );
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.decipher_only    );

    tlsX509FreeCertExt(x509ext_obj);
    XMEMFREE(x509ext_obj);
    x509ext_obj = NULL;
} // end of TEST_CASE(tlsX509getExtensions, test_ok)



static void RunAllTestGroups(void)
{
    RUN_TEST_GROUP(tlsX509getExtensions);
} // end of RunAllTestGroups


int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main


