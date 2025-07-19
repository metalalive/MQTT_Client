#include "mqtt_include.h"

tlsRespStatus tlsASN1GetIDlen(const byte *in, word32 *inlen, byte expected_idtag, word32 *datalen) {
    XASSERT(in && inlen && datalen);
    tlsRespStatus status = TLS_RESP_OK;

    if (expected_idtag != *in++) {
        status = TLS_RESP_ERR_NOT_SUPPORT;
    } else {
        word32 remain_len = *inlen - 1;
        TLS_CFG_ASN1_GET_LEN_FN(status, in, &remain_len, datalen);
        *inlen = 1 + remain_len;
        if (*datalen > TLS_MAX_BYTES_CERT_CHAIN) {
            status = TLS_RESP_ERR_CERT_OVFL;
        }
    }
    return status;
}

// ------------------------------------------------------------
TEST_GROUP(tlsX509getExtensions);

TEST_SETUP(tlsX509getExtensions) {}

TEST_TEAR_DOWN(tlsX509getExtensions) {}

TEST_GROUP_RUNNER(tlsX509getExtensions) {
    RUN_TEST_CASE(tlsX509getExtensions, test_ok_1);
    RUN_TEST_CASE(tlsX509getExtensions, test_ok_2);
    RUN_TEST_CASE(tlsX509getExtensions, test_ok_3);
    RUN_TEST_CASE(tlsX509getExtensions, corrupted_raw);
}

TEST(tlsX509getExtensions, test_ok_1) {
    byte mock_x509_ext1_raw[] =
        {
            0xa3, 0x42, 0x30, 0x40,                   // ID-length header bytes
            0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, // X509_EXT_TYPE_BASIC_CONSTRAINT
            0x04, 0x05, 0x30, 0x03, 0x1,  0x1,  0x1,  0x30, 0x12, 0x06,
            0x03, 0x55, 0x1d, 0x23, // X509_EXT_TYPE_AUTH_ID
            0x04, 0x0b, 0x30, 0x09, 0x80, 0x07, 0xbe, 0xef, 0xde, 0xad,
            0xb0, 0x0b, 0x1e, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, // X509_EXT_TYPE_KEY_UASGE
            0x04, 0x04, 0x03, 0x02, 0x05, 0xe0, 0x30, 0x0f, 0x06, 0x03,
            0x55, 0x1d, 0x0e, // X509_EXT_TYPE_SUBJ_ID
            0x04, 0x08, 0x04, 0x06, 0x5e, 0xe7, 0x33, 0xa3, 0x91, 0x2f,
        };
    word16 mock_x509_ext1_nbytes = 0x44;

    byte  *buf = &mock_x509_ext1_raw[0];
    word32 inlen = mock_x509_ext1_nbytes;
    word32 datalen = 0;

    tlsX509v3ext_t *x509ext_obj = NULL;
    tlsRespStatus   status = tlsX509getExtensions(buf, &inlen, &x509ext_obj, &datalen);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT32(2, inlen);
    TEST_ASSERT_EQUAL_UINT32(mock_x509_ext1_nbytes - 2, datalen);

    TEST_ASSERT_NOT_EQUAL(NULL, x509ext_obj);
    TEST_ASSERT_NOT_EQUAL(NULL, x509ext_obj->subjKeyID.data);
    TEST_ASSERT_NOT_EQUAL(NULL, x509ext_obj->authKeyID.data);
    TEST_ASSERT_EQUAL_UINT8(6, x509ext_obj->subjKeyID.len);
    TEST_ASSERT_EQUAL_UINT8(7, x509ext_obj->authKeyID.len);
    TEST_ASSERT_EQUAL_STRING_LEN(
        "\x5e\xe7\x33\xa3\x91\x2f", x509ext_obj->subjKeyID.data, x509ext_obj->subjKeyID.len
    );
    TEST_ASSERT_EQUAL_STRING_LEN(
        "\xbe\xef\xde\xad\xb0\x0b\x1e", x509ext_obj->authKeyID.data, x509ext_obj->authKeyID.len
    );

    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.is_ca);
    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.key_usage.digital_signature);
    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.key_usage.non_repudiation);
    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.key_usage.key_encipher);
    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.key_usage.data_encipher);
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.key_agreement);
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.key_cert_sign);
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.crl_sign);
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.decipher_only);
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.encipher_only);

    tlsX509FreeCertExt(x509ext_obj);
    XMEMFREE(x509ext_obj);
    x509ext_obj = NULL;
} // end of TEST_CASE(tlsX509getExtensions, test_ok_1)

TEST(tlsX509getExtensions, test_ok_2) {
    // New raw byte data for X.509 extension including Subject Alternative Names
    // Removed the second IP address entry and adjusted lengths accordingly.
    byte mock_x509_ext2_raw[] = {
        0xA3, 0x2E, // Context-specific, constructed, tag 3 (Extensions), total length 46 bytes
        0x30, 0x2C, // SEQUENCE (wrapper for list of extensions), length 44
        // Subject Alternative Name extension (OID 2.5.29.17)
        0x30, 0x2A,                   // SEQUENCE (Extension), length 42
        0x06, 0x03, 0x55, 0x1D, 0x11, // OID for Subject Alternative Name (2.5.29.17)
        0x04, 0x23,                   // OCTET STRING (extnValue), length 35
        0x30, 0x21,                   // SEQUENCE (GeneralNames), length 33
        // First DNS Name: "example.com"
        0xA2, 0x0B, // [2] (dNSName), length 11
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // "example.com"
        // Second DNS Name: "another.com" (with a null terminator for 12 bytes total)
        0xA2, 0x0C, // [2] (dNSName), length 12
        0x61, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x00, // "another.com\0"
        // First IP Address: "192.168.1.59"
        0x87, 0x04,             // [7] (iPAddress), length 4
        0xC0, 0xA8, 0x01, 0x3B, // 192.168.1.59
    };
    word16 mock_x509_ext2_nbytes = 0x30; // Total bytes: 48

    byte  *buf = &mock_x509_ext2_raw[0];
    word32 inlen = mock_x509_ext2_nbytes;
    word32 datalen = 0;

    tlsX509v3ext_t *x509ext_obj = NULL;
    tlsRespStatus   status = tlsX509getExtensions(buf, &inlen, &x509ext_obj, &datalen);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    // After parsing the entire extensions block (A3 2C + 44 bytes of content)
    // inlen should be 2 (the A3 2C bytes themselves)
    TEST_ASSERT_EQUAL_UINT32(2, inlen);
    // datalen should be the total length of the extensions content (44 bytes)
    TEST_ASSERT_EQUAL_UINT32(mock_x509_ext2_nbytes - 2, datalen);
    TEST_ASSERT_NOT_EQUAL(NULL, x509ext_obj);
    TEST_ASSERT_NOT_EQUAL(NULL, x509ext_obj->subjAltNames);

    // --- Verify using direct list iteration (existing logic) ---
    tlsX509SANEntry_t *current_san = (tlsX509SANEntry_t *)x509ext_obj->subjAltNames;

    // First entry: "example.com" (dNSName)
    TEST_ASSERT_NOT_EQUAL(NULL, current_san);
    TEST_ASSERT_EQUAL_UINT8(X509_EXT_SAN_DOMAIN_NAME, current_san->stype); // dNSName tag
    TEST_ASSERT_EQUAL_UINT16(11, current_san->data.domain_name.len);
    TEST_ASSERT_EQUAL_STRING_LEN(
        "example.com", current_san->data.domain_name.data, current_san->data.domain_name.len
    );

    current_san = (tlsX509SANEntry_t *)current_san->list_item.next;

    // Second entry: "another.com" (dNSName)
    TEST_ASSERT_NOT_EQUAL(NULL, current_san);
    TEST_ASSERT_EQUAL_UINT8(X509_EXT_SAN_DOMAIN_NAME, current_san->stype); // dNSName tag
    // Includes null terminator from raw data
    TEST_ASSERT_EQUAL_UINT16(12, current_san->data.domain_name.len);
    TEST_ASSERT_EQUAL_STRING_LEN(
        "another.com\x00", current_san->data.domain_name.data, current_san->data.domain_name.len
    );
    current_san = (tlsX509SANEntry_t *)current_san->list_item.next;

    // Third entry: "192.168.1.59" (iPAddress)
    TEST_ASSERT_NOT_EQUAL(NULL, current_san);
    TEST_ASSERT_EQUAL_UINT8(X509_EXT_SAN_IP_ADDR, current_san->stype); // iPAddress tag
    TEST_ASSERT_EQUAL_UINT8(4, current_san->data.ip_address.len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(
        ((byte[]){0xC0, 0xA8, 0x01, 0x3B}), (current_san->data.ip_address.data),
        (current_san->data.ip_address.len)
    );
    current_san = (tlsX509SANEntry_t *)current_san->list_item.next;
    TEST_ASSERT_EQUAL(NULL, current_san); // No more SAN entries

    // --- Verify using tlsX509FindSubjAltName (new logic) ---

    // Search for "example.com"
    mqttHost_t search_host_domain1 = {0};
    search_host_domain1.domain_name.data = (byte *)"example.com";
    search_host_domain1.domain_name.len = strlen("example.com");
    tlsX509SANEntry_t *found_san = tlsX509FindSubjAltName(x509ext_obj, &search_host_domain1);
    TEST_ASSERT_NOT_EQUAL(NULL, found_san);
    TEST_ASSERT_EQUAL_UINT8(X509_EXT_SAN_DOMAIN_NAME, found_san->stype);
    TEST_ASSERT_EQUAL_UINT16(search_host_domain1.domain_name.len, found_san->data.domain_name.len);
    TEST_ASSERT_EQUAL_STRING_LEN(
        (const char *)search_host_domain1.domain_name.data,
        (const char *)found_san->data.domain_name.data, found_san->data.domain_name.len
    );

    // Search for "another.com\0" (explicitly setting length to include null terminator)
    mqttHost_t search_host_domain2 = {0};
    search_host_domain2.domain_name.data = (byte *)"another.com\x00";
    search_host_domain2.domain_name.len = 12; // Length includes the null terminator
    found_san = tlsX509FindSubjAltName(x509ext_obj, &search_host_domain2);
    TEST_ASSERT_NOT_EQUAL(NULL, found_san);
    TEST_ASSERT_EQUAL_UINT8(X509_EXT_SAN_DOMAIN_NAME, found_san->stype);
    TEST_ASSERT_EQUAL_UINT16(search_host_domain2.domain_name.len, found_san->data.domain_name.len);
    TEST_ASSERT_EQUAL_STRING_LEN(
        (const char *)search_host_domain2.domain_name.data,
        (const char *)found_san->data.domain_name.data, found_san->data.domain_name.len
    );

    // Search for "192.168.1.59"
    byte       ip_addr_data[] = {0xC0, 0xA8, 0x01, 0x3B};
    mqttHost_t search_host_ip = {0};
    search_host_ip.ip_address.data = ip_addr_data;
    search_host_ip.ip_address.len = sizeof(ip_addr_data);
    found_san = tlsX509FindSubjAltName(x509ext_obj, &search_host_ip);
    TEST_ASSERT_NOT_EQUAL(NULL, found_san);
    TEST_ASSERT_EQUAL_UINT8(X509_EXT_SAN_IP_ADDR, found_san->stype);
    TEST_ASSERT_EQUAL_UINT8(search_host_ip.ip_address.len, found_san->data.ip_address.len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(
        search_host_ip.ip_address.data, found_san->data.ip_address.data,
        found_san->data.ip_address.len
    );

    // Search for a non-existent domain
    mqttHost_t search_host_nonexistent_domain = {0};
    search_host_nonexistent_domain.domain_name.data = (byte *)"nonexistent.com";
    search_host_nonexistent_domain.domain_name.len = strlen("nonexistent.com");
    found_san = tlsX509FindSubjAltName(x509ext_obj, &search_host_nonexistent_domain);
    TEST_ASSERT_EQUAL(NULL, found_san);

    // Search for a non-existent IP address
    byte       ip_addr_nonexistent_data[] = {0x01, 0x02, 0x03, 0x04};
    mqttHost_t search_host_nonexistent_ip = {0};
    search_host_nonexistent_ip.ip_address.data = ip_addr_nonexistent_data;
    search_host_nonexistent_ip.ip_address.len = sizeof(ip_addr_nonexistent_data);
    found_san = tlsX509FindSubjAltName(x509ext_obj, &search_host_nonexistent_ip);
    TEST_ASSERT_EQUAL(NULL, found_san);

    tlsX509FreeCertExt(x509ext_obj);
    XMEMFREE(x509ext_obj);
    x509ext_obj = NULL;
}

TEST(tlsX509getExtensions, test_ok_3) {
    // Raw byte data for X.509 extension including Key Usage and Subject Alternative Names
    byte mock_x509_ext3_raw[] = {
        0xA3, 0x35, // Context-specific, constructed, tag 3 (Extensions), total length 53 bytes
        0x30, 0x33, // SEQUENCE (wrapper for list of extensions), length 51

        // Key Usage extension (OID 2.5.29.15)
        0x30, 0x0B,                   // SEQUENCE (Extension), length 11
        0x06, 0x03, 0x55, 0x1D, 0x0F, // OID for Key Usage (2.5.29.15)
        0x04, 0x04,                   // OCTET STRING (extnValue), length 4
        0x03, 0x02, 0x05, 0xD0,       // BIT STRING (unused bits 5, value 0xD0)

        // Subject Alternative Name extension (OID 2.5.29.17)
        0x30, 0x24,                   // SEQUENCE (Extension), length 36
        0x06, 0x03, 0x55, 0x1D, 0x11, // OID for Subject Alternative Name (2.5.29.17)
        0x04, 0x1D,                   // OCTET STRING (extnValue), length 29
        0x30, 0x1B,                   // SEQUENCE (GeneralNames), length 27
        // First DNS Name: "example.com"
        0x82, 0x0B, // [2] (dNSName), length 11
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // "example.com"
        // Second DNS Name: "another.com" (with a null terminator for 12 bytes total)
        0x82, 0x0C, // [2] (dNSName), length 12
        0x61, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x00, // "another.com\0"
    };
    word16 mock_x509_ext3_nbytes = sizeof(mock_x509_ext3_raw);

    byte  *buf = &mock_x509_ext3_raw[0];
    word32 inlen = mock_x509_ext3_nbytes;
    word32 datalen = 0;

    tlsX509v3ext_t *x509ext_obj = NULL;
    tlsRespStatus   status = tlsX509getExtensions(buf, &inlen, &x509ext_obj, &datalen);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_UINT32(2, inlen);                           // A3 3B
    TEST_ASSERT_EQUAL_UINT32(mock_x509_ext3_nbytes - 2, datalen); // 59 bytes

    TEST_ASSERT_NOT_EQUAL(NULL, x509ext_obj);
    TEST_ASSERT_NOT_EQUAL(NULL, x509ext_obj->subjAltNames);

    // Verify Key Usage flags
    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.key_usage.digital_signature);
    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.key_usage.non_repudiation);
    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.key_usage.key_encipher);
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.data_encipher);
    TEST_ASSERT_EQUAL_UINT8(1, x509ext_obj->flgs.key_usage.key_agreement);
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.key_cert_sign);
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.crl_sign);
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.encipher_only);
    TEST_ASSERT_EQUAL_UINT8(0, x509ext_obj->flgs.key_usage.decipher_only);

    // Verify Subject Alternative Name entries
    tlsX509SANEntry_t *current_san = (tlsX509SANEntry_t *)x509ext_obj->subjAltNames;

    // First entry: "example.com" (dNSName)
    TEST_ASSERT_NOT_EQUAL(NULL, current_san);
    TEST_ASSERT_EQUAL_UINT8(X509_EXT_SAN_DOMAIN_NAME, current_san->stype);
    TEST_ASSERT_EQUAL_UINT16(11, current_san->data.domain_name.len);
    TEST_ASSERT_EQUAL_STRING_LEN(
        "example.com", current_san->data.domain_name.data, current_san->data.domain_name.len
    );

    current_san = (tlsX509SANEntry_t *)current_san->list_item.next;

    // Second entry: "another.com" (dNSName)
    TEST_ASSERT_NOT_EQUAL(NULL, current_san);
    TEST_ASSERT_EQUAL_UINT8(X509_EXT_SAN_DOMAIN_NAME, current_san->stype);
    TEST_ASSERT_EQUAL_UINT16(12, current_san->data.domain_name.len);
    TEST_ASSERT_EQUAL_STRING_LEN(
        "another.com\x00", current_san->data.domain_name.data, current_san->data.domain_name.len
    );

    current_san = (tlsX509SANEntry_t *)current_san->list_item.next;
    TEST_ASSERT_EQUAL(NULL, current_san); // No more SAN entries

    tlsX509FreeCertExt(x509ext_obj);
    XMEMFREE(x509ext_obj);
    x509ext_obj = NULL;
}

TEST(tlsX509getExtensions, corrupted_raw) {
    // Corrupted raw bytes: Change the initial ASN.1 tag from 0xA3 to 0x00
    byte mock_x509_ext_corrupted_raw[] = {
        0xA3, 0x21, // Corrupted length field , num bytes more than 0x21
        0x30, 0x2C, 0x30, 0x2A, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x23, 0x30,
        0x21, 0xA2, 0x0B, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63,
        0x6f, 0x6d, 0xA2, 0x0C, 0x61, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x2e,
        0x63, 0x6f, 0x6d, 0x00, 0x87, 0x04, 0xC0, 0xA8, 0x01, 0x3B,
    };
    word16 mock_x509_ext_corrupted_nbytes = sizeof(mock_x509_ext_corrupted_raw);

    byte  *buf = &mock_x509_ext_corrupted_raw[0];
    word32 inlen = mock_x509_ext_corrupted_nbytes;
    word32 datalen = 0;

    tlsX509v3ext_t *x509ext_obj = NULL;
    tlsRespStatus   status = tlsX509getExtensions(buf, &inlen, &x509ext_obj, &datalen);
    TEST_ASSERT_TRUE(status < 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERR_DECODE, status);
    TEST_ASSERT_NOT_EQUAL(NULL, x509ext_obj);

    tlsX509FreeCertExt(x509ext_obj);
    XMEMFREE(x509ext_obj);
    x509ext_obj = NULL;
}

static void RunAllTestGroups(void) {
    RUN_TEST_GROUP(tlsX509getExtensions);
} // end of RunAllTestGroups

int main(int argc, const char *argv[]) {
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main
