/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

/**
  @file rsa_verify_hash.c
  RSA PKCS #1 v1.5 or v2 PSS signature verification, Tom St Denis and Andreas Lange
*/

#ifdef LTC_MRSA

#ifdef  LTC_RSA_VERIFY_SIG_PKCS_1_V1_5_OVERWRITE
//extern int pkcs1v15extractDigestHelper(unsigned char *in, unsigned int inlen, unsigned int hash_idx, unsigned char **digest, unsigned int *digestlen);
typedef  void    multiBint_t;
typedef  hash_state    tlsHash_t;
typedef  hash_state    mqttHash_t;
#include "mqtt/mqtt_types.h"
#include "mqtt/mqtt_util.h"
#include "tls/core/tls_limits.h"
#include "tls/core/tls_types.h"
#include "tls/crypto/tls_asn1.h"
extern tlsRespStatus  tlsASN1GetIDlen(const byte *in, word32 *inlen, byte expected_idtag, word32 *datalen);
// ---- Helper funcitons for overwriting thir-party library to call the function in this MQTT/TLS implementation

// The following function overwrites part of code in rsa_verify_hash() in libtomcrypt, since its original implementation
// is not friendly to microcontroller-based platform (it takes too much space on limited RAM of MCU board).
// [pre-requisite]
// Given a byte sequence "in", decrypted by public key algorithm (RSA), and decoded by pkcs#1 v1.5 function,
// this byte sequence "in" is ASN.1 DER-encoded, and contains (wraps) pure digest string. (may be SHA256/SHA384 hashed message)
// This function aims to :
//     * check OID value parsed from "in", with given "hash_idx" point to specific hash algorithm
//     * calculate starting offset & length of the pure digest byte sequence in the sequence "in" 
static int pkcs1v15extractDigestHelper(unsigned char *in, unsigned int inlen, unsigned int hash_idx, unsigned char **digest, unsigned int *digestlen)
{
    int err = CRYPT_OK;
    word32   decoded      = 0; // number of bytes decoded in this certificate
    word32   obj_idlen_sz = 0; // size of the "1-byte ID + length field"  of the ASN1 object
    word32   obj_data_sz  = 0; // size of the data section of the ASN1 object
    tlsRespStatus status = TLS_RESP_OK;
    tlsAlgoOID  rd_oid = 0;
    word16  expect_oid = 0;
    word16  idx = 0;

    // get ID & length of the unpadded  entire certificate.
    obj_idlen_sz = inlen - decoded;
    status = tlsASN1GetIDlen(&in[decoded], &obj_idlen_sz,  (ASN_PRIMDATA_SEQUENCE | ASN_TAG_CONSTRUCTED), &obj_data_sz);
    if(status < 0) { err = CRYPT_PK_ASN1_ERROR; goto done; }
    decoded += obj_idlen_sz;

    // get OID that represents hash algorithm, possible values are : TLS_ALGO_OID_SHA256, TLS_ALGO_OID_SHA384
    obj_idlen_sz = inlen - decoded;
    status = tlsASN1GetAlgoID(&in[decoded], &obj_idlen_sz, &rd_oid, &obj_data_sz);
    if(status < 0 || rd_oid == 0) { err = CRYPT_PK_ASN1_ERROR; goto done; }
    decoded += obj_idlen_sz + obj_data_sz;

    // verify OID sum value
    // This implemtation ONLY supports SHA256 & SHA384, the first 3 bytes of the TLS_ALGO_OID_SHA256 and
    // TLS_ALGO_OID_SHA384 are always 0x60, 0x86, 0x48. TODO: find better way to implement this.
    expect_oid = 0x60 + 0x86 + 0x48;
    for(idx=3; idx<hash_descriptor[hash_idx].OIDlen; idx++) {
        expect_oid += (word16) hash_descriptor[hash_idx].OID[idx];
    }
    if(rd_oid != expect_oid) { err = CRYPT_PK_ASN1_ERROR; goto done; }

    // get starting offset & length of the pure digest byte sequence
    obj_idlen_sz = inlen - decoded;
    status = tlsASN1GetIDlen(&in[decoded], &obj_idlen_sz,  (ASN_PRIMDATA_OCTET_STRING), &obj_data_sz);
    if(status < 0) { err = CRYPT_PK_ASN1_ERROR; goto done; }
    decoded   +=  obj_idlen_sz;
    *digest    = &in[decoded];
    *digestlen =  obj_data_sz;
    decoded   +=  obj_data_sz;
done:
    return err;
} // end of pkcs1v15extractDigestHelper
#endif // end of  LTC_RSA_VERIFY_SIG_PKCS_1_V1_5_OVERWRITE

/**
  PKCS #1 de-sign then v1.5 or PSS depad
  @param sig              The signature data
  @param siglen           The length of the signature data (octets)
  @param hash             The hash of the message that was signed
  @param hashlen          The length of the hash of the message that was signed (octets)
  @param padding          Type of padding (LTC_PKCS_1_PSS, LTC_PKCS_1_V1_5 or LTC_PKCS_1_V1_5_NA1)
  @param hash_idx         The index of the desired hash
  @param saltlen          The length of the salt used during signature
  @param stat             [out] The result of the signature comparison, 1==valid, 0==invalid
  @param key              The public RSA key corresponding to the key that performed the signature
  @return CRYPT_OK on success (even if the signature is invalid)
*/
int rsa_verify_hash_ex(const unsigned char *sig,            unsigned long  siglen,
                       const unsigned char *hash,           unsigned long  hashlen,
                             int            padding,
                             int            hash_idx,       unsigned long  saltlen,
                             int           *stat,     const rsa_key       *key)
{
  unsigned long modulus_bitlen, modulus_bytelen, x;
  int           err;
  unsigned char *tmpbuf;

  LTC_ARGCHK(hash  != NULL);
  LTC_ARGCHK(sig   != NULL);
  LTC_ARGCHK(stat  != NULL);
  LTC_ARGCHK(key   != NULL);

  /* default to invalid */
  *stat = 0;

  /* valid padding? */

  if ((padding != LTC_PKCS_1_V1_5) &&
      (padding != LTC_PKCS_1_PSS) &&
      (padding != LTC_PKCS_1_V1_5_NA1)) {
    return CRYPT_PK_INVALID_PADDING;
  }

  if (padding != LTC_PKCS_1_V1_5_NA1) {
    /* valid hash ? */
    if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
       return err;
    }
  }

  /* get modulus len in bits */
  modulus_bitlen = mp_count_bits( (key->N));

  /* outlen must be at least the size of the modulus */
  modulus_bytelen = mp_unsigned_bin_size( (key->N));
  if (modulus_bytelen != siglen) {
     return CRYPT_INVALID_PACKET;
  }

  /* allocate temp buffer for decoded sig */
  tmpbuf = XMALLOC(siglen);
  if (tmpbuf == NULL) {
     return CRYPT_MEM;
  }

  /* RSA decode it  */
  x = siglen;
  if ((err = ltc_mp.rsa_me(sig, siglen, tmpbuf, &x, PK_PUBLIC, key)) != CRYPT_OK) {
     XFREE(tmpbuf);
     return err;
  }

  /* make sure the output is the right size */
  if (x != siglen) {
     XFREE(tmpbuf);
     return CRYPT_INVALID_PACKET;
  }

  if (padding == LTC_PKCS_1_PSS) {
    /* PSS decode and verify it */
#ifndef  LTC_NO_PKCS_1_PSS
    if(modulus_bitlen%8 == 1){
      err = pkcs_1_pss_decode(hash, hashlen, tmpbuf+1, x-1, saltlen, hash_idx, modulus_bitlen, stat);
    }
    else{
      err = pkcs_1_pss_decode(hash, hashlen, tmpbuf, x, saltlen, hash_idx, modulus_bitlen, stat);
    }
#endif // end of  LTC_NO_PKCS_1_PSS
  } else {
    /* PKCS #1 v1.5 decode it */
    unsigned char *out;
    unsigned long outlen;
    int           decoded;

    /* allocate temp buffer for decoded hash */
    outlen = ((modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0)) - 3;
    out    = XMALLOC(outlen);
    if (out == NULL) {
      err = CRYPT_MEM;
      goto bail_2;
    }

    if ((err = pkcs_1_v1_5_decode(tmpbuf, x, LTC_PKCS_1_EMSA, modulus_bitlen, out, &outlen, &decoded)) != CRYPT_OK) {
      XFREE(out);
      goto bail_2;
    }

    if (padding == LTC_PKCS_1_V1_5) {
#ifndef  LTC_RSA_VERIFY_SIG_PKCS_1_V1_5_OVERWRITE
      unsigned long loid[16], reallen;
      ltc_asn1_list digestinfo[2], siginfo[2];

      /* not all hashes have OIDs... so sad */
      if (hash_descriptor[hash_idx].OIDlen == 0) {
         err = CRYPT_INVALID_ARG;
         goto bail_2;
      }

      /* now we must decode out[0...outlen-1] using ASN.1, test the OID and then test the hash */
      /* construct the SEQUENCE
        SEQUENCE {
           SEQUENCE {hashoid OID
                     blah    NULL
           }
           hash    OCTET STRING
        }
     */
      LTC_SET_ASN1(digestinfo, 0, LTC_ASN1_OBJECT_IDENTIFIER, loid, sizeof(loid)/sizeof(loid[0]));
      LTC_SET_ASN1(digestinfo, 1, LTC_ASN1_NULL,              NULL,                          0);
      LTC_SET_ASN1(siginfo,    0, LTC_ASN1_SEQUENCE,          digestinfo,                    2);
      LTC_SET_ASN1(siginfo,    1, LTC_ASN1_OCTET_STRING,      tmpbuf,                        siglen);

      if ((err = der_decode_sequence_strict(out, outlen, siginfo, 2)) != CRYPT_OK) {
         /* fallback to Legacy:missing NULL */
         LTC_SET_ASN1(siginfo, 0, LTC_ASN1_SEQUENCE,          digestinfo,                    1);
         if ((err = der_decode_sequence_strict(out, outlen, siginfo, 2)) != CRYPT_OK) {
           XFREE(out);
           goto bail_2;
         }
      }

      if ((err = der_length_sequence(siginfo, 2, &reallen)) != CRYPT_OK) {
         XFREE(out);
         goto bail_2;
      }

      /* test OID */
      if ((reallen == outlen) &&
          (digestinfo[0].size == hash_descriptor[hash_idx].OIDlen) &&
        (XMEMCMP(digestinfo[0].data, hash_descriptor[hash_idx].OID, sizeof(unsigned long) * hash_descriptor[hash_idx].OIDlen) == 0) &&
          (siginfo[1].size == hashlen) &&
        (XMEMCMP(siginfo[1].data, hash, hashlen) == 0)) {
         *stat = 1;
      }
#else // if defined(LTC_RSA_VERIFY_SIG_PKCS_1_V1_5_OVERWRITE)
        unsigned char *digest = NULL;
        unsigned int   digestlen = 0;
        // not all hashes have OIDs
        if (hash_descriptor[hash_idx].OIDlen == 0) {
           err = CRYPT_INVALID_ARG;
           XFREE(out);
           goto bail_2;
        }
        // find pure digest wrapped in the ANS.1 DER-encoded byte sequence.
        err = pkcs1v15extractDigestHelper((unsigned char *)out, outlen, hash_idx, &digest, &digestlen);
        if(err == CRYPT_OK && digestlen > 0 && digest != NULL) {
            if((digestlen == hashlen) && (XMEMCMP(&digest[0], &hash[0], hashlen) == 0)) {
                *stat = 1;
            }
        }
#endif // end of LTC_RSA_VERIFY_SIG_PKCS_1_V1_5_OVERWRITE
    } else {
      /* only check if the hash is equal */
      if ((hashlen == outlen) &&
          (XMEMCMP(out, hash, hashlen) == 0)) {
        *stat = 1;
      }
    }

#ifdef LTC_CLEAN_STACK
    zeromem(out, outlen);
#endif
    XFREE(out);
  }

bail_2:
#ifdef LTC_CLEAN_STACK
  zeromem(tmpbuf, siglen);
#endif
  XFREE(tmpbuf);
  return err;
}

#endif /* LTC_MRSA */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
