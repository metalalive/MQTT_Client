#include "tomcrypt.h"

#define MOCK_HASH_SHA256_IDX  0
#define MOCK_HASH_SHA384_IDX  1

// for unit test, keep interface but ignore detailed implementation

const unsigned char  *mock_hash_curr_state[2];
const unsigned char  *mock_hash_curr_outbytes[2];
unsigned char  *mock_last_hash_in_data[2];
unsigned int    mock_last_hash_in_len[2];
unsigned char  *mock_aes_gcm_process_pt_start;
unsigned char  *mock_aes_gcm_process_ct_start;
unsigned int    mock_aes_gcm_process_ct_len;
unsigned char  *mock_aes_gcm_mac_data;

struct ltc_prng_descriptor    prng_descriptor[1];
struct ltc_cipher_descriptor  cipher_descriptor[2];
struct ltc_hash_descriptor    hash_descriptor[2];

ltc_math_descriptor  ltc_mp = { 0 };
const ltc_math_descriptor  ltm_desc = { 0 };
static ltc_ecc_curve  mock_ecc_curve_list[1];

int sha256_init(hash_state *md)
{
    return 0;
}

int sha384_init(hash_state *md)
{
    return 0;
}

static void mock_hash_state_update(hash_state *md, unsigned int idx)
{
    if(mock_hash_curr_state[idx] != NULL) {
        XMEMCPY(md, mock_hash_curr_state[idx], sizeof(hash_state));
    }
} // end of mock_hash_state_update

int sha256_process(hash_state *md, const unsigned char *in, unsigned long inlen)
{
    mock_last_hash_in_data[MOCK_HASH_SHA256_IDX] = in;
    mock_last_hash_in_len[MOCK_HASH_SHA256_IDX]  = inlen;
    mock_hash_state_update(md, MOCK_HASH_SHA256_IDX);
    return 0;
}

int sha512_process(hash_state *md, const unsigned char *in, unsigned long inlen)
{
    mock_last_hash_in_data[MOCK_HASH_SHA384_IDX] = in;
    mock_last_hash_in_len[MOCK_HASH_SHA384_IDX]  = inlen;
    mock_hash_state_update(md, MOCK_HASH_SHA384_IDX);
    return 0;
}

int sha256_done(hash_state *md, unsigned char *out)
{
    if(mock_hash_curr_outbytes[MOCK_HASH_SHA256_IDX] != NULL) {
        XMEMCPY(out, mock_hash_curr_outbytes[MOCK_HASH_SHA256_IDX], 0x20);
    }
    mock_hash_state_update(md, MOCK_HASH_SHA256_IDX);
    return 0;
}

int sha384_done(hash_state *md, unsigned char *out)
{
    if(mock_hash_curr_outbytes[MOCK_HASH_SHA384_IDX] != NULL) {
        XMEMCPY(out, mock_hash_curr_outbytes[MOCK_HASH_SHA384_IDX], 0x30);
    }
    mock_hash_state_update(md, MOCK_HASH_SHA384_IDX);
    return 0;
}


int rijndael_enc_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{ return 0; }

int rijndael_ecb_encrypt(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
{ return 0; }

int rijndael_ecb_decrypt(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
{ return 0; }

void rijndael_done(symmetric_key *skey)
{ return; }

int rijndael_enc_keysize(int *keysize)
{ return 0; }

int chacha20poly1305_init(chacha20poly1305_state *st, const unsigned char *key, unsigned long keylen)
{ return 0; }

int gcm_init(gcm_state *gcm, int cipher,  const unsigned char *key,  int keylen)
{ return 0; }

int gcm_reset(gcm_state *gcm)
{ return 0; }

int gcm_add_iv(gcm_state *gcm,  const unsigned char *IV,  unsigned long IVlen)
{ return 0; }

int gcm_add_aad(gcm_state *gcm, const unsigned char *adata,  unsigned long adatalen)
{ return 0; }

int gcm_process(gcm_state *gcm,  unsigned char *pt, unsigned long ptlen,  unsigned char *ct,  int direction)
{
    mock_aes_gcm_process_pt_start = pt;
    mock_aes_gcm_process_ct_start = ct;
    mock_aes_gcm_process_ct_len   = ptlen;
    return 0;
}

int gcm_done(gcm_state *gcm,  unsigned char *tag,  unsigned long *taglen)
{
    if(mock_aes_gcm_mac_data != NULL && tag != NULL && taglen != NULL) {
        XMEMCPY(tag, mock_aes_gcm_mac_data, *taglen);
    }
    return 0;
}

int ecc_make_key(prng_state *prng, int wprng, int keysize, ecc_key *key)
{ return 0; }

void ecc_free(ecc_key *key)
{ return; }

int ecc_ansi_x963_export(const ecc_key *key, unsigned char *out, unsigned long *outlen)
{
    if(key != NULL && out != NULL && outlen != NULL) {
        XMEMCPY(out, key, *outlen);
    }
    return 0;
}

int ecc_find_curve(const char *name_or_oid, const ltc_ecc_curve **cu)
{
    if(cu != NULL) {
        *cu = &mock_ecc_curve_list[0];
    }
    return 0;
}

int ecc_ansi_x963_import_ex(const unsigned char *in, unsigned long inlen, ecc_key *key, const ltc_ecc_curve *cu)
{
    if(key != NULL && in != NULL) {
        size_t  sz = (inlen < sizeof(ecc_key) ? inlen: sizeof(ecc_key));
        XMEMCPY(key, in, sz);
    }
    return 0;
}

int x25519_make_key(prng_state *prng, int wprng, curve25519_key *key)
{ return 0; }

int x25519_export(unsigned char *out, unsigned long *outlen,  int which, const curve25519_key *key)
{
    if(key != NULL && out != NULL && outlen != NULL) {
        XMEMCPY(out, key, *outlen);
    }
    return 0;
}

int x25519_import_raw(const unsigned char *in, unsigned long inlen, int which, curve25519_key *key)
{
    if(key != NULL && in != NULL) {
        size_t  sz = (inlen < sizeof(curve25519_key) ? inlen: sizeof(curve25519_key));
        XMEMCPY(key, in, sz);
    }
    return 0;
}

int ecc_shared_secret(const ecc_key *private_key, const ecc_key *public_key, unsigned char *out, unsigned long *outlen)
{ return 0; }

int x25519_shared_secret(const curve25519_key *private_key,  const curve25519_key *public_key,
                         unsigned char *out, unsigned long *outlen)
{ return 0; }

int hmac_memory(int hash, const unsigned char *key,  unsigned long keylen,
                const unsigned char *in,   unsigned long inlen,
                      unsigned char *out,  unsigned long *outlen)
{ return 0; }

int rsa_verify_hash_ex(const unsigned char *sig,            unsigned long  siglen,
                       const unsigned char *hash,           unsigned long  hashlen,
                             int            padding,
                             int            hash_idx,       unsigned long  saltlen,
                             int           *stat,     const rsa_key       *key)
{
    if(stat != NULL) { *stat = 1; }
    return 0;
}

int rsa_sign_hash_ex(const unsigned char *in,       unsigned long  inlen,
                           unsigned char *out,      unsigned long *outlen,
                           int            padding,
                           prng_state    *prng,     int            prng_idx,
                           int            hash_idx, unsigned long  saltlen,
                     const rsa_key *key)
{ return 0; }


int der_decode_asn1_length(const unsigned char *in, unsigned long *inlen, unsigned long *outlen)
{
   unsigned long real_len, decoded_len, offset, i;

   LTC_ARGCHK(in    != NULL);
   LTC_ARGCHK(inlen != NULL);

   if (*inlen < 1) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   real_len = in[0];

   if (real_len < 128) {
      decoded_len = real_len;
      offset = 1;
   } else {
      real_len &= 0x7F;
      if (real_len == 0) {
         return CRYPT_PK_ASN1_ERROR;
      }
      if (real_len > sizeof(decoded_len)) {
         return CRYPT_OVERFLOW;
      }
      if (real_len > (*inlen - 1)) {
         return CRYPT_BUFFER_OVERFLOW;
      }
      decoded_len = 0;
      offset = 1 + real_len;
      for (i = 0; i < real_len; i++) {
         decoded_len = (decoded_len << 8) | in[1 + i];
      }
   }

   if (outlen != NULL) *outlen = decoded_len;
   if (decoded_len > (*inlen - offset)) return CRYPT_OVERFLOW;
   *inlen = offset;

   return CRYPT_OK;
}

