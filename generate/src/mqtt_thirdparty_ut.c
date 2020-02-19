#include "mqtt_third_party_include.h"

#define MOCK_HASH_SHA256_IDX  0
#define MOCK_HASH_SHA384_IDX  1

// for unit test, keep interface but ignore detailed implementation
int    mock_mp_add_return_val;
size_t mock_mp_ubin_sz_val;
const unsigned char  *mock_hash_curr_state[2];
const unsigned char  *mock_hash_curr_outbytes[2];
unsigned char  *mock_last_hash_in_data[2];
unsigned int    mock_last_hash_in_len[2];

const  unsigned int mock_last_mp_from_ubin_max_sz = 9;
unsigned int mock_last_mp_from_ubin_idx;
unsigned char *mock_last_mp_from_ubin_in_data[9];
size_t         mock_last_mp_from_ubin_in_len[9];

struct ltc_prng_descriptor    prng_descriptor[1];
struct ltc_cipher_descriptor  cipher_descriptor[2];
struct ltc_hash_descriptor    hash_descriptor[2];

ltc_math_descriptor  ltc_mp = { 0 };
const ltc_math_descriptor  ltm_desc = { 0 };


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

mp_err mp_init(mp_int *a)
{ return 0; }

mp_err mp_from_ubin(mp_int *out, const unsigned char *buf, size_t size)
{
    if(mock_last_mp_from_ubin_max_sz > mock_last_mp_from_ubin_idx) {
        mock_last_mp_from_ubin_in_data[ mock_last_mp_from_ubin_idx ] = buf;
        mock_last_mp_from_ubin_in_len[ mock_last_mp_from_ubin_idx ]  = size;
        mock_last_mp_from_ubin_idx++;
    }
    return 0;
}

mp_err mp_add(const mp_int *a, const mp_int *b, mp_int *c)
{ return mock_mp_add_return_val; }

// mp_digit
mp_err mp_add_d(const mp_int *a, mp_digit b, mp_int *c)
{ return mock_mp_add_return_val; }

size_t mp_ubin_size(const mp_int *a)
{ return mock_mp_ubin_sz_val; }

mp_err  mp_to_ubin(const mp_int *a, unsigned char *buf, size_t maxlen, size_t *written)
{ return 0; }

void mp_clear(mp_int *a)
{ return; }


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

