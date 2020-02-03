#include "mqtt_third_party_include.h"

// for unit test, keep interface but ignore detailed implementation
int mock_mp_add_return_val;
size_t mock_mp_ubin_sz_val;


struct ltc_prng_descriptor    prng_descriptor[1];
struct ltc_cipher_descriptor  cipher_descriptor[2];
struct ltc_hash_descriptor    hash_descriptor[2];

ltc_math_descriptor  ltc_mp = { 0 };
const ltc_math_descriptor  ltm_desc = { 0 };


int sha256_init(hash_state *md)
{ return 0; }

int sha384_init(hash_state *md)
{ return 0; }

int sha256_process(hash_state *md, const unsigned char *in, unsigned long inlen)
{ return 0; }

int sha512_process(hash_state *md, const unsigned char *in, unsigned long inlen)
{ return 0; }

int sha256_done(hash_state *md, unsigned char *out)
{ return 0; }

int sha384_done(hash_state *md, unsigned char *out)
{ return 0; }

mp_err mp_init(mp_int *a)
{ return 0; }

mp_err mp_from_ubin(mp_int *out, const unsigned char *buf, size_t size)
{ return 0; }

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


