#include "tommath_private.h"
#ifdef MP_RAND_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#if (1)
// the DRBG source object & read function are for integration purpose
extern  void         **tls_drbg_src_obj;
extern  unsigned int   tlsRNGread(unsigned char *out, unsigned int outlen, void *prng);
#else
mp_err(*s_mp_rand_source)(void *out, size_t size) = s_mp_rand_platform;

void mp_rand_source(mp_err(*source)(void *out, size_t size))
{
   s_mp_rand_source = (source == NULL) ? s_mp_rand_platform : source;
}
#endif

mp_err mp_rand(mp_int *a, int digits)
{
   int i;
   mp_err err;

   mp_zero(a);

   if (digits <= 0) {
      return MP_OKAY;
   }

   if ((err = mp_grow(a, digits)) != MP_OKAY) {
      return err;
   }
#if (1)
   unsigned int nbytes_read = 0;
   nbytes_read = tlsRNGread((unsigned char *)a->dp, (unsigned int) digits * sizeof(mp_digit), *tls_drbg_src_obj);
   if(nbytes_read == 0) { return  MP_ERR; }
#else
   if ((err = s_mp_rand_source(a->dp, (size_t)digits * sizeof(mp_digit))) != MP_OKAY) {
      return err;
   }

   /* TODO: We ensure that the highest digit is nonzero. Should this be removed? */
   while ((a->dp[digits - 1] & MP_MASK) == 0u) {
      if ((err = s_mp_rand_source(a->dp + digits - 1, sizeof(mp_digit))) != MP_OKAY) {
         return err;
      }
   }
#endif
   a->used = digits;
   for (i = 0; i < digits; ++i) {
      a->dp[i] &= MP_MASK;
   }

   return MP_OKAY;
}
#endif
