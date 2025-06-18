/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

/* automatically generated file, do not edit */

#define FOR(i,n) for (i = 0;i < n;++i)
#define sv static void

typedef unsigned char u8;
typedef ulong32 u32;
typedef ulong64 u64;
typedef long64 i64;
typedef i64 gf[16];

static const u8
  _9[32] = {9};
static const gf
  gf0,
  gf1 = {1},
  _121665 = {0xDB41,1},
  D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
  D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
  X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
  Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
  I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

static int vn(const u8 *x,const u8 *y,int n)
{
  int i;
  u32 d = 0;
  FOR(i,n) d |= x[i]^y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}

static int tweetnacl_crypto_verify_32(const u8 *x,const u8 *y)
{
  return vn(x,y,32);
}

sv set25519(gf r, const gf a)
{
  int i;
  FOR(i,16) r[i]=a[i];
}

//// sv car25519(gf o)
sv car25519(i64 *o)
{
  int i;
  i64 c;
  FOR(i,16) {
    o[i]+=(1LL<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c<<16;
  }
}

sv sel25519(gf p,gf q,int b)
{
  i64 t,i,c=~(b-1);
  FOR(i,16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

sv pack25519(u8 *o,const gf n)
{
  int i,j,b;
  gf m,t;
  FOR(i,16) t[i]=n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  FOR(j,2) {
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    sel25519(t,m,1-b);
  }
  FOR(i,16) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=t[i]>>8;
  }
}

static int neq25519(const gf a, const gf b)
{
  u8 c[32],d[32];
  pack25519(c,a);
  pack25519(d,b);
  return tweetnacl_crypto_verify_32(c,d);
}

static u8 par25519(const gf a)
{
  u8 d[32];
  pack25519(d,a);
  return d[0]&1;
}

//// sv unpack25519(gf o, const u8 *n)
sv unpack25519(i64 *o, const u8 *n)
{
  int i;
  FOR(i,16) o[i]=n[2*i]+((i64)n[2*i+1]<<8);
  o[15]&=0x7fff;
}

//// sv A(gf o,const gf a,const gf b)
sv A(i64 *o,const i64 *a,const i64 *b)
{
  u8 i; //// int i;
  FOR(i,16) o[i]=a[i]+b[i];
}

//// sv Z(gf o,const gf a,const gf b)
sv Z(i64 *o,const i64 *a,const i64 *b)
{
  u8 i; //// int i;
  FOR(i,16) o[i]=a[i]-b[i];
}

//// sv M(gf o,const gf a,const gf b)
sv M(i64 *o,const i64 *a,const i64 *b)
{
  //// i64 i,j,t[31];
  u8   i,j;
  i64 *t = (i64 *)XMALLOC(sizeof(i64) * 31); // TODO: reduce number of memory allocation operations
  FOR(i,31) t[i]=0;
  FOR(i,16) FOR(j,16) t[i+j]+=a[i]*b[j];
  FOR(i,15) t[i]+=38*t[i+16];
  FOR(i,16) o[i]=t[i];
  XFREE(t);
  car25519(o);
  car25519(o);
}

//// sv S(gf o,const gf a)
sv S(i64 *o,const i64 *a)
{
  M(o,a,a);
}

sv inv25519(gf o,const gf i)
{
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

sv pow2523(gf o,const gf i)
{
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=250;a>=0;a--) {
    S(c,c);
    if(a!=1) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

#pragma GCC push_options
#pragma GCC optimize ("O0")
int tweetnacl_crypto_scalarmult(u8 *q,const u8 *n,const u8 *p)
{
  //// u8 z[32];
  i64 r,i; //// x[80],
  //// gf a,b,c,d,e,f;
  u8  *z = NULL; 
  i64 *x = NULL; 
  i64 *a = NULL; 
  i64 *b = NULL; 
  i64 *c = NULL; 
  i64 *d = NULL; 
  i64 *e = NULL; 
  i64 *f = NULL; 
  const size_t i64_sz = sizeof(i64);
  size_t tmpbuf_sz = (sizeof(u8) << 5) + (i64_sz << 4) * 11;
  u8  *tmpbuf = (u8 *) XMALLOC(tmpbuf_sz);
  z =        tmpbuf; tmpbuf += (sizeof(u8) << 5);  //// (u8 *)  XMALLOC(sizeof(u8) * 32);           
  x = (i64 *)tmpbuf; tmpbuf += (i64_sz * 80); //// (i64 *) XMALLOC(sizeof(i64) * 16 * 5);
  a = (i64 *)tmpbuf; tmpbuf += (i64_sz << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  b = (i64 *)tmpbuf; tmpbuf += (i64_sz << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  c = (i64 *)tmpbuf; tmpbuf += (i64_sz << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  d = (i64 *)tmpbuf; tmpbuf += (i64_sz << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  e = (i64 *)tmpbuf; tmpbuf += (i64_sz << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  f = (i64 *)tmpbuf; tmpbuf += (i64_sz << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);

  FOR(i,31) z[i]=n[i];
  z[31]=(n[31]&127)|64;
  z[0]&=248;
  unpack25519(x,p);
  FOR(i,16) {
    b[i]=x[i];
    d[i]=a[i]=c[i]=0;
  }
  a[0]=d[0]=1;
  for(i=254;i>=0;--i) {
    r=(z[i>>3]>>(i&7))&1;
    sel25519(a,b,r);
    sel25519(c,d,r);
    A(e,a,c);
    Z(a,a,c);
    A(c,b,d);
    Z(b,b,d);
    S(d,e);
    S(f,a);
    M(a,c,a);
    M(c,b,e);
    A(e,a,c);
    Z(a,a,c);
    S(b,a);
    Z(c,d,f);
    M(a,c,_121665);
    A(a,a,d);
    M(c,c,a);
    M(a,d,f);
    M(d,b,x);
    S(b,e);
    sel25519(a,b,r);
    sel25519(c,d,r);
  }
  FOR(i,16) {
    x[i+16]=a[i];
    x[i+32]=c[i];
    x[i+48]=b[i];
    x[i+64]=d[i];
  }
  inv25519(x+32,x+32);
  M(x+16,x+16,x+32);
  pack25519(q,x+16);
  XFREE(z);
  z = NULL;
  x = NULL;
  a = NULL;
  b = NULL;
  c = NULL;
  d = NULL;
  e = NULL;
  f = NULL;
  return 0;
}
#pragma GCC pop_options

int tweetnacl_crypto_scalarmult_base(u8 *q,const u8 *n)
{
  return tweetnacl_crypto_scalarmult(q,n,_9);
}

static int tweetnacl_crypto_hash(u8 *out,const u8 *m,u64 n)
{
  unsigned long len;
  int err, hash_idx;

  if (n > ULONG_MAX) return CRYPT_OVERFLOW;

  hash_idx = find_hash("sha512");
  len = 64;
  if ((err = hash_memory(hash_idx, m, n, out, &len)) != CRYPT_OK) return err;

  return 0;
}

sv add(gf p[4],gf q[4], u8 *pool)
{
  //// gf a,b,c,d,t,e,f,g,h;
  i64 *a = NULL;
  i64 *b = NULL;
  i64 *c = NULL;
  i64 *d = NULL;
  i64 *t = NULL;
  i64 *e = NULL;
  i64 *f = NULL;
  i64 *g = NULL;
  i64 *h = NULL;
  a = (i64 *) pool; pool += (sizeof(i64) << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  b = (i64 *) pool; pool += (sizeof(i64) << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  c = (i64 *) pool; pool += (sizeof(i64) << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  d = (i64 *) pool; pool += (sizeof(i64) << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  t = (i64 *) pool; pool += (sizeof(i64) << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  e = (i64 *) pool; pool += (sizeof(i64) << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  f = (i64 *) pool; pool += (sizeof(i64) << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  g = (i64 *) pool; pool += (sizeof(i64) << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);
  h = (i64 *) pool; pool += (sizeof(i64) << 4); //// (i64 *) XMALLOC(sizeof(i64) * 16);

  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
  //// XFREE(a);
}

sv cswap(gf p[4],gf q[4],u8 b)
{
  int i;
  FOR(i,4)
    sel25519(p[i],q[i],b);
}

sv pack(u8 *r,gf p[4])
{
  gf tx, ty, zi;
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

sv scalarmult(gf p[4],gf q[4],const u8 *s, u8 *pool)
{
  int i;
  set25519(p[0],gf0);
  set25519(p[1],gf1);
  set25519(p[2],gf1);
  set25519(p[3],gf0);
  for (i = 255;i >= 0;--i) {
    u8 b = (s[i/8]>>(i&7))&1;
    cswap(p,q,b);
    add(q,p,pool);
    add(p,p,pool);
    cswap(p,q,b);
  }
}

sv scalarbase(gf p[4],const u8 *s, u8 *pool)
{
  //// gf q[4];
  i64 *q = (i64 *) pool; pool += (sizeof(gf) << 2); //// (i64 *) XMALLOC(sizeof(gf) * 4);
  set25519(((gf *)q)[0],X);    //// set25519(q[0],X);
  set25519(((gf *)q)[1],Y);    //// set25519(q[1],Y);
  set25519(((gf *)q)[2],gf1);  //// set25519(q[2],gf1);
  M(((gf *)q)[3],X,Y);         //// M(q[3],X,Y);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
  scalarmult(p,q,s, pool);
#pragma GCC diagnostic pop
  ////XFREE(q);
}

int tweetnacl_crypto_sk_to_pk(u8 *pk, const u8 *sk)
{
  //// u8 d[64];
  //// gf p[4];
  u8  *d = NULL;
  i64 *p = NULL;
  size_t tmpbuf_sz = (sizeof(u8) << 6) + (sizeof(gf) << 2);
  tmpbuf_sz  += (sizeof(gf) << 2); // internal pool buffer for scalarbase()
  tmpbuf_sz  += 0;                 // internal pool buffer for scalarmult()
  tmpbuf_sz  += (sizeof(i64) << 4) * 9; // internal pool buffer for add()
  u8 *tmpbuf = (u8 *) XMALLOC(tmpbuf_sz);
  d = (u8  *) &tmpbuf[0]; tmpbuf += (sizeof(u8) << 6); //// (u8  *) XMALLOC(sizeof(u8) * 64);
  p = (i64 *) &tmpbuf[0]; tmpbuf += (sizeof(gf) << 2); //// (i64 *) XMALLOC(sizeof(gf) * 4);
  tweetnacl_crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
  scalarbase(p,d,tmpbuf);
  pack(pk,p);
#pragma GCC diagnostic pop
  XFREE(d);
  d = NULL;
  p = NULL;
  return 0;
}

int tweetnacl_crypto_sign_keypair(prng_state *prng, int wprng, u8 *pk, u8 *sk)
{
  int err;

  /* randombytes(sk,32); */
  if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
     return err;
  }

  if (prng_descriptor[wprng].read(sk,32, prng) != 32) {
     return CRYPT_ERROR_READPRNG;
  }

  if ((err = tweetnacl_crypto_sk_to_pk(pk, sk)) != CRYPT_OK) {
     return err;
  }

  /* FOR(i,32) sk[32 + i] = pk[i];
   * we don't copy the pk in the sk */
  return CRYPT_OK;
}

static const u64 L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

sv modL(u8 *r,i64 x[64])
{
  i64 carry,i,j;
  for (i = 63;i >= 32;--i) {
    carry = 0;
    for (j = i - 32;j < i - 12;++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry << 8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  FOR(j,32) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  FOR(j,32) x[j] -= carry * L[j];
  FOR(i,32) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

sv reduce(u8 *r)
{
  //// i64 x[64],i;
  i64 *x = (i64 *) XMALLOC(sizeof(i64) * 64);
  i64  i;
  FOR(i,64) x[i] = (u64) r[i];
  FOR(i,64) r[i] = 0;
  modL(r,x);
  XFREE(x);
}

int tweetnacl_crypto_sign(u8 *sm,u64 *smlen,const u8 *m,u64 mlen,const u8 *sk,const u8 *pk)
{
  //// u8 d[64],h[64],r[64];
  i64 i,j; //// ,x[64];
  //// gf p[4];
  u8  *d = NULL;
  u8  *h = NULL;
  u8  *r = NULL;
  i64 *x = NULL;
  i64 *p = NULL;

  size_t tmpbuf_sz = (sizeof(u8) * 64 * 3) + (sizeof(i64) << 6) + (sizeof(gf) << 2);
  tmpbuf_sz  += (sizeof(gf) << 2); // internal pool buffer for scalarbase()
  tmpbuf_sz  += 0;                 // internal pool buffer for scalarmult()
  tmpbuf_sz  += (sizeof(i64) << 4) * 9; // internal pool buffer for add()
  u8  *tmpbuf = (u8 *) XMALLOC(tmpbuf_sz);
  d = (u8 *)  &tmpbuf[0]; tmpbuf += (sizeof(u8) << 6);  //// (u8 *) XMALLOC(sizeof(u8) * 64);
  h = (u8 *)  &tmpbuf[0]; tmpbuf += (sizeof(u8) << 6);  //// (u8 *) XMALLOC(sizeof(u8) * 64);
  r = (u8 *)  &tmpbuf[0]; tmpbuf += (sizeof(u8) << 6);  //// (u8 *) XMALLOC(sizeof(u8) * 64);
  x = (i64 *) &tmpbuf[0]; tmpbuf += (sizeof(i64) << 6); //// (i64 *)XMALLOC(sizeof(i64) * 64);
  p = (i64 *) &tmpbuf[0]; tmpbuf += (sizeof(gf) << 2);  //// (i64 *)XMALLOC(sizeof(gf) * 4);

  tweetnacl_crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  *smlen = mlen+64;
  FOR(i,(i64)mlen) sm[64 + i] = m[i];
  FOR(i,32) sm[32 + i] = d[32 + i];

  tweetnacl_crypto_hash(r, sm+32, mlen+32);
  reduce(r);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
  scalarbase(p,r,tmpbuf);
  pack(sm,p);
#pragma GCC diagnostic pop

  FOR(i,32) sm[i+32] = pk[i];
  tweetnacl_crypto_hash(h,sm,mlen + 64);
  reduce(h);

  FOR(i,64) x[i] = 0;
  FOR(i,32) x[i] = (u64) r[i];
  FOR(i,32) FOR(j,32) x[i+j] += h[i] * (u64) d[j];
  modL(sm + 32,x);

  XFREE(d);
  d = NULL;
  h = NULL;
  r = NULL;
  x = NULL;
  p = NULL;
  return 0;
}

static int unpackneg(gf r[4],const u8 p[32])
{
  //// gf t, chk, num, den, den2, den4, den6;
  i64 *t    = NULL;
  i64 *chk  = NULL;
  i64 *num  = NULL;
  i64 *den  = NULL;
  i64 *den2 = NULL;
  i64 *den4 = NULL;
  i64 *den6 = NULL;

  size_t tmpbuf_sz = sizeof(gf) * 7;
  u8  *tmpbuf = (u8 *) XMALLOC(tmpbuf_sz);
  t    = (i64 *) &tmpbuf[0]; tmpbuf += sizeof(gf); //// (i64 *) XMALLOC(sizeof(gf));
  chk  = (i64 *) &tmpbuf[0]; tmpbuf += sizeof(gf); //// (i64 *) XMALLOC(sizeof(gf));
  num  = (i64 *) &tmpbuf[0]; tmpbuf += sizeof(gf); //// (i64 *) XMALLOC(sizeof(gf));
  den  = (i64 *) &tmpbuf[0]; tmpbuf += sizeof(gf); //// (i64 *) XMALLOC(sizeof(gf));
  den2 = (i64 *) &tmpbuf[0]; tmpbuf += sizeof(gf); //// (i64 *) XMALLOC(sizeof(gf));
  den4 = (i64 *) &tmpbuf[0]; tmpbuf += sizeof(gf); //// (i64 *) XMALLOC(sizeof(gf));
  den6 = (i64 *) &tmpbuf[0]; tmpbuf += sizeof(gf); //// (i64 *) XMALLOC(sizeof(gf));
  int status = 0;
  set25519(r[2],gf1);
  unpack25519(r[1],p);
  S(num,r[1]);
  M(den,num,D);
  Z(num,num,r[2]);
  A(den,r[2],den);

  S(den2,den);
  S(den4,den2);
  M(den6,den4,den2);
  M(t,den6,num);
  M(t,t,den);

  pow2523(t,t);
  M(t,t,num);
  M(t,t,den);
  M(t,t,den);
  M(r[0],t,den);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) M(r[0],r[0],I);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) { status = -1; goto done; }

  if (par25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);

  M(r[3],r[0],r[1]);
done:
  XFREE(t);
  t    = NULL;
  chk  = NULL;
  num  = NULL;
  den  = NULL;
  den2 = NULL;
  den4 = NULL;
  den6 = NULL;
  return status;
}

int tweetnacl_crypto_sign_open(int *stat, u8 *m,u64 *mlen,const u8 *sm,u64 smlen,const u8 *pk)
{
  u64 i;
  //// u8 s[32],t[32],h[64];
  //// gf p[4],q[4];
  u8  *s = NULL;
  u8  *t = NULL;
  u8  *h = NULL;
  i64 *p = NULL;
  i64 *q = NULL;
  *stat = 0;
  if (*mlen < smlen) return CRYPT_BUFFER_OVERFLOW;
  *mlen = -1;
  if (smlen < 64) return CRYPT_INVALID_ARG;

  size_t tmpbuf_sz      = (sizeof(u8) << 7) + (sizeof(gf) << 3);
  tmpbuf_sz  += (sizeof(gf) << 2); // internal pool buffer for scalarbase()
  tmpbuf_sz  += 0;                 // internal pool buffer for scalarmult()
  tmpbuf_sz  += (sizeof(i64) << 4) * 9; // internal pool buffer for add()
  u8  *tmpbuf = (u8 *) XMALLOC(tmpbuf_sz);
  s  = (u8  *) &tmpbuf[0]; tmpbuf += (sizeof(u8) << 5);//// (u8 *) XMALLOC(sizeof(u8) * 32);
  t  = (u8  *) &tmpbuf[0]; tmpbuf += (sizeof(u8) << 5);//// (u8 *) XMALLOC(sizeof(u8) * 32);
  h  = (u8  *) &tmpbuf[0]; tmpbuf += (sizeof(u8) << 6);//// (u8 *) XMALLOC(sizeof(u8) * 64);
  p  = (i64 *) &tmpbuf[0]; tmpbuf += (sizeof(gf) << 2);//// (i64 *) XMALLOC(sizeof(gf) * 4);
  q  = (i64 *) &tmpbuf[0]; tmpbuf += (sizeof(gf) << 2);//// (i64 *) XMALLOC(sizeof(gf) * 4);
  int  status = CRYPT_OK;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
  if (unpackneg(q,pk)) { status = CRYPT_ERROR; goto done; }
#pragma GCC diagnostic pop

  XMEMMOVE(m,sm,smlen);
  XMEMMOVE(s,m + 32,32);
  XMEMMOVE(m + 32,pk,32);
  tweetnacl_crypto_hash(h,m,smlen);
  reduce(h);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
  scalarmult(p,q,h,tmpbuf);

  scalarbase(q,s,tmpbuf);
  add(p,q,tmpbuf);
  pack(t,p);
#pragma GCC diagnostic pop

  smlen -= 64;
  if (tweetnacl_crypto_verify_32(sm, t)) {
    FOR(i,smlen) m[i] = 0;
    zeromem(m, smlen);
    status = CRYPT_OK; goto done;
  }

  *stat = 1;
  XMEMMOVE(m,m + 64,smlen);
  *mlen = smlen;
done:
  XFREE(s);
  s = NULL;
  t = NULL;
  h = NULL;
  p = NULL;
  q = NULL;
  return status;
}

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
