/*

  ripemd160.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sun Aug 10 00:02:15 1997 [mkojo]

  Ripe MD-160 hash function. This one is in public domain, developed by
  Antoon Bosselaers et al. 

  */

/*
 * $Id: ripemd160.c,v 1.7 1998/10/10 06:54:12 mkojo Exp $
 * $Log: ripemd160.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypti.h"
#include "sshgetput.h"
#include "ripemd160.h"

/* Define RIPEMD-160 in a transparent way (for internal use currently). */
const SshHashDef ssh_hash_ripemd160_def =
{
  /* Name of the hash function. */
  "ripemd160",
  /* ASN.1 Object identifier (to be included). */
  "1.3.36.3.2.1",
  /* ISO/IEC dedicated hash identifier. */
  0x31,
  /* Digest size. */
  20,
  /* Input block length. */
  64,
  /* Context size. */
  ssh_ripemd160_ctxsize,
  /* Reset function. */
  ssh_ripemd160_reset_context,
  /* Update function. */
  ssh_ripemd160_update,
  /* Final */
  ssh_ripemd160_final
};

/* Define RIPEMD-160 in a transparent way (for internal use currently). */
const SshHashDef ssh_hash_ripemd160_96_def =
{
  /* Name of the hash function. */
  "ripemd160-96",
  /* ASN.1 Object identifier (to be included). */
  NULL,
  /* ISO/IEC dedicated hash identifier. */
  0, /* None */
  /* Digest size. */
  12,
  /* Input block length. */
  64,
  /* Context size. */
  ssh_ripemd160_ctxsize,
  /* Reset function. */
  ssh_ripemd160_reset_context,
  /* Update function. */
  ssh_ripemd160_update,
  /* Final */
  ssh_ripemd160_96_final
};

/* Define RIPEMD-160 in a transparent way (for internal use currently). */
const SshHashDef ssh_hash_ripemd160_80_def =
{
  /* Name of the hash function. */
  "ripemd160-80",
  /* ASN.1 Object identifier (to be included). */
  NULL,
  /* ISO/IEC dedicated hash identifier. */
  0, /* None */
  /* Digest size. */
  10,
  /* Input block length. */
  64,
  /* Context size. */
  ssh_ripemd160_ctxsize,
  /* Reset function. */
  ssh_ripemd160_reset_context,
  /* Update function. */
  ssh_ripemd160_update,
  /* Final */
  ssh_ripemd160_80_final
};

/* Lets use the notation of inventors as much as possible. */
typedef struct {
  SshUInt32 aa, bb, cc, dd, ee;
  unsigned char in[64];
  SshUInt32 total_length[2];
} SshRipeMDContext;

/* Rotation for a 32-bit value. */
#define ROL(x, n)     ((((x) << (n)) | ((x) >> (32 - (n)))) & 0xffffffff)

/* The basic permutation functions. */
#define F(x, y, z)        ((x) ^ (y) ^ (z))
#define G(x, y, z)        ((z) ^ ((x) & ((y) ^ (z)))) 
/* Old version #define G(x, y, z)        (((x) & (y)) | (~(x) & (z))) */
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
/* I is equivalent to (upto a permutation) G because
   xy | ~xz  is almost xz | y~z and which is equivalent to zx | ~zy. Thus
   replacing z = x, x = y, y = z we get: */
#define I(x, y, z)        ((y) ^ ((z) & ((x) ^ (y))))
/* Old version #define I(x, y, z)        (((x) & (z)) | ((y) & ~(z))) */
#define J(x, y, z)        ((x) ^ ((y) | ~(z)))

/* A little helper macro. */
#define ZZ(func, a, b, c, d, e, x, s, i) \
{  \
  (a) += func(b, c, d) + (x) + (i); \
  (a) = ROL(a, s) + (e); \
  (c) = ROL(c, 10); \
}

/* Lets define the basic operations as macros also. These
   are more or less the ones from Bosselaers original implementation. */
#define FF(a, b, c, d, e, x, s) \
     ZZ(F, a, b, c, d, e, x, s, 0x0);

#define GG(a, b, c, d, e, x, s) \
     ZZ(G, a, b, c, d, e, x, s, 0x5a827999L); 

#define HH(a, b, c, d, e, x, s) \
     ZZ(H, a, b, c, d, e, x, s, 0x6ed9eba1L); 

#define II(a, b, c, d, e, x, s) \
     ZZ(I, a, b, c, d, e, x, s, 0x8f1bbcdcL);

#define JJ(a, b, c, d, e, x, s) \
     ZZ(J, a, b, c, d, e, x, s, 0xa953fd4eL);

#define FFF(a, b, c, d, e, x, s) \
      ZZ(F, a, b, c, d, e, x, s, 0x0);

#define GGG(a, b, c, d, e, x, s) \
      ZZ(G, a, b, c, d, e, x, s, 0x7a6d76e9L);

#define HHH(a, b, c, d, e, x, s) \
      ZZ(H, a, b, c, d, e, x, s, 0x6d703ef3L);

#define III(a, b, c, d, e, x, s) \
      ZZ(I, a, b, c, d, e, x, s, 0x5c4dd124L);

#define JJJ(a, b, c, d, e, x, s) \
      ZZ(J, a, b, c, d, e, x, s, 0x50a28be6L);

void ssh_ripemd160_reset_context(void *c)
{
  SshRipeMDContext *context = c;
  context->aa = 0x67452301L;
  context->bb = 0xefcdab89L;
  context->cc = 0x98badcfeL;
  context->dd = 0x10325476L;
  context->ee = 0xc3d2e1f0L;
  context->total_length[0] = 0;
  context->total_length[1] = 0;
}

size_t ssh_ripemd160_ctxsize()
{
  return sizeof(SshRipeMDContext);
}

static void ripemd160_transform(SshRipeMDContext *context,
                                const unsigned char *block)
{
  SshUInt32 aa = context->aa, bb = context->bb, cc = context->cc,
    dd = context->dd, ee = context->ee;
  SshUInt32 aaa = aa, bbb = bb, ccc = cc, ddd = dd, eee = ee;
  SshUInt32 X[16];

  /* Round 1 (interleaved with conversion from byte buffer) */
#define IFF(a, b, c, d, e, x, s) \
{  \
  (x) = SSH_GET_32BIT_LSB_FIRST(block); \
  block += 4; \
  FF(a, b, c, d, e, x, s); \
}

   IFF(aa, bb, cc, dd, ee, X[ 0], 11);
   IFF(ee, aa, bb, cc, dd, X[ 1], 14);
   IFF(dd, ee, aa, bb, cc, X[ 2], 15);
   IFF(cc, dd, ee, aa, bb, X[ 3], 12);
   IFF(bb, cc, dd, ee, aa, X[ 4],  5);
   IFF(aa, bb, cc, dd, ee, X[ 5],  8);
   IFF(ee, aa, bb, cc, dd, X[ 6],  7);
   IFF(dd, ee, aa, bb, cc, X[ 7],  9);
   IFF(cc, dd, ee, aa, bb, X[ 8], 11);
   IFF(bb, cc, dd, ee, aa, X[ 9], 13);
   IFF(aa, bb, cc, dd, ee, X[10], 14);
   IFF(ee, aa, bb, cc, dd, X[11], 15);
   IFF(dd, ee, aa, bb, cc, X[12],  6);
   IFF(cc, dd, ee, aa, bb, X[13],  7);
   IFF(bb, cc, dd, ee, aa, X[14],  9);
   IFF(aa, bb, cc, dd, ee, X[15],  8);
                             
   /* Round 2 */
   GG(ee, aa, bb, cc, dd, X[ 7],  7);
   GG(dd, ee, aa, bb, cc, X[ 4],  6);
   GG(cc, dd, ee, aa, bb, X[13],  8);
   GG(bb, cc, dd, ee, aa, X[ 1], 13);
   GG(aa, bb, cc, dd, ee, X[10], 11);
   GG(ee, aa, bb, cc, dd, X[ 6],  9);
   GG(dd, ee, aa, bb, cc, X[15],  7);
   GG(cc, dd, ee, aa, bb, X[ 3], 15);
   GG(bb, cc, dd, ee, aa, X[12],  7);
   GG(aa, bb, cc, dd, ee, X[ 0], 12);
   GG(ee, aa, bb, cc, dd, X[ 9], 15);
   GG(dd, ee, aa, bb, cc, X[ 5],  9);
   GG(cc, dd, ee, aa, bb, X[ 2], 11);
   GG(bb, cc, dd, ee, aa, X[14],  7);
   GG(aa, bb, cc, dd, ee, X[11], 13);
   GG(ee, aa, bb, cc, dd, X[ 8], 12);

   /* Round 3 */
   HH(dd, ee, aa, bb, cc, X[ 3], 11);
   HH(cc, dd, ee, aa, bb, X[10], 13);
   HH(bb, cc, dd, ee, aa, X[14],  6);
   HH(aa, bb, cc, dd, ee, X[ 4],  7);
   HH(ee, aa, bb, cc, dd, X[ 9], 14);
   HH(dd, ee, aa, bb, cc, X[15],  9);
   HH(cc, dd, ee, aa, bb, X[ 8], 13);
   HH(bb, cc, dd, ee, aa, X[ 1], 15);
   HH(aa, bb, cc, dd, ee, X[ 2], 14);
   HH(ee, aa, bb, cc, dd, X[ 7],  8);
   HH(dd, ee, aa, bb, cc, X[ 0], 13);
   HH(cc, dd, ee, aa, bb, X[ 6],  6);
   HH(bb, cc, dd, ee, aa, X[13],  5);
   HH(aa, bb, cc, dd, ee, X[11], 12);
   HH(ee, aa, bb, cc, dd, X[ 5],  7);
   HH(dd, ee, aa, bb, cc, X[12],  5);

   /* Round 4 */
   II(cc, dd, ee, aa, bb, X[ 1], 11);
   II(bb, cc, dd, ee, aa, X[ 9], 12);
   II(aa, bb, cc, dd, ee, X[11], 14);
   II(ee, aa, bb, cc, dd, X[10], 15);
   II(dd, ee, aa, bb, cc, X[ 0], 14);
   II(cc, dd, ee, aa, bb, X[ 8], 15);
   II(bb, cc, dd, ee, aa, X[12],  9);
   II(aa, bb, cc, dd, ee, X[ 4],  8);
   II(ee, aa, bb, cc, dd, X[13],  9);
   II(dd, ee, aa, bb, cc, X[ 3], 14);
   II(cc, dd, ee, aa, bb, X[ 7],  5);
   II(bb, cc, dd, ee, aa, X[15],  6);
   II(aa, bb, cc, dd, ee, X[14],  8);
   II(ee, aa, bb, cc, dd, X[ 5],  6);
   II(dd, ee, aa, bb, cc, X[ 6],  5);
   II(cc, dd, ee, aa, bb, X[ 2], 12);

   /* Round 5 */
   JJ(bb, cc, dd, ee, aa, X[ 4],  9);
   JJ(aa, bb, cc, dd, ee, X[ 0], 15);
   JJ(ee, aa, bb, cc, dd, X[ 5],  5);
   JJ(dd, ee, aa, bb, cc, X[ 9], 11);
   JJ(cc, dd, ee, aa, bb, X[ 7],  6);
   JJ(bb, cc, dd, ee, aa, X[12],  8);
   JJ(aa, bb, cc, dd, ee, X[ 2], 13);
   JJ(ee, aa, bb, cc, dd, X[10], 12);
   JJ(dd, ee, aa, bb, cc, X[14],  5);
   JJ(cc, dd, ee, aa, bb, X[ 1], 12);
   JJ(bb, cc, dd, ee, aa, X[ 3], 13);
   JJ(aa, bb, cc, dd, ee, X[ 8], 14);
   JJ(ee, aa, bb, cc, dd, X[11], 11);
   JJ(dd, ee, aa, bb, cc, X[ 6],  8);
   JJ(cc, dd, ee, aa, bb, X[15],  5);
   JJ(bb, cc, dd, ee, aa, X[13],  6);

   /* Parallel round 1 */
   JJJ(aaa, bbb, ccc, ddd, eee, X[ 5],  8);
   JJJ(eee, aaa, bbb, ccc, ddd, X[14],  9);
   JJJ(ddd, eee, aaa, bbb, ccc, X[ 7],  9);
   JJJ(ccc, ddd, eee, aaa, bbb, X[ 0], 11);
   JJJ(bbb, ccc, ddd, eee, aaa, X[ 9], 13);
   JJJ(aaa, bbb, ccc, ddd, eee, X[ 2], 15);
   JJJ(eee, aaa, bbb, ccc, ddd, X[11], 15);
   JJJ(ddd, eee, aaa, bbb, ccc, X[ 4],  5);
   JJJ(ccc, ddd, eee, aaa, bbb, X[13],  7);
   JJJ(bbb, ccc, ddd, eee, aaa, X[ 6],  7);
   JJJ(aaa, bbb, ccc, ddd, eee, X[15],  8);
   JJJ(eee, aaa, bbb, ccc, ddd, X[ 8], 11);
   JJJ(ddd, eee, aaa, bbb, ccc, X[ 1], 14);
   JJJ(ccc, ddd, eee, aaa, bbb, X[10], 14);
   JJJ(bbb, ccc, ddd, eee, aaa, X[ 3], 12);
   JJJ(aaa, bbb, ccc, ddd, eee, X[12],  6);

   /* Parallel round 2 */
   III(eee, aaa, bbb, ccc, ddd, X[ 6],  9); 
   III(ddd, eee, aaa, bbb, ccc, X[11], 13);
   III(ccc, ddd, eee, aaa, bbb, X[ 3], 15);
   III(bbb, ccc, ddd, eee, aaa, X[ 7],  7);
   III(aaa, bbb, ccc, ddd, eee, X[ 0], 12);
   III(eee, aaa, bbb, ccc, ddd, X[13],  8);
   III(ddd, eee, aaa, bbb, ccc, X[ 5],  9);
   III(ccc, ddd, eee, aaa, bbb, X[10], 11);
   III(bbb, ccc, ddd, eee, aaa, X[14],  7);
   III(aaa, bbb, ccc, ddd, eee, X[15],  7);
   III(eee, aaa, bbb, ccc, ddd, X[ 8], 12);
   III(ddd, eee, aaa, bbb, ccc, X[12],  7);
   III(ccc, ddd, eee, aaa, bbb, X[ 4],  6);
   III(bbb, ccc, ddd, eee, aaa, X[ 9], 15);
   III(aaa, bbb, ccc, ddd, eee, X[ 1], 13);
   III(eee, aaa, bbb, ccc, ddd, X[ 2], 11);

   /* Parallel round 3 */
   HHH(ddd, eee, aaa, bbb, ccc, X[15],  9);
   HHH(ccc, ddd, eee, aaa, bbb, X[ 5],  7);
   HHH(bbb, ccc, ddd, eee, aaa, X[ 1], 15);
   HHH(aaa, bbb, ccc, ddd, eee, X[ 3], 11);
   HHH(eee, aaa, bbb, ccc, ddd, X[ 7],  8);
   HHH(ddd, eee, aaa, bbb, ccc, X[14],  6);
   HHH(ccc, ddd, eee, aaa, bbb, X[ 6],  6);
   HHH(bbb, ccc, ddd, eee, aaa, X[ 9], 14);
   HHH(aaa, bbb, ccc, ddd, eee, X[11], 12);
   HHH(eee, aaa, bbb, ccc, ddd, X[ 8], 13);
   HHH(ddd, eee, aaa, bbb, ccc, X[12],  5);
   HHH(ccc, ddd, eee, aaa, bbb, X[ 2], 14);
   HHH(bbb, ccc, ddd, eee, aaa, X[10], 13);
   HHH(aaa, bbb, ccc, ddd, eee, X[ 0], 13);
   HHH(eee, aaa, bbb, ccc, ddd, X[ 4],  7);
   HHH(ddd, eee, aaa, bbb, ccc, X[13],  5);

   /* Parallel round 4 */
   GGG(ccc, ddd, eee, aaa, bbb, X[ 8], 15);
   GGG(bbb, ccc, ddd, eee, aaa, X[ 6],  5);
   GGG(aaa, bbb, ccc, ddd, eee, X[ 4],  8);
   GGG(eee, aaa, bbb, ccc, ddd, X[ 1], 11);
   GGG(ddd, eee, aaa, bbb, ccc, X[ 3], 14);
   GGG(ccc, ddd, eee, aaa, bbb, X[11], 14);
   GGG(bbb, ccc, ddd, eee, aaa, X[15],  6);
   GGG(aaa, bbb, ccc, ddd, eee, X[ 0], 14);
   GGG(eee, aaa, bbb, ccc, ddd, X[ 5],  6);
   GGG(ddd, eee, aaa, bbb, ccc, X[12],  9);
   GGG(ccc, ddd, eee, aaa, bbb, X[ 2], 12);
   GGG(bbb, ccc, ddd, eee, aaa, X[13],  9);
   GGG(aaa, bbb, ccc, ddd, eee, X[ 9], 12);
   GGG(eee, aaa, bbb, ccc, ddd, X[ 7],  5);
   GGG(ddd, eee, aaa, bbb, ccc, X[10], 15);
   GGG(ccc, ddd, eee, aaa, bbb, X[14],  8);

   /* Parallel round 5 */
   FFF(bbb, ccc, ddd, eee, aaa, X[12] ,  8);
   FFF(aaa, bbb, ccc, ddd, eee, X[15] ,  5);
   FFF(eee, aaa, bbb, ccc, ddd, X[10] , 12);
   FFF(ddd, eee, aaa, bbb, ccc, X[ 4] ,  9);
   FFF(ccc, ddd, eee, aaa, bbb, X[ 1] , 12);
   FFF(bbb, ccc, ddd, eee, aaa, X[ 5] ,  5);
   FFF(aaa, bbb, ccc, ddd, eee, X[ 8] , 14);
   FFF(eee, aaa, bbb, ccc, ddd, X[ 7] ,  6);
   FFF(ddd, eee, aaa, bbb, ccc, X[ 6] ,  8);
   FFF(ccc, ddd, eee, aaa, bbb, X[ 2] , 13);
   FFF(bbb, ccc, ddd, eee, aaa, X[13] ,  6);
   FFF(aaa, bbb, ccc, ddd, eee, X[14] ,  5);
   FFF(eee, aaa, bbb, ccc, ddd, X[ 0] , 15);
   FFF(ddd, eee, aaa, bbb, ccc, X[ 3] , 13);
   FFF(ccc, ddd, eee, aaa, bbb, X[ 9] , 11);
   FFF(bbb, ccc, ddd, eee, aaa, X[11] , 11);

   /* Combine results */
   ddd += cc + context->bb;
   context->bb = (context->cc + dd + eee) & 0xffffffff;
   context->cc = (context->dd + ee + aaa) & 0xffffffff;
   context->dd = (context->ee + aa + bbb) & 0xffffffff;
   context->ee = (context->aa + bb + ccc) & 0xffffffff;
   context->aa = (ddd                   ) & 0xffffffff;
}

void ssh_ripemd160_update(void *c, const unsigned char *buf, size_t len)
{
  SshRipeMDContext *context = c;
  unsigned int to_copy = 0;
  unsigned int in_buffer;
  SshUInt32 old_length = context->total_length[0];
  
  in_buffer = old_length % 64;
  
  /* 64-bit addition. */
  context->total_length[0] = (context->total_length[0] + len) & 0xffffffff;
  if (context->total_length[0] < old_length)
    context->total_length[1]++;

  /* This one is a bit complicated loop, but as this seems to be
     the convention (see e.g. sha.c) lets try this way. */
  while (len > 0)
    {
      if (in_buffer == 0 && len >= 64)
        {
          ripemd160_transform(context, buf);
          buf += 64;
          len -= 64;
          continue;
        }
      /* do copy? */
      to_copy = 64 - in_buffer;
      if (to_copy > 0)
        {
          if (to_copy > len)
            to_copy = len;
          memcpy(&context->in[in_buffer],
                 buf, to_copy);
          buf += to_copy;
          len -= to_copy;
          
          in_buffer += to_copy;
          if (in_buffer == 64)
            {
              ripemd160_transform(context, context->in);
              in_buffer = 0;
            }
        }
    }
}

void ssh_ripemd160_final(void *c, unsigned char *digest)
{
  SshRipeMDContext *context = c;
  int padding;
  unsigned char temp = 0x80;
  unsigned int in_buffer; 
  SshUInt32 total_low, total_high;

  total_low = context->total_length[0];
  total_high = context->total_length[1];

  /* Add the extra bit. */
  ssh_ripemd160_update(context, &temp, 1);

  in_buffer = context->total_length[0] % 64;
  padding = (64 - (in_buffer + 9) % 64) % 64;

  if (in_buffer > 56)
    {
      memset(&context->in[in_buffer], 0, 64 - in_buffer);
      padding -= (64 - in_buffer);
      ripemd160_transform(context, context->in);
      in_buffer = 0;
    }

  /* change the byte count to bit count */
  total_high <<= 3;
  total_high += (total_low >> 29);
  total_low <<= 3;

  SSH_PUT_32BIT_LSB_FIRST(context->in + 60, total_high);
  SSH_PUT_32BIT_LSB_FIRST(context->in + 56, total_low);

  if ((64 - in_buffer - 8) > 0)
    {
      memset(&context->in[in_buffer],
             0, 64 - in_buffer - 8);
    }

  ripemd160_transform(context, context->in);

  SSH_PUT_32BIT_LSB_FIRST(digest,      context->aa);
  SSH_PUT_32BIT_LSB_FIRST(digest + 4,  context->bb);
  SSH_PUT_32BIT_LSB_FIRST(digest + 8,  context->cc);
  SSH_PUT_32BIT_LSB_FIRST(digest + 12, context->dd);
  SSH_PUT_32BIT_LSB_FIRST(digest + 16, context->ee);

  memset(context, 0, sizeof(SshRipeMDContext));
}

void ssh_ripemd160_of_buffer(unsigned char digest[20],
                             const unsigned char *buf, size_t len)
{
  SshRipeMDContext context;
  ssh_ripemd160_reset_context(&context);
  ssh_ripemd160_update(&context, buf, len);
  ssh_ripemd160_final(&context, digest);
}

/* The version with 96 bit output. */
void ssh_ripemd160_96_final(void *c, unsigned char *digest)
{
  unsigned char tmp_digest[20];
  ssh_ripemd160_final(c, tmp_digest);
  memcpy(digest, tmp_digest, 12);
}

void ssh_ripemd160_96_of_buffer(unsigned char digest[12],
                                const unsigned char *buf, size_t len)
{
  SshRipeMDContext context;
  ssh_ripemd160_reset_context(&context);
  ssh_ripemd160_update(&context, buf, len);
  ssh_ripemd160_96_final(&context, digest);
}

/* The version with 80 bit output. */
void ssh_ripemd160_80_final(void *c, unsigned char *digest)
{
  unsigned char tmp_digest[20];
  ssh_ripemd160_final(c, tmp_digest);
  memcpy(digest, tmp_digest, 10);
}

void ssh_ripemd160_80_of_buffer(unsigned char digest[10],
                                const unsigned char *buf, size_t len)
{
  SshRipeMDContext context;
  ssh_ripemd160_reset_context(&context);
  ssh_ripemd160_update(&context, buf, len);
  ssh_ripemd160_final(&context, digest);
}


