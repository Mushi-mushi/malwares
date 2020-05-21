/*

sha.c

SHA - Secure Hash Algorithm implementation

Author: Antti Huima <huima@ssh.fi>

Copyright (C) 1996 SSH Security Communications Oy, Espoo, Finland
                   All rights reserved

                   */

/*
 * $Id: sha.c,v 1.15 1998/10/10 06:54:15 mkojo Exp $
 * $Log: sha.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypti.h"
#include "sha.h"
#include "sshgetput.h"

/* Define SHA-1 in transparent way. */
const SshHashDef ssh_hash_sha_def =
{
  /* Name of the hash function. */
  "sha1",
  /* ASN.1 Object identifier (not defined) */
  "1.3.14.3.2.26",
  /* ISO/IEC dedicated hash identifier. */
  0x33,
  /* Digest size. */
  20,
  /* Input block length. */
  64,
  /* Context size */
  ssh_sha_ctxsize,
  /* Reset function, between long usage of one context. */
  ssh_sha_reset_context,
  /* Update function */
  ssh_sha_update,
  /* Final */
  ssh_sha_final
};

/* Define SHA-1 in transparent way. */
const SshHashDef ssh_hash_sha_96_def =
{
  /* Name of the hash function. */
  "sha1-96",
  /* ASN.1 Object identifier (not defined) */
  NULL,
  /* ISO/IEC dedicated hash identifier. */
  0, /* None */
  /* Digest size. */
  12,
  /* Input block length. */
  64,
  /* Context size */
  ssh_sha_ctxsize,
  /* Reset function, between long usage of one context. */
  ssh_sha_reset_context,
  /* Update function */
  ssh_sha_update,
  /* Final */
  ssh_sha_96_final
};

/* Define SHA-1 in transparent way. */
const SshHashDef ssh_hash_sha_80_def =
{
  /* Name of the hash function. */
  "sha1-80",
  /* ASN.1 Object identifier (not defined) */
  NULL,
  /* ISO/IEC dedicated hash identifier. */
  0, /* None */
  /* Digest size. */
  10,
  /* Input block length. */
  64,
  /* Context size */
  ssh_sha_ctxsize,
  /* Reset function, between long usage of one context. */
  ssh_sha_reset_context,
  /* Update function */
  ssh_sha_update,
  /* Final */
  ssh_sha_80_final
};

typedef struct {
  SshUInt32 A, B, C, D, E;
  unsigned char in[64];
  SshUInt32 total_length[2];
} SshSHAContext;

/* Functions are (with nicer notation, to me atleast):

   f1 =
     xy + ~xz = z ^ x(y ^ z)
   f2 =
     x ^ y ^ z
   f3 =
     xy + xz + yz = x(y + z) + yz
   f4 =
     x ^ y ^ z.
  */

#define F1(x,y,z) \
            ((z ^ (x & (y ^ z))) + 0x5a827999L)
#define F2(x,y,z)   ((x ^ y ^ z) + 0x6ed9eba1L)
#define F3(x,y,z) \
      (((x & (y | z)) | (y & z)) + 0x8f1bbcdcL)
#define F4(x,y,z)   ((x ^ y ^ z) + 0xca62c1d6L)

#define ROLL_1(x)  ((((x) << 1) | ((x) >> 31)) & 0xFFFFFFFFL)
#define ROLL_30(x) ((((x) << 30) | ((x) >> 2)) & 0xFFFFFFFFL)
#define ROLL_5(x)  ((((x) << 5) | ((x) >> 27)) & 0xFFFFFFFFL)

void ssh_sha_reset_context(void *c)
{
  SshSHAContext *context = c;
  context->A = 0x67452301L;
  context->B = 0xefcdab89L;
  context->C = 0x98badcfeL;
  context->D = 0x10325476L;
  context->E = 0xc3d2e1f0L;
  context->total_length[0] = 0;
  context->total_length[1] = 0;
}

size_t ssh_sha_ctxsize()
{
  return sizeof(SshSHAContext);
}

static void sha_transform(SshSHAContext *context, const unsigned char *block)
{
  static SshUInt32 W[80];
  SshUInt32 a, b, c, d, e, f;

  a = context->A;
  b = context->B;
  c = context->C;
  d = context->D;
  e = context->E;

#if 1
  
  /* Unroll as much as one can, removing unneccessary copying etc.

     What actually happens is that the compiler must interleave all these
     operations some efficient way. On processors with only few registers
     it might be better to implement the table generation before actual
     'nonlinear' operations. On Intel processors that might be the case,
     although one never knows without trying. */

#define TABLE_IN(i)                  \
  W[i] = SSH_GET_32BIT(block); block += 4;

#define TABLE_MORE(i, t)                           \
  t = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]; \
  W[i] = ROLL_1(t);                                                  

#define NONLINEAR1(F, a, b, c, d, e, f, i) \
  TABLE_IN(i);         \
  f = ROLL_5(a);       \
  f += F(b, c, d);     \
  b = ROLL_30(b);      \
  f += e + W[i];

#define NONLINEAR2(F, a, b, c, d, e, f, i) \
  TABLE_MORE(i, f);    \
  f = ROLL_5(a);       \
  f += F(b, c, d);     \
  b = ROLL_30(b);      \
  f += e + W[i];
  
  NONLINEAR1(F1, a, b, c, d, e, f,  0);
  NONLINEAR1(F1, f, a, b, c, d, e,  1);
  NONLINEAR1(F1, e, f, a, b, c, d,  2);
  NONLINEAR1(F1, d, e, f, a, b, c,  3);
  NONLINEAR1(F1, c, d, e, f, a, b,  4);
  NONLINEAR1(F1, b, c, d, e, f, a,  5);
  NONLINEAR1(F1, a, b, c, d, e, f,  6);
  NONLINEAR1(F1, f, a, b, c, d, e,  7);
  NONLINEAR1(F1, e, f, a, b, c, d,  8);
  NONLINEAR1(F1, d, e, f, a, b, c,  9);
  NONLINEAR1(F1, c, d, e, f, a, b, 10);
  NONLINEAR1(F1, b, c, d, e, f, a, 11);
  NONLINEAR1(F1, a, b, c, d, e, f, 12);
  NONLINEAR1(F1, f, a, b, c, d, e, 13);
  NONLINEAR1(F1, e, f, a, b, c, d, 14);
  NONLINEAR1(F1, d, e, f, a, b, c, 15);
  NONLINEAR2(F1, c, d, e, f, a, b, 16);
  NONLINEAR2(F1, b, c, d, e, f, a, 17);
  NONLINEAR2(F1, a, b, c, d, e, f, 18);
  NONLINEAR2(F1, f, a, b, c, d, e, 19);
  
  NONLINEAR2(F2, e, f, a, b, c, d, 20);
  NONLINEAR2(F2, d, e, f, a, b, c, 21);
  NONLINEAR2(F2, c, d, e, f, a, b, 22);
  NONLINEAR2(F2, b, c, d, e, f, a, 23);
  NONLINEAR2(F2, a, b, c, d, e, f, 24);
  NONLINEAR2(F2, f, a, b, c, d, e, 25);
  NONLINEAR2(F2, e, f, a, b, c, d, 26);
  NONLINEAR2(F2, d, e, f, a, b, c, 27);
  NONLINEAR2(F2, c, d, e, f, a, b, 28);
  NONLINEAR2(F2, b, c, d, e, f, a, 29);
  NONLINEAR2(F2, a, b, c, d, e, f, 30);
  NONLINEAR2(F2, f, a, b, c, d, e, 31);
  NONLINEAR2(F2, e, f, a, b, c, d, 32);
  NONLINEAR2(F2, d, e, f, a, b, c, 33);
  NONLINEAR2(F2, c, d, e, f, a, b, 34);
  NONLINEAR2(F2, b, c, d, e, f, a, 35);
  NONLINEAR2(F2, a, b, c, d, e, f, 36);
  NONLINEAR2(F2, f, a, b, c, d, e, 37);
  NONLINEAR2(F2, e, f, a, b, c, d, 38);
  NONLINEAR2(F2, d, e, f, a, b, c, 39);
  
  NONLINEAR2(F3, c, d, e, f, a, b, 40);
  NONLINEAR2(F3, b, c, d, e, f, a, 41);
  NONLINEAR2(F3, a, b, c, d, e, f, 42);
  NONLINEAR2(F3, f, a, b, c, d, e, 43);
  NONLINEAR2(F3, e, f, a, b, c, d, 44);
  NONLINEAR2(F3, d, e, f, a, b, c, 45);
  NONLINEAR2(F3, c, d, e, f, a, b, 46);
  NONLINEAR2(F3, b, c, d, e, f, a, 47);
  NONLINEAR2(F3, a, b, c, d, e, f, 48);
  NONLINEAR2(F3, f, a, b, c, d, e, 49);
  NONLINEAR2(F3, e, f, a, b, c, d, 50);
  NONLINEAR2(F3, d, e, f, a, b, c, 51);
  NONLINEAR2(F3, c, d, e, f, a, b, 52);
  NONLINEAR2(F3, b, c, d, e, f, a, 53);
  NONLINEAR2(F3, a, b, c, d, e, f, 54);
  NONLINEAR2(F3, f, a, b, c, d, e, 55);
  NONLINEAR2(F3, e, f, a, b, c, d, 56);
  NONLINEAR2(F3, d, e, f, a, b, c, 57);
  NONLINEAR2(F3, c, d, e, f, a, b, 58);
  NONLINEAR2(F3, b, c, d, e, f, a, 59);
  
  NONLINEAR2(F4, a, b, c, d, e, f, 60);
  NONLINEAR2(F4, f, a, b, c, d, e, 61);
  NONLINEAR2(F4, e, f, a, b, c, d, 62);
  NONLINEAR2(F4, d, e, f, a, b, c, 63);
  NONLINEAR2(F4, c, d, e, f, a, b, 64);
  NONLINEAR2(F4, b, c, d, e, f, a, 65);
  NONLINEAR2(F4, a, b, c, d, e, f, 66);
  NONLINEAR2(F4, f, a, b, c, d, e, 67);
  NONLINEAR2(F4, e, f, a, b, c, d, 68);
  NONLINEAR2(F4, d, e, f, a, b, c, 69);
  NONLINEAR2(F4, c, d, e, f, a, b, 70);
  NONLINEAR2(F4, b, c, d, e, f, a, 71);
  NONLINEAR2(F4, a, b, c, d, e, f, 72);
  NONLINEAR2(F4, f, a, b, c, d, e, 73);
  NONLINEAR2(F4, e, f, a, b, c, d, 74);
  NONLINEAR2(F4, d, e, f, a, b, c, 75);
  NONLINEAR2(F4, c, d, e, f, a, b, 76);
  NONLINEAR2(F4, b, c, d, e, f, a, 77);
  NONLINEAR2(F4, a, b, c, d, e, f, 78);
  NONLINEAR2(F4, f, a, b, c, d, e, 79);

  /* Remember the correct order of rotated variables. */
  context->A += e;
  context->B += f;
  context->C += a;
  context->D += b;
  context->E += c;
  
#else
  
  /*

    Inefficient version (but actually not that slow, only slightly slower
    than the above one).

    */

  /* t is not currently defined so you need to define that if want to use
     these routines. */
  
  for (t = 0; t < 16; t++)
    {
      W[t] = SSH_GET_32BIT(block);
      block += 4;
    }

  for (t = 16; t < 80; t++)
    {
      f = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16];
      W[t] = ROLL_1(f);
    }

  for (t = 0; t < 80; t++)
    {
      f = ROLL_5(a);

      if (t < 40)
        {
          if (t < 20)
            f += F1(b, c, d);
          else
            f += F2(b, c, d);
        }
      else
        {
          if (t < 60)
            f += F3(b, c, d);
          else
            f += F4(b, c, d);
        }

      f += e + W[t];
      f &= 0xFFFFFFFFL;
      
      e = d;
      d = c;
      c = ROLL_30(b);
      b = a;
      a = f;
    }
  
  context->A += a;
  context->B += b;
  context->C += c;
  context->D += d;
  context->E += e;

#endif /* unrolled. */

  context->A &= 0xFFFFFFFFL;
  context->B &= 0xFFFFFFFFL;
  context->C &= 0xFFFFFFFFL;
  context->D &= 0xFFFFFFFFL;
  context->E &= 0xFFFFFFFFL;
}

void ssh_sha_update(void *c, const unsigned char *buf, size_t len)
{
  SshSHAContext *context = c;
  unsigned int to_copy = 0;
  unsigned int in_buffer;

  SshUInt32 old_length = context->total_length[0];
  
  in_buffer = old_length % 64;

  context->total_length[0] += len;
  context->total_length[0] &= 0xFFFFFFFFL;

  if (context->total_length[0] < old_length) /* carry */
    context->total_length[1]++;    

  while (len > 0)
    {
      if (in_buffer == 0 && len >= 64)
        {
          sha_transform(context, buf);
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
              sha_transform(context, context->in);
              in_buffer = 0;
            }
        }
    }
}

void ssh_sha_final(void *c, unsigned char *digest)
{
  SshSHAContext *context = c;
  int padding;
  unsigned char temp = 0x80;
  unsigned int in_buffer; 
  SshUInt32 total_low, total_high;

  total_low = context->total_length[0];
  total_high = context->total_length[1];
  
  ssh_sha_update(context, &temp, 1);

  in_buffer = context->total_length[0] % 64;
  padding = (64 - (in_buffer + 9) % 64) % 64;

  if (in_buffer > 56)
    {
      memset(&context->in[in_buffer], 0, 64 - in_buffer);
      padding -= (64 - in_buffer);
      sha_transform(context, context->in);
      in_buffer = 0;
    }

  /* change the byte count to bits count */
  total_high <<= 3;
  total_high += (total_low >> 29);
  total_low <<= 3;

  SSH_PUT_32BIT(context->in + 56, total_high);
  SSH_PUT_32BIT(context->in + 60, total_low);

  if ((64 - in_buffer - 8) > 0)
    {
      memset(&context->in[in_buffer],
             0, 64 - in_buffer - 8);
    }

  sha_transform(context, context->in);

  SSH_PUT_32BIT(digest,      context->A);
  SSH_PUT_32BIT(digest + 4,  context->B);
  SSH_PUT_32BIT(digest + 8,  context->C);
  SSH_PUT_32BIT(digest + 12, context->D);
  SSH_PUT_32BIT(digest + 16, context->E);

  memset(context, 0, sizeof(SshSHAContext));
}

void ssh_sha_of_buffer(unsigned char digest[20],
                       const unsigned char *buf, size_t len)
{
  SshSHAContext context;
  ssh_sha_reset_context(&context);
  ssh_sha_update(&context, buf, len);
  ssh_sha_final(&context, digest);
}

/* Extra routines. */
void ssh_sha_96_final(void *c, unsigned char *digest)
{
  unsigned char tmp_digest[20];
  ssh_sha_final(c, tmp_digest);
  memcpy(digest, tmp_digest, 12);
}

void ssh_sha_96_of_buffer(unsigned char digest[12],
                          const unsigned char *buf, size_t len)
{
  SshSHAContext context;
  ssh_sha_reset_context(&context);
  ssh_sha_update(&context, buf, len);
  ssh_sha_96_final(&context, digest);
}

void ssh_sha_80_final(void *c, unsigned char *digest)
{
  unsigned char tmp_digest[20];
  ssh_sha_final(c, tmp_digest);
  memcpy(digest, tmp_digest, 10);
}

void ssh_sha_80_of_buffer(unsigned char digest[10],
                          const unsigned char *buf, size_t len)
{
  SshSHAContext context;
  ssh_sha_reset_context(&context);
  ssh_sha_update(&context, buf, len);
  ssh_sha_80_final(&context, digest);
}
