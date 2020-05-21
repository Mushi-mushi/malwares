/*
 *  twofish.c
 * 
 *  Author: Markku-Juhani Saarinen <mjos@math.jyu.fi>
 * 
 *  Copyright (c) 1998  SSH Communications Security Ltd., Espoo, Finland
 *                      All rights reserved.
 * 
 *  A strict ANSI-C implementation of the twofish cipher.
 *  This implementation is based on the paper "Twofish: A 128-bit Block 
 *  Cipher" by Schneier et al, dated 15 June 1998.
 * 
 */

#include "sshincludes.h"

#include "sshrotate.h"
#include "sshgetput.h"
#include "twofish.h"

/* The twofish context is aprx. 4k */

typedef struct
{
  SshUInt32 s[4][256];                     /* Key-dependant S-Boxes */ 
  SshUInt32 k[40];                         /* Expanded key words    */
  Boolean for_encryption;                  /* encrypt / decrypt     */
} SshTwofishContext;

/* Permutation q0 */
  
const unsigned char ssh_twofish_q0[256] = 
  {      
    0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76, 
    0x9a, 0x92, 0x80, 0x78, 0xe4, 0xdd, 0xd1, 0x38, 
    0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c, 
    0x43, 0x75, 0x37, 0x26, 0xfa, 0x13, 0x94, 0x48, 
    0xf2, 0xd0, 0x8b, 0x30, 0x84, 0x54, 0xdf, 0x23, 
    0x19, 0x5b, 0x3d, 0x59, 0xf3, 0xae, 0xa2, 0x82, 
    0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c, 
    0xa6, 0xeb, 0xa5, 0xbe, 0x16, 0x0c, 0xe3, 0x61, 
    0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b, 
    0xbb, 0x4e, 0x89, 0x6b, 0x53, 0x6a, 0xb4, 0xf1, 
    0xe1, 0xe6, 0xbd, 0x45, 0xe2, 0xf4, 0xb6, 0x66, 
    0xcc, 0x95, 0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7, 
    0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba, 
    0xea, 0x77, 0x39, 0xaf, 0x33, 0xc9, 0x62, 0x71, 
    0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8, 
    0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7, 
    0xa1, 0x1d, 0xaa, 0xed, 0x06, 0x70, 0xb2, 0xd2, 
    0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90, 
    0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c, 0xb1, 0xab, 
    0x9e, 0x9c, 0x52, 0x1b, 0x5f, 0x93, 0x0a, 0xef, 
    0x91, 0x85, 0x49, 0xee, 0x2d, 0x4f, 0x8f, 0x3b,
    0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64, 
    0x2a, 0xce, 0xcb, 0x2f, 0xfc, 0x97, 0x05, 0x7a, 
    0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a, 
    0x28, 0x14, 0x3f, 0x29, 0x88, 0x3c, 0x4c, 0x02, 
    0xb8, 0xda, 0xb0, 0x17, 0x55, 0x1f, 0x8a, 0x7d, 
    0x57, 0xc7, 0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72, 
    0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 
    0x6e, 0x50, 0xde, 0x68, 0x65, 0xbc, 0xdb, 0xf8, 
    0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4, 
    0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00, 
    0x6f, 0x9d, 0x36, 0x42, 0x4a, 0x5e, 0xc1, 0xe0
  };
  
  /* Permutation q1 */
  
const unsigned char ssh_twofish_q1[256] = 
  {  
    0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8, 
    0x4a, 0xd3, 0xe6, 0x6b, 0x45, 0x7d, 0xe8, 0x4b, 
    0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1, 
    0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa, 0x06, 0x3f, 
    0x5e, 0xba, 0xae, 0x5b, 0x8a, 0x00, 0xbc, 0x9d, 
    0x6d, 0xc1, 0xb1, 0x0e, 0x80, 0x5d, 0xd2, 0xd5, 
    0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3, 
    0xb2, 0x73, 0x4c, 0x54, 0x92, 0x74, 0x36, 0x51, 
    0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96, 
    0x6c, 0x42, 0xf7, 0x10, 0x7c, 0x28, 0x27, 0x8c, 
    0x13, 0x95, 0x9c, 0xc7, 0x24, 0x46, 0x3b, 0x70, 
    0xca, 0xe3, 0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8, 
    0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc, 
    0x03, 0x6f, 0x08, 0xbf, 0x40, 0xe7, 0x2b, 0xe2, 
    0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9, 
    0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17, 
    0x66, 0x94, 0xa1, 0x1d, 0x3d, 0xf0, 0xde, 0xb3, 
    0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e, 
    0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76, 0x2a, 0x49, 
    0x81, 0x88, 0xee, 0x21, 0xc4, 0x1a, 0xeb, 0xd9, 
    0xc5, 0x39, 0x99, 0xcd, 0xad, 0x31, 0x8b, 0x01, 
    0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48, 
    0x4f, 0xf2, 0x65, 0x8e, 0x78, 0x5c, 0x58, 0x19, 
    0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64, 
    0xaf, 0x63, 0xb6, 0xfe, 0xf5, 0xb7, 0x3c, 0xa5, 
    0xce, 0xe9, 0x68, 0x44, 0xe0, 0x4d, 0x43, 0x69, 
    0x29, 0x2e, 0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e, 
    0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc, 
    0x22, 0xc9, 0xc0, 0x9b, 0x89, 0xd4, 0xed, 0xab, 
    0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9, 
    0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2, 
    0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xbe, 0x91
};

/* Multiply two numbers over GF(2^8) with irreducible polynomial g */
SshUInt32 ssh_twofish_gf256_mul(SshUInt32 a, SshUInt32 b, SshUInt32 g)
{
  SshUInt32 x;

  x = 0;  
  for (; b; b >>= 1)
    {
      if (b & 1)
        x ^= a;
      a <<= 1;
      if (a & 0x100)
        a ^= g;
    }
  return x;
}

/*
 * These are the "h" functions of key schedule (separated by input byte) 
 * l is an array of k bytes. 
 */
  
SshUInt32 ssh_twofish_keysched_h0(unsigned char x, unsigned char *l, int k) 
{
  SshUInt32 y;
  
  if (k == 4)
    x = ssh_twofish_q1[x] ^ l[3];
  if (k >= 3)
    x = ssh_twofish_q1[x] ^ l[2];
  x = ssh_twofish_q0[x] ^ l[1];
  x = ssh_twofish_q0[x] ^ l[0];
  x = ssh_twofish_q1[x];
  y = ssh_twofish_gf256_mul(x, 0xef, 0x169);
  y = (y << 24) | (y << 16) | 
    (ssh_twofish_gf256_mul(x, 0x5b, 0x169) << 8) | x;
  return y;
}
                          
SshUInt32 ssh_twofish_keysched_h1(unsigned char x, unsigned char *l, int k) 
{
  SshUInt32 y;
  
  if (k == 4)
    x = ssh_twofish_q0[x] ^ l[3];
  if (k >= 3)
    x = ssh_twofish_q1[x] ^ l[2];
  x = ssh_twofish_q1[x] ^ l[1];
  x = ssh_twofish_q0[x] ^ l[0];
  x = ssh_twofish_q0[x];
  y = ssh_twofish_gf256_mul(x, 0xef, 0x169);
  y = y | (y << 8) | (ssh_twofish_gf256_mul(x, 0x5b, 0x169) << 16) | 
    (x << 24);
  return y;
}

SshUInt32 ssh_twofish_keysched_h2(unsigned char x, unsigned char *l, int k) 
{
  SshUInt32 y;
  
  if (k == 4)
    x = ssh_twofish_q0[x] ^ l[3];
  if (k >= 3)
    x = ssh_twofish_q0[x] ^ l[2];
  x = ssh_twofish_q0[x] ^ l[1];
  x = ssh_twofish_q1[x] ^ l[0];
  x = ssh_twofish_q1[x];
  y = ssh_twofish_gf256_mul(x, 0xef, 0x169);
  y = (y << 24) | (y << 8) | 
    ssh_twofish_gf256_mul(x, 0x5b, 0x169) | (x << 16);
  return y;
}

SshUInt32 ssh_twofish_keysched_h3(unsigned char x, unsigned char *l, int k) 
{
  SshUInt32 y;
  
  if (k == 4)
    x = ssh_twofish_q1[x] ^ l[3];
  if (k >= 3)
    x = ssh_twofish_q0[x] ^ l[2];
  x = ssh_twofish_q1[x] ^ l[1];
  x = ssh_twofish_q1[x] ^ l[0];
  x = ssh_twofish_q0[x];
  y = ssh_twofish_gf256_mul(x, 0x5b, 0x169);
  y = y | (y << 24) | 
    (ssh_twofish_gf256_mul(x, 0xef, 0x169) << 16) | (x << 8);
  return y;
}
                             
/*
 *  Initialize the twofish context.
 *  (key scheduling has not been optimized for performance)
 * 
 *  context          a pointer to a SshTwofishContext
 *  key              key material
 *  keylen           length of the key in bytes (1..32)
 *  for_encryption   encryption / decryption 
 */

Boolean ssh_twofish_init(void *context,
                         const unsigned char *key, 
                         size_t keylen,
                         Boolean for_encryption)
{
  SshTwofishContext *ctx;
  unsigned char s[4][4], me[4][4], mo[4][4];
  int i, j, k, kl, klsub;
  SshUInt32 a, b;
  
  /* the rs matrix (transposed) */
  
  const unsigned char rs_matrix[8][4] = 
    {
        { 0x01, 0xa4, 0x02, 0xa4 },
        { 0xa4, 0x56, 0xa1, 0x55 },
        { 0x55, 0x82, 0xfc, 0x87 },
        { 0x87, 0xf3, 0xc1, 0x5a },
        { 0x5a, 0x1e, 0x47, 0x58 },
        { 0x58, 0xc6, 0xae, 0xdb },
        { 0xdb, 0x68, 0x3d, 0x9e },
        { 0x9e, 0xe5, 0x19, 0x03 }
    };

  /* Clear the context */

  ctx = context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->for_encryption = for_encryption;
 
  if (keylen > 32)
    keylen = 32;
  
  memset(s, 0, sizeof(s));  
  kl = (keylen + 7) >> 3;
  if (kl > 4)
    kl = 4;
  klsub = ((keylen - 1) & 7) + 1;  
  
  /* generate the key for s-box generation */
  
  for (i = 0; i < kl; i++)
    for (j = 0; j < 8; j++)
      for (k = 0; k < 4; k++)
        s[k][kl - i - 1] ^= ssh_twofish_gf256_mul(rs_matrix[j][k], 
                                              key[j + (i << 3)],
                                              0x14d);
  /* Compute the S-boxes */
  
  if (kl < 2)
    kl = 2;
  for (i = 0; i < 0x100; i++)
    {
      ctx->s[0][i] = ssh_twofish_keysched_h0(i, s[0], kl);
      ctx->s[1][i] = ssh_twofish_keysched_h1(i, s[1], kl);
      ctx->s[2][i] = ssh_twofish_keysched_h2(i, s[2], kl);
      ctx->s[3][i] = ssh_twofish_keysched_h3(i, s[3], kl);      
    }
  
  /* Compute the round keys */

  memset(me, 0, sizeof(me));
  memset(mo, 0, sizeof(mo));  
  
  for (i = 0; i < keylen; i++)
    if (i & 4)
      mo[i & 3][i >> 3] = key[i];
    else
      me[i & 3][i >> 3] = key[i];
  
  for (i = 0; i < 40; i += 2)
    {
      a = ssh_twofish_keysched_h0(i, me[0], kl) ^ 
        ssh_twofish_keysched_h1(i, me[1], kl) ^ 
        ssh_twofish_keysched_h2(i, me[2], kl) ^ 
        ssh_twofish_keysched_h3(i, me[3], kl);
      b = ssh_twofish_keysched_h0(i + 1, mo[0], kl) ^ 
        ssh_twofish_keysched_h1(i + 1, mo[1], kl) ^ 
        ssh_twofish_keysched_h2(i + 1, mo[2], kl) ^ 
        ssh_twofish_keysched_h3(i + 1, mo[3], kl);
      b = SSH_ROL32(b, 8);
      a += b;
      ctx->k[i] = a;
      a += b;
      a = SSH_ROL32(a, 9);
      ctx->k[i + 1] = a;      
    }
  
  /* Clear out sensitive data */
  
  memset(s, 0, sizeof(s));
  memset(me, 0, sizeof(me));
  memset(mo, 0, sizeof(mo));

  return TRUE;
}

/*
 *  encrypt a single block using twofish
 */

void ssh_twofish_encrypt(SshUInt32 *in, SshUInt32 *out, 
                     const SshUInt32 *k, SshUInt32 s[4][256])
{
  int i;
  SshUInt32 l0, l1, r0, r1, t0, t1;

  l0 = in[0] ^ k[0];
  l1 = in[1] ^ k[1];
  r0 = in[2] ^ k[2];
  r1 = in[3] ^ k[3];
  
  for (i = 8; i < 40; i += 4)                                         
    {                                                                   
      t0 = s[0][l0 & 0xff] ^ s[1][(l0 >> 8) & 0xff] ^     
        s[2][(l0 >> 16) & 0xff] ^ s[3][l0 >> 24];         
      t1 = s[0][l1 >> 24] ^ s[1][l1 & 0xff] ^             
        s[2][(l1 >> 8) & 0xff] ^ s[3][(l1 >> 16) & 0xff]; 
      t0 += t1;                                                            
      t1 += t0;
      t0 += k[i];
      t1 += k[i + 1];
      r0 ^= t0;
      r0 = SSH_ROR32(r0, 1);
      r1 = SSH_ROL32(r1, 1);      
      r1 ^= t1;                 
      
      t0 = s[0][r0 & 0xff] ^ s[1][(r0 >> 8) & 0xff] ^
        s[2][(r0 >> 16) & 0xff] ^ s[3][r0 >> 24];
      t1 = s[0][r1 >> 24] ^ s[1][r1 & 0xff] ^
        s[2][(r1 >> 8) & 0xff] ^ s[3][(r1 >> 16) & 0xff];      
      t0 += t1;
      t1 += t0;
      t0 += k[i + 2];
      t1 += k[i + 3];
      l0 ^= t0;
      l0 = SSH_ROR32(l0, 1);
      l1 = SSH_ROL32(l1, 1);
      l1 ^= t1;                   
    }
  
  out[0] = r0 ^ k[4];
  out[1] = r1 ^ k[5];
  out[2] = l0 ^ k[6];
  out[3] = l1 ^ k[7];
}

/*
 *  decrypt a single block using twofish 
 */

void ssh_twofish_decrypt(SshUInt32 *in, SshUInt32 *out,
                     const SshUInt32 *k, SshUInt32 s[4][256])
{
  int i;
  SshUInt32 l0, l1, r0, r1, t0, t1;
  
  r0 = in[0] ^ k[4];
  r1 = in[1] ^ k[5];
  l0 = in[2] ^ k[6];
  l1 = in[3] ^ k[7];

  for (i = 36; i >= 8; i -= 4)                                         
    { 
      t0 = s[0][r0 & 0xff] ^ s[1][(r0 >> 8) & 0xff] ^
        s[2][(r0 >> 16) & 0xff] ^ s[3][r0 >> 24];
      t1 = s[0][r1 >> 24] ^ s[1][r1 & 0xff] ^
        s[2][(r1 >> 8) & 0xff] ^ s[3][(r1 >> 16) & 0xff];      
      t0 += t1;
      t1 += t0;
      t0 += k[i + 2];
      t1 += k[i + 3];
      l0 = SSH_ROL32(l0, 1);
      l0 ^= t0;
      l1 ^= t1;                
      l1 = SSH_ROR32(l1, 1);
      
      t0 = s[0][l0 & 0xff] ^ s[1][(l0 >> 8) & 0xff] ^     
        s[2][(l0 >> 16) & 0xff] ^ s[3][l0 >> 24];         
      t1 = s[0][l1 >> 24] ^ s[1][l1 & 0xff] ^             
        s[2][(l1 >> 8) & 0xff] ^ s[3][(l1 >> 16) & 0xff]; 
      t0 += t1;                                                            
      t1 += t0;
      t0 += k[i + 0];
      t1 += k[i + 1];
      r0 = SSH_ROL32(r0, 1);
      r0 ^= t0;
      r1 ^= t1;                 
      r1 = SSH_ROR32(r1, 1);      
    }

  out[0] = l0 ^ k[0];
  out[1] = l1 ^ k[1];
  out[2] = r0 ^ k[2];
  out[3] = r1 ^ k[3];
}

/*
 *  handle different encryption modes 
 */

/* Gets the size of twofish context. */

size_t ssh_twofish_ctxsize()
{
  return (sizeof(SshTwofishContext));  
}

/* Encrypt/decrypt in electronic code book mode. */
void ssh_twofish_ecb(void *context, unsigned char *dest,
                 const unsigned char *src, size_t len,
                 unsigned char *iv)
{
  SshTwofishContext *ctx;
  SshUInt32 v[4];

  ctx = (SshTwofishContext *) context;

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          v[0] = SSH_GET_32BIT_LSB_FIRST(src);
          v[1] = SSH_GET_32BIT_LSB_FIRST(src + 4);
          v[2] = SSH_GET_32BIT_LSB_FIRST(src + 8);
          v[3] = SSH_GET_32BIT_LSB_FIRST(src + 12);

          ssh_twofish_encrypt(v, v, ctx->k, ctx->s);

          SSH_PUT_32BIT_LSB_FIRST(dest, v[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, v[1]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 8, v[2]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 12, v[3]);

          len -= 16;
          src += 16;
          dest += 16;
        }
    }
  else
    {
      while (len > 0)
        {
          v[0] = SSH_GET_32BIT_LSB_FIRST(src);
          v[1] = SSH_GET_32BIT_LSB_FIRST(src + 4);
          v[2] = SSH_GET_32BIT_LSB_FIRST(src + 8);
          v[3] = SSH_GET_32BIT_LSB_FIRST(src + 12);

          ssh_twofish_decrypt(v, v, ctx->k, ctx->s);
          
          SSH_PUT_32BIT_LSB_FIRST(dest, v[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, v[1]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 8, v[2]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 12, v[3]);
      
          len -= 16;
          src += 16;
          dest += 16;
        }
    }
}


/* Encrypt/decrypt in cipher block chaining mode. */
void ssh_twofish_cbc(void *context, unsigned char *dest,
                 const unsigned char *src, size_t len,
                 unsigned char *iv_arg)
{
  SshTwofishContext *ctx;
  SshUInt32 v[4], c[4], iv[4];
  
  ctx = (SshTwofishContext *) context;  
  iv[0] = SSH_GET_32BIT_LSB_FIRST(iv_arg);
  iv[1] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 4);
  iv[2] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 8);
  iv[3] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 12);
  
  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          iv[0] ^= SSH_GET_32BIT_LSB_FIRST(src);
          iv[1] ^= SSH_GET_32BIT_LSB_FIRST(src + 4);
          iv[2] ^= SSH_GET_32BIT_LSB_FIRST(src + 8);
          iv[3] ^= SSH_GET_32BIT_LSB_FIRST(src + 12);

          ssh_twofish_encrypt(iv, iv, ctx->k, ctx->s);
          
          SSH_PUT_32BIT_LSB_FIRST(dest, iv[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, iv[1]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 8, iv[2]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 12, iv[3]);

          src += 16;
          dest += 16;
          len -= 16;
        }      
    }
  else
    {
      while (len > 0)
        {
          c[0] = SSH_GET_32BIT_LSB_FIRST(src);
          c[1] = SSH_GET_32BIT_LSB_FIRST(src + 4);
          c[2] = SSH_GET_32BIT_LSB_FIRST(src + 8);
          c[3] = SSH_GET_32BIT_LSB_FIRST(src + 12);

          ssh_twofish_decrypt(c, v, ctx->k, ctx->s);
                          
          v[0] ^= iv[0];
          iv[0] = c[0];
          v[1] ^= iv[1];
          iv[1] = c[1];
          v[2] ^= iv[2];
          iv[2] = c[2];
          v[3] ^= iv[3];
          iv[3] = c[3];
                
          SSH_PUT_32BIT_LSB_FIRST(dest, v[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, v[1]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 8, v[2]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 12, v[3]);
          
          src += 16;
          dest += 16;
          len -= 16;      
        }
    }  
  
  SSH_PUT_32BIT_LSB_FIRST(iv_arg, iv[0]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 4, iv[1]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 8, iv[2]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 12, iv[3]);
  
  memset(v, 0, sizeof(v));
  memset(iv, 0, sizeof(iv));  
}


/* Encrypt/decrypt in output feedback mode. */
void ssh_twofish_ofb(void *context, unsigned char *dest,
                 const unsigned char *src, size_t len,
                 unsigned char *iv_arg)
{
  SshTwofishContext *ctx;
  SshUInt32 t, iv[4];
  
  ctx = (SshTwofishContext *) context;  

  iv[0] = SSH_GET_32BIT_LSB_FIRST(iv_arg);
  iv[1] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 4);
  iv[2] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 8);
  iv[3] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 12);

  while (len > 0)
    {      
      ssh_twofish_encrypt(iv, iv, ctx->k, ctx->s);

      t = SSH_GET_32BIT_LSB_FIRST(src) ^ iv[0];
      SSH_PUT_32BIT_LSB_FIRST(dest, t);      
      t = SSH_GET_32BIT_LSB_FIRST(src + 4) ^ iv[1];
      SSH_PUT_32BIT_LSB_FIRST(dest + 4, t);
      t = SSH_GET_32BIT_LSB_FIRST(src + 8) ^ iv[2];
      SSH_PUT_32BIT_LSB_FIRST(dest + 8, t);
      t = SSH_GET_32BIT_LSB_FIRST(src + 12) ^ iv[3];
      SSH_PUT_32BIT_LSB_FIRST(dest + 12, t);

      src += 16;
      dest += 16;
      len -= 16;      
    }      
  
  SSH_PUT_32BIT_LSB_FIRST(iv_arg, iv[0]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 4, iv[1]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 8, iv[2]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 12, iv[3]);

  memset(iv, 0, sizeof(iv));
}


/* Encrypt/decrypt in cipher feedback mode */

void ssh_twofish_cfb(void *context, unsigned char *dest,
                 const unsigned char *src, size_t len,
                 unsigned char *iv_arg)
{
  SshTwofishContext *ctx;
  SshUInt32 t, iv[4];
  
  ctx = (SshTwofishContext *) context;  

  iv[0] = SSH_GET_32BIT_LSB_FIRST(iv_arg);
  iv[1] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 4);
  iv[2] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 8);
  iv[3] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 12);
  
  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          ssh_twofish_encrypt(iv, iv, ctx->k, ctx->s);

          iv[0] ^= SSH_GET_32BIT_LSB_FIRST(src);
          SSH_PUT_32BIT_LSB_FIRST(dest, iv[0]);           
          iv[1] ^= SSH_GET_32BIT_LSB_FIRST(src + 4);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, iv[1]);     
          iv[2] ^= SSH_GET_32BIT_LSB_FIRST(src + 8);
          SSH_PUT_32BIT_LSB_FIRST(dest + 8, iv[2]);     
          iv[3] ^= SSH_GET_32BIT_LSB_FIRST(src + 12);
          SSH_PUT_32BIT_LSB_FIRST(dest + 12, iv[3]);    
                    
          src += 16;
          dest += 16;
          len -= 16;
        }
    }
  else
    {      
      while (len > 0)
        {
          ssh_twofish_encrypt(iv, iv, ctx->k, ctx->s);        
                  
          t = SSH_GET_32BIT_LSB_FIRST(src);     
          SSH_PUT_32BIT_LSB_FIRST(dest, iv[0] ^ t);
          iv[0] = t;
          t = SSH_GET_32BIT_LSB_FIRST(src + 4); 
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, iv[1] ^ t);
          iv[1] = t;
          t = SSH_GET_32BIT_LSB_FIRST(src + 8); 
          SSH_PUT_32BIT_LSB_FIRST(dest + 8, iv[2] ^ t);
          iv[2] = t;
          t = SSH_GET_32BIT_LSB_FIRST(src + 12);        
          SSH_PUT_32BIT_LSB_FIRST(dest + 12, iv[3] ^ t);
          iv[3] = t;

          src += 16;
          dest += 16;
          len -= 16;
        }   
    }
    
  SSH_PUT_32BIT_LSB_FIRST(iv_arg, iv[0]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 4, iv[1]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 8, iv[2]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 12, iv[3]);

  memset(iv, 0, sizeof(iv));
}
