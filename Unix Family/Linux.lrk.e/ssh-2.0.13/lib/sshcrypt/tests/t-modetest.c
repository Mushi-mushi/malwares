/*

   t-modetest.c

   Author: Markku-Juhani Saarinen <mjos@ssh.fi>
   Date:   11 Oct 1998

   Copyright (c) 1998  SSH Communications Security Ltd., Espoo, Finland
   All rights reserved.

   Tests that CBC, CFB, and OFB encryption and decryption modes are 
   correctly implemented by simulating them with ECB and comparing results. 
   
 */

#include "sshincludes.h"
#include "sshcrypt.h"

#define TEST_BLOCK 100000
#define MAX_PIECE 1000

/* global variables */

Boolean verbose;     
size_t blocklen;
size_t keylen;
unsigned char key[256];
unsigned char iv[256];
unsigned char blk1[256];
unsigned char blk2[256];

SshCipher ecb_enc;
SshCipher mode_enc; 
SshCipher mode_dec; 

unsigned char *pt;
unsigned char *ct;
unsigned char *ot;

/* free the ciphers */

void ecb_free(void)
{
  ssh_cipher_free(ecb_enc);
  ssh_cipher_free(mode_enc);
  ssh_cipher_free(mode_dec);
}

/* allocate the cipher and a corresponding ecb mode cipher */

void ecb_alloc(char *name)
{
  int i, l;
  char ecb_name[256];
  SshCryptoStatus st;

  /* get the key length */

  keylen = ssh_cipher_get_key_length(name);
  if (verbose)
    printf("  key length = %d%s\n", keylen,
           keylen == 0 ? ", using 16" : "");
  if (keylen == 0)
    keylen = 16;
  if (keylen > sizeof(key))
    keylen = sizeof(key);
  for (i = 0; i < keylen; i++)
    key[i] = rand();

  strncpy(ecb_name, name, sizeof(ecb_name));
  l = strlen(name);
  if (l <= 5)
    ssh_fatal("ecb_alloc(): Cipher name %s too short.", name);
  if (ecb_name[l - 4] != '-')
    ssh_fatal("ecb_alloc(): Cipher name %s illegal (no dash).", name);
  ecb_name[l - 3] = 'e';
  ecb_name[l - 2] = 'c';
  ecb_name[l - 1] = 'b';

  if ((st = ssh_cipher_allocate(name, key, keylen, TRUE, &mode_enc))
      != SSH_CRYPTO_OK)
    ssh_fatal("Could not allocate %s for encryption: %s", 
              name, ssh_crypto_status_message(st));

  if ((st = ssh_cipher_allocate(name, key, keylen, FALSE, &mode_dec))
      != SSH_CRYPTO_OK)
    ssh_fatal("Could not allocate %s for decryption: %s", 
              name, ssh_crypto_status_message(st));

  if ((st = ssh_cipher_allocate(ecb_name, key, keylen, TRUE, &ecb_enc))
      != SSH_CRYPTO_OK)
    ssh_fatal("Could not allocate %s for encryption: %s", 
              ecb_name, ssh_crypto_status_message(st));
  
  /* get the block length */

  blocklen = ssh_cipher_get_block_length(ecb_enc);

  if (verbose)
    printf("  block length = %d\n", blocklen);
}

/* cipher-block chaining mode */

void cbc_test(char *name)
{
  int i, j, tl;

  if (verbose)
    printf("cbc-test: %s\n", name);
  ecb_alloc(name);

  /* test encryption */

  tl = blocklen * (TEST_BLOCK / blocklen);
  for (i = 0; i < blocklen; i++)
    iv[i] = rand();
  for (i = 0; i < tl; i++)
    pt[i] = rand();

  /* encrypt in pieces */

  ssh_cipher_set_iv(mode_enc, iv);
  for (i = 0; i < tl; i += j)
    {
      j = ((rand() % MAX_PIECE) + 1) * blocklen;
      if ((i + j) > tl)
        j = tl - i;      
      ssh_cipher_transform(mode_enc, &ct[i], &pt[i], j);
    }

  /* simulate cbc encryption with ecb */

  for (i = 0; i < blocklen; i++)
    blk1[i] = iv[i];

  for (i = 0; i < tl; i += blocklen)
    {
      for (j = 0; j < blocklen; j++)
        blk1[j] ^= pt[i + j];
      
      ssh_cipher_transform(ecb_enc, blk2, blk1, blocklen);

      for (j = 0; j < blocklen; j++)
        {
          blk1[j] = blk2[j];
          ot[i + j] = blk2[j];
        }
    }

  if (memcmp(ct, ot, tl) != 0)
    ssh_fatal("cbc_test(%s): encryption failed.", name);
      
  /* decrypt in pieces */

  ssh_cipher_set_iv(mode_dec, iv);

  for (i = 0; i < tl; i += j)
    {
      j = ((rand() % MAX_PIECE) + 1) * blocklen;
      if ((i + j) > tl)
        j = tl - i;      
      ssh_cipher_transform(mode_dec, &ot[i], &ct[i], j);
    }
  
  if (memcmp(pt, ot, tl) != 0)
    ssh_fatal("cbc_test(%s): decryption failed.", name);

  ecb_free();
}


/* cipher feedback mode */

void cfb_test(char *name)
{ 
  int i, j, tl;

  if (verbose)
    printf("cfb-test: %s\n", name);
  ecb_alloc(name);

  /* test encryption */

  tl = blocklen * (TEST_BLOCK / blocklen);
  for (i = 0; i < blocklen; i++)
    iv[i] = rand();
  for (i = 0; i < tl; i++)
    pt[i] = rand();

  /* encrypt in pieces */

  ssh_cipher_set_iv(mode_enc, iv);
  for (i = 0; i < tl; i += j)
    {
      j = ((rand() % MAX_PIECE) + 1) * blocklen;
      if ((i + j) > tl)
        j = tl - i;      
      ssh_cipher_transform(mode_enc, &ct[i], &pt[i], j);
    }

  /* simulate cfb with ecb */

  for (i = 0; i < blocklen; i++)
    blk1[i] = iv[i];

  for (i = 0; i < tl; i += blocklen)
    {
      ssh_cipher_transform(ecb_enc, blk2, blk1, blocklen);
      for (j = 0; j < blocklen; j++)
        ot[i + j] = pt[i + j] ^ blk2[j];
      for (j = 0; j < blocklen; j++)
        blk1[j] = ot[i + j];
    }

  if (memcmp(ct, ot, tl) != 0)
    ssh_fatal("cfb_test(%s): encryption failed.", name);

  /* decrypt in pieces */
  
  ssh_cipher_set_iv(mode_dec, iv);

  for (i = 0; i < tl; i += j)
    {
      j = ((rand() % MAX_PIECE) + 1) * blocklen;
      if ((i + j) > tl)
        j = tl - i;      
      ssh_cipher_transform(mode_dec, &ot[i], &ct[i], j);
    }
  
  if (memcmp(pt, ot, tl) != 0)
    ssh_fatal("cfb_test(%s): decryption failed.", name);

  ecb_free();
}


/* output feedback mode*/

void ofb_test(char *name)
{
  int i, j, tl;

  if (verbose)
    printf("ofb-test: %s\n", name);
  ecb_alloc(name);

  /* test encryption */

  tl = blocklen * (TEST_BLOCK / blocklen);
  for (i = 0; i < blocklen; i++)
    iv[i] = rand();
  for (i = 0; i < tl; i++)
    pt[i] = rand();

  /* encrypt in pieces */

  ssh_cipher_set_iv(mode_enc, iv);
  for (i = 0; i < tl; i += j)
    {
      j = ((rand() % MAX_PIECE) + 1) * blocklen;
      if ((i + j) > tl)
        j = tl - i;      
      ssh_cipher_transform(mode_enc, &ct[i], &pt[i], j);
    }

  /* simulate ofb with ecb */

  for (i = 0; i < blocklen; i++)
    blk1[i] = iv[i];

  for (i = 0; i < tl; i += blocklen)
    {
      ssh_cipher_transform(ecb_enc, blk2, blk1, blocklen);
      for (j = 0; j < blocklen; j++)
        ot[i + j] = pt[i + j] ^ blk2[j];

      for (j = 0; j < blocklen; j++)
        blk1[j] = blk2[j];
    }

  if (memcmp(ct, ot, tl) != 0)
    ssh_fatal("ofb_test(%s): encryption failed.", name);

  /* decrypt in pieces */
  
  ssh_cipher_set_iv(mode_dec, iv);

  for (i = 0; i < tl; i += j)
    {
      j = ((rand() % MAX_PIECE) + 1) * blocklen;
      if ((i + j) > tl)
        j = tl - i;      
      ssh_cipher_transform(mode_dec, &ot[i], &ct[i], j);
    }
  
  if (memcmp(pt, ot, tl) != 0)
    ssh_fatal("ofb_test(%s): decryption failed.", name);

  ecb_free();
}

/* main */

int main(int argc, char **argv)
{
  int i, j, st;
  char *supported;
  char ciph[256];

  /* process arguments */

  if (argc == 2)
    {
      if (strcmp(argv[1], "-v") == 0)
        verbose = TRUE;
      else
        {
          fprintf(stderr, "Unknown argument %s\n", argv[1]);
          return -1;
        }
    }
  else
    {
      if (argc > 2)
        {
          fprintf(stderr, "Too many arguments.\n");
          return -1;
        }
      verbose = FALSE;
    }

  pt = ssh_xmalloc(TEST_BLOCK);
  ct = ssh_xmalloc(TEST_BLOCK);
  ot = ssh_xmalloc(TEST_BLOCK);

  /* go through the ciphers one at a time */

  supported = ssh_cipher_get_supported();
  if (supported == NULL)
    ssh_fatal("ssh_cipher_get_supported() failed.");

  for (i = 0;;)
    {
      for (j = 0; j < sizeof(ciph) && supported[i + j] != '\0' 
           && supported[i + j] != ','; j++)
        ciph[j] = supported[i + j];
      ciph[j] = 0;
     
      if (j > 4)
        {
          if (strcmp(&ciph[j - 4], "-cbc") == 0)
            cbc_test(ciph);
          if (strcmp(&ciph[j - 4], "-cfb") == 0)
            cfb_test(ciph);
          if (strcmp(&ciph[j - 4], "-ofb") == 0)
            ofb_test(ciph);
        }

      if (supported[i + j] != ',')
        break;
      i += j + 1;
    }

  ssh_xfree(supported);
  ssh_xfree(pt);
  ssh_xfree(ct);
  ssh_xfree(ot);

  return 0;
}
