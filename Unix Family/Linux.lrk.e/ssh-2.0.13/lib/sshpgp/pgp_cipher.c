/*

pgp_cipher.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1999 SSH Communications Security, Finland
                   All rights reserved

Implement pgp style (weird) cipher.

*/
/*
 * $Id: pgp_cipher.c,v 1.5 1999/04/06 23:51:37 tri Exp $
 * $Log: pgp_cipher.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef WITH_PGP
#include "sshcrypt.h"
#include "sshpgp.h"

#define SSH_DEBUG_MODULE "SshPgpCipher"

struct SshPgpCipherRec {
  SshCipher cipher;        /* ECB context */
  size_t offset;
  Boolean for_encryption;
  size_t block_len;
  size_t cfb_bytes_left;
  unsigned char *iv;
  unsigned char *iv_prev;
};

/* CFB transforms are isolated into their own functions even though
   there are no other modes. */
void ssh_pgp_cipher_transform_cfb_decrypt(SshPgpCipher cipher, 
                                          unsigned char *dest, 
                                          const unsigned char *src, 
                                          size_t len);
void ssh_pgp_cipher_transform_cfb_encrypt(SshPgpCipher cipher, 
                                          unsigned char *dest, 
                                          const unsigned char *src, 
                                          size_t len);
void ssh_pgp_cipher_cfb_resync(SshPgpCipher cipher);

/* pgp_cipher api functions. */
SshCryptoStatus ssh_pgp_cipher_allocate(int type,
                                        const char *key_str,
                                        int s2k_type,
                                        int s2k_hash,
                                        int s2k_count,
                                        unsigned char *s2k_salt,
                                        Boolean for_encryption,
                                        SshPgpCipher *cipher)
{
  SshPgpCipher c;
  SshCryptoStatus cr;
  SshCipher ecb_cipher;
  const char *cipher_name;
  unsigned char *key;
  size_t key_len;

  cipher_name = ssh_pgp_canonical_cipher_name(type);
  if (cipher_name == NULL)
    return SSH_CRYPTO_UNSUPPORTED;

  key_len = ssh_cipher_get_key_length(cipher_name);
  if (key_len == 0)
    {
      if ((strcmp(cipher_name, "twofish-ecb") == 0) ||
          (strcmp(cipher_name, "rc6-ecb") == 0) ||
          (strcmp(cipher_name, "rijndael-ecb") == 0) ||
          (strcmp(cipher_name, "mars-ecb") == 0) ||
          (strcmp(cipher_name, "serpent-ecb") == 0) ||
          (strcmp(cipher_name, "dfc-ecb") == 0) ||
          (strcmp(cipher_name, "e2-ecb") == 0) ||
          (strcmp(cipher_name, "crypton-ecb") == 0))
        {
          key_len = 32;
        }
      else
        {
          key_len = 16;
        }
    }
  key = ssh_xmalloc(key_len);
  if (ssh_pgp_s2k(key_str, s2k_type, s2k_salt, s2k_count, 
                  s2k_hash, key, key_len) == FALSE)
    {
      ssh_xfree(key);
      return SSH_CRYPTO_UNSUPPORTED;
    }
  cr = ssh_cipher_allocate(cipher_name,
                           key,
                           key_len,
                           TRUE,
                           &ecb_cipher);
  memset(key, 'F', key_len);
  ssh_xfree(key);
  if (cr != SSH_CRYPTO_OK)
    return cr;

  c = ssh_xcalloc(1, sizeof (*c));
  c->cipher = ecb_cipher;
  c->for_encryption = for_encryption;
  c->block_len = ssh_cipher_get_block_length(ecb_cipher);
  if (c->block_len < 8)
    {
      ssh_cipher_free(c->cipher);
      ssh_xfree(c);
      return SSH_CRYPTO_UNSUPPORTED;
    }
  c->iv = ssh_xcalloc(c->block_len, 1);
  c->iv_prev = ssh_xcalloc(c->block_len, 1);
  c->cfb_bytes_left = 0;
  *cipher = c;
  return SSH_CRYPTO_OK;
}

void ssh_pgp_cipher_transform(SshPgpCipher cipher,
                              unsigned char *dest,
                              const unsigned char *src,
                              size_t len)
{
  if (cipher->for_encryption)
    ssh_pgp_cipher_transform_cfb_encrypt(cipher, dest, src, len);
  else
    ssh_pgp_cipher_transform_cfb_decrypt(cipher, dest, src, len);
}

void ssh_pgp_cipher_resync(SshPgpCipher cipher)
{
  ssh_pgp_cipher_cfb_resync(cipher);
}

void ssh_pgp_cipher_free(SshPgpCipher cipher)
{
  ssh_cipher_free(cipher->cipher);
  memset(cipher->iv, 'F', cipher->block_len);
  ssh_xfree(cipher->iv);
  memset(cipher->iv_prev, 'F', cipher->block_len);
  ssh_xfree(cipher->iv_prev);
  memset(cipher, 'F', sizeof (*cipher));
  ssh_xfree(cipher);
  return;
}

/* CFB transforms are isolated into their own functions even though
   there are no other modes. */

/* Since SSH Crypto Library only implements CFB for complete blocks, 
   here is an implementation for 8-bit CFB, that is implemented with
   ECB mode encryption.  For speed, we handle partial blocks first and
   loop only with complete blocks.  If some bytes are still left after
   the main loop, a block of cfb bytes are generated and this partial
   block is processed. */
void ssh_pgp_cipher_transform_cfb_decrypt(SshPgpCipher cipher, 
                                          unsigned char *dest, 
                                          const unsigned char *src, 
                                          size_t len)
{
  unsigned char *iv_cur;
  unsigned char tmp;
  int i;
  
  /* Check if we have enough cfb bytes left. */
  if (len <= cipher->cfb_bytes_left) 
    {
      for (iv_cur = &(cipher->iv[cipher->block_len - cipher->cfb_bytes_left]); 
           len; 
           len--){
        tmp = *src++;
        *dest++ = *iv_cur ^ tmp;
        *iv_cur++ = tmp;
        cipher->cfb_bytes_left--;
      }
      return;
    }

  /* Consume rest of the cfb bytes. */
  if (cipher->cfb_bytes_left) 
    {
      len -= cipher->cfb_bytes_left;
      for (iv_cur = &(cipher->iv[cipher->block_len - cipher->cfb_bytes_left]);
           cipher->cfb_bytes_left;
           cipher->cfb_bytes_left--)
        {
          tmp = *src++;
          *dest++ = *iv_cur ^ tmp;
          *iv_cur++ = tmp;
        }
    }

  /* Process complete blocks. */
  while (len >= cipher->block_len) 
    {
      memcpy(cipher->iv_prev, cipher->iv, cipher->block_len);
      ssh_cipher_transform(cipher->cipher, 
                           cipher->iv, 
                           cipher->iv, 
                           cipher->block_len);
      iv_cur = cipher->iv;
      for (i = 0; i < cipher->block_len; i++) 
        {
          tmp = *src++;
          *dest++ = *iv_cur ^ tmp;
          *iv_cur++ = tmp;
        }
      len -= cipher->block_len;
    }

  /* Generate a block of cfb bytes and process rest of the input. */
  if (len) 
    {
      memcpy(cipher->iv_prev, cipher->iv, cipher->block_len);
      ssh_cipher_transform(cipher->cipher,
                           cipher->iv,
                           cipher->iv, 
                           cipher->block_len);
      cipher->cfb_bytes_left = cipher->block_len;
      cipher->cfb_bytes_left -= len;
      for (iv_cur = cipher->iv; len; len--) 
        {
          tmp = *src++;
          *dest++ = *iv_cur ^ tmp;
          *iv_cur++ = tmp;
        }
    }
}

/* Since SSH Crypto Library only implements CFB for complete blocks, 
   here is an implementation for 8-bit CFB, that is implemented with
   ECB mode encryption.  For speed, we handle partial blocks first and
   loop only with complete blocks.  If some bytes are still left after
   the main loop, a block of cfb bytes are generated and this partial
   block is processed. */
void ssh_pgp_cipher_transform_cfb_encrypt(SshPgpCipher cipher, 
                                          unsigned char *dest, 
                                          const unsigned char *src, 
                                          size_t len)
{
  unsigned char *iv_cur;
  int i;

  /* Check if we have enough cfb bytes left. */
  if (len <= cipher->cfb_bytes_left) 
    {
      for (iv_cur = &(cipher->iv[cipher->block_len - cipher->cfb_bytes_left]); 
           len; 
           (len--, cipher->cfb_bytes_left--))
        *dest++ = (*iv_cur++ ^= *src++);
      return;
    }

  /* Consume rest of the cfb bytes. */
  if (cipher->cfb_bytes_left) 
    {
      len -= cipher->cfb_bytes_left;
      for (iv_cur = &(cipher->iv[cipher->block_len - cipher->cfb_bytes_left]);
           cipher->cfb_bytes_left; 
           cipher->cfb_bytes_left--)
        *dest++ = (*iv_cur++ ^= *src++);
    }

  /* Process complete blocks. */
  while (len >= cipher->block_len) 
    {
      memcpy(cipher->iv_prev, cipher->iv, cipher->block_len);
      ssh_cipher_transform(cipher->cipher, 
                           cipher->iv, 
                           cipher->iv, 
                           cipher->block_len);

      iv_cur = cipher->iv;
      for (i = 0; i < cipher->block_len; i++)
        *dest++ = (*iv_cur++ ^= *src++);
      len -= cipher->block_len;
    }

  /* Generate a block of cfb bytes and process rest of the input. */
  if (len) 
    {
      memcpy(cipher->iv_prev, cipher->iv, cipher->block_len);
      ssh_cipher_transform(cipher->cipher, 
                           cipher->iv, 
                           cipher->iv, 
                           cipher->block_len);

      cipher->cfb_bytes_left = cipher->block_len;
      cipher->cfb_bytes_left -= len;
      for (iv_cur = cipher->iv; len; len--)
        *dest++ = (*iv_cur++ ^= *src++);
    }
}

/* This is weird resync step introduced by Phil Z.  Thanks to Phil
   Zimmermann who very slowly and patiently explained this thing to 
   me in nice restaurant by Via Veneto in Rome.  After I forgot his
   explanation I looked into code in pgp-2.6.3i, pgp-5.0i, and
   gnupg-0.9 and still didn't quite get it.  Anyway since the SSH
   Crypto Library is used in ecb mode, there is iv and iv_prev in
   cipher context somewhat like the ones in gpg.  So, I'll just 
   mangle IVs around like they do.  //tri@ssh.fi */
void ssh_pgp_cipher_cfb_resync(SshPgpCipher cipher)
{
    if (cipher->cfb_bytes_left) {
        memmove(cipher->iv + cipher->cfb_bytes_left, 
                cipher->iv, 
                cipher->block_len - cipher->cfb_bytes_left);
        memcpy(cipher->iv, 
               cipher->iv_prev + cipher->block_len - cipher->cfb_bytes_left, 
               cipher->cfb_bytes_left);
        cipher->cfb_bytes_left = 0;
    }
}

#endif /* WITH_PGP */
/* eof (pgp_cipher.c) */
