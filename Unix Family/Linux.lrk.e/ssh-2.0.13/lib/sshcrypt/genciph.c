/*
    Author: Mika Kojo <mkojo@ssh.fi>

    Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
    All rights reserved.

    Created: Mon Oct 28 06:41:24 1996 [mkojo]

    */

/*
 * $Id: genciph.c,v 1.41 1999/04/21 23:34:44 kivinen Exp $
 * $Log: genciph.c,v $
 * $EndLog$
 */


#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypti.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "nociph.h"
#include "sha.h"

#include "des.h"

#include "blowfish.h"




#include "twofish.h"

 

#ifndef KERNEL
/* These ciphers can only be used in user-mode code, not in the kernel.
   To add a cipher to be used in the kernel, you must add its object
   file to CRYPT_LNOBJS in src/ipsec/engine/Makefile.am, and move it
   outside the #ifndef KERNEL directive both here and later in this file. */

#include "arcfour.h"




#endif /* !KERNEL */

/* Algorithm definitions */

static const SshCipherDef ssh_cipher_algorithms[] =
{
  { "3des-ecb", 8, 24, ssh_des3_ctxsize, ssh_des3_init, ssh_des3_init,
    ssh_des3_ecb },
  { "3des-cbc", 8, 24, ssh_des3_ctxsize, ssh_des3_init, ssh_des3_init,
    ssh_des3_cbc },
  { "3des-cfb", 8, 24, ssh_des3_ctxsize, ssh_des3_init, ssh_des3_init,
    ssh_des3_cfb },
  { "3des-ofb", 8, 24, ssh_des3_ctxsize, ssh_des3_init, ssh_des3_init,
    ssh_des3_ofb },

  
  { "blowfish-ecb", 8, 0,
    ssh_blowfish_ctxsize, ssh_blowfish_init, ssh_blowfish_init,
    ssh_blowfish_ecb },
  { "blowfish-cbc", 8, 0,
    ssh_blowfish_ctxsize, ssh_blowfish_init, ssh_blowfish_init,
    ssh_blowfish_cbc },
  { "blowfish-cfb", 8, 0,
    ssh_blowfish_ctxsize, ssh_blowfish_init, ssh_blowfish_init,
    ssh_blowfish_cfb },
  { "blowfish-ofb", 8, 0,
    ssh_blowfish_ctxsize, ssh_blowfish_init, ssh_blowfish_init,
    ssh_blowfish_ofb },
    
  { "des-ecb", 8, 8, ssh_des_ctxsize, ssh_des_init,
    ssh_des_init_with_key_check, ssh_des_ecb },
  { "des-cbc", 8, 8, ssh_des_ctxsize, ssh_des_init,
    ssh_des_init_with_key_check, ssh_des_cbc },
  { "des-cfb", 8, 8, ssh_des_ctxsize, ssh_des_init,
    ssh_des_init_with_key_check, ssh_des_cfb },
  { "des-ofb", 8, 8, ssh_des_ctxsize, ssh_des_init,
    ssh_des_init_with_key_check, ssh_des_ofb },
  

  { "twofish-ecb", 16, 0,
    ssh_twofish_ctxsize, ssh_twofish_init, ssh_twofish_init, ssh_twofish_ecb },
  { "twofish-cbc", 16, 0,
    ssh_twofish_ctxsize, ssh_twofish_init, ssh_twofish_init, ssh_twofish_cbc },
  { "twofish-cfb", 16, 0,
    ssh_twofish_ctxsize, ssh_twofish_init, ssh_twofish_init, ssh_twofish_cfb },
  { "twofish-ofb", 16, 0,
    ssh_twofish_ctxsize, ssh_twofish_init, ssh_twofish_init, ssh_twofish_ofb },




#ifndef KERNEL
  /* The ciphers below can only be used in user-level code.  See
     the comments above for adding ciphers to the kernel. */
  

  { "arcfour", 1, 0, ssh_arcfour_ctxsize, ssh_arcfour_init, ssh_arcfour_init,
    ssh_arcfour_transform },



  
#endif /* !KERNEL */
  
  { "none", 1, 0, NULL, NULL, NULL, ssh_none_cipher },
  
  { NULL }
};

/* Mapping from common cipher names to `canonical' ones. */
struct SshCipherAliasRec {
  const char *name;
  const char *real_name;
};

/* Common cipher names. */
const struct SshCipherAliasRec ssh_cipher_aliases[] =
{
  { "des", "des-cbc" },
  { "3des", "3des-cbc" },
  { "blowfish", "blowfish-cbc" },
  { "twofish", "twofish-cbc" },
  { NULL, NULL }
};

struct SshCipherRec {
  const SshCipherDef *ops;
  unsigned char iv[SSH_CIPHER_MAX_IV_SIZE];
  void *context;
};

/* Get corresponding cipher def record by cipher name */
static const SshCipherDef *ssh_cipher_get_cipher_def_internal(const char *name)
{
  int i, j;

  if (name == NULL)
    return NULL;

  for (i = 0; ssh_cipher_algorithms[i].name; i++)
    {
      if (strcmp(ssh_cipher_algorithms[i].name, name) == 0)
        {
          return &(ssh_cipher_algorithms[i]);
        }
    }
  for (i = 0; ssh_cipher_aliases[i].name; i++)
    {
      if (strcmp(ssh_cipher_aliases[i].name, name) == 0)
        {
          name = ssh_cipher_aliases[i].real_name;
          for (j = 0; ssh_cipher_algorithms[j].name; j++)
            {
              if (strcmp(ssh_cipher_algorithms[j].name, name) == 0)
                {
                  return &(ssh_cipher_algorithms[j]);
                }
            }
        }
    }
  return NULL;
}

/* Get the native name of the cipher. */

DLLEXPORT char * DLLCALLCONV
ssh_cipher_get_native_name(const char *name)
{
  const SshCipherDef *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);

  if (cipher_def == NULL)
    return NULL;

  return ssh_xstrdup(cipher_def->name);
}

/* Check if given cipher name belongs to the set of supported ciphers
   and is not an alias. */

static Boolean ssh_cipher_supported_native(const char *name)
{
  const SshCipherDef *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);

  if (cipher_def == NULL)
    return FALSE;


  if (strcmp(name, cipher_def->name) != 0)
    return FALSE;

  return TRUE;
}

/* Check if given cipher name belongs to the set of supported ciphers
   aliases included. */

DLLEXPORT Boolean DLLCALLCONV
ssh_cipher_supported(const char *name)
{
  if (ssh_cipher_get_cipher_def_internal(name) != NULL)
    return TRUE;

  return FALSE;
}

/* Return a comma-separated list of supported native cipher algorithm names. */

DLLEXPORT char * DLLCALLCONV
ssh_cipher_get_supported_native(void)
{
  int i;
  SshBuffer buf;
  char *list;

  ssh_buffer_init(&buf);
  for (i = 0; ssh_cipher_algorithms[i].name != NULL; i++)
    {
      if (ssh_buffer_len(&buf) != 0)
        ssh_buffer_append(&buf, (unsigned char *) ",", 1);
      ssh_buffer_append(&buf, (unsigned char *) ssh_cipher_algorithms[i].name,
                    strlen(ssh_cipher_algorithms[i].name));
    }
  ssh_buffer_append(&buf, (unsigned char *) "\0", 1);
  list = ssh_xstrdup(ssh_buffer_ptr(&buf));
  ssh_buffer_uninit(&buf);
  return list;
}

/* Return a comma-separated list of supported cipher algorithm names
   alias names included. */

DLLEXPORT char * DLLCALLCONV
ssh_cipher_get_supported(void)
{
  int i;
  SshBuffer buf;
  char *list;

  ssh_buffer_init(&buf);
  list = ssh_cipher_get_supported_native();
  ssh_buffer_append(&buf, (unsigned char *)list, strlen(list));
  ssh_xfree(list);

  for (i = 0; ssh_cipher_aliases[i].name != NULL; i++)
    {
      if (ssh_cipher_supported_native(ssh_cipher_aliases[i].real_name))
        {
          if (ssh_buffer_len(&buf) != 0)
            ssh_buffer_append(&buf, (unsigned char *) ",", 1);
          ssh_buffer_append(&buf, 
                            (unsigned char *) ssh_cipher_aliases[i].name,
                            strlen(ssh_cipher_aliases[i].name));
        }
    }
  ssh_buffer_append(&buf, (unsigned char *) "\0", 1);
  list = ssh_xstrdup(ssh_buffer_ptr(&buf));
  ssh_buffer_uninit(&buf);
  return list;
}

/* Allocates and initializes a cipher of the specified name. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_allocate_internal(const char *name,
                             const unsigned char *key,
                             size_t keylen,
                             Boolean for_encryption,
                             SshCipher *cipher,
                             Boolean expand,
                             Boolean test_weak_keys)
{
  unsigned char *expanded_key;
  unsigned int expanded_key_len;
  const SshCipherDef *cipher_def;
  Boolean rv;
  
  cipher_def = ssh_cipher_get_cipher_def_internal(name);
  if (cipher_def == NULL)
    return SSH_CRYPTO_UNSUPPORTED;

  if (keylen == 0)
    {
      /* Allow zero key length for cipher `none'. */
      if ((strcmp(name, "none") != 0) && expand == FALSE)
        return SSH_CRYPTO_KEY_TOO_SHORT;
    }

  /* This portion handles the key expansion computation. It uses the
     expansion function defined in the genhash.c. It basically just
     recomputes the hash function of choice until enough key material
     is available. */
  
  if (expand)
    {
      expanded_key_len = cipher_def->key_length;
      if (expanded_key_len == 0)
        expanded_key_len = SSH_CIPHER_MINIMAL_KEY_LENGTH;
      
      expanded_key = ssh_xmalloc(expanded_key_len);
      ssh_hash_expand_key_internal(expanded_key, expanded_key_len,
                                   key, keylen,
                                   NULL, 0,
                                   /* Use SHA-1 hash function. Any other
                                      hash function defined in this manner
                                      is allowed. The application cannot
                                      currently change the function! XXX */
                                   &ssh_hash_sha_def);
    }
  else
    {
      /* No need to expand the key. */
      
      expanded_key_len = keylen;
      expanded_key = (unsigned char *)key;
    }

  /* Check for error in key expansion. No keys shorter than the key length
     of the cipher is allowed. Longer are allowed, but only the first
     bytes are used. */
  if (expanded_key_len < cipher_def->key_length)
    {
      if (expand)
        ssh_fatal("internal error: key expansion corrupted.");
      
      return SSH_CRYPTO_KEY_TOO_SHORT;
    }

  /* Initialize the cipher. */

  *cipher = ssh_xmalloc(sizeof(**cipher));

  /* Set up the cipher definition. */
  (*cipher)->ops = cipher_def;
  /* Clean the IV. */
  memset((*cipher)->iv, 0, sizeof((*cipher)->iv));

  /* Set return value (rv) to default. */
  rv = TRUE;

  /* The "ctxsize" can be NULL if and only if the cipher is the none cipher. */
  if (cipher_def->ctxsize)
    {
      /* Allocate the context of the cipher. */
      (*cipher)->context = ssh_xmalloc((*cipher_def->ctxsize)());
      
      if (test_weak_keys == FALSE)
        {
          /* Initialize the cipher without weak key checks. */
          rv = (*cipher_def->init)((*cipher)->context,
                                   expanded_key,
                                   expanded_key_len,
                                   for_encryption);
        }
      else
        {
          /* Initialize the cipher with a weak key check performed first.
             Not all ciphers have key classes that are easy or practical to
             test for. For those ciphers this function may perform
             as the plain initialization. 
             */
          rv = (*cipher_def->init_with_check)((*cipher)->context,
                                              expanded_key,
                                              expanded_key_len,
                                              for_encryption);
        }
    }
  else
    (*cipher)->context = NULL;

  /* Free memory of the expanded key if necessary. */
  if (expand)
    ssh_xfree(expanded_key);

  if (rv == FALSE)
    {
      ssh_xfree((*cipher)->context);
      ssh_xfree(*cipher);
      *cipher = NULL;
      return SSH_CRYPTO_OPERATION_FAILED;
    }
  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_allocate(const char *name,
                    const unsigned char *key,
                    size_t keylen,
                    Boolean for_encryption,
                    SshCipher *cipher)
{
  return ssh_cipher_allocate_internal(name, key, keylen, for_encryption,
                                      cipher, FALSE, FALSE);
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_allocate_with_passphrase(const char *name,
                                    const char *passphrase,
                                    Boolean for_encryption,
                                    SshCipher *cipher)
{
  return ssh_cipher_allocate_internal(name, (unsigned char *) passphrase,
                                      strlen(passphrase),
                                      for_encryption, cipher, TRUE, FALSE);
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_allocate_and_test_weak_keys(const char *name,
                                       const unsigned char *key,
                                       size_t keylen,
                                       Boolean for_encryption,
                                       SshCipher *cipher)
{
  return ssh_cipher_allocate_internal(name, key, keylen,
                                      for_encryption, cipher,
                                      FALSE, TRUE);
}

/* Free the cipher context */

DLLEXPORT void DLLCALLCONV
ssh_cipher_free(SshCipher cipher)
{
  ssh_xfree(cipher->context);
  ssh_xfree(cipher);
}

DLLEXPORT char * DLLCALLCONV
ssh_cipher_get_name(SshCipher cipher)
{
  return ssh_xstrdup(cipher->ops->name);
}

DLLEXPORT size_t DLLCALLCONV
ssh_cipher_get_key_length(const char *name)
{
  const SshCipherDef *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);
  if (cipher_def == NULL)
    return 0;

  return cipher_def->key_length;
}

DLLEXPORT size_t DLLCALLCONV
ssh_cipher_get_block_length(SshCipher cipher)
{
  return cipher->ops->block_length;
}

DLLEXPORT size_t DLLCALLCONV
ssh_cipher_get_iv_length(SshCipher cipher)
{
  /* XXX Currently just returns the block length. */
  return cipher->ops->block_length;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_set_iv(SshCipher cipher,
                  const unsigned char *iv)
{
  memcpy(cipher->iv, iv, cipher->ops->block_length);

  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_get_iv(SshCipher cipher,
                  unsigned char *iv)
{
  memcpy(iv, cipher->iv, cipher->ops->block_length);
  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_transform(SshCipher cipher,
                     unsigned char *dest,
                     const unsigned char *src,
                     size_t len)
{
  /* Check that the src length is divisible by block length of the cipher. */
  if (len % cipher->ops->block_length == 0)
    (*cipher->ops->transform)(cipher->context, dest, src, len, cipher->iv);
  else
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_transform_with_iv(SshCipher cipher,
                             unsigned char *dest,
                             const unsigned char *src,
                             size_t len,
                             unsigned char *iv)
{
  /* Check that the src length is divisible by block length of the cipher. */
  if (len % cipher->ops->block_length == 0)
    (*cipher->ops->transform)(cipher->context, dest, src, len, iv);
  else
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  return SSH_CRYPTO_OK;
}
