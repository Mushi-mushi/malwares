/*

genhash.c

Author: Antti Huima <huima@ssh.fi>
        Tatu Ylonen <ylo@ssh.fi>

Copyright (C) 1996 SSH Security Communications Oy, Espoo, Finland
                   All rights reserved
                 
*/

/*
 * $Id: genhash.c,v 1.24 1999/01/13 19:31:10 ylo Exp $
 * $Log: genhash.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypti.h"
#include "sshbuffer.h"
#include "sha.h"
#include "md5.h"
#include "ripemd160.h"

#ifndef KERNEL


#endif /* !KERNEL */

/* List of supported hash algorithms. */

static const SshHashDef *ssh_hash_algorithms[] =
{
  &ssh_hash_md5_def,
  &ssh_hash_sha_def,
  &ssh_hash_sha_96_def,
  &ssh_hash_sha_80_def,
  &ssh_hash_ripemd160_def,
  &ssh_hash_ripemd160_96_def,
  &ssh_hash_ripemd160_80_def,

#ifndef KERNEL
  

#endif /* KERNEL */

  NULL
};

struct SshHashRec
{
  const SshHashDef *ops;
  void *context;
};

/* XXX */
const SshHashDef *ssh_hash_get_definition_internal(const SshHash hash)
{
  return hash->ops;
}

/* Returns a comma-separated list of supported hash functions names.
   The caller must free the returned value with ssh_xfree(). */

DLLEXPORT char * DLLCALLCONV
ssh_hash_get_supported()
{
  int i;
  SshBuffer buf;
  char *list;

  ssh_buffer_init(&buf);
  for (i = 0; ssh_hash_algorithms[i] != NULL; i++)
    {
      if (ssh_buffer_len(&buf) != 0)
        ssh_buffer_append(&buf, (unsigned char *) ",", 1);
      ssh_buffer_append(&buf, (unsigned char *) ssh_hash_algorithms[i]->name,
                    strlen(ssh_hash_algorithms[i]->name));
    }
  ssh_buffer_append(&buf, (unsigned char *) "\0", 1);
  list = ssh_xstrdup(ssh_buffer_ptr(&buf));
  ssh_buffer_uninit(&buf);
  return list;
}

/* Check if given hash name belongs to the set of supported ciphers. */

DLLEXPORT Boolean DLLCALLCONV
ssh_hash_supported(const char *name)
{
  unsigned int i;

  if (name == NULL)
    return FALSE;
  
  for (i = 0; ssh_hash_algorithms[i] != NULL; i++)
    if (strcmp(ssh_hash_algorithms[i]->name, name) == 0)
      return TRUE;
  return FALSE;
}

/* Allocates and initializes a hash context. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_hash_allocate(const char *type, SshHash *hash)
{
  int i;

  for (i = 0; ssh_hash_algorithms[i] != NULL; i++)
    {
      if (strcmp(ssh_hash_algorithms[i]->name, type) == 0)
        {
          *hash = ssh_xmalloc(sizeof(**hash));
          (*hash)->ops = ssh_hash_algorithms[i];
          (*hash)->context = ssh_xmalloc((*ssh_hash_algorithms[i]->ctxsize)());
          (*ssh_hash_algorithms[i]->reset_context)((*hash)->context);
          return SSH_CRYPTO_OK;
        }
    }
  return SSH_CRYPTO_UNSUPPORTED;
}

/* From a given hash definition allocate a SshHash context. This can be
   used transparently (even though given hash definition need not be
   any "standard" hash function) with this interface. Defined in
   sshcrypti.h for internal usage only. */

DLLEXPORT SshHash DLLCALLCONV
ssh_hash_allocate_internal(const SshHashDef *hash_def)
{
  SshHash hash;

  if (hash_def == NULL)
    return NULL;
  hash = ssh_xmalloc(sizeof(*hash));
  hash->ops = hash_def;
  hash->context = ssh_xmalloc((hash_def->ctxsize)());
  (hash_def->reset_context)(hash->context);

  return hash;
}

/* Expand given key (ps, ps_len) with pseudo-random function to be of
   length ssh_buffer_len. Magic can be given to make hashing output
   different results for different operations. Although it is not
   neccessary to give any magic.

   Method used is a very simple expansion idea, that nevertheless seems
   very solid. The strenght is based on rehashing everything on every
   iteration. Now it seems that this infact isn't very efficient way,
   but we don't need efficient way because hashing is extremely fast.
   However, if faster expansion is needed I suggest something like:

     h_i = HASH(passphrase, f(i), magic)

   where h_i are combined as h_0 | h_1 | h_2 ... to form the expanded
   key. The function f(i) should be some bijective function (maybe
   just f(x) = x ?).
   
   This function is currently meant only for internal use. */

void ssh_hash_expand_key_internal(unsigned char *buffer, size_t buffer_len,
                                  const unsigned char *ps, size_t ps_len,
                                  unsigned char *magic, size_t magic_len,
                                  const SshHashDef *hash)
{
  unsigned char *hash_buf;
  size_t hash_buf_len;
  void *context;
  size_t i;
  
  /* Hash and expand the passphrase. Idea is to

       for i = 0 to r
         buffer[i] = H(passphrase, buffer[0], ..., buffer[i - 1], magic)

     this tries to hash passphrase as nicely to the buffer as possible.
     */

  /* Allocate enough memory. */
  hash_buf_len = ((buffer_len + hash->digest_length) / hash->digest_length) *
    hash->digest_length;

  /* Allocate just once for simplicity in freeing memory. */
  context = ssh_xmalloc((*hash->ctxsize)() + hash_buf_len);
  hash_buf = (unsigned char *)context + (*hash->ctxsize)();

  /* Iterate. */
  for (i = 0; i < hash_buf_len; i += hash->digest_length)
    {
      (*hash->reset_context)(context);
      (*hash->update)(context, ps, ps_len);
      if (i > 0)
        (*hash->update)(context, hash_buf, i);
      if (magic_len > 0)
        (*hash->update)(context, magic, magic_len);
      (*hash->final)(context, hash_buf + i);
    }
  /* Copy and free. */
  memcpy(buffer, hash_buf, buffer_len);
  memset(hash_buf, 0, hash_buf_len);
  ssh_xfree(context);
}

/* Free hash context. */

DLLEXPORT void DLLCALLCONV
ssh_hash_free(SshHash hash)
{
  ssh_xfree(hash->context);
  ssh_xfree(hash);
}

/* Returns the ASN.1 Object Identifier of the hash function if
   known. Returns NULL if OID is not known. */
DLLEXPORT const char * DLLCALLCONV
ssh_hash_asn1_oid(SshHash hash)
{
  return hash->ops->asn1_oid;
}

/* Returns the ISO/IEC dedicated hash number if available. 0 if not
   known. */
DLLEXPORT unsigned char DLLCALLCONV
ssh_hash_iso_identifier(SshHash hash)
{
  return hash->ops->iso_identifier;
}

/* Resets the hash context to its initial state. */

DLLEXPORT void DLLCALLCONV
ssh_hash_reset(SshHash hash)
{
  (*hash->ops->reset_context)(hash->context);
}

/* Get the digest lenght of the hash. */

DLLEXPORT size_t DLLCALLCONV
ssh_hash_digest_length(SshHash hash)
{
  return hash->ops->digest_length;
}

/* Get input block size (used for hmac padding). */

DLLEXPORT size_t DLLCALLCONV
ssh_hash_input_block_size(SshHash hash)
{
  return hash->ops->input_block_length;
}

/* Updates the hash context by adding the given text. */

DLLEXPORT void DLLCALLCONV
ssh_hash_update(SshHash hash, const void *buf, size_t len)
{
  (*hash->ops->update)(hash->context, buf, len);
}

/* Outputs the hash digest. */

DLLEXPORT void DLLCALLCONV
ssh_hash_final(SshHash hash, unsigned char *digest)
{
  (*hash->ops->final)(hash->context, digest);
}

/* Hashes one buffer with selected hash type and returns the digest.
   This calls ssh_fatal() if called with an invalid type. */

DLLEXPORT void DLLCALLCONV
ssh_hash_of_buffer(const char *type,
                   const void *buf, size_t len,
                   unsigned char *digest)
{
  SshHash hash;

  if (ssh_hash_allocate(type, &hash) != SSH_CRYPTO_OK)
    ssh_fatal("ssh_hash_of_buffer: unsupported hash %.100s", type);
  ssh_hash_update(hash, buf, len);
  ssh_hash_final(hash, digest);
  ssh_hash_free(hash);
}
