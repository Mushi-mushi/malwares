/*

  sshcrypti.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Jun 30 14:15:05 1997 [mkojo]

  Definitions for internal use only.

  */

/*
 * $Id: sshcrypti.h,v 1.15 1998/12/03 19:48:28 mkojo Exp $
 * $Log: sshcrypti.h,v $
 * $EndLog$
 */

#ifndef SSHCRYPTI_H
#define SSHCRYPTI_H

/* Some generally handy definitions, which bear no general meaning outside
   some particular context. */

typedef unsigned int SshCryptoType;
#define SSH_CRYPTO_TYPE_PUBLIC_KEY     1
#define SSH_CRYPTO_TYPE_PRIVATE_KEY    2
#define SSH_CRYPTO_TYPE_PK_GROUP       4 
#define SSH_CRYPTO_TYPE_CIPHER         8
#define SSH_CRYPTO_TYPE_HASH           16
#define SSH_CRYPTO_TYPE_MAC            32
#define SSH_CRYPTO_TYPE_SECRET_SHARING 64

/* The main purpose for these definitions, is to allow easier usage of
   commonly needed methods. That is, we don't need to rewrite all this
   information everywhere.

   Currently hash functions should be defined in their header files, and
   other functions in their code files. However, if need arises this
   can be changed quickly. 
   */

/* Definition structure for hash functions. That is, by using this
   structure crypto library transparently is able to use "any"
   hash functions. */
typedef struct
{
  const char *name;
  const char *asn1_oid;
  unsigned char iso_identifier;
  size_t digest_length;
  size_t input_block_length;
  size_t (*ctxsize)(void);
  void (*reset_context)(void *context);
  void (*update)(void *context, const unsigned char *buf, size_t len);
  void (*final)(void *context, unsigned char *digest);
} SshHashDef;

/* Definition structure for cipher functions. */
typedef struct
{
  const char *name;
  /* Block length is 1 for stream ciphers. */
  size_t block_length;
  /* Key length is 0 if supports any length. XXX this is adequate for
     most uses but possibly not suitable always. Might be better to have
     some fixed sized versions of the cipher, rather than variable length
     key version. */
  size_t key_length;
  size_t (*ctxsize)(void);
  /* Basic initialization without explicit key checks. */
  Boolean (*init)(void *context, const unsigned char *key,
                  size_t keylen, Boolean for_encryption);
  /* Initialization with key checks. */
  Boolean (*init_with_check)(void *context, const unsigned char *key,
                             size_t keylen, Boolean for_encryption);
  void (*transform)(void *context, unsigned char *dest,
                    const unsigned char *src, size_t len,
                    unsigned char *iv);
} SshCipherDef;

/* Definition structure for mac functions. */
typedef struct
{
  const char *name;
  size_t digest_length;
  /* Some mac functions need to allocate space of variable length, this
     will indicate it. */
  Boolean allocate_key;
  /* Indicate which hash function to use. This should be generic enough
     for all our needs. But if not, then add more options. */
  const SshHashDef *hash_def;
  size_t (*ctxsize)(const SshHashDef *hash_def);
  void (*init)(void *context, const unsigned char *key, size_t keylen,
               const SshHashDef *hash_def);
  void (*start)(void *context);
  void (*update)(void *context, const unsigned char *buf,
                 size_t len);
  void (*final)(void *context, unsigned char *digest);
  void (*mac_of_buffer)(void *context, const unsigned char *buf,
                        size_t len, unsigned char *digest);
} SshMacDef;

/* Function prototypes that are used internally. */


DLLEXPORT SshHash DLLCALLCONV
ssh_hash_allocate_internal(const SshHashDef *hash_def);

const SshHashDef *ssh_hash_get_definition_internal(const SshHash hash);


/* Expansion from a passphrase into a key. */

void ssh_hash_expand_key_internal(unsigned char *buffer, size_t ssh_buffer_len,
                                  const unsigned char *ps, size_t ps_len,
                                  unsigned char *magic, size_t magic_len,
                                  const SshHashDef *hash);

#endif /* SSHCRYPTI_H */
