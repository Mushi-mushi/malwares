/*

  genmac.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu Jan  9 12:22:52 1997 [mkojo]

  Message authentication code calculation routines. 

  */

/*
 * $Id: genmac.c,v 1.29 1999/01/13 19:30:55 ylo Exp $
 * $Log: genmac.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypti.h"
#include "sshbuffer.h"

#include "macs.h"
#include "hmac.h"

#include "md5.h"

#include "sha.h"

#include "ripemd160.h"

#ifndef KERNEL
/* These MACs/hashes can only be used in user-mode code.  To add a
   hash/mac to be used in kernel code, it must be moved outside this
   ifdef both here and later in this file, and added to CRYPT_LNOBJS
   in src/ipsec/engine/Makefile.am.  */



#endif /* !KERNEL */

/* Control structure. */
  
static const SshMacDef ssh_mac_algorithms[] =
{
  { "hmac-md5", 16, FALSE,
    &ssh_hash_md5_def,
    ssh_hmac_ctxsize, ssh_hmac_init,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_final,
    ssh_hmac_of_buffer },
  { "hmac-md5-96", 12, FALSE,
    &ssh_hash_md5_def,
    ssh_hmac_ctxsize, ssh_hmac_init,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_96_final,
    ssh_hmac_96_of_buffer },
  { "hmac-sha1", 20, FALSE,
    &ssh_hash_sha_def, 
    ssh_hmac_ctxsize, ssh_hmac_init,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_final,
    ssh_hmac_of_buffer },
  { "hmac-sha1-96", 12, FALSE,
    &ssh_hash_sha_def,
    ssh_hmac_ctxsize, ssh_hmac_init,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_96_final,
    ssh_hmac_96_of_buffer },
  { "hmac-ripemd160", 20, FALSE,
    &ssh_hash_ripemd160_def,
    ssh_hmac_ctxsize, ssh_hmac_init,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_final,
    ssh_hmac_of_buffer },
  { "hmac-ripemd160-96", 12, FALSE,
    &ssh_hash_ripemd160_def,
    ssh_hmac_ctxsize, ssh_hmac_init,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_96_final,
    ssh_hmac_96_of_buffer },

#ifndef KERNEL
  /* The macs below can only be used in user-mode code.  See comments
     above for more information. */



#endif /* !KERNEL */



  { "sha1-8", 8, TRUE,
    &ssh_hash_sha_def,
    ssh_kdk_mac_ctxsize, ssh_kdk_mac_init,
    ssh_kdk_mac_start, ssh_kdk_mac_update, ssh_kdk_mac_64_final,
    ssh_kdk_mac_64_of_buffer },
  { "sha1", 20, TRUE,
    &ssh_hash_sha_def,
    ssh_kdk_mac_ctxsize, ssh_kdk_mac_init,
    ssh_kdk_mac_start, ssh_kdk_mac_update, ssh_kdk_mac_final,
    ssh_kdk_mac_of_buffer },
  { "md5-8", 8, TRUE,
    &ssh_hash_md5_def,
    ssh_kdk_mac_ctxsize, ssh_kdk_mac_init,
    ssh_kdk_mac_start, ssh_kdk_mac_update, ssh_kdk_mac_64_final,
    ssh_kdk_mac_64_of_buffer },
  { "md5", 16, TRUE,
    &ssh_hash_md5_def,
    ssh_kdk_mac_ctxsize, ssh_kdk_mac_init,
    ssh_kdk_mac_start, ssh_kdk_mac_update, ssh_kdk_mac_final,
    ssh_kdk_mac_of_buffer },
  { "ripemd160-8", 8, TRUE,
    &ssh_hash_ripemd160_def,
    ssh_kdk_mac_ctxsize, ssh_kdk_mac_init,
    ssh_kdk_mac_start, ssh_kdk_mac_update, ssh_kdk_mac_64_final,
    ssh_kdk_mac_64_of_buffer },
  { "ripemd160", 20, TRUE,
    &ssh_hash_ripemd160_def,
    ssh_kdk_mac_ctxsize, ssh_kdk_mac_init,
    ssh_kdk_mac_start, ssh_kdk_mac_update, ssh_kdk_mac_final,
    ssh_kdk_mac_of_buffer },

#ifndef KERNEL
  /* These MACs can only be used in user-mode code.  See comments
     above for more information. */


#endif /* !KERNEL */
  
  { "none", 0, FALSE, NULL },
  { NULL }
};

struct SshMacRec
{
  const SshMacDef *ops;
  Boolean ops_allocated;
  void *context;
};

/* Returns a comma-separated list of supported mac types.  The caller
   must return the list with ssh_xfree(). */

DLLEXPORT char * DLLCALLCONV
ssh_mac_get_supported(void)
{
  int i;
  SshBuffer buf;
  char *list;

  ssh_buffer_init(&buf);
  for (i = 0; ssh_mac_algorithms[i].name != NULL; i++)
    {
      if (ssh_buffer_len(&buf) != 0)
        ssh_buffer_append(&buf, (unsigned char *) ",", 1);
      ssh_buffer_append(&buf, (unsigned char *) ssh_mac_algorithms[i].name,
                    strlen(ssh_mac_algorithms[i].name));
    }
  ssh_buffer_append(&buf, (unsigned char *) "\0", 1);
  list = ssh_xstrdup(ssh_buffer_ptr(&buf));
  ssh_buffer_uninit(&buf);
  return list;
}

/* Check if given mac name belongs to the set of supported ciphers. */

DLLEXPORT Boolean DLLCALLCONV
ssh_mac_supported(const char *name)
{
  unsigned int i;

  if (name == NULL)
    return FALSE;
  
  for (i = 0; ssh_mac_algorithms[i].name != NULL; i++)
    if (strcmp(ssh_mac_algorithms[i].name, name) == 0)
      return TRUE;
  return FALSE;
}

/* Allocate mac for use in session. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_mac_allocate(const char *type,
                 const unsigned char *key, size_t keylen,
                 SshMac *mac_return)
{
  int i;
  SshMac mac;

  /* Find the desired mac type from the array. */
  for (i = 0; ssh_mac_algorithms[i].name != NULL; i++)
    {
      if (strcmp(ssh_mac_algorithms[i].name, type) == 0)
        {
          /* Found the specified mac type.  Initialize the data structure. */
          mac = ssh_xmalloc(sizeof(*mac));
          mac->ops = &ssh_mac_algorithms[i];
          mac->ops_allocated = FALSE;
          
          if (mac->ops->ctxsize)
            {
              mac->context = ssh_xmalloc((*mac->ops->ctxsize)
                                         (ssh_mac_algorithms[i].hash_def) +
                                         (mac->ops->allocate_key ==
                                          TRUE ? keylen : 0));
              (*mac->ops->init)(mac->context, key, keylen,
                                ssh_mac_algorithms[i].hash_def);
            }
          else
            mac->context = NULL;
              
          /* Return the MAC context. */
          *mac_return = mac;
          return SSH_CRYPTO_OK;
        }
    }
  return SSH_CRYPTO_UNSUPPORTED;
}

DLLEXPORT void * DLLCALLCONV
ssh_mac_info_derive_from_hash(SshHash hash,
                              SshMacType type)
{
  const SshHashDef *hash_def;
  SshMacDef  *mac_def;
  char buffer[128], *tmp;
  
  if (hash == NULL)
    return NULL;
  hash_def = ssh_hash_get_definition_internal(hash);
  if (hash_def == NULL)
    return NULL;
  if (hash_def->name == NULL)
    return NULL;

  mac_def = ssh_xmalloc(sizeof(SshMacDef));
  mac_def->hash_def = hash_def;

  switch (type)
    {
    case SSH_MAC_TYPE_HMAC:
      mac_def->digest_length = hash_def->digest_length;
      mac_def->allocate_key  = FALSE;
      mac_def->ctxsize       = ssh_hmac_ctxsize;
      mac_def->init          = ssh_hmac_init;
      mac_def->start         = ssh_hmac_start;
      mac_def->update        = ssh_hmac_update;
      mac_def->final         = ssh_hmac_final;
      mac_def->mac_of_buffer = ssh_hmac_of_buffer;

      /* Build a name for it. */
      snprintf(buffer, 128, "hmac-%s", hash_def->name);
      tmp = ssh_xmalloc(strlen(buffer) + 1);
      memcpy(tmp, buffer, strlen(buffer) + 1);
      mac_def->name = tmp;
      break;

    case SSH_MAC_TYPE_KDK:
      mac_def->allocate_key  = TRUE;
      mac_def->init          = ssh_kdk_mac_init;
      mac_def->start         = ssh_kdk_mac_start;
      mac_def->update        = ssh_kdk_mac_update;
      mac_def->final         = ssh_kdk_mac_final;
      mac_def->mac_of_buffer = ssh_kdk_mac_of_buffer;

      /* Build a name for it. */
      snprintf(buffer, 128, "kdk-mac-%s", hash_def->name);
      tmp = ssh_xmalloc(strlen(buffer) + 1);
      memcpy(tmp, buffer, strlen(buffer) + 1);
      mac_def->name = tmp;
      break;
      
    default:
      ssh_xfree(mac_def);
      return NULL;
    }
  return (void *)mac_def;
}

DLLEXPORT void DLLCALLCONV
ssh_mac_info_free(void *mac_info)
{
  SshMacDef *mac_def = mac_info;
  ssh_xfree((char *)mac_def->name);
  ssh_xfree(mac_info);
}

/* Derive a mac from a hash. */
DLLEXPORT SshMac DLLCALLCONV
ssh_mac_allocate_with_info(const void *mac_info, 
                           unsigned char *key,
                           size_t keylen)
{
  SshMac mac;

  if (mac_info == NULL)
    return NULL;

  /* Found the specified mac type.  Initialize the data structure. */
  mac      = ssh_xmalloc(sizeof(*mac));
  mac->ops = (SshMacDef *)mac_info;
  mac->ops_allocated = TRUE;
  
  if (mac->ops->ctxsize)
    {
      mac->context = ssh_xmalloc((*mac->ops->ctxsize)
                                 (mac->ops->hash_def) +
                                 (mac->ops->allocate_key ==
                                  TRUE ? keylen : 0));
      (*mac->ops->init)(mac->context, key, keylen,
                        mac->ops->hash_def);
    }
  else
    {
      ssh_xfree(mac);
      return NULL;
    }
  
  return mac;
}

/* Free the mac. */

DLLEXPORT void DLLCALLCONV
ssh_mac_free(SshMac mac)
{
  if (mac->ops_allocated)
    {
      ssh_xfree((char *)mac->ops->name);
      ssh_xfree((SshMacDef *)mac->ops);
    }
  ssh_xfree(mac->context);
  ssh_xfree(mac);
}

/* Get the lenght of mac digest */

DLLEXPORT size_t DLLCALLCONV
ssh_mac_length(SshMac mac)
{
  if (mac->ops)
    if (mac->ops->digest_length)
      return mac->ops->digest_length;
  return 0;
}

/* Reset the mac to its initial state. This should be called before
   processing a new packet/message. */
DLLEXPORT void DLLCALLCONV
ssh_mac_start(SshMac mac)
{
  if (mac->ops)
    if (mac->ops->start)
      (*mac->ops->start)(mac->context);
}

DLLEXPORT void DLLCALLCONV
ssh_mac_update(SshMac mac, const unsigned char *data, size_t len)
{
  if (mac->ops)
    if (mac->ops->update)
      (*mac->ops->update)(mac->context, data, len);
}

DLLEXPORT void DLLCALLCONV
ssh_mac_final(SshMac mac, unsigned char *digest)
{
  if (mac->ops)
    if (mac->ops->final)
      (*mac->ops->final)(mac->context, digest);
}
