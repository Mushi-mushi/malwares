/*

pgp_s2k.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Convert passpharse to encryption key.

*/
/*
 * $Id: pgp_s2k.c,v 1.6 1999/04/05 18:01:29 tri Exp $
 * $Log: pgp_s2k.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef WITH_PGP
#include "sshcrypt.h"
#include "sshpgp.h"

#define SSH_DEBUG_MODULE "SshPgpStringToKey"

Boolean ssh_pgp_s2k(const char *passphrase, 
                    int s2k_type,
                    unsigned char *s2k_salt,
                    int s2k_count_byte,
                    int hash_algorithm,
                    unsigned char *key_buf,
                    int key_buf_len)
{
  SshHash hash;
  SshCryptoStatus cr;
  SshUInt32 s2k_count;
  const char *hash_name;
  int digest_len;
  unsigned char *digest;
  int passphrase_len;
  int i, j;
  unsigned char *tmp_data;
  size_t tmp_data_len;

  hash_name = ssh_pgp_canonical_hash_name(hash_algorithm);
  if (hash_name == NULL)
    return FALSE;
  cr = ssh_hash_allocate(hash_name, &hash);
  digest_len = ssh_hash_digest_length(hash);
  digest = ssh_xmalloc(digest_len);
  passphrase_len = strlen(passphrase);
  switch (s2k_type) 
    {
    case SSH_PGP_S2K_TYPE_SIMPLE:
    case SSH_PGP_S2K_TYPE_SALTED:
      for (i = 0; i < key_buf_len; i += digest_len)
        {
          if (i > 0)
            {
              char preload[1];

              ssh_hash_reset(hash);
              preload[0] = (i / digest_len) - 1;
              ssh_hash_update(hash, preload, 1);
            }
          if (s2k_type == SSH_PGP_S2K_TYPE_SALTED)
            ssh_hash_update(hash, s2k_salt, 8);
          ssh_hash_update(hash, passphrase, passphrase_len);
          ssh_hash_final(hash, digest);
          if ((key_buf_len - i) < digest_len)
            memcpy(&(key_buf[i]), digest, key_buf_len - i);
          else
            memcpy(&(key_buf[i]), digest, digest_len);
        }
      memset(digest, 'F', digest_len);
      ssh_xfree(digest);
      ssh_hash_free(hash);
      return TRUE;

    case SSH_PGP_S2K_TYPE_SALTED_ITERATED:
    case SSH_PGP_S2K_TYPE_ITERATED:
      s2k_count = (((SshUInt32)16 + (s2k_count_byte & 0xf)) << 
                   ((s2k_count_byte >> 4) + 6));
      if (s2k_type == SSH_PGP_S2K_TYPE_SALTED_ITERATED)
        {
          tmp_data_len = 8 + passphrase_len;
          tmp_data = ssh_xmalloc(tmp_data_len);
          memcpy(tmp_data, s2k_salt, 8);
          memcpy(&(tmp_data[8]), passphrase, passphrase_len);
        }
      else
        {
          tmp_data_len = passphrase_len;
          tmp_data = ssh_xmalloc(tmp_data_len);
          memcpy(tmp_data, passphrase, passphrase_len);
        }
      for (i = 0; i < key_buf_len; i += digest_len)
        {
          if (i > 0)
            {
              char preload[1];

              ssh_hash_reset(hash);
              preload[0] = (i / digest_len) - 1;
              ssh_hash_update(hash, preload, 1);
            }
          ssh_hash_update(hash, tmp_data, tmp_data_len);
          for (j = tmp_data_len; j < s2k_count; j += tmp_data_len)
            {
              if ((j + tmp_data_len) >= s2k_count)
                {
                  ssh_hash_update(hash, tmp_data, s2k_count - j);
                }
              else
                {
                  ssh_hash_update(hash, tmp_data, tmp_data_len);
                }
            }
          ssh_hash_final(hash, digest);
          if ((key_buf_len - i) < digest_len)
            memcpy(&(key_buf[i]), digest, key_buf_len - i);
          else
            memcpy(&(key_buf[i]), digest, digest_len);
        }
      memset(digest, 'F', digest_len);
      ssh_xfree(digest);
      memset(tmp_data, 'F', tmp_data_len);
      ssh_xfree(tmp_data);
      ssh_hash_free(hash);
      return TRUE;

    default:
      ssh_hash_free(hash);
      return FALSE;
    }
}

#endif /* WITH_PGP */
/* eof (pgp_s2k.c) */
