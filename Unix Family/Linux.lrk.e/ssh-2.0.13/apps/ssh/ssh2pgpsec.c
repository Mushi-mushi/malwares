/*

  ssh2pgpsec.c

  Authors:
        Timo J. Rinne <tri@ssh.fi>

  Copyright (C) 1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Retrieve pgp secret key blobs from keyring.

*/

#include "ssh2includes.h"

#ifdef WITH_PGP

#include "sshpgp.h"
#include "sshuser.h"
#include "sshuserfile.h"
#include "sshfilebuffer.h"
#include "sshuserfilebuf.h"
#include "ssh2pgp.h"

#define SSH_DEBUG_MODULE "Ssh2PgpSecret"

/* Search pgp keyring with given user credentials.  If secret key is
   found, it is returned as a pgp secret key blob.  
   It can be decoded with ssh_pgp_secret_key_decode or
   ssh_pgp_secret_key_decode_with_passphrase.  Blob must be freed by
   the caller with ssh_xfree.  If return value is FALSE, key was not
   found and blob pointer is not altered. */

Boolean ssh2_find_pgp_secret_key_internal(SshUser uc,
                                          const char *fn,
                                          const char *name,
                                          const char *fingerprint,
                                          SshUInt32 id,
                                          unsigned char **blob,
                                          size_t *blob_len,
                                          char **comment);

Boolean ssh2_find_pgp_secret_key_internal(SshUser uc,
                                          const char *fn,
                                          const char *name,
                                          const char *fingerprint,
                                          SshUInt32 id,
                                          unsigned char **blob,
                                          size_t *blob_len,
                                          char **comment)
{
  struct stat st;
  SshUserFile uf;
  SshFileBuffer fb;
  SshPgpPacket pp;
  Boolean found;
  char *key_comment = NULL;

  if (ssh_userfile_stat(ssh_user_uid(uc), fn, &st) < 0)
    {
      SSH_DEBUG(2, ("file %s does not exist", fn));
      return FALSE;
    }
  if ((uf = ssh_userfile_open(ssh_user_uid(uc), fn, O_RDONLY, 0)) == NULL) 
    {
      SSH_DEBUG(2, ("could not open %s", fn));
      return FALSE;
    }
  ssh_file_buffer_init(&fb);
  if (ssh_file_buffer_attach_userfile(&fb, uf) == FALSE)
    {
      SSH_DEBUG(2, ("could not attach %s userfile to file buffer", fn));
      ssh_userfile_close(uf);
      ssh_file_buffer_uninit(&fb);
      return FALSE;
    }
  if (fingerprint != NULL)
    found = ssh_pgp_find_secret_key_with_fingerprint(&fb, 
                                                     fingerprint, 
                                                     &pp,
                                                     (comment ? 
                                                      &key_comment :
                                                      NULL));
  else if (name != NULL)
    found = ssh_pgp_find_secret_key_with_name(&fb, 
                                              name, 
                                              TRUE, 
                                              &pp,
                                              (comment ? 
                                               &key_comment :
                                               NULL));
  else
    found = ssh_pgp_find_secret_key_with_key_id(&fb, 
                                                id, 
                                                &pp,
                                                (comment ? 
                                                 &key_comment :
                                                 NULL));
  ssh_file_buffer_detach(&fb);
  ssh_file_buffer_uninit(&fb);
  ssh_userfile_close(uf);
  if (found == FALSE)
    {
      SSH_DEBUG(2, ("pgp library didn't find secret key"));
      return FALSE;
    }
  *blob = ssh_xmemdup(pp->data, pp->len);
  if (blob_len)
    *blob_len = pp->len;
  ssh_pgp_packet_free(pp);
  if (comment)
    *comment = key_comment;
  return TRUE;
}

Boolean ssh2_find_pgp_secret_key_with_fingerprint(SshUser uc,
                                                  const char *fn,
                                                  const char *fingerprint,
                                                  unsigned char **blob,
                                                  size_t *blob_len,
                                                  char **comment)
{
  Boolean rv;

  rv = ssh2_find_pgp_secret_key_internal(uc,
                                         fn,
                                         NULL,
                                         fingerprint,
                                         (SshUInt32)0,
                                         blob,
                                         blob_len,
                                         comment);
  if (rv == TRUE)
    {
      SSH_DEBUG(5, ("found pgp secret key fp=\"%s\" from \"%s\"", 
                    fingerprint, fn));
      return TRUE;
    }
  return FALSE;
}

Boolean ssh2_find_pgp_secret_key_with_name(SshUser uc,
                                           const char *fn,
                                           const char *name,
                                           unsigned char **blob,
                                           size_t *blob_len,
                                           char **comment)
{
  Boolean rv;

  rv = ssh2_find_pgp_secret_key_internal(uc,
                                         fn,
                                         name,
                                         NULL,
                                         (SshUInt32)0,
                                         blob,
                                         blob_len,
                                         comment);
  if (rv == TRUE)
    {
      SSH_DEBUG(5, ("found pgp secret key name=\"%s\" from \"%s\"", 
                    name, fn));
      return TRUE;
    }
  return FALSE;
}

Boolean ssh2_find_pgp_secret_key_with_id(SshUser uc,
                                         const char *fn,
                                         SshUInt32 id,
                                         unsigned char **blob,
                                         size_t *blob_len,
                                         char **comment)
{
  Boolean rv;

  rv = ssh2_find_pgp_secret_key_internal(uc,
                                         fn,
                                         NULL,
                                         NULL,
                                         id,
                                         blob,
                                         blob_len,
                                         comment);
  if (rv == TRUE)
    {
      SSH_DEBUG(5, ("found pgp secret key id=0x%08lx from \"%s\"", 
                    (unsigned long)id, fn));
      return TRUE;
    }
  return FALSE;
}

#endif /* WITH_PGP */

/* eof (ssh2pgpsec.c) */
