/*

  ssh2pgppub.c

  Authors:
        Timo J. Rinne <tri@ssh.fi>

  Copyright (C) 1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Retrieve ssh2 keyblobs from pgp keyring.

*/

#include "ssh2includes.h"

#ifdef WITH_PGP

#include "sshpgp.h"
#include "sshuser.h"
#include "sshuserfile.h"
#include "sshfilebuffer.h"
#include "sshuserfilebuf.h"
#include "ssh2pubkeyencode.h"
#include "ssh2pgp.h"

#define SSH_DEBUG_MODULE "Ssh2PgpPublic"

/* Search pgp keyring with given user credentials.  If key is find, convert
   it to ssh2 public key blob and return it to caller in blob pointer.
   Blob must be freed by the caller with ssh_xfree.  If return value is
   FALSE, key was not found and blob pointer is not altered. */

Boolean ssh2_find_pgp_public_key_internal(SshUser uc,
                                          const char *fn,
                                          const char *name,
                                          const char *fingerprint,
                                          SshUInt32 id,
                                          unsigned char **blob,
                                          size_t *blob_len,
                                          char **comment);

Boolean ssh2_find_pgp_public_key_internal(SshUser uc,
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
  SshPgpPublicKey pgpkey;
  Boolean found;
  size_t bl;
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
    found = ssh_pgp_find_public_key_with_fingerprint(&fb, 
                                                     fingerprint, 
                                                     &pp,
                                                     (comment ? 
                                                      &key_comment :
                                                      NULL));
  else if (name != NULL)
    found = ssh_pgp_find_public_key_with_name(&fb,
                                              name, 
                                              TRUE, 
                                              &pp,
                                              (comment ? 
                                               &key_comment :
                                               NULL));
  else
    found = ssh_pgp_find_public_key_with_key_id(&fb, 
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
      SSH_DEBUG(2, ("pgp library didn't find public key"));
      return FALSE;
    }
  if (ssh_pgp_public_key_decode(pp->data, pp->len, &pgpkey) == 0)
    {
      SSH_DEBUG(2, ("pgp library fails to decode public key"));
      ssh_pgp_packet_free(pp);
      ssh_xfree(key_comment);
      return FALSE;
    }
  ssh_pgp_packet_free(pp);
  if (pgpkey->key == NULL)
    {
      SSH_DEBUG(2, ("pgp library fails to import public key"));
      ssh_pgp_public_key_free(pgpkey);
      ssh_xfree(key_comment);
      return FALSE;
    }
  if ((bl = ssh_encode_pubkeyblob(pgpkey->key, blob)) == 0)
    {
      SSH_DEBUG(2, ("unable to ssh2 encode pgp public key"));
      ssh_pgp_public_key_free(pgpkey);
      ssh_xfree(key_comment);
      return FALSE;
    }
  if (blob_len)
    *blob_len = bl;
  ssh_pgp_public_key_free(pgpkey);
  if (comment)
    *comment = key_comment;
  return TRUE;
}

Boolean ssh2_find_pgp_public_key_with_fingerprint(SshUser uc,
                                                  const char *fn,
                                                  const char *fingerprint,
                                                  unsigned char **blob,
                                                  size_t *blob_len,
                                                  char **comment)
{
  Boolean rv;

  rv = ssh2_find_pgp_public_key_internal(uc,
                                         fn,
                                         NULL,
                                         fingerprint,
                                         (SshUInt32)0,
                                         blob,
                                         blob_len,
                                         comment);
  if (rv == TRUE)
    {
      SSH_DEBUG(5, ("found pgp key fp=\"%s\" from \"%s\"", fingerprint, fn));
      return TRUE;
    }
  return FALSE;
}

Boolean ssh2_find_pgp_public_key_with_name(SshUser uc,
                                           const char *fn,
                                           const char *name,
                                           unsigned char **blob,
                                           size_t *blob_len,
                                           char **comment)
{
  Boolean rv;

  rv = ssh2_find_pgp_public_key_internal(uc,
                                         fn,
                                         name,
                                         NULL,
                                         (SshUInt32)0,
                                         blob,
                                         blob_len,
                                         comment);
  if (rv == TRUE)
    {
      SSH_DEBUG(5, ("found pgp key name=\"%s\" from \"%s\"", name, fn));
      return TRUE;
    }
  return FALSE;
}

Boolean ssh2_find_pgp_public_key_with_id(SshUser uc,
                                         const char *fn,
                                         SshUInt32 id,
                                         unsigned char **blob,
                                         size_t *blob_len,
                                         char **comment)
{
  Boolean rv;

  rv = ssh2_find_pgp_public_key_internal(uc,
                                         fn,
                                         NULL,
                                         NULL,
                                         id,
                                         blob,
                                         blob_len,
                                         comment);
  if (rv == TRUE)
    {
      SSH_DEBUG(5, ("found pgp key id=0x%08lx from \"%s\"", 
                    (unsigned long)id, fn));
      return TRUE;
    }
  return FALSE;
}

#endif /* WITH_PGP */

/* eof (ssh2pgppub.c) */
