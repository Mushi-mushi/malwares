/*

  ssh2pgp.h

  Authors:
        Timo J. Rinne <tri@ssh.fi>

  Copyright (C) 1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Retrieve ssh2 keyblobs from pgp keyring.

*/

#ifndef SSH2PGP_H
#define SSH2PGP_H

#ifdef WITH_PGP

/* Search pgp keyring with given user credentials.  If key is find, convert
   it to ssh2 public key blob and return it to caller in blob pointer.
   Blob must be freed by the caller with ssh_xfree.  If return value is
   FALSE, key was not found and blob pointer is not altered. */

Boolean ssh2_find_pgp_public_key_with_fingerprint(SshUser uc,
                                                  const char *fn,
                                                  const char *fingerprint,
                                                  unsigned char **blob,
                                                  size_t *blob_len,
                                                  char **comment);

Boolean ssh2_find_pgp_public_key_with_name(SshUser uc,
                                           const char *fn,
                                           const char *name,
                                           unsigned char **blob,
                                           size_t *blob_len,
                                           char **comment);

Boolean ssh2_find_pgp_public_key_with_id(SshUser uc,
                                         const char *fn,
                                         SshUInt32 id,
                                         unsigned char **blob,
                                         size_t *blob_len,
                                         char **comment);

/* Search pgp keyring with given user credentials.  If secret key is
   found, it is returned as a pgp secret key blob.  
   It can be decoded with ssh_pgp_secret_key_decode or
   ssh_pgp_secret_key_decode_with_passphrase.  Blob must be freed by
   the caller with ssh_xfree.  If return value is FALSE, key was not
   found and blob pointer is not altered. */

Boolean ssh2_find_pgp_secret_key_with_fingerprint(SshUser uc,
                                                  const char *fn,
                                                  const char *fingerprint,
                                                  unsigned char **blob,
                                                  size_t *blob_len,
                                                  char **comment);

Boolean ssh2_find_pgp_secret_key_with_name(SshUser uc,
                                           const char *fn,
                                           const char *name,
                                           unsigned char **blob,
                                           size_t *blob_len,
                                           char **comment);

Boolean ssh2_find_pgp_secret_key_with_id(SshUser uc,
                                         const char *fn,
                                         SshUInt32 id,
                                         unsigned char **blob,
                                         size_t *blob_len,
                                         char **comment);

#endif /* WITH_PGP */
#endif /* ! SSH2PGP_H */

/* eof (ssh2pgp.h) */
