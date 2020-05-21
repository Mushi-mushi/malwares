/*
  
  ssh2pubkeyencode.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Encode and decode ssh2 public key blobs.
  
*/

#ifndef PUBKEYENCODE_H
#define PUBKEYENCODE_H

#include "sshcrypt.h"

/* the "ssh-dss" type */
#define SSH_SSH_DSS    "ssh-dss"
#define SSH_CRYPTO_DSS "dl-modp{sign{dsa-nist-sha1},dh{plain}}"

/* the "ssh-rsa" type" */
#define SSH_SSH_RSA    "ssh-rsa"
#define SSH_CRYPTO_RSA \
        "if-modn{sign{rsa-pkcs1-md5,rsa-pkcs1-none},encrypt{rsa-pkcs1-none}}"

/* Encode a public key into a SSH2 format blob. Return size or 0 on
   failure. */

size_t ssh_encode_pubkeyblob(SshPublicKey pubkey, unsigned char **blob);

/* Decode a public key blob. Return NULL on failure. */

SshPublicKey ssh_decode_pubkeyblob(const unsigned char *blob, size_t bloblen);

/* Type of the encoded public key in blob.  Have to be freed with ssh_xfree. */
char *ssh_pubkeyblob_type(const unsigned char *blob, size_t bloblen);

#endif /* PUBKEYENCODE_H */
