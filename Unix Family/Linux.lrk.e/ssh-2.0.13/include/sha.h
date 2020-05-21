/*

  Author: Antti Huima <huima@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Fri May 17 02:25:51 1996 [huima]

  SHA - Secure Hash Algorithm

  */

/*
 * $Id: sha.h,v 1.11 1998/08/06 12:11:42 tmo Exp $
 * $Log: sha.h,v $
 * $EndLog$
 */

#ifndef SHA_H
#define SHA_H

#include "sshcrypti.h"

/* Returns the size of an SHA context. */
size_t ssh_sha_ctxsize(void);

/* Resets the SHA context to its initial state. */
void ssh_sha_reset_context(void *context);

/* Add `len' bytes from the given buffer to the hash. */
void ssh_sha_update(void *context, const unsigned char *buf,
		    size_t len);

/* Finish hashing. Return the 20-byte long digest to the
   caller-supplied buffer. */
void ssh_sha_final(void *context, unsigned char *digest);

/* Compute SHA digest from the buffer. */
void ssh_sha_of_buffer(unsigned char digest[20],
		       const unsigned char *buf, size_t len);

/* Finish hashing. Return the 12-byte long digest to the
   caller-supplied buffer. */
void ssh_sha_96_final(void *context, unsigned char *digest);

/* Compute SHA digest from the buffer. */
void ssh_sha_96_of_buffer(unsigned char digest[20],
		       const unsigned char *buf, size_t len);

/* Finish hashing. Return the 10-byte long digest to the
   caller-supplied buffer. */
void ssh_sha_80_final(void *context, unsigned char *digest);

/* Compute SHA digest from the buffer. */
void ssh_sha_80_of_buffer(unsigned char digest[20],
		       const unsigned char *buf, size_t len);

/* Make the defining structure visible everywhere. */
extern const SshHashDef ssh_hash_sha_def;
extern const SshHashDef ssh_hash_sha_96_def;
extern const SshHashDef ssh_hash_sha_80_def;

#endif /* SHA_H */

