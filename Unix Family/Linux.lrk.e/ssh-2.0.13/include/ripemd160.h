/*
  
  ripemd160.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sun Aug 10 01:17:46 1997 [mkojo]

  Prototypes for RipeMD-160 hash function. 

  */

/*
 * $Id: ripemd160.h,v 1.5 1998/08/06 12:11:40 tmo Exp $
 * $Log: ripemd160.h,v $
 * $EndLog$
 */

#ifndef RIPEMD160_H
#define RIPEMD160_H

#include "sshcrypti.h"

/* Returns the size of an RIPEMD-160 context. */
size_t ssh_ripemd160_ctxsize(void);

/* Resets the RIPEMD-160 context to its initial state. */
void ssh_ripemd160_reset_context(void *context);

/* Add `len' bytes from the given buffer to the hash. */
void ssh_ripemd160_update(void *context, const unsigned char *buf,
			  size_t len);

/* Finish hashing. Return the 20-byte long digest to the
   caller-supplied buffer. */
void ssh_ripemd160_final(void *context, unsigned char *digest);

/* Compute RIPEMD-160 digest from the buffer. */
void ssh_ripemd160_of_buffer(unsigned char digest[20],
			     const unsigned char *buf, size_t len);

/* Finish hashing. Return the 12-byte long digest to the
   caller-supplied buffer. */
void ssh_ripemd160_96_final(void *context, unsigned char *digest);

/* Compute RIPEMD-160 digest from the buffer. */
void ssh_ripemd160_96_of_buffer(unsigned char digest[20],
			     const unsigned char *buf, size_t len);

/* Finish hashing. Return the 10-byte long digest to the
   caller-supplied buffer. */
void ssh_ripemd160_80_final(void *context, unsigned char *digest);

/* Compute RIPEMD-160 digest from the buffer. */
void ssh_ripemd160_80_of_buffer(unsigned char digest[20],
			     const unsigned char *buf, size_t len);

/* Make the defining structure visible everywhere. */
extern const SshHashDef ssh_hash_ripemd160_def;
extern const SshHashDef ssh_hash_ripemd160_96_def;
extern const SshHashDef ssh_hash_ripemd160_80_def;

#endif /* RIPEMD160_H */
