/*
 * $Log: md5.h,v $
 * $EndLog$
 */

#ifndef MD5_H
#define MD5_H

#include "sshcrypti.h"

#define SSH_MD5_DIGEST_SIZE 16

/* Returns the size of an md5 context. */
size_t ssh_md5_ctxsize(void);

/* Resets the context to its initial state. */
void ssh_md5_reset_context(void *context);

/* Adds data to the MD5 context.  The effect of calling this multiple times
   is as if all data had been concatenated together and passed in a single
   call. */
void ssh_md5_update(void *context, const unsigned char *buf,
		    size_t len);

/* Returns the 16-byte (128 bit) MD5 digest of the previously updated data.
   Clears the context structure (md5_init must be called if it is to be
   used again). */
void ssh_md5_final(void *context, unsigned char *digest);

/* Implements the internal MD5 transform.  This is normally not used directly.
   buf is the current internal state of the MD5 computation, and in is 64
   bytes to be added to the internal state. */
void ssh_md5_transform(SshUInt32 buf[4], const unsigned char in[64]);

/* Directly computes the MD5 checksum of the given buffer. 
   Otherwise use md5_final. */
void ssh_md5_of_buffer(unsigned char digest[16], const unsigned char *buf,
		       size_t len);

/* Make hash transparent structure definition visible outside. */
extern const SshHashDef ssh_hash_md5_def;

#endif /* MD5_H */
