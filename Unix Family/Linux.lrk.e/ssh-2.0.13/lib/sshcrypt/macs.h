/*
  macs.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Tue Mar 18 17:33:36 1997 [mkojo]

  Implementation of message authentication code routines.

  */

/*
 * $Id: macs.h,v 1.7 1998/08/06 12:11:36 tmo Exp $
 * $Log: macs.h,v $
 * $EndLog$
 */

#ifndef MACS_H
#define MACS_H

/* Keyed MAC's. */

/* Generic interface. */

/* The basic key-data-key message authentication code routines. */

/* Remember to allocate the extra space for the key! */
size_t
ssh_kdk_mac_ctxsize(const SshHashDef *hash_def);

void 
ssh_kdk_mac_init(void *context, const unsigned char *key, size_t keylen,
		 const SshHashDef *hash_def);

void ssh_kdk_mac_start(void *context);

void ssh_kdk_mac_update(void *context, const unsigned char *buf,
			size_t len);

void ssh_kdk_mac_final(void *context, unsigned char *digest);

void ssh_kdk_mac_96_final(void *context, unsigned char *digest);

void ssh_kdk_mac_of_buffer(void *context, const unsigned char *buf,
			   size_t len, unsigned char *digest);

void ssh_kdk_mac_96_of_buffer(void *context, const unsigned char *buf,
			      size_t len, unsigned char *digest);

void ssh_kdk_mac_64_final(void *context, unsigned char *digest);

void ssh_kdk_mac_64_of_buffer(void *context, const unsigned char *buf,
			      size_t len, unsigned char *digest);

/* Specific and hopefully soon obsolete. */

/* Compute context size of md5 mac. Remember to allocate space for the
   key also. I.e. use
     context = ssh_xmalloc(ssh_mac_md5_ctxsize() + keylen).
   Freeing must be performed by upperlayer. */
size_t ssh_mac_md5_ctxsize(void);

/* Initialize preallocated md5 mac context. */
void ssh_mac_md5_init(void *context,
		      const unsigned char *key, size_t keylen);

/* Reset md5 mac. */
void ssh_mac_md5_start(void *context);

/* Update the md5 mac context with buf of len bytes. */
void ssh_mac_md5_update(void *context, const unsigned char *buf,
			size_t len);

/* Output the md5 mac digest. */
void ssh_mac_md5_final(void *context, unsigned char *digest);

/* Directly compute the md5 mac digest of given buffer. */ 
void ssh_mac_md5_of_buffer(void *context, const unsigned char *buf,
			   size_t len, unsigned char *digest);

/* Compute context size of sha mac. Remember to allocate space for the
   key also. I.e. use
     context = ssh_xmalloc(ssh_mac_sha_ctxsize() + keylen).
   Freeing must be preformed by upperlayer. */
size_t ssh_mac_sha_ctxsize(void);

/* Initialize preallocated sha mac context. */
void ssh_mac_sha_init(void *context,
		      const unsigned char *key, size_t keylen);

/* Reset sha mac. */
void ssh_mac_sha_start(void *context);

/* Update the sha mac context with buf of len bytes. */
void ssh_mac_sha_update(void *context, const unsigned char *buf,
			size_t len);

/* Output the sha mac digest. */
void ssh_mac_sha_final(void *context, unsigned char *digest);

/* Directly compute the sha mac digest of given buffer. */ 
void ssh_mac_sha_of_buffer(void *context, const unsigned char *buf,
			   size_t len, unsigned char *digest);

/* Following routines are same. */
#define ssh_mac_md5_8_ctxsize  ssh_mac_md5_ctxsize
#define ssh_mac_md5_8_init     ssh_mac_md5_init
#define ssh_mac_md5_8_start    ssh_mac_md5_start
#define ssh_mac_md5_8_update   ssh_mac_md5_update

/* Output md5-8 mac digest. */
void ssh_mac_md5_8_final(void *context, unsigned char *digest);

/* Directly compute the md5-8 mac digest of given buffer. */ 
void ssh_mac_md5_8_of_buffer(void *context, const unsigned char *buf,
			     size_t len, unsigned char *digest);

/* Following routines are same. */
#define ssh_mac_sha_8_ctxsize  ssh_mac_sha_ctxsize
#define ssh_mac_sha_8_init     ssh_mac_sha_init
#define ssh_mac_sha_8_start    ssh_mac_sha_start
#define ssh_mac_sha_8_update   ssh_mac_sha_update

/* Output sha-8 mac digest. */
void ssh_mac_sha_8_final(void *context, unsigned char *digest);

/* Directly compute the sha-8 mac digest of given buffer. */ 
void ssh_mac_sha_8_of_buffer(void *context, const unsigned char *buf,
			     size_t len, unsigned char *digest);

#if 0

/* Define one mac function. */
SshMacDef ssh_mac_md5_def =
{
  "mac-md5", 16, TRUE, ssh_hash_md5_def,
  ssh_mac_md5_ctxsize, ssh_mac_md5_init, ssh_mac_md5_start,
  ssh_mac_md5_update, ssh_mac_md5_final
};

#endif

#endif /* MACS_H */
