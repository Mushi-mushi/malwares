/*

blowfish.h

Author: Mika Kojo
Copyright (c) 1996 SSH Communications Security Oy

Created: Wed May 28 20:25 1996

The blowfish encryption algorithm, created by Bruce Schneier.

*/

/*
 * $Id: blowfish.h,v 1.18 1998/12/03 19:48:11 mkojo Exp $
 * $Log: blowfish.h,v $
 * $EndLog$
 */

#ifndef BLOWFISH_H
#define BLOWFISH_H

/* Prototypes */

/* Gives the size of memory block allocated for blowfish context */
size_t ssh_blowfish_ctxsize(void);

/* Initializes an already allocated area for blowfish encryption/decryption */
Boolean ssh_blowfish_init(void *context,
                          const unsigned char *key, size_t keylen,
                          Boolean for_encryption);

/* Encrypt/decrypt in electronic code book mode. */
void ssh_blowfish_ecb(void *context, unsigned char *dest,
                      const unsigned char *src, size_t len,
                      unsigned char *iv);

/* Encrypt/decrypt in cipher block chaining mode. */
void ssh_blowfish_cbc(void *context, unsigned char *dest,
                      const unsigned char *src, size_t len,
                      unsigned char *iv);

/* Encrypt/decrypt in cipher feedback mode. */
void ssh_blowfish_cfb(void *context, unsigned char *dest,
                      const unsigned char *src, size_t len,
                      unsigned char *iv);

/* Encrypt/decrypt in output feedback mode. */
void ssh_blowfish_ofb(void *context, unsigned char *dest,
                      const unsigned char *src, size_t len,
                      unsigned char *iv);

#endif

