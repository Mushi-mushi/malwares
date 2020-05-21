/*
 *  twofish.h
 * 
 *  Author: Markku-Juhani Saarinen <mjos@math.jyu.fi>
 * 
 *  Copyright (c) 1998  SSH Communications Security Ltd., Espoo, Finland
 *                      All rights reserved.
 */

#ifndef TWOFISH_H
#define TWOFISH_H

/* Gets the size of twofish context. */
size_t ssh_twofish_ctxsize(void);

/* Sets an already allocated twofish key */
Boolean ssh_twofish_init(void *context, const unsigned char *key,
                         size_t keylen,
                         Boolean for_encryption);

/* Encrypt/decrypt in electronic code book mode. */
void ssh_twofish_ecb(void *context, unsigned char *dest,
                 const unsigned char *src, size_t len,
                 unsigned char *iv);

/* Encrypt/decrypt in cipher block chaining mode. */
void ssh_twofish_cbc(void *context, unsigned char *dest,
                 const unsigned char *src, size_t len,
                 unsigned char *iv);

/* Encrypt/decrypt in cipher feedback mode. */
void ssh_twofish_cfb(void *context, unsigned char *dest,
                 const unsigned char *src, size_t len,
                 unsigned char *iv);

/* Encrypt/decrypt in output feedback mode. */
void ssh_twofish_ofb(void *context, unsigned char *dest,
                 const unsigned char *src, size_t len,
                 unsigned char *iv);

#endif /* TWOFISH_H */

