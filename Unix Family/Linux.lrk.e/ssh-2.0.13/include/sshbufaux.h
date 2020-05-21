/*

sshbufaux.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Wed Mar 29 02:18:23 1995 ylo

*/

/*
 * $Id: sshbufaux.h,v 1.2 1999/04/29 13:38:56 huima Exp $
 * $Log: sshbufaux.h,v $
 * $EndLog$
 */

#ifndef BUFAUX_H
#define BUFAUX_H

#include "sshbuffer.h"
#include "sshmp.h" /* was "gmp.h" */

/* Returns a hex value of the specified length from the buffer. */
unsigned int hex2int(const char *buf, size_t len);

/* Outputs a hex value of the specified length to the buffer. */
void int2hex(char *buf, size_t len, unsigned int value);

/* Stores an SshInt in the buffer in ssh2 style */
void buffer_put_mp_int_ssh2style(SshBuffer *buffer, SshInt *value);

/* Get an SshInt from a buffer in ssh2 style */
void buffer_get_mp_int_ssh2style(SshBuffer *buffer, SshInt *value);

/* Stores an SshInt in the buffer with a 2-byte msb first bit count, followed
   by (bits+7)/8 bytes of binary data, msb first. */
void buffer_put_mp_int(SshBuffer *buffer, SshInt *value);

/* Retrieves an SshInt from the buffer. */
void buffer_get_mp_int(SshBuffer *buffer, SshInt *value);



/* Returns a 32-bit integer from the buffer (4 bytes, msb first). */
unsigned long buffer_get_int(SshBuffer *buffer);

/* Stores a 32-bit integer in the buffer in 4 bytes, msb first. */
void buffer_put_int(SshBuffer *buffer, unsigned long value);

/* Returns a character from the buffer (0 - 255). */
unsigned int buffer_get_char(SshBuffer *buffer);

/* Stores a character in the buffer. */
void buffer_put_char(SshBuffer *buffer, unsigned int value);

/* Returns an arbitrary binary string from the buffer.  The string cannot
   be longer than 256k.  The returned value points to memory allocated
   with ssh_xmalloc; it is the responsibility of the calling function to free
   the data.  If length_ptr is non-NULL, the length of the returned data
   will be stored there.  A null character will be automatically appended
   to the returned string, and is not counted in length. */
void *buffer_get_uint32_string(SshBuffer *buffer, size_t *length_ptr);

/* Stores and arbitrary binary string in the buffer.  NOTE: this format
   uses uint32 length. */
void buffer_put_uint32_string(SshBuffer *buffer, const void *buf, size_t len);

/* Additions for the new protocol. */

/* Put a vlint32 into the buffer. */
void buffer_put_vlint32(SshBuffer *buffer, unsigned long value);

/* Recover a vlint32 from the buffer. */
unsigned long buffer_get_vlint32(SshBuffer *buffer);

/* Put a string into the buffer. This is similar to buffer_put_string,
   but uses vlints instead of fixed-sized integers to represent the
   length of the string. */
void buffer_put_vlint32_string(SshBuffer *buffer, const void *buf, size_t len);

/* Get a vlint32-prefixed string from the buffer.  The caller is responsible
   for freeing the string with ssh_xfree. */
void *buffer_get_vlint32_string(SshBuffer *buffer, size_t *length_ptr);

/* Store a boolean into the buffer. */
void buffer_put_boolean(SshBuffer *buffer, Boolean value);

/* Get it */
Boolean buffer_get_boolean(SshBuffer *buffer);

#endif /* BUFAUX_H */
