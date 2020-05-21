/*

sshbuffer.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995-1999 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sat Mar 18 04:12:25 1995 ylo

Code for manipulating variable-size buffers where you can easily
append data and consume it from either end.

*/

/*
 * $Id: sshbuffer.h,v 1.3 1999/03/30 14:10:08 sjl Exp $
 * $Log: sshbuffer.h,v $
 * $EndLog$
 */

#ifndef SSHBUFFER_H
#define SSHBUFFER_H

typedef struct
{
  unsigned char *buf;           /* SshBuffer for data. */
  size_t alloc;                 /* Number of bytes allocated for data. */
  size_t offset;                /* Offset of first byte containing data. */
  size_t end;                   /* Offset of last byte containing data. */
  Boolean dynamic;              /* Dynamically allocated (sanity check only) */
} SshBuffer;

/* Allocates and initializes a new buffer structure. */

SshBuffer *ssh_buffer_allocate(void);

/* Zeroes and frees any memory used by the buffer and its data structures. */

void ssh_buffer_free(SshBuffer *buffer);

/* Initializes an already allocated buffer structure. */

void ssh_buffer_init(SshBuffer *buffer);

/* Frees any memory used by the buffer, first zeroing the whole area.
   The buffer structure itself is not freed. */

void ssh_buffer_uninit(SshBuffer *buffer);

/* Clears any data from the buffer, making it empty.  This does not
   zero the memory.  This does not free the memory used by the buffer. */

void ssh_buffer_clear(SshBuffer *buffer);

/* Appends data to the buffer, expanding it if necessary. */

void ssh_buffer_append(SshBuffer *buffer,
                       const unsigned char *data, size_t len);

/* Appends space to the buffer, expanding the buffer if necessary.
   This does not actually copy the data into the buffer, but instead
   returns a pointer to the allocated region. */

void ssh_buffer_append_space(SshBuffer *buffer,
                             unsigned char **datap, size_t len);

/* Appends NUL-terminated C-strings <...> to the buffer.  The argument
   list must be terminated with a NULL pointer. */

void ssh_buffer_append_cstrs(SshBuffer *buffer, ...);

/* Returns the number of bytes of data in the buffer. */

size_t ssh_buffer_len(const SshBuffer *buffer);

/* Gets data from the beginning of the buffer.
   XXX this function will go away! */

void ssh_buffer_get(SshBuffer *buffer, unsigned char *buf, size_t len);

/* Consumes the given number of bytes from the beginning of the buffer. */

void ssh_buffer_consume(SshBuffer *buffer, size_t bytes);

/* Consumes the given number of bytes from the end of the buffer. */

void ssh_buffer_consume_end(SshBuffer *buffer, size_t bytes);

/* Returns a pointer to the first used byte in the buffer. */

unsigned char *ssh_buffer_ptr(const SshBuffer *buffer);

#endif /* SSHBUFFER_H */
