/*

sshbuffer.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995-1999 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
              All rights reserved

Created: Sat Mar 18 04:15:33 1995 ylo

Functions for manipulating fifo buffers (that can grow if needed).

*/

/*
 * $Id: sshbuffer.c,v 1.11 1999/03/30 14:11:04 sjl Exp $
 * $Log: sshbuffer.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshBuffer"

/* Allocates a new buffer. */

SshBuffer *ssh_buffer_allocate()
{
  SshBuffer *buffer = ssh_xmalloc(sizeof(*buffer));
  ssh_buffer_init(buffer);
  buffer->dynamic = TRUE;
  return buffer;
}

/* Zeroes and frees the buffer. */

void ssh_buffer_free(SshBuffer *buffer)
{
  SSH_ASSERT(buffer);
  if (!buffer->dynamic)
    ssh_fatal("ssh_buffer_free given a buffer which was not dynamically allocated.");
  ssh_buffer_uninit(buffer);
  ssh_xfree(buffer);
}

/* Initializes the buffer structure. */

void ssh_buffer_init(SshBuffer *buffer)
{
  SSH_ASSERT(buffer);

  buffer->alloc = 4096;
  buffer->buf = ssh_xmalloc(buffer->alloc);
  buffer->offset = 0;
  buffer->end = 0;
  buffer->dynamic = FALSE;
}

/* Frees any memory used for the buffer. */

void ssh_buffer_uninit(SshBuffer *buffer)
{
  SSH_ASSERT(buffer);
  memset(buffer->buf, 0, buffer->alloc);
  ssh_xfree(buffer->buf);
}

/* Clears any data from the buffer, making it empty.  This does not actually
   zero the memory. */

void ssh_buffer_clear(SshBuffer *buffer)
{
  SSH_ASSERT(buffer);

  buffer->offset = 0;
  buffer->end = 0;
}

/* Appends data to the buffer, expanding it if necessary. */

void ssh_buffer_append(SshBuffer *buffer, const unsigned char *data,
                       size_t len)
{
  unsigned char *cp;

  ssh_buffer_append_space(buffer, &cp, len);
  if (len > 0)
    memcpy(cp, data, len);
}

/* Appends space to the buffer, expanding the buffer if necessary.
   This does not actually copy the data into the buffer, but instead
   returns a pointer to the allocated region. */

void ssh_buffer_append_space(SshBuffer *buffer, unsigned char **datap,
                             size_t len)
{
  SSH_ASSERT(buffer);
  SSH_ASSERT(len >= 0);

  /* If the buffer is empty, start using it from the beginning. */
  if (buffer->offset == buffer->end)
    {
      buffer->offset = 0;
      buffer->end = 0;
    }

 restart:
  /* If there is enough space to store all data, store it now. */
  if (buffer->end + len < buffer->alloc)
    {
      *datap = buffer->buf + buffer->end;
      buffer->end += len;
      return;
    }

  /* If the buffer is quite empty, but all data is at the end, move the
     data to the beginning and retry. */
  if (buffer->offset > buffer->alloc / 2)
    {
      memmove(buffer->buf, buffer->buf + buffer->offset,
              buffer->end - buffer->offset);
      buffer->end -= buffer->offset;
      buffer->offset = 0;
      goto restart;
    }

  /* Increase the size of the buffer and retry. */
  if (buffer->alloc + len > XMALLOC_MAX_SIZE - 4096)
    ssh_fatal("ssh_buffer_append_space: buffer grows too large!");
  buffer->alloc += len + 4096;
  buffer->buf = ssh_xrealloc(buffer->buf, buffer->alloc);
  goto restart;
}

/* Appends NUL-terminated C-strings <...> to the buffer.  The argument
   list must be terminated with a NULL pointer. */

void ssh_buffer_append_cstrs(SshBuffer *buffer, ...)
{
  va_list ap;
  char *str;

  va_start(ap, buffer);

  while ((str = va_arg(ap, char *)) != NULL)
    ssh_buffer_append(buffer, (unsigned char *) str, strlen(str));

  va_end(ap);
}

/* Returns the number of bytes of data in the buffer. */

size_t ssh_buffer_len(const SshBuffer *buffer)
{
  SSH_ASSERT(buffer);
  SSH_ASSERT(buffer->offset <= buffer->end);

  return buffer->end - buffer->offset;
}

/* Gets data from the beginning of the buffer. */

void ssh_buffer_get(SshBuffer *buffer, unsigned char *buf, size_t len)
{
  SSH_ASSERT(buffer);
  SSH_ASSERT(len >= 0);

  if (len > buffer->end - buffer->offset)
    ssh_fatal("buffer_get trying to get more bytes than in buffer");
  if (len > 0)
    memcpy(buf, buffer->buf + buffer->offset, len);
  buffer->offset += len;
}

/* Consumes the given number of bytes from the beginning of the buffer. */

void ssh_buffer_consume(SshBuffer *buffer, size_t bytes)
{
  if (bytes > buffer->end - buffer->offset)
    ssh_fatal("buffer_get trying to get more bytes than in buffer");
  buffer->offset += bytes;
}

/* Consumes the given number of bytes from the end of the buffer. */

void ssh_buffer_consume_end(SshBuffer *buffer, size_t bytes)
{
  if (bytes > buffer->end - buffer->offset)
    ssh_fatal("buffer_get trying to get more bytes than in buffer");
  buffer->end -= bytes;
}

/* Returns a pointer to the first used byte in the buffer. */

unsigned char *ssh_buffer_ptr(const SshBuffer *buffer)
{
  return buffer->buf + buffer->offset;
}

/* Dumps the contents of the buffer to stderr, 16 bytes per line, prefixed
   with an offset:

   offset__ : 00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f
*/

void buffer_dump(const SshBuffer *buffer)
{
  ssh_debug_hexdump(0, &(buffer->buf[buffer->offset]),
                    buffer->end - buffer->offset);
}
