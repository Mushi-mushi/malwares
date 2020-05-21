/*

sshfilebuffer.h

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1998
              SSH Communications Security Oy, Espoo, Finland
              All rights reserved.

Created: Tue Sep  8 09:22:07 1998 tri

Code for reading files into SshBuffer.

*/

/*
 * $Id: sshfilebuffer.h,v 1.2 1999/04/06 17:39:53 tri Exp $
 * $Log: sshfilebuffer.h,v $
 * $EndLog$
 */

#ifndef SSHFILEBUFFER_H
#define SSHFILEBUFFER_H

#include "sshbuffer.h"

typedef size_t (*SshFileBufferReadCallback)(unsigned char *buf,
                                            size_t len,
                                            void *context);

typedef struct {
  FILE *f;
  Boolean attached_as_fileptr;
  SshFileBufferReadCallback read_callback;
  void *read_context;
  SshBuffer buf;
} SshFileBuffer;

/* Allocate a file buffer */
SshFileBuffer *ssh_file_buffer_allocate(void);

/* Free a file buffer */
void ssh_file_buffer_free(SshFileBuffer *buf);

/* Initialize an already allocated file buffer */
void ssh_file_buffer_init(SshFileBuffer *buf);

/* Uninitialize a file buffer initialized by ssh_file_buffer_init */
void ssh_file_buffer_uninit(SshFileBuffer *buf);

/* Clear the allocated file buffer.
   Detach the possibly attached file and zero the buffer. */
void ssh_file_buffer_clear(SshFileBuffer *buf);

/* Attach a file to a file buffer. */
Boolean ssh_file_buffer_attach(SshFileBuffer *buf, char *filename);

/* Attach a file pointer to a file buffer. */
Boolean ssh_file_buffer_attach_fileptr(SshFileBuffer *buf, FILE *f);

/* Attach a file pointer with a read callback. */
Boolean ssh_file_buffer_attach_with_read_callback(SshFileBuffer *buf, 
                                      SshFileBufferReadCallback read_callback,
                                      void *read_context);

/* Return TRUE if file is attached to a buffer. */
Boolean ssh_file_buffer_attached(SshFileBuffer *buf);

/* Detach file.  Leave the buffer untouched. */
void ssh_file_buffer_detach(SshFileBuffer *buf);

/* Read attached file so that buffer size exceeds argument bytes.
   Detach the file, if read fails or EOF is reached. */
Boolean ssh_file_buffer_expand(SshFileBuffer *buf, size_t bytes);

#endif /* ! SSHFILEBUFFER_H */
/* eof (sshfilebuffer.h) */
