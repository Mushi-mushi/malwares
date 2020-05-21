/*

sshunixfdstream.h

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

Created: Tue Aug 20 10:34:54 1996 ylo

Streams interface interfacing to file descriptors on Unix.

*/

/*
 * $Id: sshunixfdstream.h,v 1.2 1998/06/02 15:54:54 ylo Exp $
 * $Log: sshunixfdstream.h,v $
 * $EndLog$
 */

#ifndef SSHUNIXFDSTREAM_H
#define SSHUNIXFDSTREAM_H

#include "sshstream.h"

/* Creates a stream around a file descriptor.  The descriptor must be
   open for both reading and writing.  If close_on_destroy is TRUE, the
   descriptor will be automatically closed when the stream is destroyed. */
SshStream ssh_stream_fd_wrap(int fd, Boolean close_on_destroy);

/* Creates a stream around two file descriptors, one for reading and
   one for writing.  `readfd' must be open for reading, and `writefd' for
   writing.  If close_on_destroy is TRUE, both descriptors will be
   automatically closed when the stream is destroyed. */
SshStream ssh_stream_fd_wrap2(int readfd, int writefd,
			      Boolean close_on_destroy);

/* Creates a stream around the standard input/standard output of the
   current process. */
SshStream ssh_stream_fd_stdio(void);

/* Returns the file descriptor being used for reads, or -1 if the stream is
   not an fd stream. */
int ssh_stream_fd_get_readfd(SshStream stream);

/* Returns the file descriptor being used for writes, or -1 if the stream is
   not an fd stream. */
int ssh_stream_fd_get_writefd(SshStream stream);

/* Marks the stream as a forked copy.  The consequence is that when the stream
   is destroyed, the underlying file descriptors are not restored to blocking
   mode.  This should be called for each stream before destroying them
   after a fork (but only on one of parent or child). */
void ssh_stream_fd_mark_forked(SshStream stream);

#endif /* SSHUNIXFDSTREAM_H */
