/*

fdstream.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

Created: Tue Aug 20 10:43:37 1996 ylo

Streams interface interfacing to file descriptors on Unix.

*/

/*
 * $Id: sshunixfdstream.c,v 1.6 1998/06/02 17:53:40 ylo Exp $
 * $Log: sshunixfdstream.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshunixfdstream.h"
#include "sshunixeloop.h"
#include "sshtimeouts.h"

#include <sys/socket.h>  /* for shutdown() */

typedef struct
{
  int readfd;
  int writefd;
  Boolean close_on_destroy;

  Boolean write_has_failed;
  Boolean read_has_failed;
  Boolean destroyed;
  Boolean in_callback;
  Boolean keep_nonblocking;

  SshStreamCallback callback;
  void *context;
} *SshFdStream;

/* The method structure is defined later in this file. */
extern const SshStreamMethodsTable ssh_stream_fd_methods;


/* Creates a stream around a file descriptor.  The descriptor must be
   open for both reading and writing.  If close_on_destroy is TRUE, the
   descriptor will be automatically closed when the stream is destroyed. */

SshStream ssh_stream_fd_wrap(int fd, Boolean close_on_destroy)
{
  return ssh_stream_fd_wrap2(fd, fd, close_on_destroy);
}

/* Creates a stream around the standard input/standard output of the
   current process. */

SshStream ssh_stream_fd_stdio()
{
  return ssh_stream_fd_wrap2(0, 1, FALSE);
}

/* Recompute and set event loop request masks for the file descriptors. */

void ssh_stream_fd_request(SshFdStream sdata)
{
  unsigned int read_request, write_request;

  assert(!sdata->destroyed);

  if (sdata->read_has_failed)
    read_request = SSH_IO_READ;
  else
    read_request = 0;

  if (sdata->write_has_failed)
    write_request = SSH_IO_WRITE;
  else
    write_request = 0;

  if (sdata->readfd == sdata->writefd)
    {
      if (sdata->readfd >= 0)
        ssh_io_set_fd_request(sdata->readfd, read_request | write_request);
    }
  else
    {
      if (sdata->readfd >= 0)
          ssh_io_set_fd_request(sdata->readfd, read_request);
      if (sdata->writefd >= 0)
          ssh_io_set_fd_request(sdata->writefd, write_request);
    }
}

/* This function is called by the event loop whenever an event of interest
   occurs on one of the file descriptors. */

void ssh_stream_fd_callback(unsigned int events, void *context)
{
  SshFdStream sdata = (SshFdStream)context;

  /* This might get called by a pending callback, and might have been
     destroyed in the meanwhile.  Thus, we check for destroyed status.
     Note that no such events should come after the generated event that
     actually frees the context. */
  if (sdata->destroyed)
    return;

  /* Convert the event loop callback to a stream callback. */
  sdata->in_callback = TRUE;
  if (events & SSH_IO_READ)
    {
      sdata->read_has_failed = FALSE;
      if (sdata->callback)
	(*sdata->callback)(SSH_STREAM_INPUT_AVAILABLE, sdata->context);
    }
  if ((events & SSH_IO_WRITE) && !sdata->destroyed)
    {
      sdata->write_has_failed = FALSE;
      if (sdata->callback)
	(*sdata->callback)(SSH_STREAM_CAN_OUTPUT, sdata->context);
    }
  sdata->in_callback = FALSE;

  /* Check if the stream got destroyed in the callbacks. */
  if (sdata->destroyed)
    {
      memset(sdata, 'F', sizeof(*sdata));
      ssh_xfree(sdata);
      return;
    }

  /* Recompute the request masks.  Note that the context might have been
     destroyed by one of the earlier callbacks. */
  ssh_stream_fd_request(sdata);
}

/* Creates a stream around two file descriptors, one for reading and
   one for writing.  `readfd' must be open for reading, and `writefd' for
   writing.  If close_on_destroy is TRUE, both descriptors will be
   automatically closed when the stream is destroyed. */

SshStream ssh_stream_fd_wrap2(int readfd, int writefd,
			      Boolean close_on_destroy)
{
  SshFdStream sdata;

  sdata = ssh_xmalloc(sizeof(*sdata));
  memset(sdata, 0, sizeof(*sdata));
  sdata->readfd = readfd;
  sdata->writefd = writefd;
  sdata->close_on_destroy = close_on_destroy;
  sdata->read_has_failed = FALSE;
  sdata->write_has_failed = FALSE;
  sdata->destroyed = FALSE;
  sdata->in_callback = FALSE;
  sdata->keep_nonblocking = FALSE;
  sdata->callback = NULL;
  if (readfd >= 0)
    ssh_io_register_fd(readfd, ssh_stream_fd_callback, (void *)sdata);
  if (readfd != writefd && writefd >= 0)
    ssh_io_register_fd(writefd, ssh_stream_fd_callback, (void *)sdata);
  return ssh_stream_create(&ssh_stream_fd_methods, (void *)sdata);
}

/* Reads at most `size' bytes to the buffer `buffer'.  Returns 0 if
  EOF is encountered, negative value if the read would block, and
  the number of bytes read if something was read. */

int ssh_stream_fd_read(void *context, unsigned char *buf, size_t size)
{
  SshFdStream sdata = (SshFdStream)context;
  int len;

  assert(!sdata->destroyed);
  if (sdata->readfd >= 0)
    {
      len = read(sdata->readfd, buf, size);
      if (len >= 0)
	return len;
      
      if (errno == EAGAIN)
	{
	  /* No more data available at this time. */
	  sdata->read_has_failed = TRUE;
	  ssh_stream_fd_request(sdata);
	  return -1;
	}

      /* A real error occurred while reading. */
      sdata->read_has_failed = TRUE;
      ssh_stream_fd_request(sdata);
    }
  return 0;
}

/* Writes at most `size' bytes from the buffer `buffer'.  Returns 0 if the
   other end has indicated that it will no longer read (this condition is not
   guaranteed to be detected), a negative value if the write would block,
   and the number of bytes written if something was actually written. */

int ssh_stream_fd_write(void *context, const unsigned char *buf,
			size_t size)
{
  SshFdStream sdata = (SshFdStream)context;
  int len;

  assert(!sdata->destroyed);
  if (sdata->writefd >= 0)
    {
      len = write(sdata->writefd, buf, size);
      if (len >= 0)
	return len;

      if (errno == EAGAIN)
	{
	  /* Cannot write more at this time. */
	  sdata->write_has_failed = TRUE;
	  ssh_stream_fd_request(sdata);
	  return -1;
	}

      /* A real error occurred while writing. */
      sdata->write_has_failed = TRUE;
      ssh_stream_fd_request(sdata);
    }
  return 0;
}

/* Signals that the application will not write anything more to the stream. */

void ssh_stream_fd_output_eof(void *context)
{
  SshFdStream sdata = (SshFdStream)context;

  assert(!sdata->destroyed);

  /* We don't want to get more callbacks for write. */
  sdata->write_has_failed = FALSE;
  
  if (sdata->writefd >= 0)
    {
      if (sdata->writefd == sdata->readfd)
	{
	  /* Note: if writefd is not a socket, this will do nothing. */
	  shutdown(sdata->writefd, 1);
	}
      else
	{
	  /* Close the outgoing file descriptor. */
	  ssh_io_unregister_fd(sdata->writefd, sdata->keep_nonblocking);
	  close(sdata->writefd);
	  sdata->writefd = -1;
	}
    }
}

/* Sets the callback that the stream uses to notify the application of
   events of interest.  This function may be called at any time, and
   may be called multiple times.  The callback may be NULL, in which case
   it just won't be called.  Note that setting the callback does not
   automatically cause any notifications, and thus read/write must actually
   be tried to start the callback-based processing. */

void ssh_stream_fd_set_callback(void *context, SshStreamCallback callback,
				void *callback_context)
{
  SshFdStream sdata = (SshFdStream)context;

  assert(!sdata->destroyed);
  sdata->callback = callback;
  sdata->context = callback_context;
  sdata->read_has_failed = TRUE;
  sdata->write_has_failed = TRUE;
  ssh_stream_fd_request(sdata);
}

/* Closes, destroys, and frees the given stream.  Destruction is delayed,
   and the actual freeing is done from the bottom of the event loop.  This
   is needed because we might generated pending events for the object. */

void ssh_stream_fd_destroy(void *context)
{
  SshFdStream sdata = (SshFdStream)context;

  /* Mark it as destroyed. */
  assert(!sdata->destroyed);
  sdata->destroyed = TRUE;
  sdata->callback = NULL;

  /* Unregister the descriptors from the event loop. */
  if (sdata->readfd >= 0)
    ssh_io_unregister_fd(sdata->readfd, sdata->keep_nonblocking);
  if (sdata->readfd != sdata->writefd && sdata->writefd >= 0)
    ssh_io_unregister_fd(sdata->writefd, sdata->keep_nonblocking);

  /* Close the file descriptors if appropriate. */
  if (sdata->close_on_destroy)
    {
      if (sdata->readfd >= 0)
	close(sdata->readfd);
      if (sdata->readfd != sdata->writefd && sdata->writefd >= 0)
	close(sdata->writefd);
      sdata->writefd = -1;
      sdata->readfd = -1;
    }

  /* Cancel any pending timeouts for us. */
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, (void *)sdata);

  /* If this is called from a callback, delay actually freeing the context
     until we have returned from the callback.  The destroyed flag was set
     above, and will be tested after the callback has returned. */
  if (sdata->in_callback)
    return;
  
  /* Destroy the context.  We first fill it with garbage to ease debugging. */
  memset(sdata, 'F', sizeof(*sdata));
  ssh_xfree(sdata);
}

/* Returns the file descriptor being used for reads, or -1 if the stream is
   not an fd stream. */

int ssh_stream_fd_get_readfd(SshStream stream)
{
  if (ssh_stream_get_methods(stream) != &ssh_stream_fd_methods)
    return -1;
  return ((SshFdStream)ssh_stream_get_context(stream))->readfd;
}

/* Returns the file descriptor being used for writes, or -1 if the stream is
   not an fd stream. */

int ssh_stream_fd_get_writefd(SshStream stream)
{
  if (ssh_stream_get_methods(stream) != &ssh_stream_fd_methods)
    return -1;
  return ((SshFdStream)ssh_stream_get_context(stream))->writefd;
}

/* Marks the stream as a forked copy.  The consequence is that when the stream
   is destroyed, the underlying file descriptors are not restored to blocking
   mode.  This should be called for each stream before destroying them
   after a fork (but only on one of parent or child). */

void ssh_stream_fd_mark_forked(SshStream stream)
{
  if (ssh_stream_get_methods(stream) != &ssh_stream_fd_methods)
    return;
  ((SshFdStream)ssh_stream_get_context(stream))->keep_nonblocking = TRUE;
}

/* Methods table for this stream type. */

const SshStreamMethodsTable ssh_stream_fd_methods =
{
  ssh_stream_fd_read,
  ssh_stream_fd_write,
  ssh_stream_fd_output_eof,
  ssh_stream_fd_set_callback,
  ssh_stream_fd_destroy
};
