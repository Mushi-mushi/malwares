/*

filterstream.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

An object for filtering a data stream bidirectionally.  The object
allows callbacks to modify and filter data bidirectionally, and allow
them to disconnect the connection.

*/

#include "sshincludes.h"
#include "sshfilterstream.h"
#include "sshtimeouts.h"

typedef struct SshStreamFilterRec
{
  /* The underlying stream whose data we are filtering.  The "to" direction is
     data being written to this stream, and the "from" direction is data
     being read from this stream. */
  SshStream stream;
  
  /* Function to filter data to ``stream''. */
  SshFilterProc to_filter;

  /* Function to filter data from ``stream''. */
  SshFilterProc from_filter;

  /* Function to be called when the filter stream is closed. */
  void (*destroy)(void *context);

  /* Context to pass to the callback functions. */
  void *context;

  /* SshBuffer for data coming from ``stream''. */
  SshBuffer from_buffer;

  /* SshBuffer for data going to ``stream''. */
  SshBuffer to_buffer;

  /* Maximum number of bytes to store in buffer (including already accepted
     data). */
  size_t max_buffer_size;
  
  /* Number of bytes that have already been accepted but not yet written in
     the "from" direction. */
  size_t from_accepted_bytes;

  /* Number of bytes that have already been accepted but not yet written in
     the "to" direction. */
  size_t to_accepted_bytes;
  
  /* Set to TRUE if EOF is received from the stream. */
  Boolean from_eof_received;

  /* Set to TRUE if the upper level calls output_eof. */
  Boolean to_eof_received;
  
  /* Set to TRUE if the stream has been disconnected. */
  Boolean disconnected;

  /* Set to TRUE if shortcircuiting has been requested. */
  Boolean shortcircuit_requested;
  
  /* Set to TRUE if the stream has been shortcircuited and buffers flushed
     in the "from" direction. */
  Boolean from_shortcircuited;

  /* Set to TRUE if the stream has been shortcircuited and buffers flushed
     in the "to" direction. */
  Boolean to_shortcircuited;

  /* Callback to call when data can be read/written from the filter stream. */
  SshStreamCallback callback;

  /* Context to pass to ``callback''. */
  void *callback_context;
  
  /* Read from up has returned -1. */
  Boolean read_blocked;

  /* Write from up has returned -1. */
  Boolean write_blocked;
} *SshStreamFilter;

/* Called from a generated event, this calls the callback registered for
   this stream with INPUT_AVAILABLE notification. */

void ssh_stream_filter_read_upcall(void *context)
{
  SshStreamFilter sf = (SshStreamFilter)context;

  if (sf->callback)
    (*sf->callback)(SSH_STREAM_INPUT_AVAILABLE, sf->callback_context);
}

/* Called from a generated event, this calls the callback registered for
   this stream with CAN_OUTPUT notification. */

void ssh_stream_filter_write_upcall(void *context)
{
  SshStreamFilter sf = (SshStreamFilter)context;

  if (sf->callback)
    (*sf->callback)(SSH_STREAM_CAN_OUTPUT, sf->callback_context);
}

/* Schedules a call to our stream callback with INPUT_AVAILABLE, but only
   if reads are blocked (i.e., our read function has returned -1). */

void ssh_stream_filter_wake_up_reads(SshStreamFilter sf)
{
  if (!sf->read_blocked)
    return;

  ssh_register_timeout(0L, 0L, ssh_stream_filter_read_upcall, (void *)sf);
  sf->read_blocked = FALSE;
}

/* Schedules a call to our stream callback with CAN_OUTPUT, but only
   if writes are blocked (i.e., our write function has returned -1). */

void ssh_stream_filter_wake_up_writes(SshStreamFilter sf)
{
  if (!sf->write_blocked)
    return;

  ssh_register_timeout(0L, 0L, ssh_stream_filter_write_upcall, (void *)sf);
  sf->write_blocked = FALSE;
}

/* Disconnect the stream immediately.  This means that EOF will be set
   in both directions, the filter functions will not be called again,
   and no more data will be transmitted. */

void ssh_stream_filter_disconnect_now(SshStreamFilter sf)
{
  sf->disconnected = TRUE;
  ssh_stream_output_eof(sf->stream);
  ssh_stream_filter_wake_up_reads(sf);
  ssh_stream_filter_wake_up_writes(sf);
}

/* Tries to write data to the underlying stream. */

void ssh_stream_filter_try_write(SshStreamFilter sf)
{
  int len;
  
  /* If disconnected or already shortcircuiting, just return. */
  if (sf->disconnected || sf->to_shortcircuited)
    return;
  
  /* Try to write the accepted data to the stream. */
  while (sf->to_accepted_bytes > 0)
    {
      len = ssh_stream_write(sf->stream, ssh_buffer_ptr(&sf->to_buffer),
			     sf->to_accepted_bytes);
      if (len == -1)
	return;
      if (len == 0)
	return;
      sf->to_accepted_bytes -= len;
      ssh_buffer_consume(&sf->to_buffer, len);
    }
  
  /* Start shortcircuiting now if appropriate. */
  if (sf->shortcircuit_requested && ssh_buffer_len(&sf->to_buffer) == 0)
    {
      sf->to_shortcircuited = TRUE;
      if (sf->from_shortcircuited)
	ssh_stream_set_callback(sf->stream, sf->callback,
				sf->callback_context);
      return;
    }

  /* Check if we should schedule a callback to the application write
     function.  Note that a call is scheduled only if writes are blocked. */
  if (ssh_buffer_len(&sf->to_buffer) < sf->max_buffer_size)
    ssh_stream_filter_wake_up_writes(sf);
}  

/* Shortcircuit the stream; arrange not to call the filter functions
   again.  This may shortcircuit immediately, or may arrange for
   shortcircuit to happen when all data has been transmitted. */

void ssh_stream_filter_shortcircuit_now(SshStreamFilter sf)
{
  /* Mark that shortcircuit has been requested. */
  sf->shortcircuit_requested = TRUE;

  /* Shortcircuit "from" direction if buffers are empty. */
  if (ssh_buffer_len(&sf->from_buffer) == 0)
    sf->from_shortcircuited = TRUE;
  else
    sf->from_accepted_bytes = ssh_buffer_len(&sf->from_buffer);

  /* Shortcircuit "to" direction if buffers are empty. */
  if (ssh_buffer_len(&sf->to_buffer) == 0)
    sf->to_shortcircuited = TRUE;
  else
    sf->to_accepted_bytes = ssh_buffer_len(&sf->to_buffer);

  /* If both directions shortcircuited, bypass callbacks. */
  if (sf->from_shortcircuited && sf->to_shortcircuited)
    ssh_stream_set_callback(sf->stream, sf->callback, sf->callback_context);

  /* Try to finalize the shortcircuit (this is needed so that reading/writing
     wakes up to eventually empty the buffers). */
  if (!sf->from_shortcircuited)
    ssh_stream_filter_wake_up_reads(sf);
  if (!sf->to_shortcircuited)
    ssh_stream_filter_try_write(sf);
}

/* Tries to read data from the underlying stream. */

void ssh_stream_filter_try_read(SshStreamFilter sf)
{
  char buf[1024];
  int len, op;
  
  /* If disconnected or already shortcircuiting, just return. */
  if (sf->disconnected || sf->shortcircuit_requested)
    return;

  /* If already too much data buffered, don't read any more. */
  assert(ssh_buffer_len(&sf->from_buffer) <= sf->max_buffer_size);
  if (ssh_buffer_len(&sf->from_buffer) >= sf->max_buffer_size)
    return;

  for (;;)
    {
      /* Determine how much we can read without overflowing buffers. */
      len = sf->max_buffer_size - ssh_buffer_len(&sf->from_buffer);
      if (len > sizeof(buf))
	len = sizeof(buf);
      if (len == 0)
	break;

      /* Try to read data from the stream. */
      len = ssh_stream_read(sf->stream, (unsigned char *) buf, len);
      if (len < 0)
	break;
      if (len == 0)
	{
	  sf->from_eof_received = TRUE;
	  break;
	}
      ssh_buffer_append(&sf->from_buffer, (unsigned char *) buf, len);
    }

  /* Call the filter. */
  assert(sf->from_accepted_bytes <= ssh_buffer_len(&sf->from_buffer));
  if (sf->from_filter)
    op = (*sf->from_filter)(&sf->from_buffer, sf->from_accepted_bytes,
			    sf->from_eof_received, sf->context);
  else
    op = ssh_buffer_len(&sf->from_buffer) - sf->from_accepted_bytes;

  /* First handle the case that we accepted a non-zero number of bytes. */
  if (op > 0)
    {
      /* We accepted some bytes. */
      sf->from_accepted_bytes += op;

      /* Wake up reads if they are blocked. */
      ssh_stream_filter_wake_up_reads(sf);
      return;
    }

  /* Process special return values. */
  switch (op)
    {
    case SSH_FILTER_HOLD:
      /* Gather more data and continue then.
	 Note: this is equivalent to accepting zero bytes. */
      if (sf->from_accepted_bytes == 0 &&
	  ssh_buffer_len(&sf->from_buffer) == sf->max_buffer_size)
	ssh_fatal("ssh_stream_filter_try_read: SSH_FILTER_HOLD returned, but buffer already full.");
      break;
      
    case SSH_FILTER_DISCONNECT:
      ssh_stream_filter_disconnect_now(sf);
      break;
      
    case SSH_FILTER_SHORTCIRCUIT:
      ssh_stream_filter_shortcircuit_now(sf);
      break;
      
    default:
      ssh_fatal("ssh_stream_filter_try_read: filter returned bad op %d",
		op);
    }
}

/* This is called when the underlying stream wants to notify us. */

void ssh_stream_filter_callback(SshStreamNotification op, void *context)
{
  SshStreamFilter sf = (SshStreamFilter)context;

  switch (op)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      ssh_stream_filter_try_read(sf);
      break;

    case SSH_STREAM_CAN_OUTPUT:
      ssh_stream_filter_try_write(sf);
      break;

    case SSH_STREAM_DISCONNECTED:
      ssh_debug("ssh_stream_filter_callback: DISCONNECTED\n");
      break;

    default:
      ssh_fatal("ssh_stream_filter_callback: unknown op %d", (int)op);
    }
}

/* Called when the filter stream is destroyed. */

void ssh_stream_filter_destroy(void *context)
{
  SshStreamFilter sf = (SshStreamFilter)context;

  /* Sanity check: we should have an underlying stream. */
  if (sf->stream == NULL)
    ssh_fatal("ssh_stream_filter_destroy: already destroyed");
  
  /* Destroy the underlying stream. */
  ssh_stream_destroy(sf->stream);
  sf->stream = NULL;

  /* Uninitialize buffers. */
  ssh_buffer_uninit(&sf->from_buffer);
  ssh_buffer_uninit(&sf->to_buffer);

  /* Cancel any pending events for this stream. */
  ssh_cancel_timeouts(ssh_stream_filter_read_upcall, (void *)sf);
  ssh_cancel_timeouts(ssh_stream_filter_write_upcall, (void *)sf);
  
  /* Call the user destroy function if supplied. */
  if (sf->destroy)
    (*sf->destroy)(sf->context);

  /* Free the context. */
  memset(sf, 'F', sizeof(*sf));
  ssh_xfree(sf);
}

/* Called when the application reads from the filter stream. */

int ssh_stream_filter_read(void *context, unsigned char *buf, size_t size)
{
  SshStreamFilter sf = (SshStreamFilter)context;
  size_t len;

  /* If disconnected, return EOF. */
  if (sf->disconnected)
    return 0;

  /* If already shortcircuited, just pass the call through. */
  if (sf->from_shortcircuited)
    return ssh_stream_read(sf->stream, buf, size);
  
  /* See if we have data we could return. */
  len = sf->from_accepted_bytes;
  if (len > 0)
    {
      if (len > size)
	len = size;
      memcpy(buf, ssh_buffer_ptr(&sf->from_buffer), len);
      ssh_buffer_consume(&sf->from_buffer, len);
      sf->from_accepted_bytes -= len;
      ssh_stream_filter_try_read(sf);
      return len;
    }
      
  /* See if we should return EOF. */
  if (sf->from_eof_received)
    return 0;

  /* Check if we should start shortcircuiting. */
  if (sf->shortcircuit_requested)
    {
      sf->from_shortcircuited = TRUE;
      if (sf->to_shortcircuited)
	ssh_stream_set_callback(sf->stream, sf->callback,
				sf->callback_context);
      return -1;
    }
  
  /* Cannot return more data right now. */
  sf->read_blocked = TRUE;
  return -1;
}

/* Calls the filter in the "to" direction. */

void ssh_stream_filter_call_to_filter(SshStreamFilter sf)
{
  int op;

  /* Call filter. */
  assert(sf->to_accepted_bytes <= ssh_buffer_len(&sf->to_buffer));
  if (sf->to_filter)
    op = (*sf->to_filter)(&sf->to_buffer, sf->to_accepted_bytes,
			  sf->to_eof_received, sf->context);
  else
    op = ssh_buffer_len(&sf->to_buffer) - sf->to_accepted_bytes;

  /* First handle the case that we accepted a non-zero number of bytes. */
  if (op > 0)
    {
      /* We accepted some bytes. */
      sf->to_accepted_bytes += op;

      /* Try writing to the stream. */
      ssh_stream_filter_try_write(sf);
      return;
    }

  /* Process special return values. */
  switch (op)
    {
    case SSH_FILTER_HOLD:
      /* Gather more data and continue then.
	 Note: this is equivalent to accepting zero bytes. */
      if (sf->to_accepted_bytes == 0 &&
	  ssh_buffer_len(&sf->to_buffer) == sf->max_buffer_size)
	ssh_fatal("ssh_stream_filter_call_to_filter: SSH_FILTER_HOLD returned, but buffer already full.");
      break;
      
    case SSH_FILTER_DISCONNECT:
      ssh_stream_filter_disconnect_now(sf);
      break;
      
    case SSH_FILTER_SHORTCIRCUIT:
      ssh_stream_filter_shortcircuit_now(sf);
      break;
      
    default:
      ssh_fatal("ssh_stream_filter_call_to_filter: filter returned bad op %d",
		op);
    }
}

/* Processes a write from up. */

int ssh_stream_filter_write(void *context, const unsigned char *buf,
			    size_t size)
{
  SshStreamFilter sf = (SshStreamFilter)context;
  size_t len;

  /* If disconnected, return EOF. */
  if (sf->disconnected || sf->to_eof_received)
    return 0;

  /* If already shortcircuited, just pass the call through. */
  if (sf->to_shortcircuited)
    return ssh_stream_write(sf->stream, buf, size);

  /* If shortcircuit requested, but we are not yet shortcircuited,
     return -1 while we wait for buffers to drain. */
  if (sf->shortcircuit_requested)
    {
      sf->write_blocked = TRUE;
      return -1;
    }

  /* Compute the number of bytes that we can accept. */
  assert(ssh_buffer_len(&sf->to_buffer) <= sf->max_buffer_size);
  len = sf->max_buffer_size - ssh_buffer_len(&sf->to_buffer);
  if (len > size)
    len = size;

  /* If we cannot take more bytes at this time, block writes. */
  if (len == 0)
    {
      sf->write_blocked = TRUE;
      return -1;
    }

  /* Copy the bytes to the buffer. */
  ssh_buffer_append(&sf->to_buffer, buf, len);

  /* Writes are not blocked. */
  sf->write_blocked = FALSE;

  /* Call "to" filter. */
  ssh_stream_filter_call_to_filter(sf);

  return len;
}

/* Processes EOF from up. */

void ssh_stream_filter_output_eof(void *context)
{
  SshStreamFilter sf = (SshStreamFilter)context;

  /* If shortcircuited, pass directly down. */
  if (sf->to_shortcircuited)
    {
      ssh_stream_output_eof(sf->stream);
      return;
    }
  
  /* If disconnected or EOF already processed, ignore. */
  if (sf->disconnected || sf->to_eof_received)
    return;

  /* Mark that we have received EOF. */
  sf->to_eof_received = TRUE;

  /* If no buffered data, send EOF to stream. */
  if (ssh_buffer_len(&sf->to_buffer) == 0)
    ssh_stream_output_eof(sf->stream);

  /* Call "to" filter. */
  ssh_stream_filter_call_to_filter(sf);
}

/* Sets the stream callback. */

void ssh_stream_filter_set_callback(void *context, SshStreamCallback callback,
				    void *callback_context)
{
  SshStreamFilter sf = (SshStreamFilter)context;

  /* If shortcircuited, pass the upper level callback directly to the
     original stream. */
  if (sf->from_shortcircuited && sf->to_shortcircuited)
    ssh_stream_set_callback(sf->stream, callback, callback_context);

  /* Save the callback. */
  sf->callback = callback;
  sf->callback_context = callback_context;
  sf->read_blocked = TRUE;
  sf->write_blocked = TRUE;
}

/* Stream methods table for filter streams. */

const SshStreamMethodsTable ssh_stream_filter_methods =
{
  ssh_stream_filter_read,
  ssh_stream_filter_write,
  ssh_stream_filter_output_eof,
  ssh_stream_filter_set_callback,
  ssh_stream_filter_destroy
};

/* Creates a stream that can be used to filter data to/from another
   stream.  ``stream'' is an already existing stream whose data is to
   be filter.  It is wrapped into the filter stream, and will be
   closed automatically when the filter stream is closed.
   ``to_stream_filter'', if non-NULL, is a filter to call whenever
   data is written to the returned stream (and is on its way to
   ``stream'').  ``from_stream_filter'' (if non-NULL) is called
   whenever data is received from ``stream''.  ``destroy'' (if
   non-NULL) is called when the returned stream is closed; it can be
   used to free ``context''.  The filter functions must ensure that the
   buffer does not grow unboundedly.
     `stream'             stream whose data is to be filtered
     `max_buffer_size'    maximum number of bytes to buffer
     `to_stream_filter'   filter for data going to ``stream'', or NULL
     `from_stream_filter' filter for data coming from ``stream'', or NULL
     `destroy'            called when the returned stream is closed, or NULL
     `context'            context argument to pass to the functions.
   The filter functions are not allowed to directly destroy the stream. */

SshStream ssh_stream_filter_create(SshStream stream,
				   size_t max_buffer_size,
				   SshFilterProc to_stream_filter,
				   SshFilterProc from_stream_filter,
				   void (*destroy)(void *context),
				   void *context)
{
  SshStreamFilter sf;

  /* Initialize the internal state. */
  sf = ssh_xcalloc(1, sizeof(*sf));
  sf->stream = stream;
  sf->max_buffer_size = max_buffer_size;
  sf->to_filter = to_stream_filter;
  sf->from_filter = from_stream_filter;
  sf->destroy = destroy;
  sf->context = context;
  ssh_buffer_init(&sf->from_buffer);
  ssh_buffer_init(&sf->to_buffer);
  sf->read_blocked = TRUE;
  sf->write_blocked = TRUE;
  sf->callback = NULL;
  sf->callback_context = NULL;

  /* Set the original stream's callback to our callback. */
  ssh_stream_set_callback(stream, ssh_stream_filter_callback, (void *)sf);

  /* Wrap the context into a stream. */
  return ssh_stream_create(&ssh_stream_filter_methods, (void *)sf);
}
