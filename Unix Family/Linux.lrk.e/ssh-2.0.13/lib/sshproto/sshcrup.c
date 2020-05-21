/*

sshcrup.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Tero Kivinen <kivinen@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Helper functions for the cross-layer protocol.  This file contains
functions to make it very easy to implement a cross layer stream (the
"Up" direction, which implements the stream functionality and looks up
like a normal stream).

*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshbufaux.h"
#include "sshgetput.h"
#include "sshstream.h"
#include "sshmsgs.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshcross.h"

#define ALLOW_AFTER_BUFFER_FULL         (10000 + 5)
#define BUFFER_MAX_SIZE                 50000

typedef struct SshCrossUpRec {
  /* SshBuffer for a partial incoming packet. */
  SshBuffer incoming;

  /* Flag indicating whether the callback may be called (determines whether
     we can receive more data). */
  Boolean can_receive;

  /* Flag indicating whether EOF has been received from up. */
  Boolean incoming_eof;

  /* This flag is TRUE if a write by the upper protocol has failed, and
     we need to call its callback when more data can again be written. */
  Boolean up_write_blocked;

  /* This flag is TRUE if a read by the upper protocol has failed, and
     we need to call its callback when more data is available. */
  Boolean up_read_blocked;

  /* This flag is TRUE if ssh_cross_up_can_send has returned FALSE. */
  Boolean send_blocked;
  
  /* SshBuffer for outgoing data. */
  SshBuffer outgoing;

  /* Outgoing EOF. */
  Boolean outgoing_eof;

  /* Shortcircuit stream.  This is NULL if shortcircuiting not in effect. */
  SshStream shortcircuit_stream;
  
  /* Callbacks to the actual protocol implementation code. */

  SshCrossPacketProc received_packet;
  SshCrossEofProc received_eof;
  SshCrossCanSendNotify can_send;
  SshCrossUpDestroyProc destroy;
  void *context;

  /* Callbacks for the upwards stream. */
  SshStreamCallback up_callback;
  void *up_context;
} *SshCrossUp;

/* Signals the module above us that it can write more data to the stream. */

void ssh_cross_up_signal_output_proc(void *context)
{
  SshCrossUp up = (SshCrossUp)context;

  if (up->up_callback)
    (*up->up_callback)(SSH_STREAM_CAN_OUTPUT, up->up_context);
}

/* Signals the module above us that it can read more data from the stream. */

void ssh_cross_up_signal_input_proc(void *context)
{
  SshCrossUp up = (SshCrossUp)context;

  if (up->up_callback)
    (*up->up_callback)(SSH_STREAM_INPUT_AVAILABLE, up->up_context);
}

/* Signals the implementation that more data can again be sent up. */

void ssh_cross_up_signal_send_proc(void *context)
{
  SshCrossUp up = (SshCrossUp)context;

  if (up->can_send)
    (*up->can_send)(up->context);
}

/* If output is blocked, restarts output (in the view of the upper module;
   in other words, tell the upper module that it can write to the stream
   now). */

void ssh_cross_up_restart_output(SshCrossUp up)
{
  if (up->up_write_blocked)
    {
      /* Schedule an event from which we'll call the callback.  The event
         is cancelled if the stream is destroyed. */
      ssh_register_timeout(0L, 0L, ssh_cross_up_signal_output_proc,
                           (void *)up);
      up->up_write_blocked = FALSE;
    }
}

/* If input is blocked, restarts input (in the view of the upper module;
   in other words, tell the upper module that it can read from the stream
   now). */

void ssh_cross_up_restart_input(SshCrossUp up)
{
  if (up->up_read_blocked)
    {
      /* Schedule an event from which we'll call the callback.  The event
         is cancelled if the stream is destroyed. */
      ssh_register_timeout(0L, 0L, ssh_cross_up_signal_input_proc, (void *)up);
      up->up_read_blocked = FALSE;
    }
}

/* If sends are blocked, restarts sends (in the view of the implementation;
   in other words, tell the implementation that there is space in the buffer
   for more packets to be sent. */

void ssh_cross_up_restart_send(SshCrossUp up)
{
  if (up->send_blocked)
    {
      /* Schedule an event from which we'll call the callback.  The event
         is cancelled if the stream is destroyed. */
      ssh_register_timeout(0L, 0L, ssh_cross_up_signal_send_proc, (void *)up);
      up->send_blocked = FALSE;
    }
}

/* This function is used by the upper layer to read data from the stream. */

int ssh_cross_up_read(void *context, unsigned char *buf, size_t size)
{
  SshCrossUp up = (SshCrossUp)context;
  size_t len;
  
  /* Compute the number of bytes we can transmit. */
  len = ssh_buffer_len(&up->outgoing);
  if (len > size)
    len = size;

  /* Return immediately if no data available. */
  if (len == 0)
    {
      /* If shortcircuiting, pass it to the shortcircuit stream. */
      if (up->shortcircuit_stream)
        return ssh_stream_read(up->shortcircuit_stream, buf, size);

      /* Return EOF or "no more data available yet". */
      if (up->outgoing_eof)
        return 0;
      else
        {
          up->up_read_blocked = TRUE;
          return -1;
        }
    }
  
  /* Move data to the caller's buffer. */
  memcpy(buf, ssh_buffer_ptr(&up->outgoing), len);
  ssh_buffer_consume(&up->outgoing, len);

  /* Wake up the sender if appropriate. */
  if (ssh_buffer_len(&up->outgoing) == 0)
    ssh_cross_up_restart_send(up);
  
  return len;
}

/* This function is called when the upper layer writes to the stream. 
   Note that there are essentially two very different cases: an entire
   packet is received at once, and a partial packet is received.  */

int ssh_cross_up_write(void *context, const unsigned char *buf,
                       size_t size)
{
  SshCrossUp up = (SshCrossUp)context;
  size_t offset, payload_len, len;
  unsigned char *ucp;

  /* If shortcircuiting, direct the write down. */
  if (up->shortcircuit_stream)
    {
      assert(ssh_buffer_len(&up->incoming) == 0);
      return ssh_stream_write(up->shortcircuit_stream, buf, size);
    }

  offset = 0;

normal:
  while (up->can_receive && !up->incoming_eof && offset < size &&
         !up->shortcircuit_stream)
    {
      /* If already processing a partial packet, continue it now. */
      if (ssh_buffer_len(&up->incoming) > 0)
        goto partial;
      
      /* If only partial packet available, do special proccessing. */
      if (size - offset < 4)
        goto partial;  /* Need partial packet processing. */
      payload_len = SSH_GET_32BIT(buf + offset);

      if (size - offset < 4 + payload_len)
        goto partial;  /* Need partial packet processing. */
      
      /* The entire packet is available; pass it to the callback. */
      if (up->received_packet)
        (*up->received_packet)((SshCrossPacketType)buf[offset + 4],
                               buf + offset + 5, payload_len - 1, up->context);
      offset += 4 + payload_len;
    }
  /* We cannot take more data now.  If we processed some data, return
     the number of bytes processed. */
  if (offset > 0)
    return offset;

  /* We couldn't take any data.  Remember that we have returned error to
     the writer and must call the callback later. */
  up->up_write_blocked = TRUE;
  return -1;

partial:
  /* Process partial packet.  First we read its header. */
  len = ssh_buffer_len(&up->incoming);
  if (len < 4)
    {
      len = 4 - len;
      if (size - offset < len)
        len = size - offset;
      ssh_buffer_append(&up->incoming, buf + offset, len);
      offset += len;
    }
  if (ssh_buffer_len(&up->incoming) < 4)
    return offset;

  /* Get the length of the packet. */
  ucp = ssh_buffer_ptr(&up->incoming);
  payload_len = SSH_GET_32BIT(ucp);

  /* Add remaining data in the packet to the buffer. */
  len = 4 + payload_len - ssh_buffer_len(&up->incoming);
  if (len > size - offset)
    len = size - offset;
  ssh_buffer_append(&up->incoming, buf + offset, len);
  offset += len;

  /* If some data still not available, return. */
  if (ssh_buffer_len(&up->incoming) < 4 + payload_len)
    return offset;

  /* The entire packet is now in buffer. */
  ucp = ssh_buffer_ptr(&up->incoming);
  if (up->received_packet)
    (*up->received_packet)((SshCrossPacketType)ucp[4], ucp + 5, 
                           payload_len - 1,
                           up->context);
  
  /* Clear the incoming partial packet buffer and resume normal processing. */
  ssh_buffer_clear(&up->incoming);
  goto normal;
}

/* This function is called when the upper level sends EOF. */

void ssh_cross_up_output_eof(void *context)
{
  SshCrossUp up = (SshCrossUp)context;

  /* If shortcircuited, process the operation immediately. */
  if (up->shortcircuit_stream)
    {
      ssh_stream_output_eof(up->shortcircuit_stream);
      return;
    }
  
  /* Mark that we have received EOF. */
  up->incoming_eof = TRUE;

  /* Clear any partial packet that might be buffered. */
  ssh_buffer_clear(&up->incoming);

  /* Call the protocol callback. */
  if (up->received_eof)
    (*up->received_eof)(up->context);
}

/* Sets the callback used to signal the upper level when something happens
   with the stream. */

void ssh_cross_up_set_callback(void *context, SshStreamCallback callback,
                               void *callback_context)
{
  SshCrossUp up = (SshCrossUp)context;

  up->up_callback = callback;
  up->up_context = callback_context;

  up->up_read_blocked = TRUE;
  up->up_write_blocked = TRUE;
  ssh_cross_up_restart_output(up);
  ssh_cross_up_restart_input(up);

  /* If shortcircuiting, set the callbacks for the shortcircuited stream. */
  if (up->shortcircuit_stream)
    ssh_stream_set_callback(up->shortcircuit_stream, callback,
                            callback_context);
}

/* Destroys the stream.  This is called when the application destroys the
   stream.  We don't have any outgoing data that we might buffer (except
   perhaps to the application that just destroyed us, which we cannot
   deliver anyway).  Thus, we can just destroy everything immediately. */

void ssh_cross_up_destroy(void *context)
{
  SshCrossUp up = (SshCrossUp)context;

  /* Call the destroy callback. */
  if (up->destroy)
    (*up->destroy)(up->context);

  /* Cancel pending callbacks. */
  ssh_cancel_timeouts(ssh_cross_up_signal_output_proc, (void *)up);
  ssh_cancel_timeouts(ssh_cross_up_signal_input_proc, (void *)up);
  ssh_cancel_timeouts(ssh_cross_up_signal_send_proc, (void *)up);
  
  /* Uninitialize the buffers. */
  ssh_buffer_uninit(&up->outgoing);
  ssh_buffer_uninit(&up->incoming);

  /* Fill the context with garbage so that accesses after freeing are more
     reliably trapped.  This eases debugging. */
  memset(up, 'F', sizeof(*up));
  ssh_xfree(up);
}

/* Methods table for the stream. */

const SshStreamMethodsTable ssh_cross_up_methods =
{
  ssh_cross_up_read,
  ssh_cross_up_write,
  ssh_cross_up_output_eof,
  ssh_cross_up_set_callback,
  ssh_cross_up_destroy
};

/* Creates and initializes a cross-layer protocol implementation-side handler.
   This implements the cross-layer stream interface, and provides an
   interface that is easy to use for the essence of the protocol.
      `received_packet'       called when a packet is received
      `received_eof'          called when EOF is received
      `can_send'              called when can send after not being able to
      `destroy'               called when we are destroyed
      `context'               passed as argument to callbacks
   It is guaranteed that after creation the callbacks won't be called until
   from the bottom of the event loop (thus, the caller will have a chance to
   store the stream somewhere).  Any of the functions can be NULL if not
   needed. */

SshStream ssh_cross_up_create(SshCrossPacketProc received_packet,
                              SshCrossEofProc received_eof,
                              SshCrossCanSendNotify can_send,
                              SshCrossUpDestroyProc destroy,
                              void *context)
{
  SshCrossUp up;
  
  /* Allocate and initialize the context. */
  up = ssh_xcalloc(1, sizeof(*up));
  ssh_buffer_init(&up->incoming);
  ssh_buffer_init(&up->outgoing);
  up->can_receive = FALSE;
  up->incoming_eof = FALSE;
  up->outgoing_eof = FALSE;
  up->up_write_blocked = FALSE;
  up->up_read_blocked = FALSE;
  up->send_blocked = TRUE; /* Cause a callback immediately. */
  
  /* Save the callback functions. */
  up->received_packet = received_packet;
  up->received_eof = received_eof;
  up->can_send = can_send;
  up->destroy = destroy;
  up->context = context;

  up->up_callback = NULL;
  up->up_context = NULL;

  /* Cause the send callback to be called if non-NULL.  Note that it isn't
     called until from the bottom of the event loop. */
  ssh_cross_up_restart_send(up);
  
  /* Wrap it into a stream and return the stream. */
  return ssh_stream_create(&ssh_cross_up_methods, (void *)up);
}

/* Informs the cross layer code leyer about whether the more packets
   from up can be received (i.e., whether `received_packet' may be called). 
   Initially, packets cannot be received. */

void ssh_cross_up_can_receive(SshStream up_stream, Boolean status)
{
  SshCrossUp up;

  /* Verify that it is a SshCrossUp stream. */
  if (ssh_stream_get_methods(up_stream) != &ssh_cross_up_methods)
    ssh_fatal("ssh_cross_up_can_receive: not a SshCrossUp stream");
  /* Get the internal context. */
  up = (SshCrossUp)ssh_stream_get_context(up_stream);

  /* Save new status. */
  up->can_receive = status;

  /* If allowing receive and writes are blocked, restart them now. */
  if (status == TRUE && up->up_write_blocked)
    ssh_cross_up_restart_output(up);
}

/* Indicates that no more data will be sent (after what is already buffered).
   This causes EOF to be eventually returned to the higher level stream. */

void ssh_cross_up_send_eof(SshStream up_stream)
{
  SshCrossUp up;

  /* Verify that it is a SshCrossUp stream. */
  if (ssh_stream_get_methods(up_stream) != &ssh_cross_up_methods)
    ssh_fatal("ssh_cross_up_can_receive: not a SshCrossUp stream");
  /* Get the internal context. */
  up = (SshCrossUp)ssh_stream_get_context(up_stream);

  /* If EOF not already sent, signal the upper level that data is available
     for reading. */
  if (!up->outgoing_eof)
    {
      up->outgoing_eof = TRUE;
      ssh_cross_up_restart_input(up);
    }
}

/* Returns TRUE if the cross-layer implementation can take more packets. */

Boolean ssh_cross_up_can_send(SshStream up_stream)
{
  SshCrossUp up;
  Boolean status;

  /* Verify that it is a SshCrossUp stream. */
  if (ssh_stream_get_methods(up_stream) != &ssh_cross_up_methods)
    ssh_fatal("ssh_cross_up_can_receive: not a SshCrossUp stream");
  /* Get the internal context. */
  up = (SshCrossUp)ssh_stream_get_context(up_stream);

  /* Determine whether more data can be stored in the buffer. */
  status = ssh_buffer_len(&up->outgoing) <
    BUFFER_MAX_SIZE - ALLOW_AFTER_BUFFER_FULL;

  /* If no more can be stored, mark that sending is blocked.  This will
     trigger a callback when data can again be sent. */
  if (!status)
    up->send_blocked = TRUE;

  return status;
}    
  
/* Sends a cross-layer packet up, encoding the contents of the packet as
   specified for ssh_encode_cross_packet. */

void ssh_cross_up_send_encode_va(SshStream up_stream,
                              SshCrossPacketType type,
                              va_list va)
{
  SshCrossUp up;

  /* Verify that it is a SshCrossUp stream. */
  if (ssh_stream_get_methods(up_stream) != &ssh_cross_up_methods)
    ssh_fatal("ssh_cross_up_can_receive: not a SshCrossUp stream");
  /* Get the internal context. */
  up = (SshCrossUp)ssh_stream_get_context(up_stream);
  
  /* Wrap the data into a cross layer packet and append to the outgoing
     stream. */
  ssh_cross_encode_packet_va(&up->outgoing, type, va);

  /* Restart reads by upper level. */
  ssh_cross_up_restart_input(up);
  
  /* Sanity check that we didn't exceed max buffer size. */
  if (ssh_buffer_len(&up->outgoing) > BUFFER_MAX_SIZE)
    ssh_debug("ssh_cross_up_send: buffer max size exceeded: size %ld",
              (long)ssh_buffer_len(&up->outgoing));
}

/* Sends a cross-layer packet up, encoding the contents of the packet as
   specified for ssh_encode_cross_packet. */

void ssh_cross_up_send_encode(SshStream up_stream,
                              SshCrossPacketType type,
                              ...)
{
  va_list va;

  va_start(va, type);
  ssh_cross_up_send_encode_va(up_stream, type, va);
  va_end(va);
}

/* Sends a packet up.  The packet is actually buffered, and the higher level
   is signalled that data is available.  The higher level will read the data
   when convenient.  This should only be called when ssh_cross_up_can_send
   returns TRUE. */

void ssh_cross_up_send(SshStream up_stream, SshCrossPacketType type,
                       const unsigned char *data, size_t len)
{
  ssh_cross_up_send_encode(up_stream, type,
                           SSH_FORMAT_DATA, data, len,
                           SSH_FORMAT_END);
}

/* Sends a disconnect packet up. */

void ssh_cross_up_send_disconnect_va(SshStream up_stream,
                                     Boolean locally_generated,
                                     unsigned int reason_code,
                                     const char *reason_format, va_list va)
{
  char buf[256];
  const char lang[] = "en";

  /* Format the reason string. */
  vsnprintf(buf, sizeof(buf), reason_format, va);

  /* Wrap the data into a cross layer packet and append to the outgoing
     stream. */
  ssh_cross_up_send_encode(up_stream, SSH_CROSS_DISCONNECT,
                           SSH_FORMAT_BOOLEAN, locally_generated,
                           SSH_FORMAT_UINT32, (SshUInt32) reason_code,
                           SSH_FORMAT_UINT32_STR, buf, strlen(buf),
                           SSH_FORMAT_UINT32_STR, lang, strlen(lang),
                           SSH_FORMAT_END);
}

/* Sends a disconnect packet up. */

void ssh_cross_up_send_disconnect(SshStream up_stream,
                                  Boolean locally_generated,
                                  unsigned int reason_code,
                                  const char *reason_format, ...)
{
  va_list va;

  /* Format the reason string. */
  va_start(va, reason_format);
  ssh_cross_up_send_disconnect_va(up_stream, locally_generated, reason_code,
                                  reason_format, va);
  va_end(va);
}

/* Sends a debug message up.  The format is as in printf.  The message
   should not contain a newline. */

void ssh_cross_up_send_debug_va(SshStream up_stream, Boolean always_display,
                                const char *format, va_list va)
{
  char buf[256];
  const char lang[] = "en";

  /* Format the message. */
  vsnprintf(buf, sizeof(buf), format, va);

  /* Wrap the data into a cross layer packet and append to the outgoing
     stream. */
  ssh_cross_up_send_encode(up_stream, SSH_CROSS_DEBUG,
                           SSH_FORMAT_BOOLEAN, always_display, 
                           SSH_FORMAT_UINT32_STR, buf, strlen(buf),
                           SSH_FORMAT_UINT32_STR, lang, strlen(lang),
                           SSH_FORMAT_END);
}

/* Sends a debug message up.  The format is as in printf.  The message
   should not contain a newline. */

void ssh_cross_up_send_debug(SshStream up_stream, Boolean always_display,
                             const char *format, ...)
{
  va_list va;

  /* Format the message. */
  va_start(va, format);
  ssh_cross_up_send_debug_va(up_stream, always_display, format, va);
  va_end(va);
}

/* INTERNAL FUNCTION - not to be called from applications.  This
   immediately shortcircuits the up stream downward to the other
   stream.  Directs reads/writes/callbacks directly to it.  The stream
   argument may be NULL to cancel shortcircuiting.  There must be no partial
   incoming packet in the up_stream stream buffers. */

void ssh_cross_up_shortcircuit_now(SshStream up_stream, SshStream down_stream)
{
  SshCrossUp up;

  /* Verify that it is a SshCrossUp stream. */
  if (ssh_stream_get_methods(up_stream) != &ssh_cross_up_methods)
    ssh_fatal("ssh_cross_up_can_receive: not a SshCrossUp stream");
  /* Get the internal context. */
  up = (SshCrossUp)ssh_stream_get_context(up_stream);

  /* Save shortcircuit stream. */
  up->shortcircuit_stream = down_stream;

  /* We currently require there to be no partial incoming packet. */
  assert(ssh_buffer_len(&up->incoming) == 0);
  
  /* If it is non-NULL, make it use application callbacks directly. */
  if (down_stream)
    ssh_stream_set_callback(down_stream, up->up_callback, up->up_context);
}
