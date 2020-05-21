/*

sshconn.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

SSH Connection Protocol.

*/

#include "sshincludes.h"
#include "sshmsgs.h"
#include "sshencode.h"
#include "sshconn.h"

/* Maximum number of simultaneously open channels. */
#define MAX_OPEN_CHANNELS       1000
#define MAX_EXTENDED_TYPES      10
#define MAX_WINDOW_SIZE         (16*1024*1024)

#define SSH_DEBUG_MODULE "SshConnection"

/* Define this if you wish to have the ssh_conn_channel_callback to be
   called immediately after creating channel. (needed by some systems,
   breaks things in others) */
/* #define CALL_CHANNEL_CALLBACKS_IMMEDIATELY */

typedef struct SshChannelRec
{
  /* Back-link to the controlling SshConn protocol. */
  SshConn conn;

  /* Local identifier for the channel. */
  unsigned long local_id;

  /* Remote identifier for the channel. */
  unsigned long remote_id;

  /* If TRUE, the channel is still being created, and no other processing
     should be done for it. */
  Boolean ephemeral;
  
  /* Data for extended channel types.  Normal data is read from index zero. */
  struct {
    /* The data stream, or NULL if there is no stream for this data type.
       Incoming data is directed to type 0 if there is no stream of the
       listed type. */
    SshStream stream;

    /* If TRUE, never read from this stream.  It is only intended for
       writing.  This also implies that no EOF is sent to the stream.
       It also generally does not make sense to have write_only channels be
       automatically closed (auto_close TRUE), since they normally refer
       to a stream that is used also for some other purpose. */
    Boolean write_only;

    /* Flag indicating whether ``stream'' should be automatically
       closed when the channel is closed. */
    Boolean auto_close;
    
    /* A read from the data stream has failed. */
    Boolean read_has_failed;

    /* EOF has been received from the channel. */
    Boolean eof_received;
    
    /* SshBuffer for incoming data of this type.  This is allocated with
       ssh_xmalloc; its size is incoming_window_size.  This is used in a
       ring-buffer fashion. */
    unsigned char *buf;

    /* Offset of the first byte in the buffer. */
    size_t start;

    /* Total number of bytes in the buffer. */
    size_t inbuf;
  } extended[MAX_EXTENDED_TYPES];
  
  /* The next type whose data we will transfer (0 = normal data). */
  unsigned int next_type;

  /* Highest extended type number for which we have a stream. */
  unsigned int highest_type;

  /* TRUE when SSH_MSG_CHANNEL_EOF has been received for the channel. */
  Boolean eof_received;

  /* If TRUE, automatically close the stream (send SSH_MSG_CHANNEL_CLOSE)
     when EOF is received from the channel stream. */
  Boolean close_on_eof;

  /* TRUE if SSH_MSG_CHANNEL_CLOSE has already been sent for this channel. */
  Boolean close_sent;

  /* TRUE if SSH_MSG_CHANNEL_EOF has been sent for the channel. */
  Boolean eof_sent;

  /* Callback to call when EOF received from the primary channel stream. */
  void (*eof_callback)(void *context);
  void *eof_context;
  
  /* The number of bytes we can still send without receiving a window
     adjust message. */
  size_t outgoing_window_remaining;

  /* The number of bytes we have received since we last sent a window
     adjust message. */
  size_t incoming_window_received;

  /* Total number of bytes we allow the remote end to send without a
     window adjust. */
  size_t incoming_window_size;

  /* Maximum size of outgoing data packet, independent of window size.
     This can be used to send smaller packets for interactive connections
     than for bulk data transfer. */
  size_t max_outgoing_packet_size;
  
  /* Function to call when we receive a channel request. */
  SshConnChannelRequestProc request;

  /* Function to call when about to destroy channel. */
  SshConnChannelDestroyProc destroy;

  /* Context argument to pass to the callbacks. */
  void *callback_context;

  /* Callback to be called when a reply is received for a channel open.
     This is only used when the channel is ephemeral. */
  SshConnSendChannelOpenCallback open_callback;

  /* Context for ``open_callback''. */
  void *open_context;
  
  /* Callback to be called when a reply is received for a channel request.
     This is NULL when we are not expecting a reply to a request. */
  SshConnSendChannelRequestCallback request_callback;

  /* Context argument to pass to the request callback. */
  void *request_context;
} *SshChannel;

struct SshConnRec
{
  /* Interface for communicating downwards using the cross-layer
     protocol. */
  SshCrossDown down;

  /* TRUE if ssh_conn_down_can_send has returned TRUE for ``down'', and we
     haven't yet received a can_send callback from it. */
  Boolean send_blocked;
  
  /* Data for each channel.  This is indexed by the local channel number;
     each entry is either NULL (the channel does not exist) or a pointer
     to a SshChannel structure. */
  SshChannel channels[MAX_OPEN_CHANNELS];

  /* The maximum channel number that has ever been used. */
  unsigned int highest_channel;

  /* Next channel number to send data from.  Data is sent from each channel
     in turn, to guarantee fairness when the main tunnel cannot transmit
     data as far as it is available from the channels. */
  unsigned int next_channel;

  /* The service name that we are going to accept.  We only accept this
     name. */
  char *service_name;
  
  /* Array of global request name - function associations. */
  SshConnGlobalRequest *request_types;

  /* Array of channel type name - function associations. */
  SshConnChannelOpen *open_types;

  /* Function to be called when a disconnect message is received. */
  SshConnDisconnectProc disconnect;

  /* Function to be called when a debug message is received. */
  SshConnDebugProc debug;

  /* Function to be called when some special or unrecognized message is
     received. */
  SshConnSpecialProc special;

  /* Context to pass to the callback functions. */
  void *context;

  /* Function and context to call when a reply is received to a sent global
     request.  Only one such request can be out at any given time.  The
     callback is NULL when no such request is out. */
  SshConnSendGlobalRequestCallback global_request_send_callback;
  void *global_request_send_context;

  /* This is set to TRUE when SSH_CROSS_AUTHENTICATED has been received. */
  Boolean authenticated;
};

/* Allocates a new channel data structure, and allocates a local id for it.
   Initializes the ``conn'' and ``local_id'' fields to the appropriate
   values.  This may return NULL if too many channels have already been
   allocated. */

SshChannel ssh_conn_channel_allocate(SshConn conn)
{
  unsigned int local_id;
  SshChannel channel;

  /* Find a free local id. */
  for (local_id = 0; local_id < MAX_OPEN_CHANNELS; local_id++)
    if (conn->channels[local_id] == NULL)
      break;

  /* If too many channels, return NULL. */
  if (local_id >= MAX_OPEN_CHANNELS)
    return NULL;

  /* Update the highest channel id if appropriate. */
  if (local_id > conn->highest_channel)
    conn->highest_channel = local_id;
  
  /* Allocate and initialize the channel data structure.  Store it in the
     appropriate slot in the channels array. */
  channel = ssh_xcalloc(1, sizeof(*channel));
  channel->conn = conn;
  channel->local_id = local_id;

  /* Initialize some extra data, in case an event tries to do something
     for the channel before its initialization has completed. */
  channel->extended[0].stream = NULL;
  channel->highest_type = 0;
  channel->destroy = NULL;
  channel->eof_callback = NULL;

  /* Store the new channel in the channels array. */
  conn->channels[local_id] = channel;
  
  return channel;
}

/* Closes and destroys the given channel, and immediately frees any
   data structures associated with it. */

void ssh_conn_channel_free(SshConn conn, SshChannel channel)
{
  int i;

  /* We should never free a channel which is not allocated. */
  assert(conn->channels[channel->local_id] != NULL);

  /* Do this first to ensure that if the destroy callback destroys the
     connection protocol, we don't enter a recursive call to the same
     destroy function. */
  conn->channels[channel->local_id] = NULL;
  
  /* Call the channel's destroy callback if set. */
  if (channel->destroy)
    (*channel->destroy)(channel->callback_context);
  
  /* Close streams, and free any dynamically allocated data. */
  for (i = 0; i <= channel->highest_type; i++)
    {
      /* Clear the stream callback. */
      if (channel->extended[i].stream != NULL &&
          channel->extended[i].stream != SSH_CONN_POSTPONE_STREAM)
        ssh_stream_set_callback(channel->extended[i].stream, NULL, NULL);

      /* Destroy the stream if auto_close. */
      if (channel->extended[i].auto_close &&
          channel->extended[i].stream != NULL &&
          channel->extended[i].stream != SSH_CONN_POSTPONE_STREAM)
        ssh_stream_destroy(channel->extended[i].stream);

      /* Free the buffer. */
      if (channel->extended[i].buf != NULL)
        ssh_xfree(channel->extended[i].buf);
    }

  /* Fill with known value to ease debugging. */
  memset(channel, 'F', sizeof(*channel));
  ssh_xfree(channel);
}

/* Sends data from the channel down the connection.  This only processes
   data from a single channel, and a single extended type within the channel.
   This sends as much data of the given type as is available. */

Boolean ssh_conn_send_channel_data_type(SshConn conn, SshChannel channel,
                                        int i)
{
  int len;
  unsigned char buf[4096];

  for (;;)
    {
      /* If we already know that read has failed, and have not received
         INPUT_AVAILABLE callback, just return immediately. */
      if (channel->extended[i].stream == NULL ||
          channel->extended[i].stream == SSH_CONN_POSTPONE_STREAM ||
          channel->extended[i].write_only ||
          channel->extended[i].read_has_failed ||
          channel->extended[i].eof_received)
        return FALSE;
      
      /* If cannot send, record that and return. */
      if (!ssh_cross_down_can_send(conn->down))
        {
          conn->send_blocked = TRUE;
          return TRUE;
        }

      /* We cannot send any data if there is no window space. */
      if (channel->outgoing_window_remaining == 0)
        return FALSE;

      /* Determine the maximum amount of data to read. */
      len = channel->outgoing_window_remaining;
      if (len > sizeof(buf))
        len = sizeof(buf);
      if (len > channel->max_outgoing_packet_size)
        len = channel->max_outgoing_packet_size;

      /* Try to read data from the stream. */
      len = ssh_stream_read(channel->extended[i].stream, buf, len);
      if (len < 0)
        {
          /* No more data available at this time.  We'll receive an
             INPUT_AVAILABLE callback when data is again available. */
          channel->extended[i].read_has_failed = TRUE;
          return FALSE;
        }
      if (len == 0)
        {
#ifdef DEBUG
          ssh_debug("ssh_conn_send_channel_data_type eof from channel stream");
#endif
          /* EOF received from one of the streams. */
          if (i != 0 || channel->eof_sent)
            return FALSE; /* We only process EOF from the main stream. */

          channel->extended[i].eof_received = TRUE;

          /* If an EOF callback has been registered, call it now. */
          if (channel->eof_callback != NULL)
            (*channel->eof_callback)(channel->eof_context);
          
          /* Send an EOF or CLOSE message to the other side. */
          if (channel->close_on_eof)
            {
              /* Send a close message for the channel. */
              ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                                         SSH_FORMAT_CHAR,
                                         (unsigned int) SSH_MSG_CHANNEL_CLOSE,
                                         SSH_FORMAT_UINT32, (SshUInt32)
                                           channel->remote_id,
                                         SSH_FORMAT_END);
              channel->close_sent = TRUE;
            }
          else
            {
              /* Send EOF for the channel. */
              ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                                         SSH_FORMAT_CHAR,
                                         (unsigned int) SSH_MSG_CHANNEL_EOF,
                                         SSH_FORMAT_UINT32, (SshUInt32) 
                                           channel->remote_id,
                                         SSH_FORMAT_END);
              channel->eof_sent = TRUE;
            }
              
          return FALSE;
        }
      
      /* Received some data from the stream.  Now wrap it into a
         packet and send to the other side. */
      if (i == 0)
        {
          /* Send normal data. */
          ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                                     SSH_FORMAT_CHAR,
                                     (unsigned int) SSH_MSG_CHANNEL_DATA,
                                     SSH_FORMAT_UINT32, (SshUInt32)
                                     channel->remote_id,
                                     SSH_FORMAT_UINT32_STR, buf, len,
                                     SSH_FORMAT_END);
        }
      else
        {
          /* Send extended data. */
          ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                                     SSH_FORMAT_CHAR,
                                     (unsigned int)
                                     SSH_MSG_CHANNEL_EXTENDED_DATA,
                                     SSH_FORMAT_UINT32, (SshUInt32)
                                     channel->remote_id,
                                     SSH_FORMAT_UINT32, (SshUInt32) i,
                                     SSH_FORMAT_UINT32_STR, buf, len,
                                     SSH_FORMAT_END);
        }

      /* Adjust the window size. */
      channel->outgoing_window_remaining -= len;
    }
}

/* Sends data from the given channel to the downward connection.
   This only sends until either there is no more space available in the
   channel's outgoing window, or no more packets can be sent.
   This returns TRUE if this returns because no more packets can be sent;
   otherwise this returns FALSE. */

Boolean ssh_conn_send_channel_data(SshConn conn, SshChannel channel)
{
  int i;

  /* If the channel is still being created, return immediately. */
  if (channel->ephemeral || channel->close_sent || channel->eof_sent)
    return FALSE;
  
  /* We iterate over the extended types in such a way that even if write to
     the central channel blocks and data is always available from a stream,
     fairness is always guaranteed.  */
  for (i = channel->next_type; i <= channel->highest_type; i++)
    if (ssh_conn_send_channel_data_type(conn, channel, i))
      {
        channel->next_type = i + 1;
        return TRUE;
      }
  for (i = 0; i < channel->next_type; i++)
    if (ssh_conn_send_channel_data_type(conn, channel, i))
      {
        channel->next_type = i + 1;
        return TRUE;
      }

  /* Next time, start sending from extended type zero. */
  channel->next_type = 0;
  return FALSE;
}

/* Sends channel data down to the encrypted tunnel if any is available.
   This reads data from the channel streams. */

void ssh_conn_send_some_data(SshConn conn)
{
  unsigned int i;
  
  /* If write has failed, we'll eventually get a callback saying we can
     send again, and will retry then. */
  if (conn->send_blocked)
    return;

  /* We iterate over the channels in such a way that even if write to
     the central channel blocks, fairness is always gauaranteed.
     (We'll continue with the next channel the next time we are called.)
     conn->next_channel is the next channel we should try reading data
     from. */
  for (i = conn->next_channel; i <= conn->highest_channel; i++)
    if (conn->channels[i] &&
        ssh_conn_send_channel_data(conn, conn->channels[i]))
      {
        /* Cannot send more data now.  Record that we'll continue with
           the next channel. */
        conn->next_channel = i + 1;
        return;
      }
  for (i = 0; i < conn->next_channel; i++)
    if (conn->channels[i] &&
        ssh_conn_send_channel_data(conn, conn->channels[i]))
      {
        conn->next_channel = i + 1;
        return;
      }

  /* Writing didn't block.  Start from the first channel the next time. */
  conn->next_channel = 0;
}

/* Checks whether we should send a window adjust message.  This should be
   called whenever more data is received or data has been consumed from the
   incoming buffer. */

void ssh_conn_channel_check_adjust(SshConn conn, SshChannel channel)
{
  int i;
  size_t largest_inbuf, ws, still_coming;
  long adjust;

  ws = channel->incoming_window_size;
  
  /* We only adjust after we have received at least half the window. */
  if (channel->incoming_window_received < ws / 2 ||
      channel->eof_received || channel->close_sent)
    return;

  /* We only adjust if all extended types have enough buffer space
     available. */
  largest_inbuf = 0;
  for (i = 0; i <= channel->highest_type; i++)
    if (channel->extended[i].inbuf > largest_inbuf)
      largest_inbuf = channel->extended[i].inbuf;

  /* Return if cannot adjust by at least half the window size. */
  if (largest_inbuf > ws / 2)
    return;

  /* Compute the amount by which we adjust. */
  still_coming = ws - channel->incoming_window_received;
  assert(ws >= largest_inbuf + still_coming);
  adjust = ws - largest_inbuf - still_coming;

  /* Send an adjust message to the other side. */
  ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                             SSH_FORMAT_CHAR,
                             (unsigned int) SSH_MSG_CHANNEL_WINDOW_ADJUST,
                             SSH_FORMAT_UINT32, (SshUInt32) channel->remote_id,
                             SSH_FORMAT_UINT32, (SshUInt32) adjust,
                             SSH_FORMAT_END);
  channel->incoming_window_received -= adjust;
}  

/* Attempts to write data from channel buffers to the data streams.
   Sends a window adjust message if appropriate. */

void ssh_conn_channel_write(SshConn conn, SshChannel channel)
{
  Boolean did_something;
  int len, i;
  size_t ws;

  /* If we have sent close to the channel, don't write to it */
  
  if (channel->close_sent)
    return;
  
  did_something = FALSE;
  ws = channel->incoming_window_size;

  /* Try writing data to all streams from their respective buffers. */
  for (i = 0; i <= channel->highest_type; i++)
    {
      /* Keep looping for each stream until we break out.  This is because
         the data might not all be written at once. */
      for (;;)
        {
          /* If no data to write, continue with the next stream. */
          len = channel->extended[i].inbuf;
          if (len == 0)
            {
              if (channel->eof_received)
                ssh_stream_output_eof(channel->extended[i].stream);
              break;
            }

          /* Truncate length to end of ring buffer. */
          if (len > ws - channel->extended[i].start)
            len = ws - channel->extended[i].start;

          /* Try to write data to the stream. */
          len = ssh_stream_write(channel->extended[i].stream,
                                 channel->extended[i].buf +
                                 channel->extended[i].start,
                                 len);
          /* If error (or EOF on write), continue with the next stream. */
          if (len < 0)
            break;

          if (len == 0)
            {
              SSH_DEBUG(2, ("EOF received on write from channel 0x%lx, extended "\
                            "stream %d.", channel, i));

              /* EOF received from one of the streams. */
              if (i != 0 || channel->close_sent)
                break; /* We only process EOF from the main stream. */

              channel->extended[i].eof_received = TRUE;
              
              /* If an EOF callback has been registered, call it now. */
              if (channel->eof_callback != NULL)
                (*channel->eof_callback)(channel->eof_context);
          
              /* Send a close message for the channel. */
              ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                                         SSH_FORMAT_CHAR,
                                         (unsigned int) SSH_MSG_CHANNEL_CLOSE,
                                         SSH_FORMAT_UINT32, (SshUInt32) 
                                         channel->remote_id,
                                         SSH_FORMAT_END);
              channel->close_sent = TRUE;
              
              return;
            }
          
          /* Mark that we actually did something. */
          did_something = TRUE;

          /* Update the ring buffer to consume the already written data. */
          channel->extended[i].start += len;
          assert(channel->extended[i].start <= ws);
          if (channel->extended[i].start == ws)
            channel->extended[i].start = 0;
          channel->extended[i].inbuf -= len;
          /* We loop again to process any remaining data in the buffer. */
        }
    }

  /* If we did something, check whether we should adjust the window. */
  if (did_something)
    ssh_conn_channel_check_adjust(conn, channel);
}
      

/* Stream callback for the channel streams.  This is called whenever
   we can send or receive data, or the stream is disconnected. */

void ssh_conn_channel_callback(SshStreamNotification op, void *context)
{
  SshChannel channel = (SshChannel)context;
  int i;

  switch (op)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      for (i = 0; i <= channel->highest_type; i++)
        channel->extended[i].read_has_failed = FALSE;
      ssh_conn_send_some_data(channel->conn);
      break;

    case SSH_STREAM_CAN_OUTPUT:
      ssh_conn_channel_write(channel->conn, channel);
      break;

    case SSH_STREAM_DISCONNECTED:
#ifdef DEBUG
      ssh_debug("ssh_conn_channel_callback: got DISCONNECTED");
#endif
      break;
      
    default:
      ssh_fatal("ssh_conn_channel_callback: unexpected notification %d",
                (int)op);
    }
}

/* Processes a global request.  Only one global request can be active
   at any given time. */

void ssh_conn_process_global_request(SshConn conn,
                                     const unsigned char *data, size_t len)
{
  size_t bytes;
  char *request_type;
  Boolean want_reply;
  int i;

  /* Extract request type. */
  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, &request_type, NULL,
                           SSH_FORMAT_BOOLEAN, &want_reply,
                           SSH_FORMAT_END);
  if (bytes == 0)
    {
      /* Bad packet (didn't contain valid request type).  Disconnect.
         Note that the transport layer protocol will echo the request back
         up. */
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Bad request name in GLOBAL_REQUEST");
      return;
    }

  /* If no supported requests, fail. */
  if (conn->request_types == NULL)
    goto fail;

  /* Go over all request types, and call the appropriate callback if found.
     Otherwise, we fail the request. */
  for (i = 0; conn->request_types[i].name != NULL; i++)
    if (strcmp(conn->request_types[i].name, request_type) == 0)
      {
        /* Found the appropriate request type.  Call its handler function. */
        if (!(*conn->request_types[i].proc)(request_type,
                                            data + bytes, len - bytes,
                                            conn->context))
          goto fail; /* Request failed. */
        
        /* The request was successfully processed.  Send REQUEST_SUCCESS
           packet. */
        if (want_reply)
          ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                                     SSH_FORMAT_CHAR,
                                       (unsigned int) SSH_MSG_REQUEST_SUCCESS,
                                     SSH_FORMAT_END);

        ssh_xfree(request_type);
        return;
      }

  /* Send SSH_MSG_REQUEST_FAILURE to indicate that the request failed. */
fail:
  if (want_reply)
    ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                               SSH_FORMAT_CHAR,
                               (unsigned int) SSH_MSG_REQUEST_FAILURE,
                               SSH_FORMAT_END);
  ssh_xfree(request_type);
}

/* Process a received reply to a global request. */

void ssh_conn_process_global_reply(SshConn conn, unsigned int packet_type,
                                   const unsigned char *data, size_t len)
{
  SshConnSendGlobalRequestCallback cb;
  
  if (len != 0)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Extra data at end of global reply.");
      return;
    }

  /* If we are waiting for a global reply, call and clear the callback.
     Otherwise, this is a protocol error. */
  cb = conn->global_request_send_callback;
  if (cb != NULL)
    {
      conn->global_request_send_callback = NULL;
      (*cb)((packet_type == SSH_MSG_REQUEST_SUCCESS),
            conn->global_request_send_context);

    }
  else
    ssh_cross_down_send_disconnect(conn->down, TRUE,
                                   SSH_DISCONNECT_PROTOCOL_ERROR,
                                   "Received unexpected global req reply.");
}

/* Called by a channel open handler, this completes the process of opening
   a channel.  If open failed, ``data_stream'' should be NULL, and other
   fields will be ignored (except ``completion_context'').  Otherwise,
   ``data_stream'' is set as the default data stream for the channel and
   an open confirmation is sent to the remote side.
     `result'            status code to send back to client (SSH_OPEN_*)
     `data_stream'       stream to pass data to/from the channel
     `auto_close'        TRUE means close data_stream when channel closed
     `window_size'       initial window size for receiving
     `data'              type-specific part of open confirmation reply
     `len'               length of the type-specific data
     `request'           handler for channel requests, or NULL
     `destroy'           handler for channel destroy, or NULL
     `callback_context'  context argument for ``request'' and ``destroy''
     `completion_context' completion context argument from handler call. */

void ssh_conn_channel_open_completion(int result,
                                      SshStream data_stream,
                                      Boolean auto_close,
                                      Boolean close_on_eof,
                                      size_t window_size,
                                      const unsigned char *data,
                                      size_t len,
                                      SshConnChannelRequestProc request,
                                      SshConnChannelDestroyProc destroy,
                                      void *callback_context,
                                      void *completion_context)
{
  SshChannel channel = (SshChannel)completion_context;
  SshConn conn = channel->conn;
  int i;

  /* If ``data_stream'' is NULL, then open has failed. */
  if (result != SSH_OPEN_OK)
    {
      /* Open failed.  Free the channel data structures and send back
         a failure message. */
      ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                                 SSH_FORMAT_CHAR,
                                   (unsigned int) SSH_MSG_CHANNEL_OPEN_FAILURE,
                                 SSH_FORMAT_UINT32, (SshUInt32)
                                 channel->remote_id,
                                 SSH_FORMAT_UINT32, (SshUInt32) result,
                                 SSH_FORMAT_END);
      ssh_conn_channel_free(conn, channel);
      return;
    }

  assert(window_size < MAX_WINDOW_SIZE);
  
  /* Open was successful.  Finalize initializing the channel data structure. */
  channel->ephemeral = FALSE;
  channel->extended[0].stream = data_stream;
  channel->extended[0].write_only = FALSE;
  channel->extended[0].auto_close = auto_close;
  channel->extended[0].read_has_failed = FALSE;
  channel->extended[0].buf = ssh_xmalloc(window_size);
  channel->close_on_eof = close_on_eof;
  channel->incoming_window_size = window_size;
  channel->request = request;
  channel->destroy = destroy;
  channel->callback_context = callback_context;

  /* Send a channel open success message. */
  ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                             SSH_FORMAT_CHAR,
                             (unsigned int) SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
                             SSH_FORMAT_UINT32, (SshUInt32) channel->remote_id,
                             SSH_FORMAT_UINT32, (SshUInt32) channel->local_id,
                             SSH_FORMAT_UINT32, (SshUInt32) 
                               channel->incoming_window_size,
                             SSH_FORMAT_UINT32, (SshUInt32) 
                               channel->max_outgoing_packet_size,
                             SSH_FORMAT_DATA, data, len,
                             SSH_FORMAT_END);

  /* Set callbacks for ``data_stream'' to start transferring data. */
  for (i = 0; i <= channel->highest_type; i++)
    if (channel->extended[0].stream != NULL &&
        channel->extended[0].stream != SSH_CONN_POSTPONE_STREAM)
      ssh_stream_set_callback(channel->extended[0].stream,
                              ssh_conn_channel_callback, (void *)channel);

#ifdef CALL_CHANNEL_CALLBACKS_IMMEDIATELY
  for (i = 0; i <= channel->highest_type; i++)
    if (channel->extended[0].stream != NULL &&
        channel->extended[0].stream != SSH_CONN_POSTPONE_STREAM)
      ssh_conn_channel_callback(SSH_STREAM_INPUT_AVAILABLE, (void *)channel);
#endif /* CALL_CHANNEL_CALLBACKS_IMMEDIATELY */

}

/* Process a received channel open request. */

void ssh_conn_process_channel_open(SshConn conn,
                                   const unsigned char *data, size_t len)
{
  size_t bytes;
  char *channel_type;
  SshUInt32 remote_channel;
  SshUInt32 initial_window_size, max_packet_size;
  int i;
  SshChannel channel;

  /* Extract channel type and other common data. */
  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, &channel_type, NULL,
                           SSH_FORMAT_UINT32, &remote_channel,
                           SSH_FORMAT_UINT32, &initial_window_size,
                           SSH_FORMAT_UINT32, &max_packet_size,
                           SSH_FORMAT_END);
  if (bytes == 0)
    {
      /* Bad packet (didn't contain valid common data).  Disconnect.
         Note that the transport layer protocol will echo the request back
         up. */
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Bad request name in GLOBAL_REQUEST");
      return;
    }

  /* If no supported channel open types, fail. */
  if (conn->open_types == NULL)
    goto fail;
  
  /* Go over all channel types, and call the appropriate callback if found.
     Otherwise, we fail the request. */
  for (i = 0; conn->open_types[i].name != NULL; i++)
    if (strcmp(conn->open_types[i].name, channel_type) == 0)
      {
        /* Found the correct type.  Allocate a channel.  The allocated channel
           comes with channel->conn and channel->local_id initialized, and
           the channel entered in the conn->channels array.  The fact
           that channel->extended[0].stream is NULL indicates that it is still
           ephemeral. */
        channel = ssh_conn_channel_allocate(conn);
        if (channel == NULL)
          {
            ssh_cross_down_send_debug(conn->down, TRUE,
                                      "Channel allocation failed.");
            break; /* Allocation failed, send failure. */
          }

        /* Initialize the channel data structure. */
        channel->ephemeral = TRUE;
        channel->remote_id = remote_channel;
        channel->extended[0].stream = NULL;
        channel->extended[0].buf = NULL;
        channel->extended[0].start = 0;
        channel->extended[0].inbuf = 0;
        channel->next_type = 0;
        channel->highest_type = 0;
        channel->outgoing_window_remaining = initial_window_size;
        channel->incoming_window_received = 0;
        channel->incoming_window_size = 0;
        channel->max_outgoing_packet_size = max_packet_size;
        channel->request = NULL;
        channel->destroy = NULL;
        channel->callback_context = NULL;
        
        /* Call the handler procedure.  It will call the completion
           procedure when done. */
        (*conn->open_types[i].proc)(channel_type, channel->local_id,
                                    data + bytes, len - bytes,
                                    ssh_conn_channel_open_completion,
                                    (void *)channel,
                                    conn->context);

        ssh_xfree(channel_type);
        return;
      }

fail:
  
  /* The requested channel type is not supported.  Send a failure. */
  ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                             SSH_FORMAT_CHAR,
                             (unsigned int) SSH_MSG_CHANNEL_OPEN_FAILURE,
                             SSH_FORMAT_UINT32, remote_channel,
                             SSH_FORMAT_UINT32, (SshUInt32)
                             SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                             SSH_FORMAT_END);
  ssh_xfree(channel_type);
}

/* Process a received channel open confirmation. */

void ssh_conn_process_channel_open_confirmation(SshConn conn,
                                                const unsigned char *data,
                                                size_t len)
{
  size_t bytes;
  SshInt32 local_id, remote_id, initial_window_size, max_packet_size;
  SshChannel channel;
  SshConnSendChannelOpenCallback completion;

  /* Parse the packet. */
  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &local_id,
                           SSH_FORMAT_UINT32, &remote_id,
                           SSH_FORMAT_UINT32, &initial_window_size,
                           SSH_FORMAT_UINT32, &max_packet_size,
                           SSH_FORMAT_END);
  if (bytes == 0)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Extra data at end of OPEN_CONFIRMATION");
      return;
    }

  /* Check validity of the received channel number. */
  if (local_id < 0 || local_id > conn->highest_channel ||
      conn->channels[local_id] == NULL ||
      !conn->channels[local_id]->ephemeral)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Bad local id in OPEN_CONFIRMATION.");
      return;
    }

  channel = conn->channels[local_id];

  /* Finalize initializing the channel. */
  channel->ephemeral = FALSE;
  channel->remote_id = remote_id;
  channel->outgoing_window_remaining = initial_window_size;
  channel->max_outgoing_packet_size = max_packet_size;
  channel->extended[0].buf = ssh_xmalloc(channel->incoming_window_size);
  channel->extended[0].read_has_failed = FALSE;

  /* Set callbacks for the channel data stream. */
  ssh_stream_set_callback(channel->extended[0].stream,
                          ssh_conn_channel_callback, (void *)channel);

#ifdef CALL_CHANNEL_CALLBACKS_IMMEDIATELY
  if (channel->extended[0].stream != NULL &&
      channel->extended[0].stream != SSH_CONN_POSTPONE_STREAM)
    ssh_conn_channel_callback(SSH_STREAM_INPUT_AVAILABLE, (void *)channel);
#endif /* CALL_CHANNEL_CALLBACKS_IMMEDIATELY */

  /* Call the user callback, if supplied. */
  completion = channel->open_callback;
  channel->open_callback = NULL;
  if (completion)
    (*completion)(SSH_OPEN_OK, channel->local_id,
                  data + bytes, len - bytes,
                  channel->open_context);
}

/* Process a received channel open failure.  This calls the user callback
   and frees the ephemeral channel. */

void ssh_conn_process_channel_open_failure(SshConn conn,
                                           const unsigned char *data,
                                           size_t len)
{
  size_t bytes;
  SshInt32 local_id, result;
  SshChannel channel;
  SshConnSendChannelOpenCallback completion;

  /* Parse the packet. */
  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &local_id,
                           SSH_FORMAT_UINT32, &result,
                           SSH_FORMAT_END);
  if (bytes != len)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Extra data at end of OPEN_FAILURE.");
      return;
    }

  /* Check validity of the received channel number. */
  if (local_id < 0 || local_id > conn->highest_channel ||
      conn->channels[local_id] == NULL ||
      !conn->channels[local_id]->ephemeral)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Bad local id in received OPEN_FAILURE.");
      return;
    }

  channel = conn->channels[local_id];

  /* Call the user callback if non-NULL. */
  completion = channel->open_callback;
  channel->open_callback = NULL;
  if (completion)
    (*completion)(result, 0, NULL, 0, channel->open_context);

  /* Free the ephemeral channel. */
  ssh_conn_channel_free(conn, channel);
}

/* Process a received window adjust message. */

void ssh_conn_process_channel_window_adjust(SshConn conn,
                                            const unsigned char *data,
                                            size_t len)
{
  SshInt32 local_id, bytes_to_add;
  SshChannel channel;
  size_t bytes;

  /* Parse the packet. */
  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &local_id,
                           SSH_FORMAT_UINT32, &bytes_to_add,
                           SSH_FORMAT_END);
  if (bytes != len)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Extra data at end of WINDOW_ADJUST.");
      return;
    }

  /* Check validity of the received channel number. */
  if (local_id < 0 || local_id > conn->highest_channel ||
      conn->channels[local_id] == NULL ||
      conn->channels[local_id]->ephemeral)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Bad local id in received WINDOW_ADJUST");
      return;
    }

  channel = conn->channels[local_id];

  /* Check that the window size is sensible. */
  if (bytes_to_add < 0 || bytes_to_add > MAX_WINDOW_SIZE ||
      channel->outgoing_window_remaining + bytes_to_add > MAX_WINDOW_SIZE)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Bad window size in WINDOW_ADJUST.");
      return;
    }
      
  /* Update the outgoing window. */
  channel->outgoing_window_remaining += bytes_to_add;

  /* Try to send some more data.  This will wake up sending. */
  ssh_conn_send_some_data(conn);
}

/* Common part of processing for SSH_MSG_CHANNEL_DATA and EXTENDED_DATA. */

void ssh_conn_process_channel_data_common(SshConn conn,
                                          long local_id,
                                          long type,
                                          const unsigned char *data,
                                          size_t len)
{
  SshChannel channel;
  size_t offset, ws;
  
  /* Check validity of the received channel number. */
  if (local_id < 0 || local_id > conn->highest_channel ||
      conn->channels[local_id] == NULL ||
      conn->channels[local_id]->ephemeral ||
      conn->channels[local_id]->eof_received)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Bad channel in received channel data.");
      return;
    }

  channel = conn->channels[local_id];
  ws = channel->incoming_window_size;

  /* If ``type'' is invalid, force it to zero (normal data). */
  if (type < 0 || type > channel->highest_type ||
      channel->extended[type].stream == NULL)
    type = 0;

  /* It is an error to receive data for a postponed stream.  Disconnect if
     we receive any. */
  if (channel->extended[type].stream == SSH_CONN_POSTPONE_STREAM)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Window overflow received channel data.");
      return;
    }

  /* Verify that the other end is not exceeding our window. */
  if (len + channel->incoming_window_received > ws)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Window overflow received channel data.");
      return;
    }

  /* Sanity check: there should always be enough space in the buffer. */
  if (len + channel->extended[type].inbuf > ws)
    ssh_fatal("ssh_conn_process_channel_data_common: buffer overflow");

  /* Copy the received data in the buffer.  Note that the buffer is used
     in a ring-buffer fashion, and the data may need to be split in two. */
  offset = channel->extended[type].start + channel->extended[type].inbuf;
  if (offset > ws)
    offset -= ws;
  if (len < ws - offset)
    memcpy(channel->extended[type].buf + offset, data, len);
  else
    {
      memcpy(channel->extended[type].buf + offset, data, ws - offset);
      memcpy(channel->extended[type].buf, data + ws - offset,
             len - (ws - offset));
    }
  channel->extended[type].inbuf += len;

  /* Update the count of bytes received with this window.  Check if
     we should send a window adjust. */
  channel->incoming_window_received += len;
  ssh_conn_channel_check_adjust(conn, channel);

  /* Try to write data from the channel to the streams. */
  ssh_conn_channel_write(conn, channel);
}

/* Process received channel data. */

void ssh_conn_process_channel_data(SshConn conn,
                                   const unsigned char *data,
                                   size_t len)
{
  SshInt32 local_id;
  size_t bytes, p_len;
  const unsigned char *p;

  /* Parse the packet. */
  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &local_id,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &p, &p_len,
                           SSH_FORMAT_END);
  if (bytes != len)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Extra data at end of CHANNEL_DATA.");
      return;
    }

  /* Do common processing. */
  ssh_conn_process_channel_data_common(conn, local_id, 0L, p, p_len);
}

/* Process received CHANNEL_EXTENDED_DATA packet. */

void ssh_conn_process_channel_extended_data(SshConn conn,
                                            const unsigned char *data,
                                            size_t len)
{
  SshInt32 local_id, data_type;
  size_t bytes, p_len;
  const unsigned char *p;

  /* Parse the packet. */
  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &local_id,
                           SSH_FORMAT_UINT32, &data_type,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &p, &p_len,
                           SSH_FORMAT_END);
  if (bytes != len)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Extra data at end of CHANNEL_DATA.");
      return;
    }
  
  /* Do common processing. */
  ssh_conn_process_channel_data_common(conn, local_id, data_type, p, p_len);
}

/* Processes a CHANNEL_EOF message received for a channel. */

void ssh_conn_process_channel_eof(SshConn conn,
                                  const unsigned char *data, size_t len)
{
  size_t bytes;
  SshChannel channel;
  SshInt32 local_id;
  int i;

  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &local_id,
                           SSH_FORMAT_END);
  if (bytes != len)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Extra data at end of CHANNEL_EOF.");
      return;
    }

  /* Check validity of the received channel number. */
  if (local_id < 0 || local_id > conn->highest_channel ||
      conn->channels[local_id] == NULL ||
      conn->channels[local_id]->ephemeral)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Bad local id in received CHANNEL_EOF.");
      return;
    }

  channel = conn->channels[local_id];

  /* Cannnot receive EOF for a postponed channel. */
  if (channel->extended[0].stream == SSH_CONN_POSTPONE_STREAM)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Postponed channel in CHANNEL_EOF.");
      return;
    }
  
  /* Check for double-EOFs (we should only receive EOF once for a channel). */
  if (channel->eof_received)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "EOF already received in CHANNEL_EOF.");
      return;
    }

  /* Mark that we have received EOF for the channel. */
  channel->eof_received = TRUE;
  
  /* Output EOF to every stream that does not have data in buffer (those
     that have data in buffer will send EOF once the buffer has drained). */
  for (i = 0; i <= channel->highest_type; i++)
    if (channel->extended[i].stream != NULL &&
        channel->extended[i].inbuf == 0 &&
        !channel->extended[i].write_only)
      ssh_stream_output_eof(channel->extended[i].stream);
}

/* Process a received channel close message.  Sends back a channel close
   if it hasn't already been sent, and frees the channel. */

void ssh_conn_process_channel_close(SshConn conn,
                                    const unsigned char *data, size_t len)
{
  size_t bytes;
  SshChannel channel;
  SshInt32 local_id;

  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &local_id,
                           SSH_FORMAT_END);
  if (bytes != len)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Extra data at end of CHANNEL_CLOSE.");
      return;
    }

  /* Check validity of the received channel number. */
  if (local_id < 0 || local_id > conn->highest_channel ||
      conn->channels[local_id] == NULL ||
      conn->channels[local_id]->ephemeral)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Bad local id in CHANNEL_CLOSE.");
      return;
    }

  channel = conn->channels[local_id];

  /* Send back a channel close message unless we have already sent one. */
  if (!channel->close_sent)
    ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                               SSH_FORMAT_CHAR,
                               (unsigned int) SSH_MSG_CHANNEL_CLOSE,
                               SSH_FORMAT_UINT32,
                               (SshUInt32) channel->remote_id,
                               SSH_FORMAT_END);
      
  /* Free the channel now. */
  ssh_conn_channel_free(conn, channel);
  
}

/* Processes a channel request message. */

void ssh_conn_process_channel_request(SshConn conn,
                                      const unsigned char *data, size_t len)
{
  size_t bytes;
  char *type;
  Boolean want_reply;
  SshInt32 local_id;
  SshChannel channel;
  Boolean result;

  /* Parse the common part of the request message. */
  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &local_id,
                           SSH_FORMAT_UINT32_STR, &type, NULL,
                           SSH_FORMAT_BOOLEAN, &want_reply,
                           SSH_FORMAT_END);
  if (bytes == 0)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Garbage at end of CHANNEL_REQUEST.");
      return;
    }

  /* Check validity of the received channel number. */
  if (local_id < 0 || local_id > conn->highest_channel ||
      conn->channels[local_id] == NULL ||
      conn->channels[local_id]->ephemeral)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Bad local id in CHANNEL_REQUEST.");
      return;
    }

  channel = conn->channels[local_id];
  
  if (channel->request)
    result = (*channel->request)(type, data + bytes, len - bytes,
                                 channel->callback_context);
  else
    result = FALSE;

  if (want_reply)
    {
      if (result)
        ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                                   SSH_FORMAT_CHAR,
                                   (unsigned int) SSH_MSG_CHANNEL_SUCCESS,
                                   SSH_FORMAT_UINT32,
                                   (SshUInt32) channel->remote_id,
                                   SSH_FORMAT_END);
      else
        ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                                   SSH_FORMAT_CHAR,
                                   (unsigned int) SSH_MSG_CHANNEL_FAILURE,
                                   SSH_FORMAT_UINT32,
                                   (SshUInt32) channel->remote_id,
                                   SSH_FORMAT_END);
    }
  ssh_xfree(type);
}

/* Process a received reply to a channel request. */

void ssh_conn_process_channel_reply(SshConn conn, unsigned int packet_type,
                                    const unsigned char *data, size_t len)
{
  SshInt32 local_id;
  size_t bytes;
  SshChannel channel;
  SshConnSendChannelRequestCallback cb;

  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &local_id,
                           SSH_FORMAT_END);

  /* Check validity of the received channel number. */
  if (bytes == 0 || local_id < 0 || local_id > conn->highest_channel ||
      conn->channels[local_id] == NULL ||
      conn->channels[local_id]->ephemeral)
    {
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Bad local id in channel reply.");
      return;
    }
  
  channel = conn->channels[local_id];
  cb = channel->request_callback;
  channel->request_callback = NULL;

  /* Check if we are expecting a reply to a channel request. */
  if (cb == NULL)
    {
      /* Unexpect channel reply. */
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Unexpected channel reply %d ch %d",
                                     (int)packet_type, (int)local_id);
      return;
    }
  
  /* Call the request callback. */
  if (packet_type == SSH_MSG_CHANNEL_SUCCESS)
    (*cb)(TRUE, data + bytes, len - bytes, channel->request_context);
  else
    (*cb)(FALSE, NULL, 0, channel->request_context);
}

/* Processes a received data packet.
     `conn'         the connection protocol
     `packet_type'  the packet type, e.g. SSH_MSG_CHANNEL_DATA
     `data'         packet data, without packet type
     `len'          remaining data len. */

void ssh_conn_process_packet(SshConn conn, unsigned int packet_type,
                             const unsigned char *data, size_t len)
{
  switch (packet_type)
    {
    case SSH_MSG_GLOBAL_REQUEST:
      ssh_conn_process_global_request(conn, data, len);
      break;

    case SSH_MSG_REQUEST_SUCCESS:
    case SSH_MSG_REQUEST_FAILURE:
      ssh_conn_process_global_reply(conn, packet_type, data, len);
      break;
      
    case SSH_MSG_CHANNEL_OPEN:
      ssh_conn_process_channel_open(conn, data, len);
      break;
      
    case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
      ssh_conn_process_channel_open_confirmation(conn, data, len);
      break;
      
    case SSH_MSG_CHANNEL_OPEN_FAILURE:
      ssh_conn_process_channel_open_failure(conn, data, len);
      break;
      
    case SSH_MSG_CHANNEL_WINDOW_ADJUST:
      ssh_conn_process_channel_window_adjust(conn, data, len);
      break;
      
    case SSH_MSG_CHANNEL_DATA:
      ssh_conn_process_channel_data(conn, data, len);
      break;
      
    case SSH_MSG_CHANNEL_EXTENDED_DATA:
      ssh_conn_process_channel_extended_data(conn, data, len);
      break;
      
    case SSH_MSG_CHANNEL_EOF:
      ssh_conn_process_channel_eof(conn, data, len);
      break;
      
    case SSH_MSG_CHANNEL_CLOSE:
      ssh_conn_process_channel_close(conn, data, len);
      break;
      
    case SSH_MSG_CHANNEL_REQUEST:
      ssh_conn_process_channel_request(conn, data, len);
      break;
      
    case SSH_MSG_CHANNEL_SUCCESS:
    case SSH_MSG_CHANNEL_FAILURE:
      ssh_conn_process_channel_reply(conn, packet_type, data, len);
      break;
      
    default:
#ifdef DEBUG
      ssh_debug("ssh_conn_process_packet: received unexpected packet %d",
                (int)packet_type);
#endif
      ssh_cross_down_send_disconnect(conn->down, TRUE,
                                     SSH_DISCONNECT_PROTOCOL_ERROR,
                                     "Received unexpect packet %d",
                                     (int)packet_type);
      break;
    }
}

/* Processes a cross-layer packet received from the lower-level protocol.
     `type'      cross-layer packet type
     `data'      packet data
     `len'       length of packet data
     `context'   context argument (points to SshConn structure) */

void ssh_conn_received_packet(SshCrossPacketType type,
                              const unsigned char *data, size_t len,
                              void *context)
{
  SshConn conn = (SshConn)context;
  Boolean locally_generated;
  SshUInt32 reason_code;
  Boolean debug_type;
  unsigned int packet_type;
  size_t bytes;
  char *msg, *lang, *service;
  
  switch (type)
    {
    case SSH_CROSS_PACKET:
      bytes = ssh_decode_array(data, len,
                               SSH_FORMAT_CHAR, &packet_type,
                               SSH_FORMAT_END);

      if (bytes == 0)
        {
          /* Note: the transport layer will echo the disconnect message
             back up, so we'll also receive this back. */
          ssh_cross_down_send_disconnect(conn->down, TRUE,
                                         SSH_DISCONNECT_PROTOCOL_ERROR,
                                         "Bad packet (bad type field).");
          return;
        }

      if (!conn->authenticated)
        ssh_fatal("ssh_conn_received_packet: PACKET before authentication.");

      ssh_conn_process_packet(conn, packet_type, data + bytes, len - bytes);
      break;

    case SSH_CROSS_DISCONNECT:
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_BOOLEAN, &locally_generated,
                           SSH_FORMAT_UINT32, &reason_code,
                           SSH_FORMAT_UINT32_STR, &msg, NULL,
                           SSH_FORMAT_UINT32_STR, &lang, NULL,
                           SSH_FORMAT_END) == 0)
        ssh_fatal("ssh_conn_received_packet: bad DISCONNECT");

      if (conn->disconnect)
        (*conn->disconnect)((int)reason_code, msg, conn->context);

      ssh_xfree(msg);
      ssh_xfree(lang);
      break;
      
    case SSH_CROSS_DEBUG:
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_BOOLEAN, &debug_type,
                           SSH_FORMAT_UINT32_STR, &msg, NULL,
                           SSH_FORMAT_UINT32_STR, &lang, NULL,
                           SSH_FORMAT_END) == 0)
        ssh_fatal("ssh_conn_received_packet: bad DEBUG");

      if (conn->debug)
        (*conn->debug)((int)debug_type, msg, conn->context);

      ssh_xfree(msg);
      ssh_xfree(lang);
      break;

    case SSH_CROSS_SERVICE_REQUEST:
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, &service, NULL,
                           SSH_FORMAT_END) == 0)
        ssh_fatal("ssh_conn_received_packet: bad SERVICE_REQUEST");

      if (strcmp(service, SSH_CONNECTION_SERVICE) == 0)
        {
          /* Accept the service. */
          ssh_cross_down_send(conn->down, SSH_CROSS_SERVICE_ACCEPT, NULL, 0);
        }
      else
        {
          /* Wrong service requested.  Send a disconnect.  Note that the
             transport layer will echo this back up. */
          ssh_cross_down_send_disconnect(conn->down, TRUE,
                                         SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
                                         "Service `%.100s' not available.",
                                         service);
        }
      ssh_xfree(service);
      break;
      
    case SSH_CROSS_AUTHENTICATED:
      /* Extract the service name from the packet. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, NULL, NULL,
                           SSH_FORMAT_UINT32_STR, &service, NULL,
                           SSH_FORMAT_END) == 0)
        ssh_fatal("ssh_conn_received_packet: bad SSH_CROSS_AUTHENTICATED");

      /* Connected to wrong service. */
      if (strcmp(service, conn->service_name) != 0)
        {
          /* Wrong service requested.  Send a disconnect.  Note that the
             transport layer will echo this back up. */
          ssh_cross_down_send_disconnect(conn->down, TRUE,
                                         SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
                                         "Service '%.100s' not available.",
                                         service);
        }
      else
        conn->authenticated = TRUE;

      /* Pass the packet to the special callback. */
      if (conn->special)
        (*conn->special)(type, data, len, conn->context);

      ssh_xfree(service);
      break;
      
      /* fall to next case */
    case SSH_CROSS_STARTUP:
      /* fall to next case */
    case SSH_CROSS_ALGORITHMS:
      /* fall to default case */
    default:
      /* Pass the packet to the special callback. */
      if (conn->special)
        (*conn->special)(type, data, len, conn->context);
      break;
    }
}

/* Processes an EOF received from the lower-level protocol.
     `context'    context argument (points to SshConn structure). */

void ssh_conn_received_eof(void *context)
{
  SshConn conn = (SshConn)context;
  
  if (conn->disconnect)
    (*conn->disconnect)(SSH_DISCONNECT_CONNECTION_LOST,
                        "Connection closed.", conn->context);
}

/* Called when ssh_cross_down_can_send has returned FALSE and sending
   is again possible.
     `context'    context argument (points to SshConn structure) */

void ssh_conn_can_send(void *context)
{
  SshConn conn = (SshConn)context;
  
  /* Mark that sends are not blocked. */
  conn->send_blocked = FALSE;

  /* Process data going down the connection. */
  ssh_conn_send_some_data(conn);
}

/* Wraps the given lower-level protocol into a connection protocol stream.
   This will call the given request functions to process global requests,
   and the given open functions to process channel opens.
     `auth_stream'         the underlying lower-level stream
     `service_name'        service name to accept if SERVICE_REQUEST received
     `requests'            array of supported requests
     `opens'               array of supported channel types
     `disconnect'          called if disconnect msg or EOF received, or NULL
     `debug'               called if debug msg received, or NULL
     `special'             called when a special packet is received, or NULL
     `context'             argument to give to request/open functions.
   Any of the callbacks may be NULL to specify that it will be ignored. */

SshConn ssh_conn_wrap(SshStream auth_stream,
                      const char *service_name,
                      SshConnGlobalRequest *requests,
                      SshConnChannelOpen *opens,
                      SshConnDisconnectProc disconnect,
                      SshConnDebugProc debug,
                      SshConnSpecialProc special,
                      void *context)
{
  SshConn conn;
  int i;

#ifdef DEBUG
  ssh_debug("ssh_conn_wrap");
#endif
  
  /* Allocate the context structure for the protocol. */
  conn = ssh_xcalloc(1, sizeof(*conn));

  /* Create a handler for the cross-layer protocol. */
  conn->down = ssh_cross_down_create(auth_stream,
                                     ssh_conn_received_packet,
                                     ssh_conn_received_eof,
                                     ssh_conn_can_send,
                                     (void *)conn);

  /* Initialize remaining fields. */
  conn->send_blocked = FALSE;
  for (i = 0; i < MAX_OPEN_CHANNELS; i++)
    conn->channels[i] = NULL;
  conn->highest_channel = 0;
  conn->next_channel = 0;
  conn->service_name = ssh_xstrdup(service_name);
  conn->request_types = requests;
  conn->open_types = opens;
  conn->disconnect = disconnect;
  conn->debug = debug;
  conn->special = special;
  conn->context = context;
  conn->global_request_send_callback = NULL;
  conn->global_request_send_context = NULL;
  conn->authenticated = FALSE;

  /* Enable receiving packets from the down stream. */
  ssh_cross_down_can_receive(conn->down, TRUE);

  return conn;
}

/* Destroys the conn protocol, closes the underlying stream, calls the
   destroy function for all open channels and closes the all channel streams.
   This returns immediately, but buffered data will be drained before the
   protocol is actually destroyed.  None of the supplied application
   callbacks will be called after this has returned. */

void ssh_conn_destroy(SshConn conn)
{
  int i;

#ifdef DEBUG
  ssh_debug("ssh_conn_destroy");
#endif
  
  /* Free all channels. */
  for (i = 0; i < MAX_OPEN_CHANNELS; i++)
    if (conn->channels[i] != NULL)
      ssh_conn_channel_free(conn, conn->channels[i]);

  /* Destroy the downward cross-layer protocol object.  Note that buffers
     will be drained before it actually closes. */
  ssh_cross_down_destroy(conn->down);

  /* Free the service name. */
  if (conn->service_name)
    ssh_xfree(conn->service_name);
  
  /* Fill the context with a garbage value (to ease debugging) and free. */
  memset(conn, 'F', sizeof(*conn));
  ssh_xfree(conn);
}

/* Sends a disconnect message to the stream, but does not close or destroy
   it.  ssh_conn_destroy should be called for the stream after this call.
     `conn'      the connection protocol object
     `reason'    numeric disconnection reason
     `fmt'       printf-style format string */

void ssh_conn_send_disconnect(SshConn conn, int reason, const char *fmt, ...)
{
  va_list va;

  va_start(va, fmt);
  ssh_cross_down_send_disconnect_va(conn->down, TRUE, reason, fmt, va);
  va_end(va);
}

/* Sends a debug message to the stream. 
     `conn'      the connection protocol object
     `display'   whether `always_display' parameter will be set
     `fmt'       printf-style format string */

void ssh_conn_send_debug(SshConn conn, Boolean display, const char *fmt, ...)
{
  va_list va;

  /* Ignore the debug message if buffers are full. */
  if (!ssh_cross_down_can_send(conn->down))
    {
      ssh_debug("ssh_conn_send_debug: cannot send - debug message ignored");
      return;
    }
  
  /* Otherwise, send the message. */
  va_start(va, fmt);
  ssh_cross_down_send_debug_va(conn->down, display, fmt, va);
  va_end(va);
}

/* Sends a global request to the stream.  `data' is type-specific part of the
   request.  The completion procedure will be called when a reply is
   received from the server; it will receive information about whether the
   request completed successfully or not.
     `conn'      the connection protocol object
     `type'      request type
     `data'      type-specific request data, NULL if none
     `len'       length of type-specific request data, 0 if none
     `completion' completion procedure to call when reply received, or NULL
     `context'   context to pass to completion procedure */

void ssh_conn_send_global_request(SshConn conn,
                                  const char *type,
                                  const unsigned char *data,
                                  size_t len,
                                  SshConnSendGlobalRequestCallback completion,
                                  void *completion_context)
{
  if (conn->global_request_send_callback != NULL)
    ssh_fatal("ssh_conn_send_global_request: previous request not yet completed");
  conn->global_request_send_callback = completion;
  conn->global_request_send_context = completion_context;

  ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                             SSH_FORMAT_CHAR,
                             (unsigned int) SSH_MSG_GLOBAL_REQUEST,
                             SSH_FORMAT_UINT32_STR, type, strlen(type),
                             SSH_FORMAT_BOOLEAN, (Boolean)(completion != NULL),
                             SSH_FORMAT_DATA, data, len,
                             SSH_FORMAT_END);
}

/* Sends a channel open request to the stream.
     `conn'        the connection protocol object
     `type'        channel type to open
     `data_stream' data stream for the channel
     `auto_close'  if TRUE, close ``data_stream'' when channel closed
     `window_size' maximum window size for the channel
     `max_packet_size' max size of data packet to send
     `data'        type-specific data for the request, NULL if none
     `len'         length of type-specific data, 0 if none
     `request'     function to process channel requests, or NULL
     `destroy'     function to process channel destroy, or NULL
     `callback_context' context for the callbacks
     `completion'  function to call when reply received, or NULL
     `completion_context' context to pass to `completion' */

void ssh_conn_send_channel_open(SshConn conn,
                                const char *type,
                                SshStream data_stream,
                                Boolean auto_close,
                                Boolean close_on_eof,
                                size_t window_size,
                                size_t max_packet_size,
                                const unsigned char *data,
                                size_t len,
                                SshConnChannelRequestProc request,
                                SshConnChannelDestroyProc destroy,
                                void *callback_context,
                                SshConnSendChannelOpenCallback completion,
                                void *completion_context)
{
  SshChannel channel;

  assert(window_size < MAX_WINDOW_SIZE);
  
  /* Allocate a local channel number. */
  channel = ssh_conn_channel_allocate(conn);
  if (channel == NULL)
    {
      ssh_debug("Channel allocation failed.");
      (*completion)(SSH_OPEN_RESOURCE_SHORTAGE, 0, NULL, 0,
                    completion_context);
    }

  /* Initialize channel data structures. */
  channel->ephemeral = TRUE;
  channel->extended[0].stream = data_stream;
  channel->extended[0].auto_close = auto_close;
  channel->close_on_eof = close_on_eof;
  channel->incoming_window_size = window_size;
  channel->max_outgoing_packet_size = max_packet_size;
  channel->request = request;
  channel->destroy = destroy;
  channel->callback_context = callback_context;

  /* Save the open completion procedure. */
  channel->open_callback = completion;
  channel->open_context = completion_context;
  
  /* Send an open request to the other side. */
  ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                             SSH_FORMAT_CHAR,
                             (unsigned int) SSH_MSG_CHANNEL_OPEN,
                             SSH_FORMAT_UINT32_STR, type, strlen(type),
                             SSH_FORMAT_UINT32, (SshUInt32) channel->local_id,
                             SSH_FORMAT_UINT32, (SshUInt32) window_size,
                             SSH_FORMAT_UINT32,
                               (SshUInt32) channel->max_outgoing_packet_size,
                             SSH_FORMAT_DATA, data, len,
                             SSH_FORMAT_END);
}

/* Sends a channel request to the stream.  ``data'' is type-specific part
   of the request.  The callback ``cb'' will be called when a reply has
   been received for the request (it may be NULL).  One cannot send another
   request with non-NULL callback before the callback of the previous request
   has been called.
     `conn'        the connection protocol
     `channel_id'  local identifier for the channel
     `type'        request type
     `data'        type-specific part of the request
     `len'         length of type-specific part of the request
     `cb'          callback to be called when reply received, or NULL
     `context'     context to pass to ``cb''. */

void ssh_conn_send_channel_request(SshConn conn,
                                   int channel_id,
                                   const char *type,
                                   const unsigned char *data,
                                   size_t len,
                                   SshConnSendChannelRequestCallback cb,
                                   void *context)
{
  SshChannel channel;
  Boolean want_reply;

  /* Check that ``channel_id'' is valid. */
  if (channel_id < 0 || channel_id > conn->highest_channel ||
      conn->channels[channel_id] == NULL ||
      conn->channels[channel_id]->ephemeral ||
      conn->channels[channel_id]->close_sent)
    ssh_fatal("ssh_conn_send_channel_request: bad channel_id %d.",
              (int)channel_id);

  /* Save the callback. */
  channel = conn->channels[channel_id];
  channel->request_callback = cb;
  channel->request_context = context;

  /* We want a reply if ``cb'' is non-NULL. */
  want_reply = (cb != NULL);
  
  /* Send the request packet. */
  ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                             SSH_FORMAT_CHAR,
                             (unsigned int) SSH_MSG_CHANNEL_REQUEST,
                             SSH_FORMAT_UINT32, (SshUInt32) channel->remote_id,
                             SSH_FORMAT_UINT32_STR, type, strlen(type),
                             SSH_FORMAT_BOOLEAN, want_reply,
                             SSH_FORMAT_DATA, data, len,
                             SSH_FORMAT_END);
}

/* Registers a separate stream for extended data of the specified type.
     `conn'         the connection protocol object
     `channel_id'   local identifier for the channel
     `extended_type' extended type for which we register the stream
     `stream'       stream to use for communicating extended data of the type
     `write_only'   the stream may only be written, not read
     `auto_close'   TRUE means automatically destroy stream when channel closed
   Initially, all extended data is sent to the default stream, and no extended
   data is sent.  If a separate stream has been registered, extended data of
   that type is sent to the stream, and any data available from the stream
   is sent as extended data of the given type. */

void ssh_conn_channel_register_extended(SshConn conn,
                                        int channel_id,
                                        int extended_type,
                                        SshStream stream,
                                        Boolean write_only,
                                        Boolean auto_close)
{
  SshChannel channel;
  
  /* Check that ``channel_id'' is valid. */
  if (channel_id < 0 || channel_id > conn->highest_channel ||
      conn->channels[channel_id] == NULL ||
      conn->channels[channel_id]->close_sent)
    ssh_fatal("ssh_conn_channel_register_extended: bad channel_id %d.",
              channel_id);

  /* Save the callback. */
  channel = conn->channels[channel_id];
  
  /* Check that the extended type value is sensible. */
  if (extended_type < 0 || extended_type >= MAX_EXTENDED_TYPES)
    ssh_fatal("ssh_conn_channel_register_extended: bad extended type %d",
              (int)extended_type);

  /* Currently we do not allow changing an existing stream. */
  if (channel->extended[extended_type].stream != NULL &&
      channel->extended[extended_type].stream != SSH_CONN_POSTPONE_STREAM)
    ssh_fatal("ssh_conn_channel_register_extended: type already has stream.");

  /* Update highest_type. */
  if (extended_type > channel->highest_type)
    channel->highest_type = extended_type;

  /* Initialize data for that extended type. */
  channel->extended[extended_type].stream = stream;
  channel->extended[extended_type].write_only = write_only;
  channel->extended[extended_type].auto_close = auto_close;
  channel->extended[extended_type].read_has_failed = FALSE;
  channel->extended[extended_type].eof_received = FALSE;
  channel->extended[extended_type].buf =
    ssh_xmalloc(channel->incoming_window_size);
  channel->extended[extended_type].start = 0;
  channel->extended[extended_type].inbuf = 0;

  /* Set stream callback for the stream. */
  if (!channel->ephemeral)
    ssh_stream_set_callback(stream, ssh_conn_channel_callback,
                            (void *)channel);
}

/* Registers a callback that is to be called when EOF is received from the
   primary channel stream.  This is called before the stream is closed (if
   close_on_eof is set).
     `conn'           the connection protocol object
     `channel_id'     identifies the channel
     `callback'       function to call when EOF received
     `context'        argument to pass to ``callback''. */

void ssh_conn_channel_register_eof_callback(SshConn conn,
                                            int channel_id,
                                            void (*callback)(void *context),
                                            void *context)
{
  SshChannel channel;
  
  /* Check that ``channel_id'' is valid. */
  if (channel_id < 0 || channel_id > conn->highest_channel ||
      conn->channels[channel_id] == NULL ||
      conn->channels[channel_id]->close_sent)
    ssh_fatal("ssh_conn_channel_register_eof_callback: bad channel_id %d.",
              channel_id);

  /* Save the callback. */
  channel = conn->channels[channel_id];

  /* Save the callback. */
  channel->eof_callback = callback;
  channel->eof_context = context;
}

/* Closes the channel.  The channel will be destroyed (and the destroy
   callback called) when we receive a response from the remote side.
     `conn'        the connection protocol object
     `channel_id'  identifies the channel. */

void ssh_conn_channel_close(SshConn conn, int channel_id)
{
  SshChannel channel;
  
  /* Check that ``channel_id'' is valid. */
  if (channel_id < 0 || channel_id > conn->highest_channel ||
      conn->channels[channel_id] == NULL ||
      conn->channels[channel_id]->ephemeral ||
      conn->channels[channel_id]->close_sent)
    ssh_fatal("ssh_conn_channel_close: bad channel_id %d.",
              channel_id);

  /* Save the callback. */
  channel = conn->channels[channel_id];

  /* Send back a channel close message unless we have already sent one.
     The channel will be freed when we receive a reply from the other
     side. */
  ssh_cross_down_send_encode(conn->down, SSH_CROSS_PACKET,
                             SSH_FORMAT_CHAR,
                             (unsigned int) SSH_MSG_CHANNEL_CLOSE,
                             SSH_FORMAT_UINT32, (SshUInt32) channel->remote_id,
                             SSH_FORMAT_END);
  channel->close_sent = TRUE;
}

/* Sends an arbitrary cross-layer packet down to the lower-level protocol.
   This can be used e.g. to send rekey requests.  Arguments are as for
   ssh_cross_down_send_encode.
     `conn'        the connection protocol object
     `type'        cross-layer packet type to send
     `...'         varialble length SSH_FORMAT_* list. */

void ssh_conn_send_encode(SshConn conn, SshCrossPacketType type, ...)
{
  va_list va;

  va_start(va, type);
  ssh_cross_down_send_encode_va(conn->down, type, va);
  va_end(va);
}

/* XXX change all disconnects to go through ssh_conn_send_disconnect. */
/* XXX grouping data from several reads together. */
/* XXX there is a probable memory leak (at least with t-conn).  FIX! */
