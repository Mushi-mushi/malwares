/*

sshconn.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

SSH Connection Protocol.

*/

#ifndef SSHCONN_H
#define SSHCONN_H

#include "sshstream.h"
#include "sshcross.h"

/* The normal service name for the SSH connection protocol. */
#define SSH_CONNECTION_SERVICE  "ssh-connection"

/* An invalid stream that can be passed to SshConnChannelOpenProc completion
   callback as the stream.  This indicates that we don't want to supply
   a stream yet, and receiving data is a protocol error.  We'll set up
   the stream later using ssh_conn_channel_register_extended for type 0. */
#define SSH_CONN_POSTPONE_STREAM  (SshStream)1

/* Callback function for global requests.  A function of this type is
   registered for each for each supported global request type.  The function
   is called when request of the given type is received.  ``data'' will contain
   the request-specific part of the request.
     `type'    request type (e.g., "tcpip-forward")
     `data'    request-specific part of the packet
     `len'     length of request-specific part
     `context' context argument passed when the protocol was created
   This returns TRUE if the request was successfully processed, and FALSE
   if the request failed. */
typedef Boolean (*SshConnGlobalRequestProc)(const char *type,
					    const unsigned char *data,
					    size_t len,
					    void *context);

/* Callback function for processing channel requests.  This is registered
   when channel open completes successfully, and is called whenever a channel
   request is received for that channel.
     `type'        request type, e.g. "pty"
     `data'	   request type specific part of request packet
     `len'         length of request-specific part
     `callback_context' the context argument registered with the callback
   This returns TRUE if the request was successfully processed, and FALSE
   if the request failed. */
typedef Boolean (*SshConnChannelRequestProc)(const char *type,
					     const unsigned char *data,
					     size_t len,
					     void *callback_context);

/* Callback function for destroying a channel.  The destroy function,
   if specified, always gets called for a channel, regardless of
   whether the channel was successfully created.  This is called some
   time after calling the open completion function.  This will
   typically destroy the channel context, but may also perform other
   actions. */
typedef void (*SshConnChannelDestroyProc)(void *callback_context);

/* Callback function called by the channel-type specific open code when
   the channel open is complete.  This may be called wither directly from
   the SshConnChannelOpenProc callback, or from an event later.  This is used
   to pass the SshStream and callbacks used for communication with the
   channel.  If ``data_stream'' is NULL, the request has failed, and the
   other arguments (except ``completion_context'') are ignored.  The
   ``request'' callback is called whenever a channel request is received
   (unless it is NULL, in which case all requests fail).  The ``destroy''
   callback is called just before closing ``data_stream'' if non-NULL.
   ``data_stream'' will be closed automatically by the connection protocol
   after calling ``destroy''.  ``stream' may be SSH_CONN_POSTPONE_STREAM.
     `result'		result code (SSH_OPEN_*, e.g. SSH_RESULT_OK)
     `data_stream'      stream to use for communication, or NULL
     `auto_close'       TRUE means close data_stream when channel closed
     `close_on_eof'     if TRUE, close channel when EOF from stream
     `window_size'	size of incoming buffer
     `data'		type-specific part of open confirmation reply
     `len'              length of the type-specific data
     `request'		callback for processing channel request, or NULL
     `destroy'          callback for destroying callback_context, or NULL
     `callback_context' context to pass to ``request'' and ``destroy''
     `completion_context' the original completion_context argument */
typedef void (*SshConnOpenCompletionProc)(int result,
					  SshStream data_stream,
					  Boolean auto_close,
					  Boolean close_on_eof,
					  size_t window_size,
					  const unsigned char *data,
					  size_t len,
					  SshConnChannelRequestProc request,
					  SshConnChannelDestroyProc destroy,
					  void *callback_context,
					  void *completion_context);

/* Callback function called whenever a channel open request is
   received from the other side.  These are registered together with
   the name, and the appropriate callback is will be called.  ``type''
   is the requested channel type, ``channel_id'' is a local identifier
   for the channel; this can be used to refer to the channel later.
   ``data'' is type-specific part of the request packet.  This should
   eventually call ``completion'' with ``completion_context'' (either
   during this call, or from a later event).
     `type'       channel type from request
     `channel_id' local channel identifier
     `data'       type-specific part of the open request packet
     'len'        length of the type-specific part
     `completion' function to call to complete/fail the open request
     `completion_context' argument to ``completion''
     `context'    context argument registered with the callback */
typedef void (*SshConnChannelOpenProc)(const char *type,
				       int channel_id,
				       const unsigned char *data,
				       size_t len,
				       SshConnOpenCompletionProc completion,
				       void *completion_context,
				       void *context);

/* Callback function called when a disconnect message or EOF is
   received from the other side.  The connection protocol should be
   destroyed after receiving this callback (typically from within this
   callback).  If this callback is not registered (was NULL), a
   default callback which simply destroys the protocol context is
   used.  If this is called because of EOF being received from the
   other side, ``reason'' will be SSH_DISCONNECT_CONNECTION_LOST,
   and ``msg'' an appropriate descriptive message.
     `reason'     numeric reason for disconnection (usable for localization)
     `msg'        disconnect message in English
     `context'    context argument from when the callback was registered */
typedef void (*SshConnDisconnectProc)(int reason,
				      const char *msg,
				      void *context);

/* Callback function called when a debug message is received from the other
   side.  If this is NULL, all received debug messages are ignored.
     `type'    message type (SSH_DEBUG_DISPLAY, SSH_DEBUG_DEBUG)
     `msg'     the debugging message (normally English)
     `context' context argument passed when the callback was registered. */
typedef void (*SshConnDebugProc)(int type,
				 const char *msg,
				 void *context);

/* Callback function to be called whenever a SSH_CROSS_STARTUP,
   SSH_CROSS_ALGORITHMS, or SSH_CROSS_AUTHENTICATED packet is received
   from the lower layer protocols.  Any received unrecognized
   cross-layer packets will also be passed to this function.
     `type'     the cross-layer packet type
     `data'     data of the cross-layer packet
     `len'      length of the cross-layer packet data
     `context'  context argument from when the callback was registered. */
typedef void (*SshConnSpecialProc)(SshCrossPacketType type,
				   const unsigned char *data,
				   size_t len,
				   void *context);

/* Data structure for global request functions.  An array of these is passed
   to the connection protocol.  The last entry in the array should have
   NULL name. */
typedef struct
{
  const char *name;
  SshConnGlobalRequestProc proc;
} SshConnGlobalRequest;

/* Data structure for channel open functions.  An array of these is passed
   to the connection protocol.  The last entry in the array should have
   NULL name. */
typedef struct
{
  const char *name;
  SshConnChannelOpenProc proc;
} SshConnChannelOpen;

/* Type to represent the connection protocol. */
typedef struct SshConnRec *SshConn;

/* Wraps the given lower-level protocol into a connection protocol stream.
   This will call the given request functions to process global requests,
   and the given open functions to process channel opens.
     `auth_stream'         the underlying lower-level stream
     `service_name'	   service name to accept if SERVICE_REQUEST received
     `requests'		   array of supported requests, or NULL for none
     `opens'		   array of supported channel types, or NULL for none
     `disconnect'	   called if disconnect msg or EOF received, or NULL
     `debug'               called if debug msg received, or NULL
     `special'		   called when a special packet is received, or NULL
     `context'		   argument to give to request/open functions.
   Any of the callbacks may be NULL to specify that it will be ignored.
   The ``auth_stream'' will be automatically closed when the SshConn object
   is destroyed.  The SshConn object is typically destoyed from the
   ``disconnect'' callback, though a reasonably place may also sometimes be
   the destroy callback of some channel. */
SshConn ssh_conn_wrap(SshStream auth_stream,
		      const char *service_name,
		      SshConnGlobalRequest *requests,
		      SshConnChannelOpen *opens,
		      SshConnDisconnectProc disconnect,
		      SshConnDebugProc debug,
		      SshConnSpecialProc special,
		      void *context);

/* Destroys the conn protocol, closes the underlying stream, calls the
   destroy function for all open channels and closes the all channel streams.
   This returns immediately, but buffered data will be drained before the
   protocol is actually destroyed.  None of the supplied application
   callbacks will be called after this has returned. */
void ssh_conn_destroy(SshConn conn);

/* Sends a disconnect message to the stream, but does not close or destroy
   it.  ssh_conn_destroy should be called for the stream after this call.
     `conn'      the connection protocol object
     `reason'    numeric disconnection reason
     `fmt'       printf-style format string */
void ssh_conn_send_disconnect(SshConn conn, int reason, const char *fmt, ...);

/* Sends a debug message to the stream. 
     `conn'      the connection protocol object
     `display'   whether `always_display' parameter will be set
     `fmt'       printf-style format string */
void ssh_conn_send_debug(SshConn conn, Boolean display, const char *fmt, ...);

/* Callback function to the be called when a global request has been processed
   and a reply has been received from the remote side.  The reply is ignored
   if NULL is specified as the callback.
     `success'     TRUE indicates request successfully processed, FALSE failed
     `context'     context argument from sending the request. */
typedef void (*SshConnSendGlobalRequestCallback)(Boolean success,
						 void *context);

/* Sends a global request to the stream.  ``data'' is type-specific
   part of the request.  The completion procedure will be called when
   a reply is received from the server; it will receive information
   about whether the request completed successfully or not.
     `conn'      the connection protocol object
     `type'      request type
     `data'	 type-specific request data, NULL if none
     `len'       length of type-specific request data, 0 if none
     `completion' completion procedure to call when reply received, or NULL
     `context'   context to pass to completion procedure */
void ssh_conn_send_global_request(SshConn conn,
				  const char *type,
				  const unsigned char *data,
				  size_t len,
				  SshConnSendGlobalRequestCallback completion,
				  void *completion_context);

/* Callback function to be called when a channel open request has been
   processed and a reply has been received from the remote side.
     `result'     result code, SSH_OPEN_OK on success
     `channel_id' local identifier for the channel
     `data'       type-specific data from the open confirmation packet
     `len'        length of the type-specific data
     `context'    context argument from sending the open request.
   The ``data_stream'' is automatically closed after this call if opening the
   channel failed.  The specified ``destroy'' function will be called if the
   request fails. */
typedef void (*SshConnSendChannelOpenCallback)(int result,
					       int channel_id,
					       const unsigned char *data,
					       size_t len,
					       void *context);

/* Sends a channel open request to the stream.
     `conn'        the connection protocol object
     `type'	   channel type to open
     `data_stream' data stream for the channel
     `auto_close'  if TRUE, close ``data_stream'' when channel closed
     `close_on_eof' if TRUE, automatically close channel when EOF from stream
     `window_size' maximum window size for the channel
     `max_packet_size' max size of data packet to send
     `data'	   type-specific data for the request, NULL if none
     `len'         length of type-specific data, 0 if none
     `request'     function to process channel requests, or NULL
     `destroy'     function to process channel destroy, or NULL
     `callback_context' context for the callbacks
     `completion'  function to call when reply received, or NULL
     `completion_context' context to pass to `completion'
   If the open fails, the ``destroy'' function will be called for the
   ``callback_context''. */
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
				void *completion_context);

/* Callback function to be called when a reply has been received for a
   channel request.
     `success'    TRUE indicates that the request was processed successfully
     `data'	  request-specific part of reply
     `len'        length of request-specific part
     `context'    context argument from sending the request. */
typedef void (*SshConnSendChannelRequestCallback)(Boolean success,
						  const unsigned char *data,
						  size_t len,
						  void *context);

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
				   void *context);

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
   is sent as extended data of the given type.  It is permissible to call
   this from a channel open callback, but only after calling the completion
   procedure. */
void ssh_conn_channel_register_extended(SshConn conn,
					int channel_id,
					int extended_type,
					SshStream stream,
					Boolean write_only,
					Boolean auto_close);

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
					    void *context);

/* Closes the channel.  The channel will be destroyed (and the destroy
   callback called) when we receive a response from the remote side.
     `conn'        the connection protocol object
     `channel_id'  identifies the channel. */
void ssh_conn_channel_close(SshConn conn, int channel_id);

/* Sends an arbitrary cross-layer packet down to the lower-level protocol.
   This can be used e.g. to send rekey requests.  Arguments are as for
   ssh_cross_down_send_encode.
     `conn'        the connection protocol object
     `type'        cross-layer packet type to send
     `...'	   varialble length SSH_FORMAT_* list. */
void ssh_conn_send_encode(SshConn conn, SshCrossPacketType type, ...);

#endif /* SSHCONN_H */
