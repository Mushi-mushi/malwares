/*

sshcross.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Tero Kivinen <kivinen@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Helper functions for the cross-layer protocol.

*/

#ifndef SSHCROSS_H
#define SSHCROSS_H

#include "sshbuffer.h"
#include "sshstream.h"

/****** Definitions for the cross-layer protocol and packets types *******/

/* Version of the cross-layer protocol described below. */
#define SSH_CROSS_LAYER_VERSION "1.0"

/* Different levels of the SSH 2.0 protocol implementation talk to each other
   using a simple stream-based protocol.  Each protocol looks like a single
   stream, and talks to the others with the SSH Cross Layer Protocol.
   That protocol and tools for manipulating it are described here.

   Each protocol level is looks like an SshStream to higher levels.  Packets
   of the following format are transmitted on the stream:
     - 4 bytes: packet length (MSB first, not including length itself)
     - 1 byte: packet type (see SshCrossPacketType)
     - n-1 bytes: payload
*/

typedef enum {
  /* This is a normal data packet being transmitted in either
     direction.  The payload is a full transport layer packet payload
     in the format required by the transport layer protocol.  In other
     words, it must begin with a valid 8-bit char packet type.
     XXX disconnects currently sent down with these packets, change to be
     sent using SSH_CROSS_DISCONNECT packets. */
  SSH_CROSS_PACKET,

  /* This packet may be sent in either direction.  When sent down, it causes
     the lower level to send a disconnect message to the other side and to
     disconnect; the lower protocol layer will send the same message back
     up when disconnected.  If a lower protocol layer initiates disconnect,
     it will send this message up.  This packet can be sent at any time -
     even before the STARTUP packet to notify that connection establishment
     failed.  This is also sent after a SSH_MSG_DISCONNECT packet is sent
     locally.  After this message has been sent, the stream will be
     automatically closed, the protocol terminated, and the streams
     closed.  The payload will be of the following format:
        boolean locally_generated
	uint32  reason code (as in SSH protocol)
	string  description in human-readable English
	string  language tag
     Higher-level protocols can rely on this message being reflected back up
     by some lower-level protocol when they send this down. */
  SSH_CROSS_DISCONNECT,

  /* Sends/receives a debugging data packet.  The payload is in the
     following format:
        boolean always_display  
	string  message
	string  language tag
     XXX implement this */
  SSH_CROSS_DEBUG,
  
  /* This packet is sent from the transport layer to higher protocol
     layers exactly once after the initial connection establishment.
     This message should be passed upwards through all protocol layers.
     The payload for this message is of the following format:
       string  cross-layer protocol version
       string  session id (usually 16 or 20 8-bit bytes)
       string  remote version identification string
       string  remote IP address, or empty if not available
       string  remote port number, or empty if not available
  */
  SSH_CROSS_STARTUP,

  /* This packet is only sent from the transport layer to higher protocol
     layers.  This contains information about the algorithms chosen.  This
     is first sent immediately after the session id message after connection
     establishment, and then again after each rekey.  This message
     should be passed upwards through all protocol layers. The payload for this
     message is of the following format:
       string   kex_algorithm
       string   server_host_key_algorithm
       string   server_host_key
       string   encryption_algorithm_client_to_server
       string   encryption_algorithm_server_to_client
       string   mac_algorithm_client_to_server
       string   mac_algorithm_server_to_client
       string   compression_algorithm_client_to_server
       string   compression_algorithm_server_to_client
       string   hash_algorithm
  */
  SSH_CROSS_ALGORITHMS,

  /* This packet is only sent by higher layers to lower layers.  This request
     rekeying (the transport layer is also allowed to initiate rekey on its
     own).  This message should be passed downwards through all protocol
     layers.  Each algorithm is specified as a comma-separated list of
     acceptable algorithm names.  The sender may receive other packets after
     this; rekey is complete when it receives an SSH_CROSS_ALGORITHMS
     packet listing the chosen algorithms.

     The payload for this message is as follows:
       string   encryption_algorithm_client_to_server
       string   encryption_algorithm_server_to_client
       string   mac_algorithm_client_to_server
       string   mac_algorithm_server_to_client
       string   compression_algorithm_client_to_server
       string   compression_algorithm_server_to_client
  */
  SSH_CROSS_REKEY_REQUEST,

  /* This packet is sent by the authentication protocol to higher protocols
     when the user has been authenticated.  This should be passed up to all
     higher protocol layers.  The payload of this message is as follows:
       string   user
       string   service
  */
  SSH_CROSS_AUTHENTICATED,

  /* This packet is sent by the server when it receives a service request.
     The client should respond by either sending a disconnect, or by
     sending SSH_CROSS_SERVICE_ACCEPT.  The payload is as follows:
       string  service name
  */
  SSH_CROSS_SERVICE_REQUEST,

  /* The server should send this packet if it accepts the requested
     service.  Otherwise, it should send a disconnect. */
  SSH_CROSS_SERVICE_ACCEPT
  
} SshCrossPacketType;

/* Appends a cross-layer packet at the end of the buffer as specified
   by the variable-length argument list.  The packet will have the
   given type.  Each element in the variable-length part of the
   argument list must start with a SshPacketFormat type, be followed
   by arguments of the appropriate type, and the list must end with
   SSH_FORMAT_END.  This returns the number of bytes added to the buffer. */
size_t ssh_cross_encode_packet(SshBuffer *buffer, SshCrossPacketType type, ...);

/* Appends a cross-layer packet at the end of the buffer as specified
   by the variable-length argument list.  The packet will have the
   given type.  Each element in the variable-length part of the
   argument list must start with a SshPacketFormat type, be followed
   by arguments of the appropriate type, and the list must end with
   SSH_FORMAT_END.  This returns the number of bytes added to the buffer. */
size_t ssh_cross_encode_packet_va(SshBuffer *buffer, SshCrossPacketType type,
				  va_list ap);


/****** Helper functions for implementing upward cross-layer stream *****/

/* Notifices of the receipt of a cross-layer packet.  Packets are only
   received if the have been allowed by ssh_cross_up_can_receive or
   ssh_cross_down_can_receive.  Initially, receiving is not allowed.
   This function should not modify or free `data'. */
typedef void (*SshCrossPacketProc)(SshCrossPacketType type,
				   const unsigned char *data, size_t len,
				   void *context);

/* Notifies of the receipt of EOF.  This is not affected by whether we
   can receive packets. */
typedef void (*SshCrossEofProc)(void *context);

/* This is called whenever more data can be sent.  This is only called if
   a previous call to ssh_cross_up_can_send or ssh_cross_down_can_send
   has returned FALSE. */
typedef void (*SshCrossCanSendNotify)(void *context);

/* Notifies that the upper layer has been destroyed.  No more calls can be
   made to the cross layer code.  The cross layer code will make no more
   calls to the callbacks.  Normally, any data related to the protocol and
   downward streams is destroyed.  The up stream should not be destroyed
   explicitly in this call; it will automatically destroy itself after calling
   this callback. */
typedef void (*SshCrossUpDestroyProc)(void *context);

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
   needed.  It is illegal to desroy the stream from the callbacks (this is
   usually not a problem, since only the application will normally call
   ssh_stream_destroy for this.  The `can_send' callback will be called once
   after creation even without ssh_cross_up_can_send having being called. */
SshStream ssh_cross_up_create(SshCrossPacketProc received_packet,
			      SshCrossEofProc received_eof,
			      SshCrossCanSendNotify can_send,
			      SshCrossUpDestroyProc destroy,
			      void *context);

/* Informs the cross layer code leyer about whether the more packets
   from up can be received (i.e., whether `received_packet' may be called). 
   Initially, packets cannot be received. */
void ssh_cross_up_can_receive(SshStream up, Boolean status);

/* Indicates that no more data will be sent (after what is already buffered).
   This causes EOF to be eventually returned to the higher level stream. */
void ssh_cross_up_send_eof(SshStream up);

/* Returns TRUE if the cross-layer implementation can take more packets.
   If this returns FALSE, and the `can_send' callback is non-NULL, it
   will be called when packets can again be sent.  It is not strictly an
   error to send packets after this has returned FALSE; however, if too
   much data is sent, the system may crash.  To give a specific value,
   sending at most 10000 values after this returns FALSE is ok (this provision
   exists to avoid checks in disconnect or debug messages). */
Boolean ssh_cross_up_can_send(SshStream up);

/* Sends a packet up.  The packet is actually buffered, and the higher level
   is signalled that data is available.  The higher level will read the data
   when convenient.  This should only be called when ssh_cross_up_can_send
   returns TRUE. */
void ssh_cross_up_send(SshStream up, SshCrossPacketType type,
		       const unsigned char *data, size_t len);

/* Sends a disconnect packet up.  The message should not contain a newline. */
void ssh_cross_up_send_disconnect(SshStream up,
				  Boolean locally_generated,
				  unsigned int reason_code,
				  const char *reason_format, ...);

/* Sends a disconnect packet up.  The message should not contain a newline.
   Note that the format argument list is a va_list. */
void ssh_cross_up_send_disconnect_va(SshStream up,
				     Boolean locally_generated,
				     unsigned int reason_code,
				     const char *reason_format, va_list va);

/* Sends a debug message up.  The format is as in printf.  The message
   should not contain a newline. */
void ssh_cross_up_send_debug(SshStream up, Boolean always_display,
			     const char *format, ...);

/* Sends a debug message up.  The format is as in printf.  The message
   should not contain a newline.  Note that the format argument list
   is a va_list. */
void ssh_cross_up_send_debug_va(SshStream up, Boolean always_display,
				const char *format, va_list va);

/* Sends a cross-layer packet up, encoding the contents of the packet as
   specified for ssh_encode_cross_packet. */
void ssh_cross_up_send_encode(SshStream up,
			      SshCrossPacketType type,
			      ...);

/* Sends a cross-layer packet up, encoding the contents of the packet as
   specified for ssh_encode_cross_packet.  Note that the format argument
   list is a va_list. */
void ssh_cross_up_send_encode_va(SshStream up,
				 SshCrossPacketType type,
				 va_list va);

/****** Helper functions for implementing downward cross-layer stream *****/

/* Data type for downward cross-layer streams. */
typedef struct SshCrossDownRec *SshCrossDown;

/* Creates a cross-layer packet handler for the stream going downwards.
   This makes it easy for applications and protocol levels to use the
   cross-layer interface.  This returns a context handle that should be
   destroyed with ssh_cross_down_destroy when the downward connection is
   to be closed.  The stream will be destroyed automatically when this is
   closed.  This will take control of the stream.
      `down_stream'          stream to lower-level protocol (or network)
      `received_packet'      called when a packet is received
      `received_eof'         called when EOF is received
      `can_send'             called when we can send after not being able to
      `context'              passed as argument to callbacks
   Any of the functions can be NULL if not needed.  Destroying the
   SshCrossDown object is legal in any callback. */
SshCrossDown ssh_cross_down_create(SshStream down_stream,
				   SshCrossPacketProc received_packet,
				   SshCrossEofProc received_eof,
				   SshCrossCanSendNotify can_send,
				   void *context);

/* Closes and destroys the downward connection.  This automatically
   closes the underlying stream.  Any buffered data will be sent out
   before the stream is actually closed.  It is illegal to access the
   object after this has been called. */
void ssh_cross_down_destroy(SshCrossDown down);

/* Informs the packet code whether `received_packet' can be called.  This is
   used for flow control.  Initially, packets cannot be received. */
void ssh_cross_down_can_receive(SshCrossDown down, Boolean status);

/* Sends EOF to the downward stream (after sending out any buffered data).
   It is illegal to send any packets after calling this. */
void ssh_cross_down_send_eof(SshCrossDown down);

/* Returns TRUE if it is OK to send more data.  It is not an error to
   send small amounts of data (e.g. a disconnect) when this returns
   FALSE, but sending lots of data when this returns FALSE will
   eventually crash the system.  To give a specific value, it is OK to send
   10000 bytes after this starts returning FALSE (this provision exists to
   avoid checks in disconnect and debug messages). */
Boolean ssh_cross_down_can_send(SshCrossDown down);

/* Sends the given packet down.  The packet may actually get buffered. */
void ssh_cross_down_send(SshCrossDown down, SshCrossPacketType type,
			 const unsigned char *data, size_t len);

/* Sends a disconnect message down.  However, this does not
   automatically destroy the object.  It is legal to destroy the
   object immediately after calling this; that will properly drain the
   buffers.  The message should not contain a newline.  Note that the
   SSH transport layer will echo back any received disconnect
   messages. */
void ssh_cross_down_send_disconnect(SshCrossDown down,
				    Boolean locally_generated,
				    unsigned int reason_code,
				    const char *reason_format, ...);

/* Sends a disconnect message down.  However, this does not automatically
   destroy the object.  It is legal to destroy the object immediately
   after calling this; that will properly drain the buffers.  The message
   should not contain a newline.  Note that the format argument list is a
   va_list.  Note that the SSH transport layer will echo back any received
   disconnect messages. */
void ssh_cross_down_send_disconnect_va(SshCrossDown down,
				       Boolean locally_generated,
				       unsigned int reason_code,
				       const char *reason_format, va_list va);

/* Sends a debug message down.  The format is as in printf.  The message
   should not contain a newline. */
void ssh_cross_down_send_debug(SshCrossDown down, Boolean always_display,
			       const char *format, ...);

/* Sends a debug message down.  The format is as in printf.  The message
   should not contain a newline.  Note that the format argument list
   is a va_list. */
void ssh_cross_down_send_debug_va(SshCrossDown down, Boolean always_display,
				  const char *format, va_list va);

/* Encodes and sends a packet as specified for ssh_encode_cross_packet. */
void ssh_cross_down_send_encode(SshCrossDown down, SshCrossPacketType type,
				...);

/* Encodes and sends a packet as specified for ssh_encode_cross_packet.
   Note that the format argument list is a va_list. */
void ssh_cross_down_send_encode_va(SshCrossDown down, SshCrossPacketType type,
				   va_list va);

/* Causes any I/O requests from up to be directly routed to the lower level
   stream, without processing any more data on this level.  This will
   automatically allow sends/receives in each direction as appropriate.
   Destroy is not shortcircuited, and the destroy callback should
   destroy the downward stream.  This can only be called from a SshCrossDown
   packet callback. */
void ssh_cross_shortcircuit(SshStream up,
			    SshCrossDown down);

/* INTERNAL FUNCTION - not to be called from applications.  This
   immediately shortcircuits the up stream downward to the other
   stream.  Directs reads/writes/callbacks directly to it.  The stream
   argument may be NULL to cancel shortcircuiting.  There must be no partial
   incoming packet in the cross_impl stream buffers. */
void ssh_cross_up_shortcircuit_now(SshStream cross_impl, SshStream stream);

#endif /* SSHCROSS_H */
