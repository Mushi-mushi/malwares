/*

sshchtcpfwd.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Public interface to TCP/IP forwarding channels.

*/

#ifndef SSHCHTCPFWD_H
#define SSHCHTCPFWD_H

#include "sshtcp.h"

typedef struct SshLocalTcpForwardRec 
{
  /* Pointer to next forwarding. */
  struct SshLocalTcpForwardRec *next;

  /* Pointer to the common object. */
  SshCommon common;

  /* Host and port to connect on the remote side when a connection is
     received. */
  char *connect_to_host;
  char *connect_to_port;

  /* Port number to listen. */
  char *port;

  /* Listener for the port. */
  SshTcpListener listener;
} *SshLocalTcpForward;

typedef struct SshRemoteTcpForwardRec 
{
  /* Pointer to next forwarding. */
  struct SshRemoteTcpForwardRec *next;

  /* Pointer to the common object. */
  SshCommon common;

  /* Address to bind locally. */
  char *address_to_bind;

  /* Port number to listen. */
  char *port;
  
  /* Host and port to connect on the remote side when a connection is
     received.  These are only used on the side that initiated the
     forwarding (otherwise they are NULL). */
  char *connect_to_host;
  char *connect_to_port;

  /* Socket listener.  This is only used at the remote end. */
  SshTcpListener listener;
} *SshRemoteTcpForward;

typedef struct SshChannelTypeTcpForwardRec
{
  SshCommon common;
  SshRemoteTcpForward remote_forwards;
} *SshChannelTypeTcpForward;

typedef struct SshChannelTypeTcpDirectRec
{
  SshCommon common;
  SshLocalTcpForward local_forwards;
} *SshChannelTypeTcpDirect;

/* This function is called whenever an open request is received for a
   remote forwarded tcp/ip channel. */
void ssh_channel_ftcp_open_request(const char *type,
                                   int channel_id,
                                   const unsigned char *data,
                                   size_t len,
                                   SshConnOpenCompletionProc completion,
                                   void *completion_context,
                                   void *context);

/* This function is called once when a SshCommon object is created. */
void *ssh_channel_ftcp_create(SshCommon common);

/* This function is called once when an SshCommon object is being
   destroyed.  This should destroy all remote forwarded tcp/ip
   channels and listeners and free the context. */
void ssh_channel_ftcp_destroy(void *context);

#if 0
/* This function is called whenever a protocol request is received to
   set up a remote TCP/IP forwarding. */
Boolean ssh_channel_ftcp_global_forward(const char *type,
                                        const unsigned char *data,
                                        size_t len,
                                        void *context);

/* This function is called whenever a protocol request is received to cancel
   a remote TCP/IP forwarding. */
Boolean ssh_channel_ftcp_global_cancel_forward(const char *type,
                                               const unsigned char *data,
                                               size_t len,
                                               void *context);
#endif
/* Returns the channel type context from the SshCommon object. */

SshChannelTypeTcpForward ssh_channel_ftcp_ct(SshCommon common);

/* This function is called whenever an open request is received for a
   locally forwarded tcp/ip channel. */
void ssh_channel_dtcp_open_request(const char *type,
                                   int channel_id,
                                   const unsigned char *data,
                                   size_t len,
                                   SshConnOpenCompletionProc completion,
                                   void *completion_context,
                                   void *context);

/* This function is called once when a SshCommon object is created. */
void *ssh_channel_dtcp_create(SshCommon common);

/* This function is called once when an SshCommon object is being
   destroyed.  This should destroy all locally forwarded tcp/ip
   channels and listeners and free the context. */
void ssh_channel_dtcp_destroy(void *context);

/* Returns the channel type context from the SshCommon object. */

SshChannelTypeTcpDirect ssh_channel_dtcp_ct(SshCommon common);

/* Processes a received request to set up remote TCP/IP forwarding. */
Boolean ssh_channel_remote_tcp_forward_request(const char *type,
                                               const unsigned char *data,
                                               size_t len,
                                               void *context);

/* Processes a received request to cancel remote TCP/IP forwarding. */
Boolean ssh_channel_tcp_forward_cancel(const char *type,
                                       const unsigned char *data,
                                       size_t len,
                                       void *context);

/* Requests forwarding of the given remote TCP/IP port.  If the completion
   procedure is non-NULL, it will be called when done. */
void ssh_channel_start_remote_tcp_forward(SshCommon common,
                                          const char *address_to_bind,
                                          const char *port,
                                          const char *connect_to_host,
                                          const char *connect_to_port,
                                          void (*completion)(Boolean ok,
                                                             void *context),
                                          void *context);

/* Requests forwarding of the given local TCP/IP port.  Returns TRUE if
   forwarding was successfully started, FALSE otherwise. */
Boolean ssh_channel_start_local_tcp_forward(SshCommon common,
                                        const char *address_to_bind,
                                        const char *port,
                                        const char *connect_to_host,
                                        const char *connect_to_port);

/* Opens a direct connection to the given TCP/IP port at the remote side.
   The originator values should be set to useful values and are passed
   to the other side.  ``stream'' will be used to transfer channel data.
   The stream will be closed when the channel is closed, or if opening
   the channel fails. */
void ssh_channel_dtcp_open_to_remote(SshCommon common, SshStream stream,
                                     const char *connect_to_host,
                                     const char *connect_to_port,
                                     const char *originator_ip,
                                     const char *originator_port);

#endif /* SSHCHTCPFWD_H */
