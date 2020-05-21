/*

sshclient.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

SSH client functionality for processing a connection.

*/

#ifndef SSHCLIENT_H
#define SSHCLIENT_H

#include "sshcommon.h"
#include "sshcrypt.h"
#include "sshconfig.h"
#include "sshauthmethods.h"
#include "sshuser.h"
#include "sshtrans.h"

/* Data type for the SSH client object.  The client object processes
   one connection (potentially multiple sessions/channels). */

struct SshClientRec
{
  /* Used to make sure that a given SshClient-object will only be destroyed
     once. Earlier it was possible for ssh_client_destroy to be called
     again from a callback when ssh_client_destroy()'s earlier call was not
     yet complete. */
  Boolean being_destroyed;
  
  /* Connection data for both client and server. */
  SshCommon common;

  /* Configuration options that are relevant for this client. */
  SshConfig config;
  
  /* Authentication methods. */
  SshAuthClientMethod *methods;

  /* Data for the user at the client end. */
  SshUser user_data;

  /* Contains the application level compatibility flags needed to
     interoperate with other/older versions. */
  SshTransportCompat compat_flags;
};

typedef struct SshClientRec *SshClient;

/* Data type for SSH client's general data. Holds practically everything
 needed by client prog.  */

typedef struct {
  SshConfig config;
  SshRandomState random_state;
  SshUser user_data;

  char *command;
  int exit_status; /* command's exit status */

  Boolean allocate_pty;
  Boolean forward_x11;
  Boolean forward_agent;
  Boolean is_subsystem;
  Boolean no_session_channel;
  char *term;
  char **env;

  SshClient client;
  Boolean debug;

  SshForward local_forwards;
  SshForward remote_forwards;
} *SshClientData;

/* Callback function called when a disconnect message or EOF is
   received from the other side.  The client protocol should be
   destroyed after receiving this callback (typically from within this
   callback).  If this callback is not registered (was NULL), a
   default callback which simply destroys the protocol context is
   used.  If this is called because of EOF being received from the
   other side, ``reason'' will be SSH_DISCONNECT_CONNECTION_LOST,
   and ``msg'' an appropriate descriptive message.
     `reason'     numeric reason for disconnection (usable for localization)
     `msg'        disconnect message in English
     `context'    context argument from when the callback was registered */
typedef void (*SshClientDisconnectProc)(int reason,
                                        const char *msg,
                                        void *context);

/* Callback function called when a debug message is received from the other
   side.  If this is NULL, all received debug messages are ignored.
     `type'    message type (SSH_DEBUG_DISPLAY, SSH_DEBUG_DEBUG)
     `msg'     the debugging message (normally English)
     `context' context argument passed when the callback was registered. */
typedef void (*SshClientDebugProc)(int type,
                                   const char *msg,
                                   void *context);

/* Callback function to be called whenever a channel is closed.
     `channel_id'    the channel id passed when the channel was created
     `context'       context argument from ssh_client_wrap. */
typedef void (*SshClientChannelCloseProc)(int channel_id,
                                          void *context);

/* Takes a stream, and creates an SSH client for processing that
   connection.  This closes the stream and returns NULL (without
   calling the destroy function) if an error occurs.  The random state
   is required to stay valid until the client has been destroyed.
   ``config'' must remain valid until the client is destroyed; it is
   not automatically freed.
     `stream'        the connection stream
     `config'        configuration data (not freed, must remain valid)
     `user_data'     data for client user
     `server_host_name' name of the server host, as typed by the user
     `user'          (initial) user to log in as (may be changed during auth)
     `random_state'  random number generator state
     `disconnect'    function to call on disconnect
     `debug'         function to call on debug message (may be NULL)
     `authenticated_notify' function to call when authenticated (may be NULL)
     `context'       context to pass to ``destroy''
   The object should be destroyed from the ``disconnect'' callback or from
   a ``close_notify'' callback (see below).  */
SshClient ssh_client_wrap(SshStream stream, SshConfig config,
                          SshUser user_data,
                          const char *server_host_name,
                          const char *user,
                          SshRandomState random_state,
                          SshClientDisconnectProc disconnect,
                          SshClientDebugProc debug,
                          void (*authentiated_notify)(const char *user,
                                                      void *context),
                          void *context);

/* Forcibly destroys the given connection. */
void ssh_client_destroy(SshClient client);

/* Starts a new command at the server.
     `client'       the client protocol object
     `stdio_stream' stream for stdin/stdout data
     `stderr_stream' stream for stderr data, or NULL to merge with stdout
     `auto_close'   automatically close stdio and stderr on channel close
     `is_subsystem' TRUE if command is a subsystem name instead of command
     `command'      command to execute, or NULL for shell
     `allocate_pty' TRUE if pty should be allocated for the command
     `term'         terminal type for pty (e.g., "vt100"), NULL otherwise
     `env'          NULL, or "name=value" strings to pass as environment
     `forward_x11'  TRUE to request X11 forwarding
     `forward_agent' TRUE to request agent forwarding
     `completion'   completion procedure to be called when done (may be NULL)
     `close_notify' function to call when ch closed (may be NULL)
     `context'      argument to pass to ``completion''.
   It is not an error if some forwarding fails, or an environment variable
   passing is denied.  The ``close_notify'' callback will be called
   regardless of the way the session is destroyed - ssh_client_destroy will
   call ``close_notify'' for all open channels.  It is also called if opening
   the cannnel fails.  It is legal to call ssh_conn_destroy from
   ``close_notify'', unless it has already been called. */
void ssh_client_start_session(SshClient client, SshStream stdio_stream,
                              SshStream stderr_stream, Boolean auto_close,
                              Boolean is_subsystem, const char *command,
                              Boolean allocate_pty, const char *term,
                              const char **env,
                              Boolean forward_x11, Boolean forward_agent,
                              void (*completion)(Boolean success,
                                                 void *context),
                              void (*close_notify)(void *context),
                              void *context);

/* Requests forwarding of the given remote TCP/IP port.  If the completion
   procedure is non-NULL, it will be called when done. */
void ssh_client_remote_tcp_ip_forward(SshClient client,
                                      const char *address_to_bind,
                                      const char *port,
                                      const char *connect_to_host,
                                      const char *connect_to_port,
                                      void (*completion)(Boolean success,
                                                         void *context),
                                      void *context);

/* Requests forwarding of the given local TCP/IP port.  If the completion
   procedure is non-NULL, it will be called when done. */
Boolean ssh_client_local_tcp_ip_forward(SshClient client,
                                        const char *address_to_bind,
                                        const char *port,
                                        const char *connect_to_host,
                                        const char *connect_to_port);

/* Opens a direct connection to the given TCP/IP port at the remote side.
   The originator values should be set to useful values and are passed
   to the other side.  ``stream'' will be used to transfer channel data. */
void ssh_client_open_remote_tcp_ip(SshClient client, SshStream stream,
                                   const char *connect_to_host,
                                   const char *connect_to_port,
                                   const char *originator_ip,
                                   const char *originator_port);

#endif /* SSHCLIENT_H */
