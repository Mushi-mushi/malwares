/*

sshserver.h

  Authors:
        Tatu Ylönen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

SSH server functionality for processing a connection.

*/

#ifndef SSHSERVER_H
#define SSHSERVER_H

#include "sshcrypt.h"
#include "sshconfig.h"
#include "sshcommon.h"
#include "sshauth.h"
#include "sshconn.h"
#include "sshtrans.h"

/* Data type for an SSH server object.  The server object processes one
   connection (potentially multiple sessions/channels). */

struct SshServerRec
{
  /* Connection data for both client and server. */
  SshCommon common;

  /* Configuration options that apply to the server. */
  SshConfig config;
  
  /* Authentication methods. */
  SshAuthServerMethod *methods;

  /* Contains the application level compatibility flags needed to
     interoperate with other/older versions. */
  SshTransportCompat compat_flags;
};

typedef struct SshServerRec *SshServer;

/* Callback function called when a disconnect message or EOF is
   received from the other side.  The server protocol should be
   destroyed after receiving this callback (typically from within this
   callback).  If this callback is not registered (was NULL), a
   default callback which simply destroys the protocol context is
   used.  If this is called because of EOF being received from the
   other side, ``reason'' will be SSH_DISCONNECT_CONNECTION_LOST,
   and ``msg'' an appropriate descriptive message.
     `reason'     numeric reason for disconnection (usable for localization)
     `msg'        disconnect message in English
     `context'    context argument from when the callback was registered */
typedef void (*SshServerDisconnectProc)(int reason,
                                        const char *msg,
                                        void *context);

/* Callback function called when a debug message is received from the other
   side.  If this is NULL, all received debug messages are ignored.
     `type'    message type (SSH_DEBUG_DISPLAY, SSH_DEBUG_DEBUG)
     `msg'     the debugging message (normally English)
     `context' context argument passed when the callback was registered. */
typedef void (*SshServerDebugProc)(int type,
                                   const char *msg,
                                   void *context);


/* Takes a stream, and creates an SSH server for processing that
   connection.  This closes the stream and returns NULL (without
   calling the destroy function) if an error occurs.  This does not
   free the given server key.  The random state is required to stay
   valid until the server has been destroyed.  ``config'' must remain
   valid until the server is destroyed; it is not automatically freed.
     `stream'        the connection stream
     `config'        configuration data (not freed, must remain valid)
     `random_state'  random number generator state
     `private_server_key'   private key that changes every hour or NULL
     `disconnect'    function to call on disconnect
     `debug'         function to call on debug message (may be NULL)
     `version_check' version check callback (may be NULL)
     `context'       context to pass to the callbacks
   The object should be destroyed from the ``disconnect'' callback. */
SshServer ssh_server_wrap(SshStream stream, SshConfig config,
                          SshRandomState random_state,
                          SshPrivateKey private_server_key,
                          SshServerDisconnectProc disconnect,
                          SshServerDebugProc debug,
                          SshVersionCallback version_check,
                          SshAuthPolicyProc auth_policy_proc,
                          SshCommonAuthenticatedNotify authenticated_notify,
                          void *context);

/* Forcibly destroys the given connection. */
void ssh_server_destroy(SshServer server);

#endif /* SSHSERVER_H */
