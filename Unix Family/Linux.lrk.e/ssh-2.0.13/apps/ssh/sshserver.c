/*

sshserver.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

SSH server functionality for processing a connection.  Most of the
implementation is actually shared with the client (in sshcommon.c).

*/

#include "ssh2includes.h"
#include "sshtrans.h"
#include "sshauth.h"
#include "sshconn.h"
#include "sshauthmethods.h"
#include "sshcommon.h"
#include "sshserver.h"
#include "sshuserfiles.h"
#include "sshcipherlist.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "SshServer"

/* Fetches values for the transport parameters (e.g., encryption algorithms)
   from the config data. */

Boolean ssh_server_update_transport_params(SshConfig config,
                                           SshTransportParams params)
{
  char *hlp;

  if (config->ciphers != NULL)
    {
      hlp = ssh_cipher_list_canonialize(config->ciphers);

      if (hlp)
        {
          ssh_xfree(params->ciphers_c_to_s);
          params->ciphers_c_to_s = ssh_xstrdup(hlp);
          ssh_xfree(params->ciphers_s_to_c);
          params->ciphers_s_to_c = ssh_xstrdup(hlp);

          ssh_xfree(hlp);
        }
    }

  hlp = ssh_public_key_list_canonialize(params->host_key_algorithms);
  ssh_xfree(params->host_key_algorithms);
  params->host_key_algorithms = hlp;

  hlp = ssh_hash_list_canonialize(params->hash_algorithms);
  ssh_xfree(params->hash_algorithms);
  params->hash_algorithms = hlp;

  return TRUE;
}

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
                          void *context)
{
  SshServer server;
  SshStream trans, auth;
  SshTransportParams params;

  /* Create parameters. */
  params = ssh_transport_create_params();
  if (!ssh_server_update_transport_params(config, params))
    {
      ssh_stream_destroy(stream);
      ssh_transport_destroy_params(params);
      return NULL;
    }

  /* Check the host key. */

  if (config->private_host_key == NULL || 
      config->public_host_key_blob == NULL)
    ssh_fatal("ssh_server_wrap: no host key !");

  /* Create the server object. */
  server = ssh_xcalloc(1, sizeof(*server));
  server->config = config;
  
  /* Create a transport layer protocol object. */
  ssh_debug("ssh_server_wrap: creating transport protocol");
  trans = ssh_transport_server_wrap(stream, random_state, 
                                    SSH2_PROTOCOL_VERSION_STRING,
                                    params, config->private_host_key,
                                    private_server_key,
                                    config->public_host_key_blob,
                                    config->public_host_key_blob_len,
                                    version_check,
                                    (void *)context);

  
  ssh_transport_get_compatibility_flags(trans, &server->compat_flags);
  
  /* Create the authentication methods array for the server. */
  server->methods = ssh_server_authentication_initialize();
  /* XXX config data */
  
  /* Create an authentication protocol object. */
  ssh_debug("ssh_server_wrap: creating userauth protocol");
  /* XXX policy_proc */
  auth = ssh_auth_server_wrap(trans, auth_policy_proc, (void *)server,
                              server->methods, (void *)server);

  /* Create the common part of client/server objects. */
  server->common = ssh_common_wrap(stream, auth, FALSE, config, random_state,
                                   NULL,
                                   disconnect, debug, authenticated_notify,
                                   context);

  if (server->common == NULL)
    {
      ssh_server_authentication_uninitialize(server->methods);
      ssh_xfree(server);
      return NULL;
    }
  
  return server;
}

/* External declaration. (this is defined is sshd2.c.)*/
extern void ssh_login_grace_time_exceeded(void *context);

/* Forcibly destroys the given server. */
  
void ssh_server_destroy(SshServer server)
{
  /* Cancel grace timeout. */
  ssh_cancel_timeouts(ssh_login_grace_time_exceeded, SSH_ALL_CONTEXTS);
  ssh_common_destroy(server->common);
  ssh_xfree(server->compat_flags);
  ssh_server_authentication_uninitialize(server->methods);
  memset(server, 'F', sizeof(*server));
  ssh_xfree(server);
}
