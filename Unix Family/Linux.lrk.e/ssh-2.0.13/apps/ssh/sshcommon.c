/*

  sshcommon.c
  
  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
  
  This file implements the core of the SSH2 channel protocols.  This interface
  is shared by server and client code.  Most of the real stuff is in
  channel type specific modules (sshch*.c and sshch*.h).  This file
  is mostly just glue to put them together.

  To define a new channel type, write sshch*.h and sshch*.c files for
  it, and add it to the tables in this module.  Use existing channel
  types as a model.
  
*/

#include "ssh2includes.h"
#include "sshtcp.h"
#include "sshencode.h"
#include "sshmsgs.h"
#include "sshuser.h"
#include "sshcommon.h"
#include "sshtimeouts.h"

#ifdef SSH_CHANNEL_SESSION
#include "sshchsession.h"
#endif /* SSH_CHANNEL_SESSION */

#ifdef SSH_CHANNEL_X11
#include "sshchx11.h"
#endif /* SSH_CHANNEL_X11 */

#ifdef SSH_CHANNEL_AGENT
#include "sshchagent.h"
#endif /* SSH_CHANNEL_AGENT */
#ifdef SSH_CHANNEL_SSH1_AGENT
#include "sshchssh1agent.h"
#endif /* SSH_CHANNEL_SSH1_AGENT */

#ifdef SSH_CHANNEL_TCPFWD
#include "sshchtcpfwd.h"
#endif /* SSH_CHANNEL_TCPFWD */

#define SSH_DEBUG_MODULE "Ssh2Common"

/* This array completely defines all channel types and global requests
   supported by the system.  To add a new channel, write the appropriate
   header file and implementation, include the header into this file, and
   add the channel type into this array. */

struct {
  const char *name;
  SshConnChannelOpenProc open_proc;
  SshChannelTypeCreateProc type_create_proc;
  SshChannelTypeDestroyProc type_destroy_proc;
  SshConnGlobalRequest global_requests[10];
} ssh_channel_types[] =
{

#ifdef SSH_CHANNEL_SESSION
  /* Interactive session channels. */
  { "session", ssh_channel_session_open, NULL, NULL },
#endif /* SSH_CHANNEL_SESSION */

#ifdef SSH_CHANNEL_X11
  /* X11 forwarding channels. */
  { "x11", ssh_channel_x11_open, ssh_channel_x11_create,
    ssh_channel_x11_destroy },
#endif /* SSH_CHANNEL_X11 */

#ifdef SSH_CHANNEL_AGENT
  /* Authentication agent forwarding channels. */
  { "auth-agent", ssh_channel_agent_open, ssh_channel_agent_create,
    ssh_channel_agent_destroy },
#endif /* SSH_CHANNEL_AGENT */

#ifdef SSH_CHANNEL_SSH1_AGENT
  /* Ssh1 authentication agent forwarding channels. */
  { "auth-ssh1-agent", ssh_channel_ssh1_agent_open, 
    ssh_channel_ssh1_agent_create, ssh_channel_ssh1_agent_destroy },
#endif /* SSH_CHANNEL_SSH1_AGENT */

#ifdef SSH_CHANNEL_TCPFWD
  /* Forwarded TCP/IP channels. */
  { "forwarded-tcpip", ssh_channel_ftcp_open_request, ssh_channel_ftcp_create,
    ssh_channel_ftcp_destroy,
    { { "tcpip-forward", ssh_channel_remote_tcp_forward_request },
      { "cancel-tcpip-forward", ssh_channel_tcp_forward_cancel },
      { NULL, NULL } } },
  { "direct-tcpip", ssh_channel_dtcp_open_request, ssh_channel_dtcp_create,
    ssh_channel_dtcp_destroy },
#endif /* SSH_CHANNEL_TCPFWD */

  { NULL },
};

/* Timeout to destroy the common structure from the bottom of the event
   loop. */

void common_destroy_timeout(void *ctx)
{
  SshCommon common = (SshCommon)ctx;

  ssh_common_destroy(common);
}

/* Processes a disconnect message received from the connection protocol.
   Currently, a DISCONNECT message is sent if the protocol terminates. */

void ssh_common_disconnect(int reason, const char *msg, void *context)
{
  SshCommon common = (SshCommon)context;

  SSH_DEBUG(2, ("DISCONNECT received: %s", msg));

  /* Log the disconnect in the system log. */
  ssh_log_event(common->config->log_facility, SSH_LOG_INFORMATIONAL,
                "Remote host disconnected: %s", msg);

  /* Call the disconnect function.  Note that it is always given.
     This will call ssh_common_destroy, destroying the SshCommon object
     and all channels. */
  (*common->disconnect)(reason, msg, common->context);
}

/* Processes a debug message received from the connection protocol. */

void ssh_common_debug(int type, const char *msg, void *context)
{
  SshCommon common = (SshCommon)context;

  SSH_DEBUG(3, ("DEBUG received: %s", msg));

  /* Call the user-supplied debug function if non-NULL. */
  if (common->debug)
    (*common->debug)(type, msg, common->context);
}

/* Processes a special packet received from the connection protocol. */

void ssh_common_special(SshCrossPacketType type, const unsigned char *data,
                        size_t len, void *context)
{
  SshCommon common = (SshCommon)context;

  SSH_DEBUG(1, ("special packet received from connection protocol: %d",
                (int)type));

  switch (type)
    {
    case SSH_CROSS_AUTHENTICATED:
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, &common->user, NULL,
                           SSH_FORMAT_END) == 0)
        ssh_fatal("ssh_common_special: bad AUTHENTICATED packet");

      /* XXX change to use data saved in HostBased authentication. */
      common->authenticated_client_host = ssh_xstrdup("XXX");

      /* In server, retrieve information about the authenticated user.  This
         is not used in the client. */
      if (!common->client)
        {
          common->user_data = ssh_user_initialize(common->user, TRUE);
          if (!common->user_data)
            /* XXX do not call ssh_fatal, disconnect instead. */
            ssh_fatal("ssh_common_special: user data init failed for '%s'",
                      common->user);
        }

      /* Call the authenticated notify function if given. */
      if (common->authenticated_notify)
        (*common->authenticated_notify)(common->user, common->context);

      break;

    case SSH_CROSS_STARTUP:
    case SSH_CROSS_ALGORITHMS:
      /* Do nothing. */
      break;
      
    default:
      SSH_TRACE(0, ("Unknown special packet %d", (int)type));
      break;
    }
}

void ssh_common_finalize(SshIpError error,
                         const char *result,
                         void *context)
{
  SshCommon common = (SshCommon) context;
  
  if (error == SSH_IP_OK)
    {
      SSH_DEBUG(3, ("remote hostname is \"%s\".", result));
      common->remote_host = ssh_xstrdup(result);
    }
  else
    {
      SSH_DEBUG(2, ("DNS lookup failed. Using host-IP-number (\"%s\") " \
                    "as hostname.", common->remote_ip));
      ssh_log_event(common->config->log_facility,
                    SSH_LOG_WARNING,
                    "DNS lookup failed for \"%s\".",
                    common->remote_ip);
      
      common->remote_host = ssh_xstrdup(common->remote_ip);
    }
  
  /* Create connection protocol object. */
  SSH_DEBUG(5, ("creating connection protocol"));
  common->conn = ssh_conn_wrap(common->auth, SSH_CONNECTION_SERVICE,
                               common->global_requests,
                               common->channel_opens,
                               ssh_common_disconnect,
                               ssh_common_debug,
                               ssh_common_special,
                               (void *)common);
  SSH_DEBUG(5, ("connection protocol created"));
}

/* Creates the common processing object for the SSH server/client connection.
   This also creates the connection protocol object.
     `connection'   the connection to the other side
     `auth'         authentication protocol object
     `client'       TRUE if we are a client, FALSE if a server
     `config'       configuration data
     `random_state' initialized random state
     `server_host_name' name of server host, or NULL in server
     `disconnect'    function to call on disconnect (may be NULL)
     `debug'         function to call on debug message (may be NULL)
     `authenticated_notify' function to call when authenticated (may be NULL)
     `context'       context to pass to ``destroy''
   The object should be destroyed from the ``disconnect'' callback or from
   a ``close_notify'' callback (see below).  */

SshCommon ssh_common_wrap(SshStream connection,
                          SshStream auth,
                          Boolean client,
                          SshConfig config,
                          SshRandomState random_state,
                          const char *server_host_name,
                          SshConnDisconnectProc disconnect,
                          SshConnDebugProc debug,
                          SshCommonAuthenticatedNotify authenticated_notify,
                          void *context)
{
  SshCommon common;
  int i, j, num_requests, num_types;

  SSH_DEBUG(5, ("creating SshCommon object"));
  
  /* Sanity check: disconnect should not be NULL. */
  if (disconnect == NULL)
    ssh_fatal("ssh_common_wrap: disconnect must not be NULL.");
  
  /* Create the common object. */
  common = ssh_xcalloc(1, sizeof(*common));
  common->client = client;
  common->config = config;
  common->num_channels = 0;
  common->disconnect = disconnect;
  common->debug = debug;
  common->authenticated_notify = authenticated_notify;
  common->context = context;
  common->random_state = random_state;
  common->server_host_name =
    server_host_name ? ssh_xstrdup(server_host_name) : NULL;
  common->being_destroyed = FALSE;
  common->auth = auth;

  common->last_login_time = 0;
  common->sizeof_last_login_from_host = 100;
  common->last_login_from_host =
    ssh_xcalloc(common->sizeof_last_login_from_host, sizeof(char));
  
  /* Get information from the connection. */
  common->remote_ip = ssh_xmalloc(100);
  if (!ssh_tcp_get_remote_address(connection, common->remote_ip, 100))
    strcpy(common->remote_ip, "UNKNOWN");
  common->remote_port = ssh_xmalloc(100);
  if (!ssh_tcp_get_remote_port(connection, common->remote_port, 100))
    strcpy(common->remote_port, "UNKNOWN");
  common->local_ip = ssh_xmalloc(100);
  if (!ssh_tcp_get_local_address(connection, common->local_ip, 100))
    strcpy(common->local_ip, "UNKNOWN");
  common->local_port = ssh_xmalloc(100);
  if (!ssh_tcp_get_local_port(connection, common->local_port, 100))
    strcpy(common->local_port, "UNKNOWN");

  SSH_DEBUG(5, ("initializing channel types and requests"));
  
  /* Count the number of channel types and global requests. */
  num_types = 0;
  num_requests = 0;
  for (i = 0; ssh_channel_types[i].name; i++)
    {
      num_types++;
      for (j = 0; ssh_channel_types[i].global_requests[j].name; j++)
        num_requests++;
    }
  assert(num_types == i);

  /* Allocate memory for channel types and global requests. */
  common->global_requests = ssh_xcalloc(num_requests + 1,
                                        sizeof(common->global_requests[0]));
  common->channel_opens = ssh_xcalloc(num_types + 1,
                                      sizeof(common->channel_opens[0]));
  common->type_contexts = ssh_xcalloc(num_types,
                                      sizeof(common->type_contexts[0]));
  /* Note: the arrays are initialized to zero.  The code below relies on the
     last element (after ones that we initialize below) already being
     zeroed. */

  /* Initialize channel opens and global requests. */
  num_requests = 0;
  for (i = 0; ssh_channel_types[i].name; i++)
    {
      for (j = 0; ssh_channel_types[i].global_requests[j].name; j++)
        {
          common->global_requests[num_requests++] =
            ssh_channel_types[i].global_requests[j];
        }
      common->channel_opens[i].name = ssh_channel_types[i].name;
      common->channel_opens[i].proc = ssh_channel_types[i].open_proc;
      if (ssh_channel_types[i].type_create_proc)
        common->type_contexts[i] =
          (*ssh_channel_types[i].type_create_proc)(common);
      else
        common->type_contexts[i] = NULL;
    }
  
  /* Set remote host name to ip address. There is no need to do
     reverse mapping in the client (yet) */
  if (!client)
    {
      ssh_tcp_get_host_by_addr(common->remote_ip, ssh_common_finalize,
                               (void *)common);
    }
  else
    {    
      common->remote_host = ssh_xstrdup(common->remote_ip);
    }
  
  if(client)
    ssh_common_finalize(SSH_IP_OK, common->remote_ip, common);
  
  return common;
}

/* Closes all channels, destroys channel-specific and channel type specific
   data, and destroys any context common to all channels. */
  
void ssh_common_destroy(SshCommon common)
{
  int i;

  /* If the common-object is already being destroyed, just return */
  if (common->being_destroyed == TRUE)
    return;
  
  /* We set this flag, so that we wouldn't try to destroy this struct from
     other functions or callbacks. */
  common->being_destroyed = TRUE;
  
  /* If there are timeouts already waiting to destroy this structure,
     cancel them*/
  
  ssh_cancel_timeouts(common_destroy_timeout, (void *)common);
  
  /* Call channel type specific destructors and free the context array. */
  for (i = 0; ssh_channel_types[i].name; i++)
    {
      if (ssh_channel_types[i].type_destroy_proc)
        (*ssh_channel_types[i].type_destroy_proc)(common->type_contexts[i]);
      common->type_contexts[i] = NULL;
    }
  
  ssh_xfree(common->type_contexts);
  common->type_contexts = NULL;
  
  /* Destroy global requests and open procs. */
  ssh_xfree(common->global_requests);
  ssh_xfree(common->channel_opens);
  
  /* Destroy the connection protocol context. */
  if (common->conn)
    ssh_conn_destroy(common->conn);
  common->conn = NULL;

  /* Free allocated fields. */
  ssh_xfree(common->server_host_name);
  ssh_xfree(common->user);
  if (common->user_data)
    ssh_user_free(common->user_data, FALSE);
  ssh_xfree(common->remote_ip);
  ssh_xfree(common->remote_port);
  ssh_xfree(common->local_ip);
  ssh_xfree(common->local_port);
  ssh_xfree(common->authenticated_client_host);

  memset(common, 'F', sizeof(*common));
  ssh_xfree(common);
}

/* Returns the channel type context for the channel type identified by
   the name. */

void *ssh_common_get_channel_type_context(SshCommon common, const char *name)
{
  int i;

  if (common->type_contexts == NULL)
    {
      SSH_DEBUG(5, ("type_contexts is already destroyed."));
      return NULL;
    }
  
  for (i = 0; ssh_channel_types[i].name; i++)
    {
      if (strcmp(ssh_channel_types[i].name, name) == 0)
        return common->type_contexts[i];
    }
  
  SSH_DEBUG(5, ("type '%s' not found", name));
  return NULL;
}

/* Informs the channel type independent code that a channel has been
   destroyed.  This may destroy the SshCommon object if there are no
   more channels, causing a call to the channel type specific destroy
   function.  Care should be taken to call this function as the last thing
   done in a channel destroy function. */

void ssh_common_destroy_channel(SshCommon common)
{
  common->num_channels--;
  SSH_DEBUG(1, ("num_channels now %d", common->num_channels));

  /* If the common-object is already being destroyed, the set timeout would
     be accessing memory that has already been freed. That would not be
     legal. */
  if (common->num_channels == 0 && !common->no_session_channel && !common->being_destroyed)
    {
      /* Schedule the destruction of common struct from the bottom of the
       event loop */
      ssh_register_timeout(0L, 0L, common_destroy_timeout, (void *)common);
    }
}

/* Informs the channel type independent code that a new channel has been
   created. */

void ssh_common_new_channel(SshCommon common)
{
  common->num_channels++;
  SSH_DEBUG(1, ("num_channels now %d", common->num_channels));
}
