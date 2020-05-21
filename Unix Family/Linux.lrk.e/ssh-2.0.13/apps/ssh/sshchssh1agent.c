/*

sshchssh1agent.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Code for ssh1 authentication agent forwarding channels for SSH2 
servers and clients.

*/

#include "ssh2includes.h"
#include "sshfilterstream.h"
#include "sshtimeouts.h"
#include "sshgetput.h"
#include "sshtcp.h"
#include "sshencode.h"
#include "sshmsgs.h"
#include "sshconn.h"
#include "sshcommon.h"
#include "sshagentint.h"

#ifdef SSH_CHANNEL_SSH1_AGENT

#include "sshchssh1agent.h"

#define SSH_DEBUG_MODULE "Ssh2ChannelSsh1Agent"

#define AGENT_WINDOW_SIZE        10000
#define AGENT_PACKET_SIZE         1024

typedef struct SshChannelTypeSsh1AgentRec
{
  /* Pointer to the SshCommon object. */
  SshCommon common;

  /* Data for the proxy agent on the server side. */
  char *agent_path;
  SshLocalListener agent_listener;

  /* Flag indicating that agent forwarding has been requested. */
  Boolean agent_requested;
} *SshChannelTypeSsh1Agent;

typedef struct SshChannelSsh1AgentSessionRec
{
  SshCommon common;
} *SshChannelSsh1AgentSession;

/***********************************************************************
 * Glue functions for creating/destroying the channel type context.
 ***********************************************************************/

/* This function is called once when a SshCommon object is created. */

void *ssh_channel_ssh1_agent_create(SshCommon common)
{
  SshChannelTypeSsh1Agent ct;
  
  ct = ssh_xcalloc(1, sizeof(struct SshChannelTypeSsh1AgentRec));
  ct->common = common;
  return ct;
}

/* This function is called once when an SshCommon object is being
   destroyed.  This should destroy all agent channels and listeners and
   free the context. */

void ssh_channel_ssh1_agent_destroy(void *context)
{
  SshChannelTypeSsh1Agent ct = (SshChannelTypeSsh1Agent)context;

  /* Destroy all existing channels.
     XXX not implemented. */

  /* Destroy the listener. */
  if (ct->agent_listener)
    {
      ssh_local_destroy_listener(ct->agent_listener);

      /* Destroy the socket. */
      remove(ct->agent_path);
    }

  /* Free the path name. */
  ssh_xfree(ct->agent_path);

  /* Destroy the channel type context. */
  ssh_xfree(ct);
}

/* This function is called once for each session channel that is created.
   This should initialize per-session state for agent forwarding.  The
   argument points to a void pointer that will be given as argument to
   the following functions.  It can be used to store the per-session
   state. */

void ssh_channel_ssh1_agent_session_create(SshCommon common,
                                          void **session_placeholder)
{
  SshChannelSsh1AgentSession session;

  /* Allocate a session context. */
  session = ssh_xcalloc(1, sizeof(*session));
  session->common = common;

  *session_placeholder = (void *)session;
}
                                        
/* This function is called once whenever a session channel is destroyed.
   This should free any agent forwarding state related to the session. */

void ssh_channel_ssh1_agent_session_destroy(void *session_placeholder)
{
  SshChannelSsh1AgentSession session = (SshChannelSsh1AgentSession)session_placeholder;

  /* Free the session context. */
  ssh_xfree(session);
}

/* Returns the channel type context from the SshCommon object. */

SshChannelTypeSsh1Agent ssh_channel_ssh1_agent_ct(SshCommon common)
{
  return (SshChannelTypeSsh1Agent)ssh_common_get_channel_type_context(common,
                                                          "auth-ssh1-agent");
}

/***********************************************************************
 * Functions that are used in the SSH server end.  These receive
 * incoming agent connections, and cause channel open requests to be
 * sent to the SSH client.
 ***********************************************************************/

/* Function to be called when a forwarded agent connection is closed.  Note
   that this takes SshCommon as context, as the forwarded connection might
   outlive the session in which it was created. */

void ssh_channel_ssh1_agent_connection_destroy(void *context)
{
  SshCommon common = (void *)context;

  /* Inform the SshCommon object that a channel has been destroyed.  Note
     that this may cause the SshCommon object to be destroyed, and the
     destroy function for agent forwarding to be called. */
  ssh_common_destroy_channel(common);
}

/* Processes an incoming connection to the agent.  This is called when
   a connection is received at the agent listener.  This will open the
   agent channel to the client. */

void ssh_channel_ssh1_agent_connection(SshStream stream, void *context)
{
  SshCommon common = (SshCommon)context;

  SSH_DEBUG(5, ("incoming connection to agent proxy"));
   
  /* Increase the number of open channels.  This will be decremented in
     the destroy function. */
  ssh_common_new_channel(common);

  /* Send a channel open message.  If this fails, the stream will be
     automatically closed. */
  ssh_conn_send_channel_open(common->conn, "auth-ssh1-agent",
                             stream, TRUE, TRUE,
                             AGENT_WINDOW_SIZE, AGENT_PACKET_SIZE,
                             NULL, 0, NULL,
                             ssh_channel_ssh1_agent_connection_destroy,
                             (void *)common, NULL, NULL);
}

/***********************************************************************
 * Functions that are used at the SSH client end for connecting to the
 * real authentication agent.
 ***********************************************************************/

typedef struct SshAgentConnectionRec
{
  SshCommon common;
  int channel_id;
  SshConnOpenCompletionProc completion;
  void *context;
} *SshAgentConnection;

/* This function is called when a connecting to a real agent has been
   completed (possibly with error). */

void ssh_channel_open_ssh1_agent_connected(SshStream stream,
                                          void *context)
{
  SshAgentConnection a = (SshAgentConnection)context;
  SshBuffer buffer;
  unsigned char *cp;

  if (stream == NULL)
    {
      SSH_DEBUG(1, ("Connecting to the real agent failed."));
      (*a->completion)(SSH_OPEN_CONNECT_FAILED,
                       NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                       a->context);
      ssh_xfree(a);
      return;
    }

  SSH_DEBUG(5, ("connection to real agent established"));

  /* Increment the number of channels. */
  ssh_common_new_channel(a->common);

  if (a->common->config->ssh_agent_compat == SSH_AGENT_COMPAT_SSH2)
    {
      /* We are required to send a FORWARDING_NOTIFY to the agent to inform it
         that the connection is actually forwarded.  Format that packet now. */
      ssh_buffer_init(&buffer);
      ssh_encode_buffer(&buffer,
                        SSH_FORMAT_DATA, "1234", (size_t)4,
                        SSH_FORMAT_CHAR,
                        (unsigned int) SSH_AGENT_FORWARDING_NOTICE,
                        SSH_FORMAT_UINT32_STR,
                        a->common->server_host_name,
                        strlen(a->common->server_host_name),
                        SSH_FORMAT_UINT32_STR,
                        a->common->remote_ip, strlen(a->common->remote_ip),
                        SSH_FORMAT_UINT32,
                        (SshUInt32) atol(a->common->remote_port),
                        SSH_FORMAT_END);
      cp = ssh_buffer_ptr(&buffer);
      SSH_PUT_32BIT(cp, ssh_buffer_len(&buffer) - 4);

      /* Write the buffer to the channel.  This is a kludge; this assumes that
         we can always write this much to the internal buffers. */
      if (ssh_stream_write(stream, ssh_buffer_ptr(&buffer),
                           ssh_buffer_len(&buffer)) !=
          ssh_buffer_len(&buffer))
        ssh_fatal("ssh_channel_open_agent_connected: kludge failed");
      ssh_buffer_uninit(&buffer);
    }

  /* Create the channel. */
  (*a->completion)(SSH_OPEN_OK, stream, TRUE, TRUE, AGENT_WINDOW_SIZE, NULL, 0,
                   NULL, ssh_channel_ssh1_agent_connection_destroy,
                   (void *)a->common, a->context);
  ssh_xfree(a);
}

/***********************************************************************
 * Receiving an open request for an agent channel.  This call typically
 * happens in the SSH client, and this will contact the local real
 * authentication agent.
 ***********************************************************************/

/* Processes an open request for an agent channel. */

void ssh_channel_ssh1_agent_open(const char *type, int channel_id,
                                const unsigned char *data, size_t len,
                                SshConnOpenCompletionProc completion,
                                void *completion_context, void *context)
{
  SshCommon common = (SshCommon)context;
  SshChannelTypeSsh1Agent ct;
  SshAgentConnection a;

  SSH_DEBUG(5, ("agent channel open request received"));

  ct = ssh_channel_ssh1_agent_ct(common);
  
  if (len != 0)
    {
      SSH_DEBUG(0, ("Bad agent channel open request"));
      (*completion)(SSH_OPEN_CONNECT_FAILED,
                    NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                    completion_context);
      return;
    }

  /* Do not allow agent opens at the server. */
  if (!common->client)
    {
      ssh_warning("Refused attempted agent connection to server.");
      (*completion)(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                    NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                    completion_context);
      return;
    }

  /* Do not allow agent opens if we didn't request agent forwarding. */
  if (!ct->agent_requested)
    {
      ssh_warning("Refused attempted agent connection when forwarding not requested.");
      (*completion)(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                    NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                    completion_context);
      return;
    }
  
  /* Create a context argument for connecting. */
  a = ssh_xcalloc(1, sizeof(*a));
  a->common = common;
  a->channel_id = channel_id;
  a->completion = completion;
  a->context = completion_context;

  /* Try to connect to the real agent. */
  ssh_agenti_connect(ssh_channel_open_ssh1_agent_connected, TRUE, (void *)a);
}

/***********************************************************************
 * Processing a request to start agent forwarding at server end.
 ***********************************************************************/

/* Processes a received agent forwarding request.  This creates a listener
   at the server end for incoming agent connections. */

Boolean ssh_channel_ssh1_agent_process_request(void *session_placeholder,
                                              const unsigned char *data,
                                              size_t len)
{
  SshChannelTypeSsh1Agent ct;
  SshChannelSsh1AgentSession session;

  SSH_DEBUG(5, ("request to start agent forwarding received"));

  session = (SshChannelSsh1AgentSession)session_placeholder;
  ct = ssh_channel_ssh1_agent_ct(session->common);
  
  if (ct->agent_path != NULL)
    return TRUE; /* We've alread created a fake listener. */
  ct->agent_listener =
    ssh_agenti_create_listener(ssh_user_uid(ct->common->user_data),
                               &ct->agent_path, 
                               ssh_channel_ssh1_agent_connection,
                               TRUE,
                               ct->common);
  return TRUE;
}

/* Sending a request to start authentication agent forwarding. */

void ssh_channel_ssh1_agent_send_request(SshCommon common, 
                                        int session_channel_id)
{
  SshChannelTypeSsh1Agent ct;
  
  SSH_DEBUG(5, ("sending request to start agent forwarding"));

  ct = ssh_channel_ssh1_agent_ct(common);
  
  ssh_conn_send_channel_request(common->conn, session_channel_id,
                                "auth-ssh1-agent-req", NULL, 0, NULL, NULL);
  ct->agent_requested = TRUE;
}

/* Returns the authentication agent path, or NULL if agent is not set.  The
   returned value will remain valid until the SshCommon object is destroyed. */

const char *ssh_channel_ssh1_agent_get_path(SshCommon common)
{
  SshChannelTypeSsh1Agent ct;
  
  ct = ssh_channel_ssh1_agent_ct(common);
  return ct->agent_path;
}

#endif /* SSH_CHANNEL_SSH1_AGENT */
