/*

sshchssh1agent.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Public interface for SSH1 authentication agent forwarding channels.

*/

#ifndef SSHCHSSH1AGENT_H
#define SSHCHSSH1AGENT_H

/* This function is called whenever an open request is received for an
   authentication agent forwarding channel. */
void ssh_channel_ssh1_agent_open(const char *type,
                               int channel_id,
                               const unsigned char *data,
                               size_t len,
                               SshConnOpenCompletionProc completion,
                               void *completion_context,
                               void *context);

/* This function is called once when a SshCommon object is created. */
void *ssh_channel_ssh1_agent_create(SshCommon common);

/* This function is called once when an SshCommon object is being
   destroyed.  This should destroy all authentication agent channels
   and listeners and free the context. */
void ssh_channel_ssh1_agent_destroy(void *context);

/* This function is called once for each session channel that is created.
   This should initialize per-session state for agent forwarding.  The
   argument points to a void pointer that will be given as argument to
   the following functions.  It can be used to store the per-session
   state. */
void ssh_channel_ssh1_agent_session_create(SshCommon common,
                                         void **session_placeholder);
                                        
/* This function is called once whenever a session channel is destroyed.
   This should free any agent forwarding state related to the session. */
void ssh_channel_ssh1_agent_session_destroy(void *session_placeholder);

/* Processes a received agent forwarding request.  This creates a listener
   at the server end for incoming agent connections. */
Boolean ssh_channel_ssh1_agent_process_request(void *session_placeholder,
                                             const unsigned char *data,
                                             size_t len);

/* Sending a request to start authentication agent forwarding. */
void ssh_channel_ssh1_agent_send_request(SshCommon common, int session_channel_id);

/* Returns the authentication agent path, or NULL if agent is not set.  The
   returned value will remain valid until the SshCommon object is destroyed. */
const char *ssh_channel_ssh1_agent_get_path(SshCommon common);

#endif /* SSHCHSSH1AGENT_H */
