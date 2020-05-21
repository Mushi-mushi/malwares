/*

sshagentint.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Unix implementation internal header for the ssh-agent interface.

*/

#ifndef SSHAGENTINT_H
#define SSHAGENTINT_H

#include "sshlocalstream.h"

/* Requests sent by agent clients. */
#define SSH_AGENT_REQUEST_VERSION         1  /* for compat with old agent */
#define SSH_AGENT_ADD_KEY               202
#define SSH_AGENT_DELETE_ALL_KEYS       203
#define SSH_AGENT_LIST_KEYS             204
#define SSH_AGENT_PRIVATE_KEY_OP        205
#define SSH_AGENT_FORWARDING_NOTICE     206
#define SSH_AGENT_DELETE_KEY            207
#define SSH_AGENT_LOCK                  208
#define SSH_AGENT_UNLOCK                209
#define SSH_AGENT_PING                  212
/* Responses from the agent. */
#define SSH_AGENT_SUCCESS               101
#define SSH_AGENT_FAILURE               102
#define SSH_AGENT_VERSION_RESPONSE      103
#define SSH_AGENT_KEY_LIST              104
#define SSH_AGENT_OPERATION_COMPLETE    105
#define SSH_AGENT_ALIVE                 150

/* SSH1 agent request codes. */
#define SSH1_AGENT_LIST_KEYS            1
#define SSH1_AGENT_AUTH_CHALLENGE       3
#define SSH1_AGENT_ADD_KEY              7
#define SSH1_AGENT_REMOVE_KEY           8
#define SSH1_AGENT_REMOVE_ALL_KEYS      9

/* SSH1 agent response codes. */
#define SSH1_AGENT_KEY_LIST             2
#define SSH1_AGENT_AUTH_RESPONSE        4
#define SSH1_AGENT_FAILURE              5
#define SSH1_AGENT_SUCCESS              6

/* Constraints that can be given to the key in SSH_AGENT_ADD_KEY packet */
#define SSH_AGENT_CONSTRAINT_OLD_TIMEOUT            1
#define SSH_AGENT_CONSTRAINT_OLD_USE_LIMIT          2
#define SSH_AGENT_CONSTRAINT_OLD_FORWARDING_STEPS   3
#define SSH_AGENT_CONSTRAINT_OLD_FORWARDING_PATH    4
#define SSH_AGENT_CONSTRAINT_OLD_COMPAT             5
#define SSH_AGENT_CONSTRAINT_OLD_STATUS             6
#define SSH_AGENT_CONSTRAINT_TIMEOUT                50
#define SSH_AGENT_CONSTRAINT_USE_LIMIT              51
#define SSH_AGENT_CONSTRAINT_FORWARDING_STEPS       52
#define SSH_AGENT_CONSTRAINT_FORWARDING_PATH        100
#define SSH_AGENT_CONSTRAINT_COMPAT                 150
#define SSH_AGENT_CONSTRAINT_STATUS                 53


/* Pathname for the ssh-agent socket.  It takes two arguments, the
   user name and the process id of the agent. */
#define SSH_AGENT_SOCKET_DIR "/tmp/ssh-%s"
#define SSH_AGENT_SOCKET     "ssh2-%d-agent"

/* Filename of the ssh1 compatible agent socket */
#define SSH1_AGENT_SOCKET    "ssh1-%d-agent"

/* Environment variable that contains the authentication agent socket
   name if present. */
#define SSH_AGENT_VAR "SSH2_AUTH_SOCK"
#define SSH_AA_VAR    "SSH_AA_SOCK"

/* Environment variable for agent's pid. */
#define SSH_AGENT_PID "SSH2_AGENT_PID"

/* Environment variables that contains the ssh1 authentication 
   agent socket name and pid if present. */
#define SSH1_AGENT_VAR "SSH_AUTH_SOCK"
#define SSH1_AGENT_PID "SSH_AGENT_PID"

/* Creates a listener for agent connections for the given uid.  This
   might be a normal socket, or might be a listener for some kind of
   interprocess communication.  This returns NULL if an error occurs.
   If `path_return' is non-NULL, it will be set to point to the path
   name of the created listener (regardless of whether creation was
   successful).  The caller is responsible for freeing it with ssh_xfree
   when no longer needed.   `callback' and `context' will be called
   when the listener receives a connection. */
SshLocalListener ssh_agenti_create_listener(uid_t uid, char **path_return,
                                            SshLocalCallback callback,
                                            Boolean ssh1_agent,
                                            void *context);

/* Connects to an existing authentication agent.  In Unix, this gets
   the path of a unix domain socket from an environment variable and
   connects that socket.  This calls the given function when the connection
   is complete. */
void ssh_agenti_connect(SshLocalCallback callback, 
                        Boolean ssh1_agent,
                        void *context);

#endif /* SSHAGENTINT_H */
