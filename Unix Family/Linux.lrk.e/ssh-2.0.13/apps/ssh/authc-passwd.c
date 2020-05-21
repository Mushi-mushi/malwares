/*

  authc-passwd.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Password authentication, client side.
  
*/

#include "ssh2includes.h"
#include "sshencode.h"
#include "sshauth.h"
#include "readpass.h"
#include "sshclient.h"
#include "sshconfig.h"

#define SSH_DEBUG_MODULE "Ssh2AuthPasswdClient"

/* Password authentication, client-side. */

void ssh_client_auth_passwd(SshAuthClientOperation op,
                            const char *user,
                            unsigned int packet_type,
                            SshBuffer *packet_in,
                            const unsigned char *session_id,
                            size_t session_id_len,
                            void **state_placeholder,
                            SshAuthClientCompletionProc completion,
                            void *completion_context,
                            void *method_context)
{
  char *password;
  SshBuffer *b;
  char buf[100];
  SshConfig clientconf = ((SshClient)method_context)->config;

  SSH_DEBUG(6, ("auth_password op = %d  user = %s", op, user));

  switch (op)
    {
    case SSH_AUTH_CLIENT_OP_START:
      if (clientconf->password_prompt == NULL)
        snprintf(buf, sizeof(buf), "%s's password: ", user);
      else
        snprintf(buf, sizeof(buf), "%s", clientconf->password_prompt);
      password = ssh_read_passphrase(buf, FALSE);
      if (password == NULL)
        {
          (*completion)(SSH_AUTH_CLIENT_FAIL, user, NULL, completion_context);
          break;
        }
      b = ssh_buffer_allocate();
      ssh_encode_buffer(b,
                        SSH_FORMAT_BOOLEAN, FALSE,
                        SSH_FORMAT_UINT32_STR, password, strlen(password),
                        SSH_FORMAT_END);
      ssh_xfree(password);
      (*completion)(SSH_AUTH_CLIENT_SEND, user, b, completion_context);
      ssh_buffer_free(b);
      break;
      
    case SSH_AUTH_CLIENT_OP_START_NONINTERACTIVE:
      (*completion)(SSH_AUTH_CLIENT_FAIL, user, NULL, completion_context);
      break;
      
    case SSH_AUTH_CLIENT_OP_CONTINUE:
      /* XXX add support for changing passwords here. */
      (*completion)(SSH_AUTH_CLIENT_FAIL, user, NULL, completion_context);
      break;
      
    case SSH_AUTH_CLIENT_OP_ABORT:
      *state_placeholder = NULL;
      
      break;
      
    default:
      ssh_debug("ssh_client_auth_password: unknown op %d", (int)op);
      (*completion)(SSH_AUTH_CLIENT_FAIL, user, NULL, completion_context);
      break;
    }
}

