/*

  authc-hostbased.c

  Author: Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Hostbased authentication, client-side.

*/

#include "ssh2includes.h"
#include "sshauth.h"
#include "sshpacketstream.h"
#include "sshencode.h"
#include "sshmsgs.h"
#include "sshclient.h"
#include "sshunixpipestream.h"
#include "sshtcp.h"
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif /* HAVE_SYS_PARAM_H */
#include "sshuserfiles.h"
#include "ssh2pubkeyencode.h"
#include "authc-hostbased.h"
#include "sshconfig.h"

#define SSH_DEBUG_MODULE "Ssh2AuthHostBasedClient"

typedef struct SshClientHostbasedAuthContextRec
{
  SshPacketWrapper wrapper;
  const unsigned char *session_id;
  size_t session_id_len;
  const char *user;
  char *pubkey_algorithm;
  unsigned char *pubkeyblob;
  size_t pubkeyblob_len;
  const char *local_user_name;
  char *local_host_name;
  SshAuthClientCompletionProc completion;
  void *completion_context;
  unsigned char *packet;
  size_t packet_len;
  void **state_placeholder;
  SshConfig server_conf;
} *SshClientHostbasedAuth;

/* Callback, which is used to notify that our packetstream has a
   packet for us.*/
void auth_hostbased_received_packet(SshPacketType type,
                                    const unsigned char *packet,
                                    size_t packet_len,
                                    void *context)
{
  SshBuffer *b;

  SshClientHostbasedAuth state = (SshClientHostbasedAuth) context;
  
  switch(type)
    {
    case SSH_AUTH_HOSTBASED_PACKET:
      SSH_TRACE(2, ("ssh-signer returned SSH_AUTH_HOSTBASED_PACKET "\
                    "(this is an error)"));
      /* signer shouldn't send this to us, so this is an error.*/
      /* XXX */
      break;
    case SSH_AUTH_HOSTBASED_SIGNATURE:
      SSH_TRACE(2, ("ssh-signer returned SSH_AUTH_HOSTBASED_SIGNATURE"));
      /* We've got a signature. */
      b = ssh_buffer_allocate();


      /* Destroy wrapper (and signer) */
      ssh_packet_wrapper_send_eof(state->wrapper);
      ssh_packet_wrapper_destroy(state->wrapper);
      state->wrapper = NULL;
      
      ssh_encode_buffer(b,
                        /* public key algorithm (string) */
                        SSH_FORMAT_UINT32_STR,
                        state->pubkey_algorithm,
                        strlen(state->pubkey_algorithm),
                        /* public key (string) */
                        SSH_FORMAT_UINT32_STR, state->pubkeyblob,
                        state->pubkeyblob_len,
                        /* client host name (FQDN, string) */
                        SSH_FORMAT_UINT32_STR, state->local_host_name,
                        strlen(state->local_host_name),
                        /* user name at client side */
                        SSH_FORMAT_UINT32_STR, state->local_user_name,
                        strlen(state->local_user_name),
                        /* signature */
                        SSH_FORMAT_DATA, packet, packet_len,
                        SSH_FORMAT_END);

      /* Detach the state structure from the state_placeholder. */
      *state->state_placeholder = NULL;
  
      /* Call the authentication method completion procedure. */
      (*state->completion)(SSH_AUTH_CLIENT_SEND, state->user, b,
                           state->completion_context);

      /* Free the buffer */
      ssh_buffer_free(b);

      /* XXX Free the state. */

      break;
    case SSH_AUTH_HOSTBASED_ERROR:
      /* Destroy wrapper (and signer) */
      ssh_packet_wrapper_send_eof(state->wrapper);
      ssh_packet_wrapper_destroy(state->wrapper);
      state->wrapper = NULL;

      SSH_TRACE(0, ("ssh-signer returned SSH_AUTH_HOSTBASED_ERROR"));
      /* Send failure message to server, and return. */
      (*state->completion)(SSH_AUTH_CLIENT_FAIL, state->user, NULL,
                           state->completion_context);
      break;
    }
}

/* Callback, which notifies that packetstream has received EOF from
   the other side. */
void auth_hostbased_received_eof(void *context)
{
  SshClientHostbasedAuth state = (SshClientHostbasedAuth) context;
  
  SSH_TRACE(0, ("received EOF from ssh-signer2."));
  
  ssh_packet_wrapper_send_eof(state->wrapper);
  ssh_packet_wrapper_destroy(state->wrapper);
  state->wrapper = NULL;

  *(state->state_placeholder) = NULL;
  
  /* Send failure message up, and return. */
  (*state->completion)(SSH_AUTH_CLIENT_FAIL, state->user, NULL,
                       state->completion_context);
}

void ssh_client_auth_hostbased_send_to_signer(void *context)
{
  SshClientHostbasedAuth state = (SshClientHostbasedAuth) context;

  static Boolean packet_already_sent = FALSE;
  
  SSH_ASSERT(state != NULL);

  if (packet_already_sent)
    return;
  else
    packet_already_sent = TRUE;
  
  ssh_packet_wrapper_send_encode(state->wrapper, SSH_AUTH_HOSTBASED_PACKET,
                                 /* session_id*/
                                 SSH_FORMAT_UINT32_STR, state->session_id,
                                 state->session_id_len,
                                 /* SSH_MSG_USERAUTH_REQUEST */
                                 SSH_FORMAT_CHAR,
                                 (unsigned int) SSH_MSG_USERAUTH_REQUEST,
                                 /* user name */
                                 SSH_FORMAT_UINT32_STR, state->user,
                                 strlen(state->user),
                                 /* service ("ssh-userauth") */
                                 SSH_FORMAT_UINT32_STR,
                                 SSH_USERAUTH_SERVICE,
                                 strlen(SSH_USERAUTH_SERVICE),
                                 /* "hostbased" */
                                 SSH_FORMAT_UINT32_STR,
                                 SSH_AUTH_HOSTBASED,
                                 strlen(SSH_AUTH_HOSTBASED),
                                 /* public key algorithm (string) */
                                 SSH_FORMAT_UINT32_STR,
                                 state->pubkey_algorithm,
                                 strlen(state->pubkey_algorithm),
                                 /* public key (string) */
                                 SSH_FORMAT_UINT32_STR, state->pubkeyblob,
                                 state->pubkeyblob_len,
                                 /* client host name (FQDN, string) */
                                 SSH_FORMAT_UINT32_STR, state->local_host_name,
                                 strlen(state->local_host_name),
                                 /* user name at client side */
                                 SSH_FORMAT_UINT32_STR, state->local_user_name,
                                 strlen(state->local_user_name),
                                 SSH_FORMAT_END);
}

/* Callback, which notifies that packetstream is ready for sending. */
void auth_hostbased_can_send(void *context)
{
  ssh_client_auth_hostbased_send_to_signer(context);
}


void ssh_client_auth_hostbased(SshAuthClientOperation op,
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
  SshClientHostbasedAuth state;
  SshClient client;
  SshStream stdio_stream;
  char hostkeyfile[512];
  /*  char *keytype;
  SshPublicKey pubkey;*/
  char **signer_argv;
  char config_filename[512];
  size_t hostname_len;
  
  SSH_DEBUG(6, ("auth_hostbased op = %d  user = %s", op, user));

  client = (SshClient)method_context;
  state = *state_placeholder;

  switch (op)
    {
      /* This operation is always non-interactive, as hostkeys
         shouldn't have passphrases. Check for it, though. XXX */
    case SSH_AUTH_CLIENT_OP_START_NONINTERACTIVE:
      /* XXX There is a bug in sshauthc.c (or
         elsewhere). Authentication methods, that are not allowed,
         should not be tried. Now it calls
         SSH_AUTH_CLIENT_OP_START_NONINTERACTIVE for every
         authentication method before checking.*/
      (*completion)(SSH_AUTH_CLIENT_FAIL, user, NULL, completion_context);
      break;
      
    case SSH_AUTH_CLIENT_OP_START:
      /* This is the first operation for doing hostbased authentication.
         We should not have any previous saved state when we come here. */
      SSH_ASSERT(*state_placeholder == NULL);

      /* Initialize a context. */
      state = ssh_xcalloc(1, sizeof(*state));

      state->session_id = session_id;
      state->session_id_len = session_id_len;
      state->user = ssh_xstrdup(user);

      /* We have to dig up the server configuration to get the place
         for the client host's publickey. This is a very kludgeish
         solution. XXX*/
      state->server_conf = ssh_server_create_config();
      
      /* Dig up hosts publickey. */
      
      snprintf(config_filename, sizeof(config_filename), "%s/%s",
               SSH_SERVER_DIR, SSH_SERVER_CONFIG_FILE);
      
      if (!ssh_config_read_file(client->user_data, state->server_conf,
                                NULL, config_filename, NULL))
        SSH_TRACE(2, ("Failed to read config file %s", \
                      config_filename));


      if(state->server_conf->public_host_key_file[0] != '/')
        {
          snprintf(hostkeyfile, sizeof(hostkeyfile), "%s/%s", SSH_SERVER_DIR,
                   state->server_conf->public_host_key_file);
        }
      else
        {
          snprintf(hostkeyfile, sizeof(hostkeyfile), "%s",
                   state->server_conf->public_host_key_file);  
        }

      /* This pubkey*-stuff is for the client _host's_ public
         hostkey. */
      SSH_DEBUG(4, ("Reading pubkey-blob from %s...", hostkeyfile));
      if (ssh2_key_blob_read(client->user_data, hostkeyfile, NULL,
                             &state->pubkeyblob,
                             &state->pubkeyblob_len, NULL) 
          != SSH_KEY_MAGIC_PUBLIC)
        {         
          goto error;
        }
      
      SSH_DEBUG(4, ("done."));
      if ((state->pubkey_algorithm =
           ssh_pubkeyblob_type(state->pubkeyblob,
                               state->pubkeyblob_len))
          == NULL)
        {
          goto error;
        }
      
      state->local_user_name = ssh_user_name(client->user_data);
      state->local_host_name = ssh_xmalloc(MAXHOSTNAMELEN + 1);
      ssh_tcp_get_host_name(state->local_host_name, MAXHOSTNAMELEN + 1);
      hostname_len = strlen(state->local_host_name);
      /* Sanity check */
      SSH_ASSERT(hostname_len + 2 < MAXHOSTNAMELEN);
      /* We want FQDN. */
      state->local_host_name[hostname_len] = '.';
      state->local_host_name[hostname_len + 1] = '\0';
      
      state->completion = completion;
      state->completion_context = completion_context;
      state->state_placeholder = state_placeholder;
      
      /* Assign the state to the placeholder that survives across
         calls.  (this is actually not needed, as hostbased
         authentication procedure is very simple. Just one packet from
         client to server, and server's response in one packet.) */
      *state_placeholder = state;

      /* Open a pipestream connection to ssh-signer. */
      switch (ssh_pipe_create_and_fork(&stdio_stream, NULL))
        {
        case SSH_PIPE_ERROR:
          /* Something went wrong. */
          ssh_warning("Couldn't create pipe to connect to %s.",
                      client->config->signer_path);
          goto error;
          break;
        case SSH_PIPE_CHILD_OK:
          /* Exec ssh-signer */
          SSH_TRACE(0, ("Child: Execing ssh-signer...(path: %s)", \
                        client->config->signer_path));

          signer_argv = ssh_xcalloc(2, sizeof(char *));
          signer_argv[0] = client->config->signer_path;
          signer_argv[1] = NULL;
          
          execvp(client->config->signer_path, signer_argv);
          fprintf(stderr, "Couldn't exec '%s' (System error message: %s)",
                  client->config->signer_path, strerror(errno));
          ssh_fatal("Executing ssh-signer failed.");
          break;
        case SSH_PIPE_PARENT_OK:
          state->wrapper = ssh_packet_wrap(stdio_stream,
                                           auth_hostbased_received_packet,
                                           auth_hostbased_received_eof,
                                           auth_hostbased_can_send,
                                           state);
          /* We don't check wrapper's validity, as ssh_packet_wrap
             should always succeed.*/
          break;
        }
      /* Here we continue as parent. */
      
      /* sign packet with ssh-signer (a suid-program). */
      if (ssh_packet_wrapper_can_send(state->wrapper))
        {
          ssh_client_auth_hostbased_send_to_signer(state);
        }
      /* If ssh_packet_wrapper_can_send returns FALSE,
         auth_hostbased_can_send will call the ...send_to_signer
         function above. */
      
      /* Rest is done in callbacks. */
      break;
      
    case SSH_AUTH_CLIENT_OP_CONTINUE:          
      SSH_TRACE(2, ("Invalid message. We didn't return " \
                    "SSH_AUTH_CLIENT_SEND_AND_CONTINUE at any stage!"));
      /* Send failure message.*/
      (*completion)(SSH_AUTH_CLIENT_FAIL, user, NULL, completion_context);
      return;

    case SSH_AUTH_CLIENT_OP_ABORT:
      /* Abort the authentication operation immediately. */
      /* XXX Destroy 'state'-object. */
      *state_placeholder = NULL;
      break;

    default:
      /* something weird is going on.. */
      ssh_fatal("ssh_client_auth_hostbased: unknown op %d", (int)op);
    }
  return;

 error:
  /* XXX Destroy state. */
  /* Send failure message.*/
  (*completion)(SSH_AUTH_CLIENT_FAIL, user, NULL, completion_context);
  return;
}
