/*

  sshclient.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  SSH client functionality for processing a connection.  Most of the
  implementation is actually shared with the server (in sshcommon.c).

*/

#include "ssh2includes.h"
#include "sshtrans.h"
#include "sshauth.h"
#include "sshconn.h"
#include "sshauthmethods.h"
#include "sshcommon.h"
#include "sshclient.h"
#include "sshuserfiles.h"
#include "sshmsgs.h"
#include "sshcipherlist.h"
#include "sshgetopt.h"
#include "sshdsprintf.h"

#ifdef SSH_CHANNEL_SESSION
#include "sshchsession.h"
#endif /* SSH_CHANNEL_SESSION */

#ifdef SSH_CHANNEL_TCPFWD
#include "sshchtcpfwd.h"
#endif /* SSH_CHANNEL_TCPFWD */

#define SSH_DEBUG_MODULE "Ssh2Client"

/* Define this to test trkex-keycheck callbacks. (gives a two-second
   time-out.*/

#undef TEST_KEYCHECK
#ifdef TEST_KEYCHECK
#include "sshtimeouts.h"

typedef struct SshKeyCheckTestContextRec
{
  void (*callback)(Boolean result,
                   void *result_context);
  Boolean result;
  void *result_context;
} *SshKeyCheckTestContext;

void test_timeout(void *context)
{
  SshKeyCheckTestContext ctx = (SshKeyCheckTestContext) context;

  fprintf(stderr, "Delay ended, hiirr wee aar. (Calling result-callback.)\n");
  (*ctx->callback)(ctx->result, ctx->result_context);

  ssh_xfree(ctx);
  
}
#endif /* TEST_KEYCHECK */
     
/* Callback function that is used to check the validity of the server
   host key.
     `server_name'  The server name as passed in when the protocol
                    was created.  This is expected to be the name that
                    the user typed.
     `blob'         The linear representation of the public key (including
                    optional certificates).
     `len'          The length of the public key blob.
     `result_cb'    This function must be called when the validity has been
                    determined.  The argument must be TRUE if the host key
                    is to be accepted, and FALSE if it is to be rejected.
     `result_context' This must be passed to the result function.
     `context'      Context argument.
   This function should call the result callback in every case.  This is not
   allowed to destroy the protocol context.  This function is allowed to
   do basically anything before calling the result callback. */

void ssh_client_key_check(const char *server_name,
                          const unsigned char *blob, size_t len,
                          void (*result_cb)(Boolean result,
                                            void *result_context),
                          void *result_context,
                          void *context)
{
  SshClient client;
  char *udir, filen[1024], comment[1024];
  unsigned char *blob2;
  size_t blob2_len;
  int i, j;
  SshTime now;
  unsigned long magic;
  struct stat st;
  char *time_str;

  assert(context != NULL);

  client = (SshClient) context;
 
  if (server_name == NULL || strlen(server_name) == 0)
    {
      ssh_debug("ssh_client_key_check: server_name is NULL or zero-length");
      (*result_cb)(FALSE, result_context);
      return;
    }

  if ((udir = ssh_userdir(client->user_data, client->config, TRUE)) == NULL)
    ssh_fatal("ssh_client_key_check: no user directory.");

  snprintf(filen, sizeof(filen)-20, "%s/hostkeys", udir);
  if (stat(filen, &st) < 0)
    {
      if (mkdir(filen, 0700) < 0)
        {
          ssh_warning("ssh_userdir: could not create user's ssh hostkey" 
                      "directory %s", filen);
        }
    }

  /* produce a file name from the server name */
  snprintf(filen, sizeof(filen)-20, "%s/hostkeys/key_%s_", 
           udir, client->common->config->port);
  ssh_xfree(udir);
  j = strlen(filen);

  for (i = 0; server_name[i] != '\0'; i++)
    {
      if (j > sizeof(filen) - 10)
        break;

      if (isalpha(server_name[i]))
        {
          filen[j++] = tolower(server_name[i]);
          continue;
        }
      if (isdigit(server_name[i]) || server_name[i] == '.' || 
          server_name[i] == '-')
        {
          filen[j++] = server_name[i];
          continue;
        }

      /* escape this character in octal */
      filen[j++] = '_';
      filen[j++] = '0' + (server_name[i] >> 6);
      filen[j++] = '0' + ((server_name[i] >> 3) & 7);
      filen[j++] = '0' + (server_name[i] & 7);
    }
  filen[j] = '\0';
  strcat(filen, ".pub");

  SSH_DEBUG(6, ("key_check: checking %s", filen));

  /* ok, now see if the file exists */
  
  blob2 = NULL;

  magic = ssh2_key_blob_read(client->user_data, filen, NULL,
                            &blob2, &blob2_len, NULL);

  switch(magic)
    {
    case SSH_KEY_MAGIC_FAIL:
      ssh_warning("Accepting host %s key without checking.",
                server_name);
      now = ssh_time();
      time_str = ssh_readable_time_string(now, TRUE);
      snprintf(comment, sizeof(comment)-1, 
               "host key for %s, accepted by %s %s", 
               server_name, ssh_user_name(client->user_data),
               time_str);
      ssh_xfree(time_str);

      if (ssh2_key_blob_write(client->user_data, filen, 0600,
                             SSH_KEY_MAGIC_PUBLIC,
                             comment, blob, len, NULL))
        ssh_warning("Unable to write host key %s", filen);
      ssh_debug("Host key saved to %s", filen);
      ssh_debug("%s", comment);
      break;
      
    case SSH_KEY_MAGIC_PUBLIC:

      if (blob2_len == len && memcmp(blob, blob2, len) == 0)
        break;

      /* break left out intentionally */

    default:

      ssh_warning("** !! ILLEGAL HOST KEY FOR %s !! **",
                server_name);
      ssh_warning("Remove %s and try again if you think that this is normal.",
                filen);

      memset(blob2, 0, blob2_len);
      ssh_xfree(blob2);

      /* disconnect now */
      (*client->common->disconnect)(SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, 
                                    "Illegal host key.", 
                                    client->common->context);

#if 0
      /* XXX We don't call the result callback, as it would result in
         a SIGSEGV. This is because *client->common->disconnect calls
         ssh_conn_destroy, which basically screws everything up for
         anything else to be done (it destroys the protocol context,
         the underlying stream, etc etc.)*/
      (*result_cb)(FALSE, result_context);
#endif /* 0 */
      return;
    }

  if (blob2 != NULL)
    {
      memset(blob2, 0, blob2_len);
      ssh_xfree(blob2);
    }

  ssh_debug("Host key found from the database.");

#ifdef TEST_KEYCHECK
  {
    SshKeyCheckTestContext ctx;

    ctx = ssh_xcalloc(1, sizeof(struct SshKeyCheckTestContextRec));
    ctx->callback = result_cb;
    ctx->result = TRUE;
    ctx->result_context = result_context;
    ssh_register_timeout(2L, 0L, test_timeout, ctx);
    fprintf(stderr,
            "Entering (atleast) two second delay in "
            "ssh_client_key_check()...\n");
  }
#else
  (*result_cb)(TRUE, result_context);
#endif
}

/* Fetches values for the transport parameters (e.g., encryption algorithms)
   from the config data. */

Boolean ssh_client_update_transport_params(SshConfig config,
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

  if (config->compression == TRUE)
    {
      ssh_xfree(params->compressions_c_to_s);
      params->compressions_c_to_s = ssh_xstrdup("zlib");
      ssh_xfree(params->compressions_s_to_c);
      params->compressions_s_to_c = ssh_xstrdup("zlib");
    }

  hlp = ssh_public_key_list_canonialize(params->host_key_algorithms);
  ssh_xfree(params->host_key_algorithms);
  params->host_key_algorithms = hlp;

  hlp = ssh_hash_list_canonialize(params->hash_algorithms);
  ssh_xfree(params->hash_algorithms);
  params->hash_algorithms = hlp;

  return TRUE;
}

/* Checks the remote version number, and execs a compatibility program as
   appropriate. */

void ssh_client_version_check(const char *version, void *context)
{
  SshClient client = (SshClient)context;
  char **args = NULL;
  int args_alloced = 20;  
  int args_used = 0;  
  int i;
  extern char **environ;
  char *host = NULL;
  int option;
  
  ssh_debug("Remote version: %s", version);

  if (strncmp(version, "SSH-1.", 6) == 0 &&
      strncmp(version, "SSH-1.99", 8) != 0 &&
      client->config->ssh1compatibility == TRUE &&
      client->config->ssh1_path != NULL &&
      client->config->ssh1_argv != NULL)
    {
      ssh_warning("Executing %s for ssh1 compatibility.",
                  client->config->ssh1_path);

      /* Close the old connection to the server. */
      close(client->config->ssh1_fd);
      
      args = ssh_xcalloc(args_alloced, sizeof(*args));

      args[0] = ssh_xstrdup("ssh");
      args_used++;
        
      /* Clear the getopt data. */
      ssh_getopt_init_data(&ssh_getopt_default_data);

      ssh_opterr = 0;
      ssh_optallowplus = 1;
      ssh_optind = 1;
        
      while(1)
        {
          if (args_alloced < args_used + 10)
            args = ssh_xrealloc(args,
                                (args_alloced + 10)*sizeof(*args));
            
          option = ssh_getopt(client->config->ssh1_argc,
                              client->config->ssh1_argv,
                              SSH2_GETOPT_ARGUMENTS, NULL);
          
          if ((option == -1) && (host == NULL))
            {
              host = client->config->ssh1_argv[ssh_optind];
                
              if (!host)
                ssh_fatal("No host name found from args to ssh1."
                          "(e.g. ssh1-argv struct has been corrupted.)");
                
              args[args_used] = ssh_xstrdup(host);
              args_used++;
              
              ssh_optind++;
              SSH_DEBUG(3, ("ssh1_args: remote host = \"%s\"", host));
              ssh_optreset = 1;
              option = ssh_getopt(client->config->ssh1_argc,
                                  client->config->ssh1_argv,
                                  SSH2_GETOPT_ARGUMENTS,NULL);
            }
          if (option == -1)
            {
              /* Rest ones are the command and arguments. */
              if (client->config->ssh1_argc > ssh_optind)
                {
                  for (i = 0;
                       i < (client->config->ssh1_argc - ssh_optind); i++)
                    {
                      args[args_used] = ssh_xstrdup(client->config->
                                                    ssh1_argv[ssh_optind
                                                             + i]);
                      args_used++;
                        
                      if (args_alloced < args_used + 10)
                        args =
                          ssh_xrealloc(args,
                                       (args_alloced
                                        + 10)*sizeof(*args));
                    }
                }
              break;
            }

          switch(option)
            {
              /* Ignored. */
            case 'S':
            case 's':
            case 'F':
              continue;
              /* Strip argument. */ 
            case 'd':
              /* Options without arguments. */
            case 'a':
            case 'C':
            case 'v':
            case 'f':
            case 'h':
            case 'n':
            case 'P':
            case 'q':
            case 'k':
            case '8':
            case 'g':
            case 'V':
              ssh_dsprintf(&args[args_used], "-%c", option);
              args_used++;
              continue;
              /* Options with arguments. */
            case 'i':
            case 'o': /* XXX conf options are different in ssh2 and ssh1 */
            case 'l':
            case 'e':
            case 'p':
            case 'L':
            case 'R':
            case 'c': /* XXX ciphers are different in ssh2 and ssh1 */
              ssh_dsprintf(&args[args_used], "-%c", option);
              args_used++;
              args[args_used] = ssh_xstrdup(ssh_optarg);
              args_used++;                
              continue;
            }
        }

      args[args_used] = NULL;
      
      for (i = 0; args[i]; i++)
        SSH_TRACE(2, ("args[%d] = %s", i, args[i]));

      /* Use ssh1 to connect. */
      execve(client->config->ssh1_path, args, environ);
      ssh_fatal("Executing ssh1 in compatibility mode failed.");
    }
}

/* Takes a stream, and creates an SSH client for processing that
   connection.  This closes the stream and returns NULL (without
   calling the destroy function) if an error occurs. The random state
   is required to stay valid until the client has been destroyed.
   ``config'' must remain valid until the client is destroyed; it is
   not automatically freed.
     `stream'        the connection stream
     `config'        configuration data (not freed, must remain valid)
     `user_data'     data for the client user
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
                          void (*authenticated_notify)(const char *user,
                                                       void *context),
                          void *context)
{
  SshClient client;
  SshStream trans, auth;
  SshTransportParams params;

  /* Create parameters. */
  params = ssh_transport_create_params();
  if (!ssh_client_update_transport_params(config, params))
    {
      ssh_stream_destroy(stream);
      ssh_transport_destroy_params(params);
      return NULL;
    }

  /* Create the client object. */
  client = ssh_xcalloc(1, sizeof(*client));
  client->user_data = user_data;
  client->config = config;
  client->being_destroyed = FALSE;

  /* Create a transport layer protocol object. */
  ssh_debug("ssh_client_wrap: creating transport protocol");
  trans = ssh_transport_client_wrap(stream, random_state, 
                                    SSH2_PROTOCOL_VERSION_STRING,
                                    SSH_USERAUTH_SERVICE,
                                    params, server_host_name,
                                    ssh_client_key_check,
                                    (void *)client,
                                    (config->ssh1_path && config->ssh1compatibility) ?
                                      ssh_client_version_check : NULL,
                                    (void *)client);

  
  ssh_transport_get_compatibility_flags(trans, &client->compat_flags);

  /* Create the authentication methods array. */
  client->methods = ssh_client_authentication_initialize();
  
  /* Create an authentication protocol object. */
  ssh_debug("ssh_client_wrap: creating userauth protocol");
  auth = ssh_auth_client_wrap(trans, user, SSH_CONNECTION_SERVICE,
                              client->methods, (void *)client);
  
  /* Create the common part of client/client objects. */
  client->common = ssh_common_wrap(stream, auth, TRUE, config, random_state,
                                   server_host_name,
                                   disconnect, debug, authenticated_notify,
                                   context);

  if (client->common == NULL)
    {
      ssh_client_authentication_uninitialize(client->methods);
      ssh_xfree(client);
      return NULL;
    }
  
  return client;
}

/* Forcibly destroys the given client. */
  
void ssh_client_destroy(SshClient client)
{
  if(client->being_destroyed == FALSE)
    { 
      client->being_destroyed = TRUE;
      ssh_common_destroy(client->common);
      ssh_xfree(client->compat_flags);
      ssh_client_authentication_uninitialize(client->methods);
      memset(client, 'F', sizeof(*client));
      ssh_xfree(client);
    }
}

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
                              void *context)
{
  ssh_channel_start_session(client->common, stdio_stream, stderr_stream,
                            auto_close, is_subsystem, command, allocate_pty,
                            term, env, forward_x11, forward_agent,
                            completion, close_notify,
                            context);
}

#ifdef SSH_CHANNEL_TCPFWD

/* Requests forwarding of the given remote TCP/IP port.  If the completion
   procedure is non-NULL, it will be called when done. */

void ssh_client_remote_tcp_ip_forward(SshClient client,
                                      const char *address_to_bind,
                                      const char *port,
                                      const char *connect_to_host,
                                      const char *connect_to_port,
                                      void (*completion)(Boolean success,
                                                         void *context),
                                      void *context)
{
  ssh_channel_start_remote_tcp_forward(client->common, address_to_bind, port,
                                       connect_to_host, connect_to_port,
                                       completion, context);
}

/* Requests forwarding of the given local TCP/IP port.  If the completion
   procedure is non-NULL, it will be called when done. */

Boolean ssh_client_local_tcp_ip_forward(SshClient client,
                                        const char *address_to_bind,
                                        const char *port,
                                        const char *connect_to_host,
                                        const char *connect_to_port)
{
  return ssh_channel_start_local_tcp_forward(client->common, address_to_bind,
                                             port, connect_to_host,
                                             connect_to_port);
}

/* Opens a direct connection to the given TCP/IP port at the remote side.
   The originator values should be set to useful values and are passed
   to the other side.  ``stream'' will be used to transfer channel data. */

void ssh_client_open_remote_tcp_ip(SshClient client, SshStream stream,
                                   const char *connect_to_host,
                                   const char *connect_to_port,
                                   const char *originator_ip,
                                   const char *originator_port)
{
  ssh_channel_dtcp_open_to_remote(client->common, stream,
                                  connect_to_host, connect_to_port,
                                  originator_ip, originator_port);
}

#endif /* SSH_CHANNEL_TCPFWD */
