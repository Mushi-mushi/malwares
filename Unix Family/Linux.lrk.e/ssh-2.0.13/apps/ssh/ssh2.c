/*

  ssh2.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

*/

#include "ssh2includes.h"
#include "sshclient.h"
#include "sshunixptystream.h"
#include "sshtty.h"
#include "sshsignals.h"
#include "sshtimeouts.h"
#include "sshfilterstream.h"
#include "sshtcp.h"
#include "sshunixfdstream.h"
#include "sshcrypt.h"
#include "sshbuffer.h"
#include "sshmsgs.h"
#include "sshuser.h"
#include "sshconfig.h"
#include "sshuserfiles.h"
#include "sshunixeloop.h"
#include "sshstdiofilter.h"
#include "sshgetopt.h"
#include "sshmiscstring.h"

#define SSH_DEBUG_MODULE "Ssh2"

#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#include <syslog.h>
#ifdef NEED_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif /* NEED_SYS_SYSLOG_H */
int allow_severity = SSH_LOG_INFORMATIONAL;
int deny_severity = SSH_LOG_WARNING;
#endif /* HAVE_LIBWRAP */

/* Program name, without path. */
const char *av0;
SshRandomState random_state;

void client_disconnect(int reason, const char *msg, void *context)
{
  SshClientData data = (SshClientData)context;

  ssh_debug("client_disconnect: %s", msg);

  switch(reason)
    {
    case SSH_DISCONNECT_CONNECTION_LOST:
      ssh_warning("\r\nDisconnected; connection lost%s%s%s.",
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;
    case SSH_DISCONNECT_BY_APPLICATION:
      ssh_warning("\r\nDisconnected by application%s%s%s.",
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;
    case SSH_DISCONNECT_PROTOCOL_ERROR:
      ssh_warning("\r\nDisconnected; protocol error%s%s%s.",
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;
    case SSH_DISCONNECT_SERVICE_NOT_AVAILABLE:
      ssh_warning("\r\nDisconnected; service not available%s%s%s.",
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;
    case SSH_DISCONNECT_MAC_ERROR:
      ssh_warning("\r\nDisconnected; MAC error%s%s%s.",
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;
    case SSH_DISCONNECT_COMPRESSION_ERROR:
      ssh_warning("\r\nDisconnected; compression error%s%s%s%s%s%s.",
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;
    case SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT:
      ssh_warning("\r\nDisconnected; host not allowed to connect%s%s%s.",
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;
    case SSH_DISCONNECT_HOST_AUTHENTICATION_FAILED:
      ssh_warning("\r\nDisconnected; host authentication failed%s%s%s.",
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;
    case SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED:
      ssh_warning("\r\nDisconnected; protocol version not supported%s%s%s.",
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;
    case SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE:
      ssh_warning("\r\nDisconnected; host key not verifiable%s%s%s.",
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;
    case SSH_DISCONNECT_AUTHENTICATION_ERROR:
      ssh_warning("\r\nDisconnected; authentication error%s%s%s.",
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;
    case SSH_DISCONNECT_KEY_EXCHANGE_FAILED:
      ssh_warning("\r\nDisconnected; key exchange or algorith negotiation failed%s%s%s.",
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;
    default:
      ssh_warning("\r\nDisconnected; unknown disconnect code %d%s%s%s.",
                  reason,
                  ((msg && msg[0]) ? " (" : ""),
                  ((msg && msg[0]) ? msg  : ""),
                  ((msg && msg[0]) ? ")"  : ""));
      break;      
    }
  
  ssh_client_destroy(data->client);
  data->client = NULL;
}

void client_debug(int type, const char *msg, void *context)
{
  SshClientData data = (SshClientData)context;
  
  switch (type)
    {
    case SSH_DEBUG_DEBUG:
      if (data->debug)
        fprintf(stderr, "%s\r\n", msg);
      break;
      
    case SSH_DEBUG_DISPLAY:
      fprintf(stderr, "%s\r\n", msg);
      break;
      
    default:
      fprintf(stderr, "UNKNOWN DEBUG DATA TYPE %d: %s\r\n", type, msg);
      break;
    }
  clearerr(stderr); /*XXX*/
}

void client_ssh_debug(const char *msg, void *context)
{
  SshClientData data = (SshClientData)context;

  if (data->config->quiet_mode)
    return;

  if (data->debug)
    fprintf(stderr, "debug: %s\r\n", msg);
  clearerr(stderr); /*XXX*/
}

void client_ssh_warning(const char *msg, void *context)
{
  SshClientData data = (SshClientData)context;
  if (data->config->quiet_mode)
    return;

  fprintf(stderr, "%s\r\n", msg);
}

void client_ssh_fatal(const char *msg, void *context)
{
  fprintf(stderr, "FATAL: %s\r\n", msg);
  ssh_leave_non_blocking(-1);
  ssh_leave_raw_mode(-1);
  exit(255);
}

void session_close(void *context)
{
  SshClientData data = (void *)context;
  int ret = 0;
  SshCommon common = data->client->common;

  /* We save the number of channels, because if nm_channels is 0 we
     eventually destroy the common structure, and using
     common->num_channels later would be an error. */
  unsigned int num_channels = common->num_channels;
  
  ssh_debug("session_close");

  if (num_channels == 0)
    {      
      if (data->client)
        {
          ssh_debug("destroying client struct...");
          ssh_client_destroy(data->client);
          data->client = NULL;
        }
    }

  ssh_leave_non_blocking(-1);
  ssh_leave_raw_mode(-1);
  
  /* If there are forwarded channels open, we fork to background to wait
     for them to complete. */
  if (num_channels != 0)
    {
      ssh_debug("Forking... parent pid = %d", getpid());
      
      ret = fork();
      if (ret == -1)
        {
          ssh_warning("Fork failed.");
        }
      else if (ret != 0)
        {
          exit(0);
        }
      ssh_debug("num_channels now %d", common->num_channels);
      ssh_warning("ssh2[%d]: number of forwarded channels still "
                  "open, forked to background to wait for completion.",
                  getpid());

#ifdef HAVE_DAEMON
      if (daemon(0, 1) < 0)
        ssh_fatal("daemon(): %.100s", strerror(errno));
#else /* HAVE_DAEMON */
#ifdef HAVE_SETSID
#ifdef ultrix
      setpgrp(0, 0);
#else /* ultrix */
      if (setsid() < 0)
        ssh_warning("setsid: %.100s", strerror(errno));
#endif /* ultrix */
#endif /* HAVE_SETSID */
#endif /* HAVE_DAEMON*/
    }
}

int ssh_stream_sink_filter(SshBuffer *data,
                           size_t offset,
                           Boolean eof_received,
                           void *context)
{
  size_t received_len;

  received_len = ssh_buffer_len(data) - offset;

  ssh_buffer_consume(data, received_len);

  return SSH_FILTER_ACCEPT(0);
}

void ssh_stream_sink_filter_destroy(void *context)
{
  ssh_leave_raw_mode(-1);
  return;
}

void remote_forward_completion(Boolean success, void *context)
{
  SshForward fwd = (SshForward) context;
  
  if (!success)
    {
      ssh_warning("Remote forward %s:%s:%s failed. Operation was denied by " \
                  "the server.",
                  fwd->port, fwd->connect_to_host, fwd->connect_to_port);    
    }
  else
    {
      SSH_TRACE(2, ("Remote forward request %s:%s:%s succeeded.",
                    fwd->port, fwd->connect_to_host, fwd->connect_to_port));
    }
}

void client_authenticated(const char *user, void *context)
{
  int ret = 0;
  SshClientData data = (SshClientData)context;
  SshStream filtered_stdio_stream;
#ifdef SSH_CHANNEL_TCPFWD
  SshForward fwd;
#endif /* SSH_CHANNEL_TCPFWD */
  
  SSH_TRACE(2, ("client_authenticated"));

  /* If we are requested to go to background, do it now. */
  if (data->config->go_background)
    {
      ret = fork();
      if (ret == -1)
        {
          ssh_warning("Fork failed.");
        }
      else if (ret != 0)
        {
          exit(0);
        }
      data->allocate_pty = FALSE;
      data->config->dont_read_stdin = TRUE;
      
#ifdef HAVE_DAEMON
          if (daemon(0, 1) < 0)
            ssh_fatal("daemon(): %.100s", strerror(errno));
#else /* HAVE_DAEMON */
#ifdef HAVE_SETSID
#ifdef ultrix
      setpgrp(0, 0);
#else /* ultrix */
      if (setsid() < 0)
        ssh_warning("setsid: %.100s", strerror(errno));
#endif /* ultrix */
#endif /* HAVE_SETSID */
#endif /* HAVE_DAEMON*/
    }
  
#ifdef SSH_CHANNEL_TCPFWD  
  for (fwd = data->config->local_forwards; fwd; fwd = fwd->next)
    if (!ssh_client_local_tcp_ip_forward(data->client, fwd->local_addr,
                                         fwd->port, fwd->connect_to_host,
                                         fwd->connect_to_port))
      ssh_warning("Local TCP/IP forwarding for port %s failed.",
                  fwd->port);

  for (fwd = data->config->remote_forwards; fwd; fwd = fwd->next)
    ssh_client_remote_tcp_ip_forward(data->client, fwd->local_addr,
                                     fwd->port, fwd->connect_to_host,
                                     fwd->connect_to_port,
                                     remote_forward_completion,
                                     (void *) fwd);
#endif /* SSH_CHANNEL_TCPFWD */

  if (data->config->dont_read_stdin)
    {
      freopen("/dev/null", "r", stdin);
    }

  if (data->no_session_channel == FALSE)
    {
      /* XXX */
      if ((data->config->escape_char != NULL) && isatty(fileno(stdin)))
        filtered_stdio_stream = 
          ssh_stream_filter_create(ssh_stream_fd_stdio(), 
                                   1024, 
                                   ssh_stdio_output_filter,
                                   ssh_stdio_input_filter,
                                   ssh_stdio_filter_destroy,
                                   (void *)data->config->escape_char);
      else 
        filtered_stdio_stream = ssh_stream_fd_stdio();
    }
  else
    {
      filtered_stdio_stream = 
        ssh_stream_filter_create(ssh_stream_fd_stdio(), 
                                 1024, 
                                 ssh_stdio_output_filter,
                                 ssh_stdio_input_filter,
                                 ssh_stdio_filter_destroy,
                                 (void *)data->config->escape_char);
      filtered_stdio_stream = 
        ssh_stream_filter_create(filtered_stdio_stream, 
                                 1024, 
                                 ssh_stream_sink_filter,
                                 ssh_stream_sink_filter,
                                 ssh_stream_sink_filter_destroy,
                                 NULL);
      ssh_enter_raw_mode(-1);
    }

  ssh_client_start_session(data->client, 
                           ((data->no_session_channel == FALSE) ?
                            filtered_stdio_stream :
                            NULL),
                           ((data->no_session_channel == FALSE) ?
                            ssh_stream_fd_wrap2(-1, 2, FALSE):
                            NULL),
                           TRUE,
                           data->is_subsystem, 
                           data->command, data->allocate_pty,
                           data->term, (const char **)data->env,
                           data->forward_x11,
                           data->forward_agent,
                           NULL, session_close, (void *)data);
}

void connect_done(SshIpError error, SshStream stream, void *context)
{
  SshClientData data = (SshClientData)context;

  if (error != SSH_IP_OK)
    ssh_fatal("Connecting to %s failed: %s",
              data->config->host_to_connect, ssh_tcp_error_string(error));

  /* Set socket to nodelay mode if configuration suggests this. */
  ssh_socket_set_nodelay(stream, data->config->no_delay);
  /* Set socket to keepalive mode if configuration suggests this. */
  ssh_socket_set_keepalive(stream, data->config->keep_alive);
  
  /* Save the file descriptor for ssh1 compatibility code. */
  data->config->ssh1_fd = ssh_stream_fd_get_readfd(stream);
  
  data->client = ssh_client_wrap(stream, data->config,
                                 data->user_data, 
                                 data->config->host_to_connect, 
                                 data->config->login_as_user,
                                 data->random_state,
                                 client_disconnect, client_debug,
                                 client_authenticated, (void *)data);

  /* This is done, because in ssh_common_* functions we don't know anything
     about the SshClient* structures. no_session_channel's value must
     however be known there.*/
  data->client->common->no_session_channel = data->no_session_channel;
}

static void finalize_password_prompt(char **prompt, char *host, char *user)
{
  char *tmp;

  tmp = ssh_replace_in_string(*prompt, "%H", host);
  ssh_xfree(*prompt);
  *prompt = tmp;
  tmp = ssh_replace_in_string(*prompt, "%U", user);
  ssh_xfree(*prompt);
  *prompt = tmp;
}

void ssh2_version(const char *name)
{
  fprintf(stderr, "%s: ", name);
  fprintf(stderr, "SSH Version %s\n", SSH2_VERSION);
}

void ssh2_help(const char *name)
{
  ssh2_version(name);
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage: %s [options] host [command]\n", name);
  fprintf(stderr, "\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -l user     Log in using this user name.\n");
  fprintf(stderr, "  -n          Redirect input from /dev/null.\n");
  fprintf(stderr, "  +a          Enable authentication agent forwarding.\n");
  fprintf(stderr, "  -a          Disable authentication agent forwarding.\n");
  fprintf(stderr, "  +x          Enable X11 connection forwarding.\n");
  fprintf(stderr, "  -x          Disable X11 connection forwarding.\n");
  fprintf(stderr, "  -i file     Identity file for public key authentication\n");
  fprintf(stderr, "  -F file     Read an alternative configuration file.\n");
  fprintf(stderr, "  -t          Tty; allocate a tty even if command is given.\n");
  fprintf(stderr, "  -v          Verbose; display verbose debugging messages.  Equal to `-d 2'\n");
  fprintf(stderr, "  -d level    Set debug level.\n");
  fprintf(stderr, "  -V          Display version number only.\n");
  fprintf(stderr, "  -q          Quiet; don't display any warning messages.\n");
  fprintf(stderr, "  -f          Fork into background after authentication.\n");
  fprintf(stderr, "  -e char     Set escape character; ``none'' = disable (default: ~).\n");
  fprintf(stderr, "  -c cipher   Select encryption algorithm. Multiple -c options are \n");
  fprintf(stderr, "              allowed and a single -c flag can have only one cipher.\n");
  fprintf(stderr, "  -p port     Connect to this port.  Server must be on the same port.\n");
  fprintf(stderr, "  -P          Don't use priviledged source port.\n");
  fprintf(stderr, "  -S          Don't request a session channel. \n");
  fprintf(stderr, "  -L listen-port:host:port   Forward local port to remote address\n");
  fprintf(stderr, "  -R listen-port:host:port   Forward remote port to local address\n");
  fprintf(stderr, "              These cause ssh to listen for connections on a port, and\n");
  fprintf(stderr, "              forward them to the other side by connecting to host:port.\n");
  fprintf(stderr, "  +C          Enable compression.\n");
  fprintf(stderr, "  -C          Disable compression.\n");
  fprintf(stderr, "  -o 'option' Process the option as if it was read from a configuration file.\n");
  fprintf(stderr, "  -h          Display this help.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Command can be either:\n");
  fprintf(stderr, "  remote_command [arguments] ...    Run command in remote host.\n");
  fprintf(stderr, "  -s service                        Enable a service in remote server.\n");
  fprintf(stderr, "\n");
}

/* 
 *  This function digs out the first non-option parameter, ie. the host to 
 * connect to.
 */
char *ssh_get_host_name_from_command_line(int argc, char **argv)
{
  struct SshGetOptDataRec getopt_data;

  ssh_getopt_init_data(&getopt_data);
  getopt_data.reset = 1;
  getopt_data.allow_plus = 1;
  getopt_data.err = 0;

  while (ssh_getopt(argc, argv, SSH2_GETOPT_ARGUMENTS, &getopt_data) != -1)
    /*NOTHING*/;
  if ((argc <= getopt_data.ind) || (argv[getopt_data.ind] == NULL))
      return NULL;
  else
      return ssh_xstrdup(argv[getopt_data.ind]);
}


/*
 * 
 *  SSH2 main
 * 
 */
int main(int argc, char **argv)
{
  int i;
  char *host, *user, *userdir, *socks_server, *command;
  SshClientData data;
  SshUser tuser;
  char temp_s[1024];
  int have_c_arg;

#if 0
  sleep(30);
#endif

  have_c_arg = 0;
  /* Save program name. */
  if (strchr(argv[0], '/'))
    av0 = strrchr(argv[0], '/') + 1;
  else
    av0 = argv[0];
  
  /* Initializations. */
  tuser = ssh_user_initialize(NULL, FALSE);
  user = ssh_xstrdup(ssh_user_name(tuser));
  data = ssh_xcalloc(1, sizeof(*data));
  ssh_event_loop_initialize();
  
  /* Initialize config with built-in defaults. */
  data->config = ssh_client_create_config();
  data->is_subsystem = FALSE;
  data->no_session_channel = FALSE;
  data->exit_status = 0;
  
  /* Save arguments for ssh1 compatibility. */
  data->config->ssh1_argv = argv;
  data->config->ssh1_argc = argc;
  
  /* Register debug, fatal, and warning callbacks. */
  ssh_debug_register_callbacks(client_ssh_fatal, client_ssh_warning,
                               client_ssh_debug, (void *)data);
  /* If -d is the first flag, we set debug level here.  It is reset
     later, but something may be lost, if we leave it 'til that. */
  if ((argc >= 3) && (strcmp("-d", argv[1]) == 0))
    {
      ssh_debug_set_level_string(argv[2]);
      if (strcmp("0", argv[2]) != 0)
        data->debug = TRUE;
      else
        data->debug = FALSE;
    }
  else if (((argc >= 2) && ((strcmp("-v", argv[1]) == 0) || 
                            (strcmp("-h", argv[1]) == 0))) || (argc == 1))
    {
      if (argc <= 2)
        {
          ssh2_help(av0);
          exit(0);
        }
      else
        {
          ssh_debug_set_level_string("2");
          data->debug = TRUE;
        }
    }
  else if ((argc >= 2) && (strcmp("-V", argv[1]) == 0))
    {
      ssh2_version(av0);
      exit(0);
    }
  
  /* Prevent core dumps from revealing sensitive information. */
  ssh_signals_prevent_core(TRUE, data);
  ssh_register_signal(SIGPIPE, NULL, NULL);
  
  /* Try to read the global configuration file */
  ssh_config_read_file(tuser, data->config, NULL,
                       SSH_CLIENT_GLOBAL_CONFIG_FILE, NULL);

  host = NULL;
  
  host = ssh_get_host_name_from_command_line(argc, argv);

  if (host)
    {
      char *p;
      
      /* check whether form 'user@host' is used */
      if ((p = strchr(host, '@')) != NULL)
        {
          /* If so, cut string */
          *p = '\0';
          p++;
          data->config->host_to_connect = ssh_xstrdup(p);          
          ssh_xfree(data->config->login_as_user);
          data->config->login_as_user = ssh_xstrdup(host);
          user = data->config->login_as_user;
          /* make 'host' to point to the real hostname */
          host = p;
        }
      else
        {
          data->config->host_to_connect = ssh_xstrdup(host);          
        }
    }
  else
    {
      ssh_warning("You didn't specify a host name.\n");
      ssh2_help(av0);
      exit(1);
    }
  
  ssh_debug("hostname is '%s'.", data->config->host_to_connect);

  /* Try to read in the user configuration file. */

  userdir = ssh_userdir(tuser, data->config, TRUE);
  if (userdir == NULL)
    {
      ssh_fatal("Failed to create user ssh directory.");
    }
  
  snprintf(temp_s, sizeof (temp_s), "%s/%s",
           userdir, SSH_CLIENT_CONFIG_FILE);
  ssh_xfree(userdir);

  ssh_config_read_file(tuser, data->config, data->config->host_to_connect, 
                       temp_s, NULL);
  
  if (data->config->login_as_user)
    {
      user = data->config->login_as_user;
    }

  host = NULL;
  ssh_opterr = 0;
  ssh_optallowplus = 1;

  /* Interpret the command line parameters. */
  while (1)
    {
      int option;
      
      option = ssh_getopt(argc, argv, SSH2_GETOPT_ARGUMENTS, NULL);
      
      if ((option == -1) && (host == NULL))
          {
            host = argv[ssh_optind];
            if (!host)
              {
                ssh_warning("You didn't specify a host name.\n");
                ssh2_help(av0);
                exit(1);
              }
            ssh_optind++;
            SSH_DEBUG(3, ("remote host = \"%s\"", host));
            ssh_optreset = 1;
            option = ssh_getopt(argc, argv, SSH2_GETOPT_ARGUMENTS, NULL);
          }
      if (option == -1)
        {
          /* Rest ones are the command and arguments. */
          if (argc <= ssh_optind)
            {
              if (!(data->is_subsystem))
                {
                  command = NULL;
                }
            }
          else
            {
              if (data->is_subsystem)
                {
                  ssh_fatal("No command allowed with subsystem.");
                }
              command = ssh_xstrdup(argv[ssh_optind]);
              for (i = 1; i < (argc - ssh_optind); i++)
                {
                  char *newcommand;

                  newcommand = ssh_string_concat_3(command, 
                                                   " ", 
                                                   argv[ssh_optind + i]);
                  ssh_xfree(command);
                  command = newcommand;
                }
              SSH_DEBUG(3, ("remote command = \"%s\"", command));
              if (!(*command))
                {
                  /* Empty command string equals to no command at all. */
                  ssh_xfree(command);
                  command = NULL;
                }
            }
          break;
        }

      SSH_DEBUG(5, ("ssh_getopt(...) -> %d '%c'", option, option));
      SSH_DEBUG(5, (" ssh_opterr = %d", ssh_opterr));
      SSH_DEBUG(5, (" ssh_optind = %d", ssh_optind));
      SSH_DEBUG(5, (" ssh_optval = %d", ssh_optval));
      SSH_DEBUG(5, (" ssh_optopt = %d", ssh_optopt));
      SSH_DEBUG(5, (" ssh_optreset = %d", ssh_optreset));
      SSH_DEBUG(5, (" ssh_optarg = %p \"%s\"", 
                    ssh_optarg, ssh_optarg ? ssh_optarg : "NULL"));
      SSH_DEBUG(5, (" ssh_optmissarg = %d", ssh_optmissarg));
      SSH_DEBUG(5, (" ssh_optargnum = %d", ssh_optargnum));
      SSH_DEBUG(5, (" ssh_optargval = %d", ssh_optargval));

      switch (option)
        {
          /* Forward agent */
        case 'a':
          data->config->forward_agent = !(ssh_optval);
          break;

              /* add a cipher name to the list */
        case 'c':             
          {
            char *cname;

            if (!ssh_optval)
              ssh_fatal("%s: Illegal -c parameter.", av0);
              
            cname = ssh_cipher_get_native_name(ssh_optarg);

            if (cname == NULL)
              ssh_fatal("%s: Cipher %s is not supported.", av0,
                        ssh_optarg);
                
            if (!have_c_arg)
              {
                have_c_arg = 1;
                if (data->config->ciphers != NULL)
                  {
                    ssh_xfree(data->config->ciphers);
                    data->config->ciphers = NULL;
                  }
              }
            if (data->config->ciphers == NULL)
              {
                data->config->ciphers = ssh_xstrdup(cname);
              }
            else
              {                                 
                char *hlp = ssh_string_concat_3(data->config->ciphers, 
                                                ",", 
                                                cname);
                ssh_xfree(data->config->ciphers);
                data->config->ciphers = hlp;
              }
          }
          SSH_DEBUG(3, ("Cipherlist is \"%s\"", data->config->ciphers));
          i++;
          break;

            /* Compression */
        case 'C':
          data->config->compression = !(ssh_optval);
          break;

          /* Verbose mode */
        case 'v':
          data->config->verbose_mode = TRUE;
          ssh_debug_set_level_string("2");
          break;

              /* Debug level. */
        case 'd':
          if (!ssh_optval)
            ssh_fatal("%s: bad -d parameter.", av0);
          data->config->verbose_mode = (ssh_optval != 0);
          ssh_debug_set_level_string(ssh_optarg);
          i++;
          break;

              /* specify escape character */
        case 'e':
          if (ssh_optval)
            {
              ssh_xfree(data->config->escape_char);
              data->config->escape_char = NULL;
              break;
            }
              
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -e parameter.", av0);

          ssh_xfree(data->config->escape_char);       
          data->config->escape_char = ssh_xstrdup(ssh_optarg);
          i++;
          break;

              /* a "go background" flag */
        case 'f':
          data->config->go_background = (ssh_optval != 0);
          break;
              
          /* read in an alternative configuration file */
        case 'F':
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -F parameter.", av0);
              
          if (!ssh_config_read_file(tuser, data->config, 
                                    data->config->host_to_connect, 
                                    ssh_optarg, NULL))
            ssh_fatal("%s: Failed to read config file %s", av0, ssh_optarg);
          i++;
          break;

              /* specify the identity file */
        case 'i':
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -i parameter.", av0);
          ssh_xfree(data->config->identity_file);
          data->config->identity_file = ssh_xstrdup(ssh_optarg);
          i++;
          break;
              
              /* specify a login name */
        case 'l':
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -l parameter.", av0);

          ssh_xfree(data->config->login_as_user);
          data->config->login_as_user = ssh_xstrdup(ssh_optarg);
          user = data->config->login_as_user;
          i++;
          break;

          /* Specify a local forwarding */
        case 'L':
#ifdef SSH_CHANNEL_TCPFWD
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -L parameter.", av0);

          if (ssh_parse_forward(&(data->config->local_forwards), ssh_optarg))
            ssh_fatal("Bad local forward definition \"%s\"", ssh_optarg);
          i++;
#else /* SSH_CHANNEL_TCPFWD */
          ssh_fatal("TCP forwarding disabled.");
#endif /* SSH_CHANNEL_TCPFWD */
          break;

          /* don't read stdin ? */
        case 'n':
          data->config->dont_read_stdin = (ssh_optval != 0);
          break;
              
          /* Give one line of configuration data directly. */
        case 'o':
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -o parameter.", av0);
              
          ssh_config_parse_line(data->config, ssh_optarg);            
          i++;
          break;
              
          /* specify the login port */
        case 'p':
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -p parameter.", av0);
          ssh_xfree(data->config->port);
          data->config->port = ssh_xstrdup(ssh_optarg);
          i++;
          break;
              
          /* use privileged port. This option is only recognized for
             backwards compatibility with ssh1 */
        case 'P':
          break;

          /* quiet mode */
        case 'q':
          data->config->quiet_mode = (ssh_optval != 0);
          break;
              
          /* Is this a subsystem ? */
        case 's':
          if (data->is_subsystem)
            {
              ssh_fatal("%s: No multiple -s flags allowed.", av0);
            }
          data->is_subsystem = (ssh_optval != 0);
          command = ssh_xstrdup(ssh_optarg);
          break;

        case 'S':
          data->no_session_channel = (ssh_optval != 0);
          break;

              /* Force ptty allocation ? */
        case 't':
          data->config->force_ptty_allocation = (ssh_optval != 0);
          break;

          /* X11 forwarding */
        case 'x':
          data->config->forward_x11 = (ssh_optval == 0);
          break;

#ifdef SSH_CHANNEL_TCPFWD
          /* Specify a remote forwarding */
        case 'R':
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -R parameter.", av0);   

          if (ssh_parse_forward(&(data->config->remote_forwards), ssh_optarg))
            ssh_fatal("Bad remote forward definition \"%s\"", ssh_optarg);
          i++;
#else /* SSH_CHANNEL_TCPFWD */
          ssh_fatal("TCP forwarding disabled.");
#endif /* SSH_CHANNEL_TCPFWD */
          break;

        case 'h':
          ssh2_help(av0);
          exit(0);
          break;

          /* Specify 8-bit clean. This option is only recognized for
             backwards compatibility with ssh1, and is passed to
             rsh/rlogin if falling back to them. (ssh2 doesn't fall
             back to rsh; it wouldn't be secure (and it would be
             against the draft))*/
        case '8':
          break;

          /* Gateway ports?  If yes, remote hosts may connect to
             locally forwarded ports. */
        case 'g':
          data->config->gateway_ports = (ssh_optval == 0);
          break;

        case 'V':
          ssh2_version(av0);
          exit(0);
          break;
          
        default:
          if (ssh_optmissarg)
            {
              fprintf(stderr, "%s: option -%c needs an argument\n",
                      av0, ssh_optopt);
            }
          else
            {
              fprintf(stderr, "%s: unknown option -%c\n", av0, ssh_optopt);
            }
          exit(1);
        }
    }

  /* Initializations */
  
  data->config->login_as_user = user;
  host = data->config->host_to_connect;

  finalize_password_prompt(&data->config->password_prompt, host, user);

  data->random_state = ssh_randseed_open(tuser, data->config);

  data->user_data = tuser;
  data->command = command;
  data->allocate_pty = ((command == NULL) || 
                        data->config->force_ptty_allocation);
  data->forward_x11 = data->config->forward_x11;
  data->forward_agent = data->config->forward_agent;  
  
  if ((data->term = getenv("TERM")) == NULL)
    data->term = ssh_xstrdup("vt100");
  else
    data->term = ssh_xstrdup(data->term);    

  data->env = NULL;
  data->debug = data->config->verbose_mode;

  /* Finalize initialization. */
  ssh_config_init_finalize(data->config);

  /* Figure out the name of the socks server, if any.  It can specified
     at run time using the SSH_SOCKS_SERVER environment variable, or at
     compile time using the SOCKS_DEFAULT_SERVER define.  The environment
     variable overrides the compile-time define. */
  socks_server = getenv("SSH_SOCKS_SERVER");
#ifdef SOCKS_DEFAULT_SERVER
  if (!socks_server)
    socks_server = SOCKS_DEFAULT_SERVER;
#endif /* SOCKS_DEFAULT_SERVER */
  if (socks_server && strcmp(socks_server, "") == 0)
    socks_server = NULL;
  
  /* Connect to the remote host. */
  ssh_debug("connecting to %s...", host);
  ssh_tcp_connect_with_socks(host, data->config->port, 
                             socks_server, 5, 
                             connect_done, (void *)data);
  
  ssh_debug("entering event loop");
  ssh_event_loop_run();

  ssh_signals_reset();

  /* Update random seed file. */
  ssh_randseed_update(tuser, data->random_state, data->config);
  
  ssh_debug("uninitializing event loop");

  ssh_event_loop_uninitialize();

  ssh_leave_non_blocking(-1);
  ssh_leave_raw_mode(-1);

  ssh_user_free(tuser, FALSE);

  /* XXX free user, command, host ? */

  /* XXX should be done with static variable, and data should be freed */
  return data->exit_status;
}
