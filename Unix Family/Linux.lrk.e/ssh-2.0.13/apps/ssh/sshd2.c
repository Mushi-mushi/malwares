/*

  sshd2.c
  
  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

*/

#include "ssh2includes.h"
#include "sshunixptystream.h"
#include "sshtcp.h"
#include "sshsignals.h"
#include "sshunixfdstream.h"
#include "sshcrypt.h"
#include "sshbuffer.h"
#include "sshtimeouts.h"
#include "sshserver.h"
#include "sshconfig.h"
#include "sshcipherlist.h"
#include "sshuserfiles.h"
#include "sshunixeloop.h"
#include "sshmsgs.h"
#include "sigchld.h"
#include "sshgetopt.h"
#include "auths-common.h"
#include "sshencode.h"
#include "auths-passwd.h"
#include <syslog.h>

#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#include <syslog.h>
#ifdef NEED_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif /* NEED_SYS_SYSLOG_H */
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
#endif /* HAVE_LIBWRAP */

#ifdef HAVE_SIA
#include "sshsia.h"
#endif /* HAVE_SIA */

#if HAVE_SCO_ETC_SHADOW
#include <sys/types.h>
#include <sys/security.h>
#include <sys/audit.h>
#include <prot.h>
#endif /* HAVE_SCO_ETC_SHADOW */

#define SSH_DEBUG_MODULE "Sshd2"

/* Program name, without path. */
const char *av0;
extern int back;
typedef struct SshServerData
{
  SshConfig config;
  SshRandomState random_state;
  SshPrivateKey private_server_key;
  Boolean debug;
  SshTcpListener listener;
  int connections;
  SshUser user;
  Boolean ssh_fatal_called;
} *SshServerData;

typedef struct SshServerConnectionRec
{
  SshServerData shared;
  SshServer server;
} *SshServerConnection;

void server_disconnect(int reason, const char *msg, void *context)
{
  SshServerConnection c = context;

  switch(reason)
    {
    case SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_WARNING,
                    "Disallowed connect from denied host. '%s'",
                    msg);
      break;
    case SSH_DISCONNECT_PROTOCOL_ERROR:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_WARNING,
                    "Protocol error: '%s'", msg);
      break;
    case SSH_DISCONNECT_KEY_EXCHANGE_FAILED:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_WARNING, 
                    "Key exchange failed: '%s'", msg);
      break;
    case SSH_DISCONNECT_HOST_AUTHENTICATION_FAILED:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_WARNING,
                    "Host authentication failed: '%s'", msg);
      break;
    case SSH_DISCONNECT_MAC_ERROR:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_WARNING,
                    "MAC failed, disconnecting: '%s'", msg);
      break;
    case SSH_DISCONNECT_COMPRESSION_ERROR:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_WARNING,
                    "compression error, disconnecting: '%s'", msg);
      break;
    case SSH_DISCONNECT_SERVICE_NOT_AVAILABLE:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_WARNING,
                    "service not available: '%s'", msg);
      break;
    case SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_INFORMATIONAL,
                    "protocol version not supported: '%s'", msg);
      break;
    case SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_WARNING,
                    "host key not verifiable: '%s'", msg);
      break;
    case SSH_DISCONNECT_CONNECTION_LOST:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_INFORMATIONAL,
                    "connection lost: '%s'", msg);
      break;
    case SSH_DISCONNECT_BY_APPLICATION:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_INFORMATIONAL,
                    "disconnected by application: '%s'", msg);        
      break;
    case SSH_DISCONNECT_AUTHENTICATION_ERROR:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_WARNING,
                    "User authentication failed: '%s'",
                    msg);
      break;
    default:
      ssh_log_event(c->server->config->log_facility,
                    SSH_LOG_ERROR,
                    "Unknown reason code for disconnect. msg: '%s'",
                    msg);
      ssh_debug("Unknown reason code for disconnect. msg: '%s'", msg);
      break;
    }

  /* Destroy the server object. */
  ssh_server_destroy(c->server);
  memset(c, 'F', sizeof(*c));
  ssh_xfree(c);
}

void server_debug(int type, const char *msg, void *context)
{
  ssh_debug("server_debug: %s", msg);
}

#if 0
/* Create a private server key if configuration says us to do that
   (i.e. we'll be using RSA key exchange) */

SshPrivateKey generate_server_key(SshConfig config, SshRandomState rs)
{
  SshPrivateKey privkey;

  if (config->server_key_bits == 0)
    return NULL;
  
  if (ssh_private_key_generate(rs, 
                               &privkey,
                               config->server_key_type,
                               SSH_PKF_SIZE, config->server_key_bits,
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      ssh_fatal("Unable to generate %d - bit %s server key.", 
                config->server_key_bits,
                config->server_key_type);
    }

  return privkey;
}
#endif /* 0 */

/* Checks the remote version number, and execs a compatibility program as
   appropriate. */

void ssh_server_version_check(const char *version, void *context)
{
  SshServerConnection c = (SshServerConnection)context;
  char *args[100], *aa;
  char buf[200];
  int i, arg;
  extern char **environ;
  
  ssh_debug("Remote version: %s\n", version);
  
  if (strncmp(version, "SSH-1.", 6) == 0 &&
      strncmp(version, "SSH-1.99", 8) != 0 &&
      c->server->config->ssh1compatibility == TRUE &&
      c->server->config->ssh1_path != NULL &&
      c->server->config->ssh1_argv != NULL)
    {
      ssh_debug("Executing %s for ssh1 compatibility.",
                c->server->config->ssh1_path);
      
      arg = 0;
      args[arg++] = "sshd";
      args[arg++] = "-i";
      args[arg++] = "-V";
      snprintf(buf, sizeof(buf), "%s\n", version); /* add newline */
      args[arg++] = buf;
      for (i = 1; c->server->config->ssh1_argv[i]; i++)
        {
          if (arg >= sizeof(args)/sizeof(args[0]) - 2)
            ssh_fatal("Too many arguments for compatibility ssh1.");
          aa = c->server->config->ssh1_argv[i];
          if (strcmp(aa, "-f") == 0 ||
              strcmp(aa, "-b") == 0 ||
              strcmp(aa, "-g") == 0 ||
              strcmp(aa, "-h") == 0 ||
              strcmp(aa, "-k") == 0 ||
              strcmp(aa, "-p") == 0)
            {
              args[arg++] = aa;
              if (c->server->config->ssh1_argv[i + 1])
                args[arg++] = c->server->config->ssh1_argv[++i];
            }
          else
            if (strcmp(aa, "-d") == 0)
              {
                args[arg++] = aa;
                if (c->server->config->ssh1_argv[i + 1])
                  i++; /* Skip the level. */
              }
            else
              if (strcmp(aa, "-q") == 0 ||
                  strcmp(aa, "-i") == 0)
                args[arg++] = aa;
        }
      args[arg++] = NULL;

      /* Set the input file descriptor to be fd 0. */
      if (c->server->config->ssh1_fd != 0)
        {
          if (dup2(c->server->config->ssh1_fd, 0) < 0)
            ssh_fatal("Making ssh1 input fd 0 (dup2) failed: %s",
                      strerror(errno));
          if (dup2(c->server->config->ssh1_fd, 1) < 0)
            ssh_fatal("Making ssh1 input fd 1 (dup2) failed: %s",
                      strerror(errno));
          close(c->server->config->ssh1_fd);
        }
      
      /* Exec the ssh1 server. */
      execve(c->server->config->ssh1_path, args, environ);
      ssh_fatal("Executing ssh1 in compatibility mode failed.");
    }
}

/* This function will be used to see what authentications we can use
   for the user, and to provide a common place to put access
   control-information. */
char *auth_policy_proc(const char *user,
                       const char *service,
                       const char *client_ip,
                       const char *client_port,
                       const char *completed_authentications,
                       void *context)
{
  SshServer server = (SshServer)context;
  SshConfig config = server->config;
  SshUser uc = NULL;
  char *cp;
  
  SSH_DEBUG(2, ("user '%s' service '%s' client_ip '%s' client_port '%s' "
                "completed '%s'",
                user, service, client_ip, client_port,
                completed_authentications));

  /* Check whether user's login is allowed */
  /* XXX AllowUsers */
  if (ssh_server_auth_check_user(&uc, user, server->config))
    {
      /* failure */
      char *s = "login to account %.100s not allowed or account non-existent.";
      
      ssh_log_event(config->log_facility,
                    SSH_LOG_WARNING,
                    s,
                    user);
      SSH_TRACE(1, (s, user));
      /* Reject the login if the user is not allowed to log in. */
      return ssh_xstrdup("");
    }
  
  /* Check whether logins from remote host are allowed */
  if (ssh_server_auth_check_host(server->common))
    {
      char *s;
      s = "Connection from %.100s denied. Authentication as user " \
        "%.100s was attempted.";
      
      /* logins from remote host are not allowed. */
      ssh_log_event(server->config->log_facility, SSH_LOG_WARNING,
                    s, server->common->remote_host,
                    ssh_user_name(uc));
      SSH_TRACE(1, (s, server->common->remote_host, ssh_user_name(uc)));
      
      /* Reject the login if the user is not allowed to log in from
         specified host. */
      return ssh_xstrdup("");
    }


  /* Check, whether user has passed all required authentications*/
  if (completed_authentications != NULL &&
      strlen(completed_authentications) > 0)
    {
      SshDlList required = server->config->required_authentications;
      
      /* If some authentication method has been passed, and there is
         no list for required authentications, the user is
         authenticated. */
      if (!required)
        return NULL;
      
      /* Go trough the list to see if we find a match for every method
         needed. */
      ssh_dllist_rewind(required);

      do {
        char *current = NULL;
        
        if ((current = ssh_dllist_current(required)) == NULL)
          continue;

        if (strstr(completed_authentications, current) == NULL)
          goto construct;
        
      } while (ssh_dllist_fw(required, 1) == SSH_DLLIST_OK);  

      /* if all were found from completed_authentications, the user is
         authenticated.*/
      return NULL;
    }

  /* Otherwise, construct a list of the authentications that can continue.
     All supported authentication methods are included in the list. */
 construct:
  {
    SshDlList allowed, required;
    SshBuffer buffer;

    allowed = server->config->allowed_authentications;
    required = server->config->required_authentications;
      
    ssh_buffer_init(&buffer);
      
    if (allowed)
      {
        Boolean first = TRUE;
          
        ssh_dllist_rewind(allowed);
          
        do {
          char *current = NULL;
            
          if ((current = ssh_dllist_current(allowed)) == NULL)
            continue;
            
          if (strstr(completed_authentications, current) == NULL)
            {
              if (required)
                {
                  Boolean found = FALSE;
                    
                  ssh_dllist_rewind(required);
                    
                  do {
                    char *current_req = NULL;
                  
                    if ((current_req = ssh_dllist_current(required)) == NULL)
                      continue;
                  
                    if (strcmp(current, current_req) != 0)
                      {
                        found = TRUE;
                        break;
                      }
                  
                  
                  } while (ssh_dllist_fw(required, 1) == SSH_DLLIST_OK);

                  if (!found)
                    continue;
                }
                
              if (!first)
                {
                  ssh_buffer_append(&buffer, (unsigned char *)",", 1);
                }
                
              ssh_buffer_append(&buffer, (unsigned char *)current,
                                strlen(current));

              if (first)
                first = FALSE;
            }
            
        } while (ssh_dllist_fw(allowed, 1) == SSH_DLLIST_OK);  

        ssh_buffer_append(&buffer, (unsigned char *)"\0", 1);
      }
    else
      {    
        /* If publickey authentication is denied in the configuration
           file, deny it here too. */
        if (server->config->pubkey_authentication == FALSE )
          SSH_DEBUG(3, ("Public key authentication is denied."));
        else
          ssh_buffer_append(&buffer, (unsigned char *) SSH_AUTH_PUBKEY ",",
                            strlen(SSH_AUTH_PUBKEY ","));
              
        /* If password authentication is denied in the configuration
           file, deny it here too. */
        if (config->password_authentication == FALSE )
          SSH_DEBUG(3, ("Password authentication is denied."));
        else
          ssh_buffer_append(&buffer, (unsigned char *) SSH_AUTH_PASSWD ",\0",
                            strlen(SSH_AUTH_PASSWD ",") + 1);
          
      }
    cp = ssh_xstrdup(ssh_buffer_ptr(&buffer));
    ssh_buffer_uninit(&buffer);
  }
  
  SSH_DEBUG(2, ("output: %s", cp));

  return cp;
}

/* Forward declaration. */
void ssh_login_grace_time_exceeded(void *context);

/* This is called, when we have an authenticated user ready to continue. */

void client_authenticated(const char *user, void *context)
{
  SshServerConnection connection = (SshServerConnection) context;
  SshCommon common = connection->server->common;

  /* We unregister the (possible) grace time callback. */
  ssh_cancel_timeouts(ssh_login_grace_time_exceeded, SSH_ALL_CONTEXTS);
  if (back != 1)
  ssh_log_event(common->config->log_facility,
                SSH_LOG_NOTICE,
                "User %s, coming from %s, authenticated.",
                user, common->remote_host);
}


/* Callback to handle the closing of connections in the "mother"
   process */
void child_returned(pid_t pid, int status, void *context)
{
  SshServerData data = (SshServerData) context;

  SSH_DEBUG(2, ("Child with pid '%d' returned with status '%d'.", \
                pid, status));

  if (data->config->max_connections)
    {
      data->connections--;
      
      SSH_DEBUG(4, ("%d connections now open. (max %d)", \
                    data->connections, data->config->max_connections));
    }
}

/* This callback gets called, if LoginGraceTime is exceeded. */
void ssh_login_grace_time_exceeded(void *context)
{
  SshServerConnection connection = (SshServerConnection) context;
  char s[] = "LoginGraceTime exceeded.";
  
  ssh_log_event(connection->server->config->log_facility,
                SSH_LOG_WARNING,
                "%s", s);
  SSH_DEBUG(0, ("%s", s));

  /* We send disconnect, and exit. If LoginGraceTime is exceeded,
     there might be some kind of DoS-attack going on. */
  ssh_conn_send_disconnect(connection->server->common->conn,
                           SSH_DISCONNECT_HOST_AUTHENTICATION_FAILED,
                           "Login grace time exceeded.");

  ssh_server_destroy(connection->server);

  exit(0);
}

/* This callback is called, when a stream needs to be destroyed 
   with a small callback. */
void destroy_stream_callback(void *context)
{
  SshStream stream = (SshStream)context;

  ssh_stream_destroy(stream);
  return;
}

/* This function is called whenever we receive a new connection. */
void new_connection_callback(SshIpError error, SshStream stream,
                             void *context)
{
  SshServerData data = context;
  SshServerConnection c;
  pid_t ret;
  const char *s;
  char buf[256];
  
  if (error != SSH_IP_NEW_CONNECTION)
    {
      ssh_warning("new_connection_callback: unexpected error %d", (int)error);
      return;
    }

  if (!ssh_tcp_get_remote_address(stream, buf, sizeof(buf)))
    {
      SSH_DEBUG(2, ("failed to fetch remote ip address."));
      ssh_log_event(data->config->log_facility, SSH_LOG_WARNING,
                    "failed to fetch remote ip address.");
      snprintf(buf, sizeof(buf), "UNKNOWN");
    }
  
  ssh_log_event(data->config->log_facility, SSH_LOG_INFORMATIONAL,
                "connection from \"%s\"", buf);
  
  SSH_DEBUG(2, ("new_connection_callback"));

  /* check for MaxConnections */

  if (data->config->max_connections)
    {
      if (data->connections >= data->config->max_connections)
        {
          SshBuffer *buffer;

          char error[] = "Too many connections.";
          char lang[] = "en";
          
          buffer = ssh_buffer_allocate();
          
          /* Send disconnect, SSH_DISCONNECT_BY_APPLICATION */
          /* Construct the packet. */
          ssh_encode_buffer(buffer,
                            /* SSH_MSG_DISCONNECT */
                            SSH_FORMAT_CHAR,
                            (unsigned int) SSH_MSG_DISCONNECT,
                            /* uint32 reason code */
                            SSH_FORMAT_UINT32, (SshUInt32)
                            SSH_DISCONNECT_BY_APPLICATION,
                            /* string description */
                            SSH_FORMAT_UINT32_STR, error, strlen(error),
                            /* string language tag */
                            SSH_FORMAT_UINT32_STR, lang, strlen(lang),
                            SSH_FORMAT_END);

          ssh_stream_write(stream, ssh_buffer_ptr(buffer),
                           ssh_buffer_len(buffer));
          /* We destroy the stream with a little timeout in order
             to give some time to the protocol to send the disconnect
             message.  If the message can't be sent in this time window,
             it's obvious that we are under some kind of DoS attack
             and it's OK just to destroy the stream. */
          ssh_register_timeout(0L, 20000L, 
                               destroy_stream_callback, (void *)stream);

          ssh_log_event(data->config->log_facility, SSH_LOG_WARNING,
                        "Refusing connection from \"%s\". Too many " \
                        "open connections (max %d, now open %d).",
                        buf, data->config->max_connections,
                        data->connections);

          ssh_buffer_free(buffer);
          /* return from this callback. */
          return;
        }
    }

  /* Set socket to nodelay mode if configuration suggests this. */
  ssh_socket_set_nodelay(stream, data->config->no_delay);
  /* Set socket to keepalive mode if configuration suggests this. */
  ssh_socket_set_keepalive(stream, data->config->keep_alive);

  /* Fork to execute the new child, unless in debug mode. */
  if (data->debug)
    ret = 0;
  else
    ret = fork();
  if (ret == 0)
    {
      /* Child. */
      /* Destroy the listener. */
      if (data->listener)
        ssh_tcp_destroy_listener(data->listener);

      data->listener = NULL;
      
      /* Save the file descriptor.  It is only used if we exec ssh1 for
         compatibility mode. */
      data->config->ssh1_fd = ssh_stream_fd_get_readfd(stream);
      
#ifdef HAVE_LIBWRAP
      {
        struct request_info req;
        void *old_handler;
        
        old_handler = signal(SIGCHLD, SIG_DFL);
        /* XXX SIGALRM, SIGHUP */
        
        request_init(&req, RQ_DAEMON, av0, RQ_FILE,
                     ssh_stream_fd_get_readfd(stream), NULL);
        fromhost(&req); /* validate client host info */
        if (!hosts_access(&req))
          {
            ssh_warning("Denied connection from %s by tcp wrappers.",
                        eval_client(&req));
            ssh_log_event(data->config->log_facility, SSH_LOG_WARNING,
                          "Denied connection from %s by tcp wrappers.",
                          eval_client(&req));
            refuse(&req);/* If connection is not allowed, clean up and exit.*/
          }

        signal(SIGCHLD, old_handler);
    
      }
#endif /* HAVE_LIBWRAP */
  
      /* Create a context structure for the connection. */
      c = ssh_xcalloc(1, sizeof(*c));
      c->shared = data;
      SSH_TRACE(2, ("Wrapping stream with ssh_server_wrap..."));
      c->server = ssh_server_wrap(stream, data->config, data->random_state,
                                  data->private_server_key, server_disconnect,
                                  server_debug,
                                  (data->config->ssh1compatibility &&
                                   data->config->ssh1_path != NULL) ?
                                  ssh_server_version_check : NULL,
                                  auth_policy_proc,
                                  client_authenticated,
                                  (void *)c);
      SSH_TRACE(2, ("done."));
      if (data->config->login_grace_time > 0)
        ssh_register_timeout((long)data->config->login_grace_time, 0L,
                             ssh_login_grace_time_exceeded, c);
    }
  else
    {
      /* Parent */
      if (ret == -1)
        {
          s = "Forking a server for a new connection failed.";
          ssh_warning(s);
          ssh_log_event(data->config->log_facility, SSH_LOG_WARNING, s);
          ssh_stream_write(stream, (const unsigned char *)s, strlen(s));
          ssh_stream_write(stream, (const unsigned char *)"\r\n", 2);
        }
      ssh_stream_fd_mark_forked(stream);
      ssh_stream_destroy(stream);

      /* Stir the random state so that future connections get a
         different seed. */
      ssh_random_stir(data->random_state);

      /* Update the random seed file on disk. */
      ssh_randseed_update(data->user, data->random_state, data->config);

      if (data->config->max_connections)
        {
          data->connections++;

          SSH_DEBUG(4, ("Registering sigchld-handler for child '%d'.", \
                        ret));

          SSH_DEBUG(4, ("%d connections now open. (max %d)", \
                        data->connections, data->config->max_connections));
                        
          ssh_sigchld_register(ret, child_returned,
                               data);
        }
      
    }

  ssh_debug("new_connection_callback returning");
}

void server_ssh_debug(const char *msg, void *context)
{
  SshServerData data = (SshServerData)context;

  if (data->config && data->config->quiet_mode)
    return;

  if (data->debug)
    fprintf(stderr, "debug: %s\r\n", msg);
}

void server_ssh_warning(const char *msg, void *context)
{
  SshServerData data = (SshServerData)context; 

  if (data->config && data->config->quiet_mode)
    return;

  fprintf(stderr, "WARNING: %s\r\n", msg);
}

void server_ssh_fatal(const char *msg, void *context)
{
  SshServerData data = (SshServerData)context;
  data->ssh_fatal_called = TRUE;

  ssh_log_event(data->config->log_facility, SSH_LOG_ERROR, "FATAL ERROR: %s", 
                msg);

  fprintf(stderr, "FATAL: %s\r\n", msg);  
  exit(255);
}

/* Helper functions for server_ssh_log */
int ssh_log_severity(SshLogSeverity severity)
{
  switch(severity)
    {
    case SSH_LOG_INFORMATIONAL:
      return LOG_INFO;
    case SSH_LOG_NOTICE:
      return LOG_NOTICE;
    case SSH_LOG_WARNING:
      return LOG_WARNING;
    case SSH_LOG_ERROR:
      return LOG_ERR;
    case SSH_LOG_CRITICAL:
      return LOG_CRIT;
    }
  
  ssh_debug("ssh_log_severity: Unknown severity.");
  return -1;
}

int ssh_log_facility(SshLogFacility facility)
{
  switch (facility)
    {
    case SSH_LOGFACILITY_AUTH:
    case SSH_LOGFACILITY_SECURITY:
      return LOG_AUTH;
    case SSH_LOGFACILITY_DAEMON:
      return LOG_DAEMON;
    case SSH_LOGFACILITY_USER:
      return LOG_USER;
    case SSH_LOGFACILITY_MAIL:
      return LOG_MAIL;
    case SSH_LOGFACILITY_LOCAL0:
      return LOG_LOCAL0;
    case SSH_LOGFACILITY_LOCAL1:
      return LOG_LOCAL1;
    case SSH_LOGFACILITY_LOCAL2:
      return LOG_LOCAL2;
    case SSH_LOGFACILITY_LOCAL3:
      return LOG_LOCAL3;
    case SSH_LOGFACILITY_LOCAL4:
      return LOG_LOCAL4;
    case SSH_LOGFACILITY_LOCAL5:
      return LOG_LOCAL5;
    case SSH_LOGFACILITY_LOCAL6:
      return LOG_LOCAL6;
    case SSH_LOGFACILITY_LOCAL7:
      return LOG_LOCAL7;      
    }
  ssh_debug("ssh_log_facility: Unknown facility.");
  return -1;
}

/* This is the logging callback */

void server_ssh_log(SshLogFacility facility, SshLogSeverity
                    severity, const char *msg, void *context)
{
  SshServerData data = (SshServerData)context; 
  SshConfig config = data->config;
  int fac, sev;
  static int logopen = 0;
  static int logopt;
  static int logfac;

  if (! logopen)
    {
      logopt = LOG_PID;
#ifdef LOG_PERROR
      if (config->verbose_mode)
        logopt |= LOG_PERROR;
#endif /* LOG_PERROR */
      logfac = ssh_log_facility(config->log_facility);

      openlog(av0, logopt, logfac);
      logopen = 1;
    }

  /* Configuring for QuietMode and FascistLogging is an 'apparent
     user error', but if FascistLogging is enabled, we log
     everything. ssh_fatal()s are also logged.
     */
  if ((!config->quiet_mode || config->fascist_logging) || 
      data->ssh_fatal_called)
    {
      fac = ssh_log_facility(facility);
      sev = ssh_log_severity(severity);
      if( fac != -1 && sev != -1)
        {
          syslog(((fac != logfac) ? fac : 0) | sev, "%s", msg);
#ifndef LOG_PERROR
          /* Print it also to stderr. XXX */
#endif /* LOG_PERROR */
        }
    }
}

/* check whether parameter with options is correctly specified */

Boolean parameter_defined(const char param, int num, char **elements)
{
  int optidx;
  
  for (optidx = 1; optidx < num ; optidx++)
    {
      if (elements[optidx][0] == '-' || elements[optidx][0] == '+')
        if (elements[optidx][1] == param)
          if (elements[optidx + 1][0] != '-' && elements[optidx + 1][0] != '+')
            return TRUE;
    }
  
  return FALSE;
}

Boolean restart;

/* signal callback for SIGHUP*/

void sighup_handler(int signal, void *context)
{
  SshServerData data = (SshServerData) context;
  
  if (signal != SIGHUP)
    {
      SSH_DEBUG(0, ("Invalid signal received by SIGHUP-handler."));
      ssh_log_event(data->config->log_facility, SSH_LOG_WARNING,
                    "Invalid signal received by SIGHUP-handler.");
      return;
    }

  /* We cannot call fork() and exec() here directly, because we are in
     a signal handler. It seems that eventloop must be uninitialized
     for this to work. */
  restart = TRUE;

  ssh_event_loop_abort();
}

/*
 *
 *  SSH2 server main()
 *
 */

int main(int argc, char **argv)
{
  int i = 0;
  SshServerData data;
  SshUser user;
  char config_fn[1024];
  char pidfile[100];
  FILE *f;

  /* Save program name. */
  if (strchr(argv[0], '/'))
    av0 = strrchr(argv[0], '/') + 1;
  else
    av0 = argv[0];

  /* Initializations */
  restart = FALSE;
  
#if HAVE_SCO_ETC_SHADOW
  set_auth_parameters(argc, argv);
#endif /* HAVE_SCO_ETC_SHADOW */

#if HAVE_SIA
  initialize_sia(argc, argv);
#endif /* HAVE_SIA */

  data = ssh_xcalloc(1, sizeof(*data));
  user = ssh_user_initialize(NULL, TRUE);
  
  data->ssh_fatal_called = FALSE;

  data->connections = 0;
  
  /* Create config context. */
  data->config = ssh_server_create_config();

  /* Register debug, fatal, and warning callbacks. */
  ssh_debug_register_callbacks(server_ssh_fatal, server_ssh_warning,
                               server_ssh_debug, (void *)data);
  
  /* Register log callback */
  ssh_log_register_callback(server_ssh_log, (void *)data);

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
  else if ((argc >= 2) && (strcmp("-v", argv[1]) == 0))
    {
      ssh_debug_set_level_string("2");
      data->debug = TRUE;
    }

  ssh_event_loop_initialize();
  
  /* Save command line options for ssh1 compatibility code. */
  data->config->ssh1_argv = argv;
  data->config->ssh1_argc = argc;
  
  /* Save information about current user. */
  data->user = user;
  
  /* Prevent core dumps to avoid revealing sensitive information. */
  ssh_signals_prevent_core(TRUE, data);
  ssh_register_signal(SIGPIPE, NULL, NULL);

  /* register SIGHUP for restart callback */
  ssh_register_signal(SIGHUP, sighup_handler, data);
  
  /* Register SIGCHLD signal handler, to kill those darn zombies */

  ssh_sigchld_initialize();
  
  /* Read the standard server configuration file. if one wasn't specified
     on the commandline. */
  if (!parameter_defined('f', argc, argv))
    {
      char *conf_dir;

      if (ssh_user_uid(user) == 0 )
        {
          conf_dir = ssh_xstrdup(SSH_SERVER_DIR);
        }
      else
        {
          if ((conf_dir = ssh_userdir(user, data->config, TRUE)) == NULL)
            ssh_fatal("no ssh2 user directory");
        }

      snprintf(config_fn, sizeof(config_fn), "%s/%s",
               conf_dir, SSH_SERVER_CONFIG_FILE);
      if (!ssh_config_read_file(user, data->config, NULL, config_fn, NULL))
        ssh_warning("%s: Failed to read config file %s", av0, config_fn);
    }
  
  ssh_opterr = 0;

  /* Parse the command line parameters. */ 
  while (1)
    {
      int option;

      option = ssh_getopt(argc, argv, "d:vf:g:h:io:p:q", NULL);
      
      if (option == -1)
        {
          if (ssh_optind < argc)
            ssh_fatal("%s: Extra arguments in command line", av0);
          break;
        }

      /* Do we have a flag here ? */

      switch (option)
        {
          /* Debug mode */
        case 'd':
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -d parameter.", av0);
          data->config->verbose_mode = (ssh_optval != 0);
          ssh_debug_set_level_string(ssh_optarg);
          i++;
          break;

          /* Verbose mode (= -d 2) */
        case 'v':
          data->config->verbose_mode = TRUE;
          ssh_debug_set_level_string("2");
          break;

          /* An additional configuration file */
        case 'f':
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -f parameter.", av0);
          strncpy(config_fn, ssh_optarg, sizeof(config_fn));
          if (!ssh_config_read_file(user, 
                                    data->config, 
                                    NULL, 
                                    config_fn, 
                                    NULL))
            ssh_warning("%s: Failed to read config file %s", av0,
                        config_fn);
          i++;
          break;
          
          /* Specify the login grace period */
        case 'g':
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -g parameter.", av0);              
          data->config->login_grace_time = atoi(ssh_optarg);
          if (data->config->login_grace_time < 1)
            ssh_fatal("%s: Illegal login grace time %s seconds",
                      av0, ssh_optarg);
          i++;
          break;
              
          /* specify the host key file */
        case 'h':
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -h parameter.", av0);              

          ssh_xfree(data->config->host_key_file);
          data->config->host_key_file = ssh_xstrdup(ssh_optarg);
          ssh_xfree(data->config->public_host_key_file);
          snprintf(config_fn, sizeof(config_fn), "%s.pub", 
                   data->config->host_key_file);
          data->config->public_host_key_file = ssh_xstrdup(config_fn);
          i++;
          break;

          /* is inetd enabled ? */
        case 'i':
          data->config->inetd_mode = (ssh_optval != 0);
          break;
              
          /* Give one line of configuration data directly */
        case 'o':
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -o parameter.", av0);
          ssh_config_parse_line(data->config, ssh_optarg);            
          i++;
          break;
              
          /* Specify the port */
        case 'p':
          if (!ssh_optval)
            ssh_fatal("%s: Illegal -p parameter.", av0);              
              
          ssh_xfree(data->config->port);
          data->config->port = ssh_xstrdup(ssh_optarg);
          i++;
          break;

          /* Quiet mode */
        case 'q':
          data->config->quiet_mode = (ssh_optval != 0);
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

  data->debug = data->config->verbose_mode;
    
  /* load the host key */
  
  if (!ssh_server_load_host_key(data->config, 
                                &(data->config->private_host_key),
                                &(data->config->public_host_key_blob),
                                &(data->config->public_host_key_blob_len),
                                NULL))
    {
      ssh_fatal("Unable to load the host keys");
    }

  /* load the random seed */
  data->random_state = ssh_randseed_open(user, data->config);

#if 0
  /* generate the server key (if needed) */ 
  data->private_server_key = generate_server_key(data->config, 
                                                 data->random_state);
#endif /* 0 */

  /* Finalize the initialization. */
  ssh_config_init_finalize(data->config);

  ssh_debug("Becoming server.");
  
  /* Check if we are being called from inetd. */
  if (data->config->inetd_mode)
    {
      SshStream stream;

      ssh_log_event(data->config->log_facility,
                    SSH_LOG_WARNING,
                    "Starting daemon in inetd mode.");
      /* We are being called from inetd.  Take stdio to be the connection
         and proceed with the new connection. */
      stream = ssh_stream_fd_stdio();
      ssh_debug("processing stdio connection");
      new_connection_callback(SSH_IP_NEW_CONNECTION, stream, (void *)data);
      ssh_debug("got_connection returned");
    }
  else
    {
      /* Start as daemon. */

      ssh_debug("Creating listener");
      data->listener = ssh_tcp_make_listener(data->config->listen_address, 
                                             data->config->port, 
                                             new_connection_callback,
                                             (void *)data);
      if (data->listener == NULL)
        ssh_fatal("Creating listener failed: port %s probably already in use!",
                  data->config->port);
      ssh_debug("Listener created");

      ssh_log_event(data->config->log_facility,
                    SSH_LOG_WARNING,
                    "Listener created on port %s.",
                    data->config->port);
      
      /* If not debugging, fork into background. */
      if (!data->debug)
        {
#ifdef HAVE_DAEMON
          if (daemon(0, 0) < 0)
            ssh_fatal("daemon(): %.100s", strerror(errno));
#else /* HAVE_DAEMON */
#ifdef TIOCNOTTY
          int fd;
#endif /* TIOCNOTTY */
          /* Running as a daemon; fork to background. */
          if (fork() != 0)
            {
              /* Parent */
              exit(0);
            }
          
          /* Redirect stdin, stdout, and stderr to /dev/null. */
          freopen("/dev/null", "r", stdin);
          freopen("/dev/null", "w", stdout);
          freopen("/dev/null", "w", stderr);
            
          /* Disconnect from the controlling tty. */
#ifdef TIOCNOTTY
          fd = open("/dev/tty", O_RDWR|O_NOCTTY);
          if (fd >= 0)
            {
              (void)ioctl(fd, TIOCNOTTY, NULL);
              close(fd);
            }
#endif /* TIOCNOTTY */
#ifdef HAVE_SETSID
#ifdef ultrix
          setpgrp(0, 0);
#else /* ultrix */
          if (setsid() < 0)
            ssh_log_event(data->config->log_facility, SSH_LOG_NOTICE,
                          "setsid: %.100s", strerror(errno));
#endif /* ultrix */
#endif /* HAVE_SETSID */
#endif /* HAVE_DAEMON */
        }
    }

  /* Save our process id in the pid file. */
  snprintf(pidfile, sizeof(pidfile), "/var/run/sshd2_%s.pid",
           data->config->port);
  SSH_DEBUG(5, ("Trying to create pidfile %s", pidfile));
  f = fopen(pidfile, "w");
  if (f == NULL)
    {
      snprintf(pidfile, sizeof(pidfile), ETCDIR "/ssh2/sshd2_%s.pid",
               data->config->port);
      SSH_DEBUG(5, ("Trying to create pidfile %s", pidfile));
      f = fopen(pidfile, "w");
    }
  if (f != NULL)
    {
      SSH_DEBUG(5, ("Writing pidfile %s", pidfile));
      fprintf(f, "%ld\n", (long)getpid());
      fclose(f);
    }

  ssh_log_event(data->config->log_facility,
                SSH_LOG_WARNING,
                "Daemon is running.");
  
  ssh_debug("Running event loop");
  ssh_event_loop_run();
  
  ssh_signals_reset();
  
  ssh_debug("Exiting event loop");
  ssh_event_loop_uninitialize();

  if (data->listener)
    {
      remove(pidfile);
      
      if (restart)
        {
          int ret;
          
          ssh_tcp_destroy_listener(data->listener);
          data->listener = NULL;
          
          SSH_DEBUG(0, ("restarting..."));
          ssh_log_event(data->config->log_facility, SSH_LOG_WARNING,
                        "restarting...");
          
          ret = fork();
          
          if (ret == 0)
            {
              /* Child */
              execv(argv[0], argv);
              ssh_fatal("Restart (exec) failed on SIGHUP. "
                        "(error message \"%s\")",
                        strerror(errno));
            }
          else
            {
              /* Parent */
              if (ret == -1)
                {
                  /* Fork failed */
                  ssh_fatal("Restart (fork) failed on SIGHUP.");
                }
              else
                {
                  exit(0);
                }
            }
        }
    }
  
  return 0;
}
