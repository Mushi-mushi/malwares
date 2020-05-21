/*

Author: Tatu Ylonen <ylo@ssh.fi>
        Antti Huima <huima@ssh.fi>

Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
All rights reserved.

Interface to sockets.

*/

/*
 * $Id: sshtcp.c,v 1.8 1999/01/26 15:32:36 sjl Exp $
 * $Log: sshtcp.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshstream.h"
#include "sshtcp.h"
#include "sshbuffer.h"
#include "sshsocks.h"
#include "sshurl.h"

typedef enum
{
  CONNECT_STATE_HOST_LOOKUP,
  CONNECT_STATE_SOCKS_LOOKUP,
  CONNECT_STATE_HOST_CONNECT,
  CONNECT_STATE_SOCKS_CONNECT,
  CONNECT_STATE_SOCKS_SEND,
  CONNECT_STATE_SOCKS_RECEIVE
} ConnectState;

/* A context used to track SOCKS server connection status. */

typedef struct {
  ConnectState state;                   /* Status of the connect operation. */
  
  /* Information about the target host. */
  char *host_name;                      /* host to connect to. */
  char *host_addresses;                 /* addresses for the host to connect */
  const char *next_address;             /* next address to try */
  unsigned int host_port;               /* port to connect on the host */

  /* User callback. */
  SshTcpCallback user_callback;
  void *user_context;

  /* Miscellaneous request information. */
  unsigned int connection_attempts;
  unsigned int attempts_done;

  /* Information about the socks server. */
  char *socks_host;                     /* socks server host */
  char *socks_exceptions;               /* exceptions when to use socks */
  unsigned char *socks_addresses;       /* socks server addresses */
  const char *socks_next_address;       /* next address to try */
  unsigned int socks_port;              /* socks port */
  char *user_name;                      /* user requesting connection */
  SshBuffer *socks_buf;                 /* Socks buffer */

  /* An open stream to either the socks server or the final destination. */
  SshStream stream;
} *ConnectContext;


/* Connects to the given address/port, and makes a stream for it.
   The address to use is the first address from the list.  This
   function is defined in the machine-specific file. */
void ssh_socket_low_connect(const char *address_list, unsigned int port,
                            SshTcpCallback callback, void *context);

/* Forward declaration; defined later in this file. */
void ssh_socket_connect_step(ConnectContext);

/* Opens a TCP/IP connection to the given port on the host, and calls
   the callback when the connection is either ready or has failed.  The
   connection is attempted several times before giving up.  The callback
   will receive the resulting stream as an argument if the connection
   is successful.  Note that the callback may be called either during this
   call or some time later.

   The `host_name_or_address' argument may be a numeric IP address or a
   host name (domain name), in which case it is looked up from the name
   servers.
   
   This call supports SOCKS (version 4) for going out through firewalls.
   `socks_server_name' specifies the SOCKS host, and `socks_port' the port
   on which the SOCKS server listens.  If `socks_server_name' is NULL or
   empty, the connection will be made without SOCKS.  If `socks_port' is
   NULL or empty, the default SOCKS port (1080) will be used.

   `connection_attempts' specifies the number of times to attempt the
   connection before giving up.  (Some systems appear to spuriously fail
   connections without apparent reason, and retrying usually succeeds in
   those cases). */
void ssh_tcp_connect_with_socks(const char *host_name_or_address,
                                const char *port_or_service,
                                const char *socks_server_url,
                                unsigned int connection_attempts,
                                SshTcpCallback callback,
                                void *context)
{
  ConnectContext c;
  c = ssh_xmalloc(sizeof(*c));
  memset(c, 0, sizeof(*c));

  c->host_name = ssh_xstrdup(host_name_or_address);
  c->host_port = ssh_tcp_get_port_by_service(port_or_service, "tcp");
  c->host_addresses = NULL;
  c->next_address = NULL;

  c->user_callback = callback;
  c->user_context = context;
  
  c->connection_attempts = connection_attempts;
  c->attempts_done = 0;

  c->stream = NULL;

  c->state = CONNECT_STATE_HOST_LOOKUP;
  
  /* Initialize socks-related data. */
  if (socks_server_url != NULL && strcmp(socks_server_url, "") != 0)
    {
      char *scheme, *port;

      ssh_url_parse_and_decode(socks_server_url, &scheme,
                               &(c->socks_host), &port,
                               &(c->user_name), NULL, &(c->socks_exceptions));
      
      if (scheme != NULL && strcmp(scheme, "socks") != 0)
        ssh_warning("Socks server scheme not socks");
      if (scheme != NULL)
        ssh_xfree(scheme);

      if (c->socks_host != NULL)
        {
          c->socks_buf = ssh_buffer_allocate();
          c->socks_addresses = NULL;
          if (port == NULL || strcmp(port, "") == 0)
            c->socks_port = 1080; /* The standard socks port. */
          else
            c->socks_port = ssh_tcp_get_port_by_service(port, "tcp");
        }
      if (port != NULL)
        ssh_xfree(port);
    }
  else
    c->socks_host = NULL;

  /* Perform a step. */
  ssh_socket_connect_step(c);
}

/* Opens a connection to the specified host, and calls the callback
   when the connection has been established or has failed.  If
   connecting is successful, the callback will be called with error
   set to SSH_TCP_OK and an SshStream object for the connection passed
   in in the stream argument.  Otherwise, error will indicate the
   reason for the connection failing, and the stream will be NULL. */

void ssh_tcp_connect(const char *host_name_or_address,
                     const char *port_or_service,
                     SshTcpCallback callback,
                     void *context)
{
  ssh_tcp_connect_with_socks(host_name_or_address, port_or_service,
                             NULL, 1, callback, context);
}

/* Destroys the connection context. */

void ssh_socket_destroy_connect_context(ConnectContext c)
{
  if (c->host_name)
    ssh_xfree(c->host_name);
  if (c->host_addresses)
    ssh_xfree(c->host_addresses);
  if (c->socks_host)
    ssh_xfree(c->socks_host);
  if (c->socks_addresses)
    ssh_xfree(c->socks_addresses);
  if (c->user_name)
    ssh_xfree(c->user_name);
  if (c->socks_exceptions)
    ssh_xfree(c->socks_exceptions);
  if (c->socks_buf)
    ssh_buffer_free(c->socks_buf);
  if (c->stream)
    ssh_stream_destroy(c->stream);
  ssh_xfree(c);
}

/* Calls the user callback with the given error code and stream.
   Destroys the context. */

void ssh_socket_connect_final(ConnectContext c, SshStream stream,
                              SshIpError error)
{
  if (stream)
    {
      /* Prevent the stream from being freed when the context is freed. */
      c->stream = NULL;

      /* Clear our callback function.  We don't want to get notifications
         for this stream anymore. */
      ssh_stream_set_callback(stream, NULL, NULL);
    }

  /* Call the user callback. */
  (*c->user_callback)(error, stream, c->user_context);

  /* Destroy the context. */
  ssh_socket_destroy_connect_context(c);
}

/* Increments the attempt count, and returns true if we have used all of
   our attempts.  If that happens, this will call the user callback
   with the error, and destroy the context; the caller should just return. */

Boolean ssh_socket_failure(ConnectContext c, SshIpError error)
{
  c->attempts_done++;
  if (c->attempts_done < c->connection_attempts)
    return FALSE;

  ssh_socket_connect_final(c, NULL, error);
  return TRUE;
}

/* This callback is called when the host addresses have been looked up. */

void ssh_socket_connect_host_lookup_done(SshIpError error,
                                         const char *result,
                                         void *context)
{
  ConnectContext c = (ConnectContext)context;
  if (error != SSH_IP_OK)
    {
      if (ssh_socket_failure(c, error))
        return;

      /* Try again. */
      ssh_socket_connect_step(c);
      return;
    }

  /* Save the lookup result. */
  c->host_addresses = ssh_xstrdup(result);
  c->next_address = c->host_addresses;

  /* Enter the next state. */
  if (c->socks_host)
    c->state = CONNECT_STATE_SOCKS_LOOKUP;
  else
    c->state = CONNECT_STATE_HOST_CONNECT;
  ssh_socket_connect_step(c);
}

/* This callback is called when the socks server addresses have been looked
   up. */

void ssh_socket_connect_socks_lookup_done(SshIpError error,
                                          const char *result,
                                          void *context)
{
  ConnectContext c = (ConnectContext)context;
  if (error != SSH_IP_OK)
    {
      if (ssh_socket_failure(c, error))
        return;
      
      /* Try again. */
      ssh_socket_connect_step(c);
      return;
    }
  
  /* Save the lookup result. */
  c->socks_addresses = ssh_xstrdup(result);
  c->socks_next_address = (char *) c->socks_addresses;

  /* Enter the next state. */
  if (c->socks_exceptions)
    {
      char *next;
      next = strchr(c->host_addresses, ',');
      if (next)
        *next = '\0';
      if (ssh_inet_compare_netmask(c->socks_exceptions,
                                   c->host_addresses))
        c->state = CONNECT_STATE_HOST_CONNECT;
      else
        c->state = CONNECT_STATE_SOCKS_CONNECT;
      if (next)
        *next = ',';
    }
  else
    c->state = CONNECT_STATE_SOCKS_CONNECT;
  ssh_socket_connect_step(c);
}

/* This callback is called when the target host has been connected, or the
   attempt has failed.  This will either call user callback or retry. */

void DLLCALLCONV ssh_socket_host_connect_done(SshIpError error,
                                              SshStream stream,
                                              void *context)
{
  ConnectContext c = (ConnectContext)context;

  if (error != SSH_IP_OK)
    {
      /* Get next address. */
      if (strchr(c->next_address, ','))
        c->next_address = strchr(c->next_address, ',') + 1;
      else
        { /* At end of list; consider it as a failure. */
          if (ssh_socket_failure(c, error))
            return;
          c->next_address = c->host_addresses;
        }
      /* Try connecting again. */
      ssh_socket_low_connect(c->next_address, c->host_port,
                             ssh_socket_host_connect_done, (void *)c);
      return;
    }

  /* Successfully connected to the host.  Call the user callback and
     destroy context. */
  ssh_socket_connect_final(c, stream, SSH_IP_OK);
}

/* We are called whenever a notification is received from the stream.
   This shouldn't really happen unless read/write has failed, though
   I wouldn't count on it.  */

void ssh_socket_socks_notify(SshStreamNotification notification,
                             void *context)
{
  ConnectContext c = (ConnectContext)context;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
    case SSH_STREAM_CAN_OUTPUT:
      /* Just retry the processing for the current state. */
      ssh_socket_connect_step(c);
      break;

    case SSH_STREAM_DISCONNECTED:
      ssh_debug("ssh_socket_socks_notify: DISCONNECTED");
      ssh_stream_destroy(c->stream);
      c->stream = NULL;
      /* Count this as a failure. */
      if (ssh_socket_failure(c, SSH_IP_FAILURE))
        return;
      if (c->socks_host)
        {
          if (c->socks_exceptions)
            {
              char *next;
              next = strchr(c->host_addresses, ',');
              if (next)
                *next = '\0';
              if (ssh_inet_compare_netmask(c->socks_exceptions,
                                           c->host_addresses))
                c->state = CONNECT_STATE_HOST_CONNECT;
              else
                c->state = CONNECT_STATE_SOCKS_CONNECT;
              if (next)
                *next = ',';
            }
          else
            c->state = CONNECT_STATE_SOCKS_CONNECT;
        }
      else
        c->state = CONNECT_STATE_HOST_CONNECT;
      ssh_socket_connect_step(c);
      break;

    default:
      ssh_fatal("ssh_socket_socks_notify: unexpected notification %d",
                (int)notification);
    }
}

/* This callback is called when a connection to the socks server
   is complete or has failed.  This will either call the user callback,
   retry, or switch to the next state. */

void DLLCALLCONV ssh_socket_socks_connect_done(SshIpError error,
                                               SshStream stream,
                                               void *context)
{
  ConnectContext c = (ConnectContext)context;
  struct SocksInfoRec socksinfo;
  SocksError ret;
  char host_port[64];

  if (error != SSH_IP_OK)
    {
      /* Get next address. */
      if (strchr(c->socks_next_address, ','))
        c->socks_next_address = strchr(c->socks_next_address, ',') + 1;
      else
        { /* At end of list; consider it as a failure. */
          if (ssh_socket_failure(c, error))
            return;
          c->socks_next_address = (char *) c->socks_addresses;
        }
      /* Try connecting again. */
      ssh_socket_low_connect(c->socks_next_address, c->socks_port,
                             ssh_socket_socks_connect_done, (void *)c);
      return;
    }

  /* Save the stream. */
  c->stream = stream;

  /* Set the callback so that we'll get any required read/write
     notifications. */
  ssh_stream_set_callback(stream, ssh_socket_socks_notify, (void *)c);

  socksinfo.socks_version_number = 4;
  socksinfo.command_code = SSH_SOCKS_COMMAND_CODE_CONNECT;
  socksinfo.ip = (char *) c->next_address;
  snprintf(host_port, sizeof(host_port), "%d", c->host_port);
  socksinfo.port = host_port;
  socksinfo.username = c->user_name;

  ssh_buffer_clear(c->socks_buf);
  ret = ssh_socks_client_generate_open(c->socks_buf, &socksinfo);
  if (ret != SSH_SOCKS_SUCCESS)
    {
      if (ret == SSH_SOCKS_ERROR_INVALID_ARGUMENT)
        ssh_socket_connect_final(c, NULL, SSH_IP_NO_ADDRESS);
      else
        ssh_socket_connect_final(c, NULL, SSH_IP_FAILURE);
      return;
    }

  /* Switch to the next state. */
  c->state = CONNECT_STATE_SOCKS_SEND;
  ssh_socket_connect_step(c);
}

/* Performs the next step of connecting.  This may be a name server lookup,
   connecting to the socks server, conversation with the socks server, or
   retrying. */

void ssh_socket_connect_step(ConnectContext c)
{
  int len;
  
restart:
  switch (c->state)
    {
    case CONNECT_STATE_HOST_LOOKUP:
      ssh_tcp_get_host_addrs_by_name(c->host_name,
                                     ssh_socket_connect_host_lookup_done,
                                     (void *)c);
      break;
      
    case CONNECT_STATE_SOCKS_LOOKUP:
      ssh_tcp_get_host_addrs_by_name(c->socks_host,
                                     ssh_socket_connect_socks_lookup_done,
                                     (void *)c);
      break;
      
    case CONNECT_STATE_HOST_CONNECT:
      ssh_socket_low_connect(c->next_address, c->host_port,
                             ssh_socket_host_connect_done, (void *)c);
      break;
      
    case CONNECT_STATE_SOCKS_CONNECT:
      ssh_socket_low_connect(c->socks_next_address, c->socks_port,
                             ssh_socket_socks_connect_done, (void *)c);
      break;
      
    case CONNECT_STATE_SOCKS_SEND:
      /* Loop trying to send until either write fails or we are done. */
      do
        {
          len = ssh_stream_write(c->stream, ssh_buffer_ptr(c->socks_buf),
                                 ssh_buffer_len(c->socks_buf));
          if (len > 0)
            ssh_buffer_consume(c->socks_buf, len);
          if (ssh_buffer_len(c->socks_buf) == 0)
            {
              c->state = CONNECT_STATE_SOCKS_RECEIVE;
              goto restart;
            }
        }
      while (len > 0);
      break;

    case CONNECT_STATE_SOCKS_RECEIVE:
      /* Loop trying to read until read fails or we are done. */
      do
        {
          unsigned char *p;

          ssh_buffer_append_space(c->socks_buf, &p, 1);
          len = ssh_stream_read(c->stream, p, 1);
          if (len == 0)
            { /* Premature EOF received. */
              goto socks_fail;
            }
          if (len > 0)
            {
              SocksError err;

              err = ssh_socks_client_parse_reply(c->socks_buf, NULL);
              if (err == SSH_SOCKS_TRY_AGAIN)
                continue;
              if (err == SSH_SOCKS_SUCCESS)
                {
                  ssh_socket_connect_final(c, c->stream, SSH_IP_OK);
                  return;
                }
              /* Failure; try the next one. */
              goto socks_fail;
            }
          else
            {
              ssh_buffer_consume_end(c->socks_buf, 1);
            }
          continue;

        socks_fail:
          /* Connecting has failed.  Try the next host address. */
          ssh_stream_destroy(c->stream);
          c->stream = NULL;
          /* Get the next host address. */
          if (strchr(c->next_address, ','))
            c->next_address = strchr(c->next_address, ',') + 1;
          else
            {
              if (ssh_socket_failure(c, SSH_IP_FAILURE))
                return;
              c->next_address = c->host_addresses;
            }
          if (c->socks_exceptions)
            {
              char *next;
              next = strchr(c->host_addresses, ',');
              if (next)
                *next = '\0';
              if (ssh_inet_compare_netmask(c->socks_exceptions,
                                           c->host_addresses))
                c->state = CONNECT_STATE_HOST_CONNECT;
              else
                c->state = CONNECT_STATE_SOCKS_CONNECT;
              if (next)
                *next = ',';
            }
          else
            c->state = CONNECT_STATE_SOCKS_CONNECT;
          goto restart;
        }
      while (len > 0);
      break;
      
    default:
      ssh_fatal("ssh_socket_connect_step: bad state %d", (int)c->state);
    }
}

char *ssh_tcp_error_string(SshIpError error)
{
  switch (error)
    {
    case SSH_IP_OK:
     return "OK";
    case SSH_IP_NEW_CONNECTION:
     return "New TCP Connection";
    case SSH_IP_NO_ADDRESS:
     return "No address associated to the name";
    case SSH_IP_NO_NAME:
     return "No name associated to the address";
    case SSH_IP_UNREACHABLE:
     return "Destination Unreachable";
    case SSH_IP_REFUSED:
     return "Connection Refused";
    case SSH_IP_TIMEOUT:
     return "Connection Timed Out";
    case SSH_IP_FAILURE:
     return "TCP/IP Failure";
    default:
     return "Unknown Error";
    }
  /*NOTREACHED*/
}
