/*

sshchtcpfwd.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Code implementing TCP/IP forwarding channels for SSH2 servers and clients.

*/


#include "ssh2includes.h"
#include "sshtcp.h"
#include "sshencode.h"
#include "sshmsgs.h"
#include "sshconn.h"
#include "sshuser.h"
#include "sshcommon.h"

#ifdef SSH_CHANNEL_TCPFWD

#include "sshchtcpfwd.h"

#ifdef HAVE_LIBWRAP
#include <netdb.h>
#include <tcpd.h>
#include <syslog.h>
#include "sshunixfdstream.h"
#ifdef NEED_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif /* NEED_SYS_SYSLOG_H */
#endif /* HAVE_LIBWRAP */

#define SSH_DEBUG_MODULE "Ssh2ChannelTcpFwd"

#define SSH_TCPIP_WINDOW         30000
#define SSH_TCPIP_PACKET_SIZE     4096

typedef struct SshChannelTcpFwdConnectRec 
{
  SshRemoteTcpForward fwd;
  int channel_id;
  SshConnOpenCompletionProc completion;
  void *completion_context;
} *SshChannelTcpFwdConnect;

/***********************************************************************
 * Glue functions for creating/destroying channel type and session
 * contexts.
 ***********************************************************************/

/* This function is called once when a SshCommon object is created. */

void *ssh_channel_ftcp_create(SshCommon common)
{
  SshChannelTypeTcpForward ct;

  ct = ssh_xcalloc(1, sizeof(*ct));
  ct->common = common;
  return ct;
}

/* This function is called once when an SshCommon object is being
   destroyed.  This should destroy all remote forwarded TCP/IP
   channels and listeners and free the context. */

void ssh_channel_ftcp_destroy(void *context)
{
  SshChannelTypeTcpForward ct = (SshChannelTypeTcpForward)context;
  SshRemoteTcpForward remote_fwd, remote_next;

  /* Destroy all existing channels.
     XXX not implemented. */

  /* Free any remote forwarding records. */
  for (remote_fwd = ct->remote_forwards; remote_fwd;
       remote_fwd = remote_next)
    {
      remote_next = remote_fwd->next;
      if (remote_fwd->listener)
        ssh_tcp_destroy_listener(remote_fwd->listener);
      ssh_xfree(remote_fwd->address_to_bind);
      ssh_xfree(remote_fwd->port);
      ssh_xfree(remote_fwd->connect_to_host);
      ssh_xfree(remote_fwd->connect_to_port);
      memset(remote_fwd, 'F', sizeof(*remote_fwd));
      ssh_xfree(remote_fwd);
    }

  /* Destroy the channel type context. */
  memset(ct, 'F', sizeof(*ct));
  ssh_xfree(ct);
}

/* Returns the channel type context from the SshCommon object. */

SshChannelTypeTcpForward ssh_channel_ftcp_ct(SshCommon common)
{
  return (SshChannelTypeTcpForward)
    ssh_common_get_channel_type_context(common, "forwarded-tcpip");
}

/* This function is called once when a SshCommon object is created. */

void *ssh_channel_dtcp_create(SshCommon common)
{
  SshChannelTypeTcpDirect ct;

  ct = ssh_xcalloc(1, sizeof(*ct));
  ct->common = common;
  return ct;
}

/* This function is called once when an SshCommon object is being
   destroyed.  This should destroy all locally forwarded TCP/IP
   channels and listeners and free the context. */

void ssh_channel_dtcp_destroy(void *context)
{
  SshChannelTypeTcpDirect ct = (SshChannelTypeTcpDirect)context;
  SshLocalTcpForward local_fwd, local_next;

  /* Destroy all existing channels.
     XXX not implemented. */
  
  /* Free local forwarding records. */
  for (local_fwd = ct->local_forwards; local_fwd;
       local_fwd = local_next)
    {
      local_next = local_fwd->next;
      if (local_fwd->listener)
        ssh_tcp_destroy_listener(local_fwd->listener);
      ssh_xfree(local_fwd->connect_to_host);
      ssh_xfree(local_fwd->connect_to_port);
      memset(local_fwd, 'F', sizeof(*local_fwd));
      ssh_xfree(local_fwd);
    }

  /* Destroy the channel type context. */
  memset(ct, 'F', sizeof(*ct));
  ssh_xfree(ct);
}

/* Returns the channel type context from the SshCommon object. */

SshChannelTypeTcpDirect ssh_channel_dtcp_ct(SshCommon common)
{
  return (SshChannelTypeTcpDirect)
    ssh_common_get_channel_type_context(common, "direct-tcpip");
}

/***********************************************************************
 * Handling destruction of a TCP/IP channel.
 ***********************************************************************/

/* Function to be called when a forwarded TCP/IP connection is closed.
   This function is used for all types of TCP/IP channels. */

void ssh_channel_tcp_connection_destroy(void *context)
{
  SshCommon common = (SshCommon)context;

  /* Inform the common code that a channel has been destroyed. */
  ssh_common_destroy_channel(common);
}

/***********************************************************************
 * Processing a channel open request for a remote-forwarded TCP/IP
 * channel, and connecting to the destination address/port.
 ***********************************************************************/

/* Called when a connection to the real TCP/IP port (that the
   connection was forwarded to) has been established. */

void ssh_channel_ftcp_open_connected(SshIpError error,
                                     SshStream stream,
                                     void *context)
{
  SshChannelTcpFwdConnect c = (SshChannelTcpFwdConnect)context;

  if (error != SSH_IP_OK)
    {
      ssh_warning("Connecting to %s:%s failed (remote forward, port %s)",
                  c->fwd->connect_to_host, c->fwd->connect_to_port,
                  c->fwd->port);
      (*c->completion)(SSH_OPEN_CONNECT_FAILED,
                       NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                       c->completion_context);
      memset(c, 'F', sizeof(*c));
      ssh_xfree(c);
      return;
    }

  /* Record that we now have a new channel. */
  ssh_common_new_channel(c->fwd->common);
  
  /* Call the completion procedure to indicate that we are done. */
  (*c->completion)(SSH_OPEN_OK,
                   stream, TRUE, TRUE, SSH_TCPIP_WINDOW, NULL, 0,
                   NULL, ssh_channel_tcp_connection_destroy,
                   (void *)c->fwd->common, c->completion_context);
  memset(c, 'F', sizeof(*c));
  ssh_xfree(c);
}

/* Processes an open request for a remote-forwarded TCP/IP channel. */

void ssh_channel_ftcp_open_request(const char *type, int channel_id,
                                   const unsigned char *data, size_t len,
                                   SshConnOpenCompletionProc completion,
                                   void *completion_context, void *context)
{
  SshCommon common = (SshCommon)context;
  SshUInt32 port, originator_port;
  char *address_to_bind, *originator_ip;
  char port_string[20];
  SshRemoteTcpForward fwd;
  SshChannelTcpFwdConnect c;
  SshChannelTypeTcpForward ct;

  SSH_DEBUG(5, ("open request for remote forwarded TCP/IP channel"));

  ct = ssh_channel_ftcp_ct(common);

  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR, &address_to_bind, NULL,
                       SSH_FORMAT_UINT32, &port, 
                       SSH_FORMAT_UINT32_STR, &originator_ip, NULL,
                       SSH_FORMAT_UINT32, &originator_port,
                       SSH_FORMAT_END) != len)
    {
      /* XXX should disconnect? */
      SSH_DEBUG(0, ("bad data"));
      (*completion)(SSH_OPEN_RESOURCE_SHORTAGE,
                    NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                    completion_context);
      return;
    }

  snprintf(port_string, sizeof(port_string), "%ld", (long) port);

  ssh_debug("Received remote TCP/IP forward connect for port %s from %s:%ld",
            port_string, originator_ip, (long)originator_port);
  
  for (fwd = ct->remote_forwards; fwd; fwd = fwd->next)
    if (strcmp(fwd->address_to_bind, address_to_bind) == 0 &&
        strcmp(fwd->port, port_string) == 0)
      {
        c = ssh_xcalloc(1, sizeof(*c));
        c->fwd = fwd;
        c->channel_id = channel_id;
        c->completion = completion;
        c->completion_context = completion_context;

        ssh_tcp_connect_with_socks(fwd->connect_to_host, fwd->connect_to_port,
                           NULL, 1, ssh_channel_ftcp_open_connected,
                           (void *)c);

        ssh_xfree(address_to_bind);
        ssh_xfree(originator_ip);
        return;
      }

  ssh_warning("Received remote TCP/IP connect for non-forwarded port %s from %s:%ld",
              port_string, originator_ip, (long)originator_port);

  ssh_xfree(address_to_bind);
  ssh_xfree(originator_ip);
  
  (*completion)(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                completion_context);
}

/***********************************************************************
 * Processing a channel open request for a direct tcp/ip connection
 * to some port.  This is typically used for local forwards.
 ***********************************************************************/

typedef struct {
  SshCommon common;
  int channel_id;
  SshConnOpenCompletionProc completion;
  void *completion_context;
} *SshDirectTcp;

/* Called when connecting to the real destination port is complete. */

void ssh_channel_dtcp_connected(SshIpError error,
                                SshStream stream, void *context)
{
  SshDirectTcp tcp = (SshDirectTcp)context;

  SSH_DEBUG(5, ("direct connected: %d", (int)error));

  /* Check result. */
  if (error != SSH_IP_OK)
    {
      /* Connection failed. */
      (*tcp->completion)(SSH_OPEN_CONNECT_FAILED,
                         NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                         tcp->completion_context);
      memset(tcp, 'F', sizeof(*tcp));
      ssh_xfree(tcp);
      return;
    }

  /* Record that we have a new channel. */
  ssh_common_new_channel(tcp->common);
  
  /* Connection was successful.  Establish the channel. */
  (*tcp->completion)(SSH_OPEN_OK,
                     stream, TRUE, TRUE, SSH_TCPIP_WINDOW, NULL, 0,
                     NULL, ssh_channel_tcp_connection_destroy,
                     (void *)tcp->common, tcp->completion_context);
  memset(tcp, 'F', sizeof(*tcp));
  ssh_xfree(tcp);
}

/* Processes an open request for a TCP/IP forwarding to given address. */

void ssh_channel_dtcp_open_request(const char *type, int channel_id,
                                   const unsigned char *data, size_t len,
                                   SshConnOpenCompletionProc completion,
                                   void *completion_context, void *context)
{
  SshCommon common = (SshCommon)context;
  char *connect_to_host, connect_to_port[20], *originator_ip;
  SshUInt32 port, originator_port;
  SshDirectTcp tcp;

  SSH_DEBUG(5, ("direct TCP/IP channel open request"));
  
  /* Parse packet data. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR, &connect_to_host, NULL,
                       SSH_FORMAT_UINT32, &port,
                       SSH_FORMAT_UINT32_STR, &originator_ip, NULL,
                       SSH_FORMAT_UINT32, &originator_port,
                       SSH_FORMAT_END) != len)
    {
      /* XXX disconnect? */
      SSH_DEBUG(0, ("bad data"));
      (*completion)(SSH_OPEN_RESOURCE_SHORTAGE,
                    NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                    completion_context);
      return;
    }

  /* We do not currently allow direct connections from server to client. */
  if (common->client)
    {
      ssh_warning("Direct TCP/IP connection request from server "
                  "to %s:%ld denied.",
                  connect_to_host, (long)port);
      /* Free dynamically allocated data. */
      ssh_xfree(originator_ip);
      ssh_xfree(connect_to_host);
      (*completion)(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                    NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                    completion_context);
      return;
    }


  /* Convert port number to string. */
  snprintf(connect_to_port, sizeof(connect_to_port), "%ld", (long) port);

  ssh_debug("Direct TCP/IP connect to %s:%s from %s:%ld",
            connect_to_host, connect_to_port, originator_ip,
            (long)originator_port);
  
  /* Save data for callback. */
  tcp = ssh_xcalloc(1, sizeof(*tcp));
  tcp->common = common;
  tcp->channel_id = channel_id;
  tcp->completion = completion;
  tcp->completion_context = completion_context;

  /* Connect to the given host/port. */
  ssh_tcp_connect_with_socks(connect_to_host, connect_to_port, 
                             NULL, 1, ssh_channel_dtcp_connected, 
                             (void *)tcp);

  /* Free dynamically allocated data. */
  ssh_xfree(originator_ip);
  ssh_xfree(connect_to_host);
}

/***********************************************************************
 * Processing an incoming connection to a remotely forwarded socket.
 ***********************************************************************/

/* This function is called whenever a connection is received at a remotely
   forwarded socket.  This sends a channel open request to the other
   side. */

void ssh_channel_ftcp_incoming_connection(SshIpError error, SshStream stream,
                                          void *context)
{
  SshRemoteTcpForward fwd = (SshRemoteTcpForward)context;
  char ip[20], port[20];
  SshBuffer buffer;

  SSH_DEBUG(5, ("connection to forwarded TCP/IP port"));
  
  /* We should only receive new connection notifications. */
  if (error != SSH_IP_NEW_CONNECTION)
    ssh_fatal("ssh_channel_ftcp_incoming_connection: error %d", (int)error);

  /* Get remote ip address and port. */
  if (!ssh_tcp_get_remote_address(stream, ip, sizeof(ip)))
    strcpy(ip, "UNKNOWN");
  if (!ssh_tcp_get_remote_port(stream, port, sizeof(port)))
    strcpy(port, "UNKNOWN");

  SSH_TRACE(0, ("Connection to forwarded port %s from %s:%s",
                fwd->port, ip, port));
  ssh_log_event(fwd->common->config->log_facility,
                SSH_LOG_INFORMATIONAL,
                "Connection to forwarded port %s from %s:%s",
                fwd->port, fwd->common->remote_host, port);

  /* XXXXXXXX */
#ifdef HAVE_LIBWRAP
  {
    struct request_info req;
    struct servent *serv;
    char fwdportname[32];
    void *old_handler;
    
    old_handler = signal(SIGCHLD, SIG_DFL);

    /* try to find port's name in /etc/services */
    serv = getservbyport(atoi(fwd->port), "tcp");
    if (serv == NULL)
      {
        /* not found (or faulty getservbyport) -
           use the number as a name */
        snprintf(fwdportname, sizeof(fwdportname), "sshdfwd-%s", fwd->port);
      }
    else
      {
        snprintf(fwdportname, sizeof(fwdportname), "sshdfwd-%.20s",
                 serv->s_name);
      }
    /* fill req struct with port name and fd number */
    request_init(&req, RQ_DAEMON, fwdportname,
                 RQ_FILE, ssh_stream_fd_get_readfd(stream), NULL);
    fromhost(&req);
    if (!hosts_access(&req))
      {
        ssh_conn_send_debug(fwd->common->conn, TRUE,
                            "Fwd connection from %.500s to local port " \
                            "%s refused by tcp_wrappers.",
                            eval_client(&req), fwdportname);
        ssh_stream_destroy(stream);
        signal(SIGCHLD, old_handler);
    
        return;
      }
    signal(SIGCHLD, old_handler);
        
    ssh_log_event(fwd->common->config->log_facility, SSH_LOG_INFORMATIONAL,
                  "Remote fwd connect from %.500s to local port %s",
                  eval_client(&req), fwdportname);
  }
#endif /* HAVE_LIBWRAP */

  /* Register that we have an open channel. */
  ssh_common_new_channel(fwd->common);
  
  /* Send a request to open a channel and connect it to the given port. */
  ssh_buffer_init(&buffer);
  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_UINT32_STR,
                    fwd->address_to_bind, strlen(fwd->address_to_bind),
                    SSH_FORMAT_UINT32, (SshUInt32) atol(fwd->port),
                    SSH_FORMAT_UINT32_STR, ip, strlen(ip),
                    SSH_FORMAT_UINT32, (SshUInt32) atol(port),
                    SSH_FORMAT_END);
  ssh_conn_send_channel_open(fwd->common->conn, "forwarded-tcpip",
                             stream, TRUE, FALSE, SSH_TCPIP_WINDOW,
                             SSH_TCPIP_PACKET_SIZE,
                             ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer),
                             NULL,
                             ssh_channel_tcp_connection_destroy,
                             (void *)fwd->common, NULL, NULL);
  ssh_buffer_uninit(&buffer);
}  

/***********************************************************************
 * Processes a request to set up TCP/IP forwarding.  This is typically
 * used in the server.
 ***********************************************************************/

/* Processes a received request to set up remote TCP/IP forwarding. */

Boolean ssh_channel_remote_tcp_forward_request(const char *type,
                                               const unsigned char *data,
                                               size_t len,
                                               void *context)
{
  SshCommon common = (SshCommon)context;
  char *address_to_bind;
  SshUInt32 port;
  char port_string[20];
  SshRemoteTcpForward fwd;
  SshChannelTypeTcpForward ct;

  SSH_DEBUG(5, ("remote TCP/IP forwarding request received"));
  ssh_log_event(common->config->log_facility,
                SSH_LOG_INFORMATIONAL,
                "Remote TCP/IP forwarding request received from host \"%s\", "\
                "by authenticated user \"%s\".",
                common->remote_host,
                ssh_user_name(common->user_data));
  
  ct = ssh_channel_ftcp_ct(common);
  
  /* Don't allow a server to send remote forwarding requests to the client. */
  if (common->client)
    {
      ssh_warning("Remote TCP/IP forwarding request from server denied.");
      return FALSE;
    }
  
  /* Parse the request. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR, &address_to_bind, NULL,
                       SSH_FORMAT_UINT32, &port,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG(0, ("bad data"));
      return FALSE;
    }

  /* Convert port number to a string. */
  snprintf(port_string, sizeof(port_string), "%ld", (unsigned long) port);

  /* If user is not logged in as a privileged user, don't allow
     forwarding of privileged ports. */
  if (port < 1024)
    {
      if (ssh_user_uid(common->user_data))
        {
          SSH_TRACE(2, ("User \"%s\" not root, tried to forward " \
                        "privileged port %ld.",
                        ssh_user_name(common->user_data),
                        (unsigned long) port));
          ssh_log_event(common->config->log_facility,
                        SSH_LOG_WARNING,
                        "User \"%s\" not root, tried to forward " \
                        "privileged port %ld.",
                        ssh_user_name(common->user_data),
                        (unsigned long) port);
          return FALSE;
        }
      else
        {
          ssh_log_event(common->config->log_facility,
                        SSH_LOG_NOTICE,
                        "Privileged user \"%s\" forwarding a privileged port.",
                        ssh_user_name(common->user_data));
        }
    }

  if (port >= 65536)
    {
      SSH_TRACE(2, ("User \"%s\" tried to forward " \
                    "port above 65535 (%ld).",
                    ssh_user_name(common->user_data), (unsigned long) port));
      ssh_log_event(common->config->log_facility,
                    SSH_LOG_WARNING,
                    "User \"%s\" tried to forward " \
                    "port above 65535 (%ld).",
                    ssh_user_name(common->user_data), (unsigned long) port);
      return FALSE;
    }
  
      
  /* Create a socket listener. */
  fwd = ssh_xcalloc(1, sizeof(*fwd));
  fwd->listener = ssh_tcp_make_listener(address_to_bind, port_string,
                                        ssh_channel_ftcp_incoming_connection,
                                        (void *)fwd);
  if (fwd->listener == NULL)
    {
      ssh_debug("Creating remote listener for %s:%s failed.",
                address_to_bind, port_string);
      ssh_log_event(common->config->log_facility,
                    SSH_LOG_NOTICE,
                    "Creating remote listener for %s:%s failed.",
                    address_to_bind, port_string);
      
      ssh_xfree(address_to_bind);
      ssh_xfree(fwd);
      return FALSE;
    }

  /* Fill the remaining fields. */
  fwd->common = common;
  fwd->address_to_bind = address_to_bind;
  fwd->port = ssh_xstrdup(port_string);
  fwd->connect_to_host = NULL;
  fwd->connect_to_port = NULL;

  /* Add to list of forwardings. */
  fwd->next = ct->remote_forwards;
  ct->remote_forwards = fwd;

  ssh_log_event(common->config->log_facility,
                SSH_LOG_INFORMATIONAL,
                "Port %ld set up for remote forwarding.",
                (unsigned long) port);
  
  return TRUE;
}  

/* Processes a received request to cancel remote TCP/IP forwarding. */

Boolean ssh_channel_tcp_forward_cancel(const char *type,
                                       const unsigned char *data,
                                       size_t len,
                                       void *context)
{
  SshCommon common = (SshCommon)context;
  char *address_to_bind;
  SshUInt32 port;
  char port_string[20];
  SshRemoteTcpForward fwd, *fwdp;
  SshChannelTypeTcpForward ct;

  SSH_DEBUG(5, ("remote TCP/IP cancel request received"));

  ct = ssh_channel_ftcp_ct(common);
  
  /* Don't allow a server to send remote forwarding requests to the client. */
  if (common->client)
    {
      ssh_warning("Remote TCP/IP forwarding cancel from server denied.");
      return FALSE;
    }
  
  /* Parse the request. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR, &address_to_bind, NULL,
                       SSH_FORMAT_UINT32, &port,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG(0, ("bad data"));
      return FALSE;
    }

  /* Convert port number to a string. */
  snprintf(port_string, sizeof(port_string), "%ld", (unsigned long) port);

  for (fwdp = &ct->remote_forwards; *fwdp; fwdp = &fwd->next)
    {
      fwd = *fwdp;
      if (strcmp(port_string, fwd->port) == 0 &&
          strcmp(address_to_bind, fwd->address_to_bind) == 0)
        {
          ssh_tcp_destroy_listener(fwd->listener);
          ssh_xfree(fwd->address_to_bind);
          ssh_xfree(fwd->port);
          *fwdp = fwd->next;
          ssh_xfree(fwd);
          ssh_xfree(address_to_bind);
          return TRUE;
        }
    }

  SSH_DEBUG(1, ("port %s address_to_bind %s not found",
                port_string, address_to_bind));
  ssh_xfree(address_to_bind);
  return FALSE;
}

/***********************************************************************
 * Sending a request to start remote TCP/IP forwarding.
 ***********************************************************************/

/* Requests forwarding of the given remote TCP/IP port.  If the completion
   procedure is non-NULL, it will be called when done. */

void ssh_channel_start_remote_tcp_forward(SshCommon common,
                                          const char *address_to_bind,
                                          const char *port,
                                          const char *connect_to_host,
                                          const char *connect_to_port,
                                          void (*completion)(Boolean ok,
                                                             void *context),
                                          void *context)
{
  SshRemoteTcpForward fwd;
  SshBuffer buffer;
  SshChannelTypeTcpForward ct;

  SSH_DEBUG(5, ("requesting remote forwarding for port %s", port));

  ct = ssh_channel_ftcp_ct(common);
  
  /* Create a context for the forwarding. */
  fwd = ssh_xcalloc(1, sizeof(*fwd));
  fwd->common = common;
  fwd->address_to_bind = ssh_xstrdup(address_to_bind);
  fwd->port = ssh_xstrdup(port);
  fwd->connect_to_host = ssh_xstrdup(connect_to_host);
  fwd->connect_to_port = ssh_xstrdup(connect_to_port);

  /* Add it to the list of remote forwardings. */
  fwd->next = ct->remote_forwards;
  ct->remote_forwards = fwd;

  /* Send a forwarding request to the remote side. */
  ssh_buffer_init(&buffer);
  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_UINT32_STR,
                      address_to_bind, strlen(address_to_bind),
                    SSH_FORMAT_UINT32, (SshUInt32) atol(port),
                    SSH_FORMAT_END);
  ssh_conn_send_global_request(common->conn, "tcpip-forward",
                               ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer),
                               completion, context);
  ssh_buffer_uninit(&buffer);
}

/***********************************************************************
 * Handling incoming connections to a locally forwarded port
 ***********************************************************************/

/* This function is called whenever a locally forwarded TCP/IP port is
   connected. */

void ssh_channel_dtcp_incoming_connection(SshStreamNotification op,
                                          SshStream stream, void *context)
{
  SshLocalTcpForward fwd = (SshLocalTcpForward)context;
  char ip[20], port[20];

  /* We should only receive new connection notifications. */
  if (op != SSH_IP_NEW_CONNECTION)
    ssh_fatal("ssh_channel_dtcp_incoming_connection: op %d", (int)op);

  /* Get remote ip address and port. */
  if (!ssh_tcp_get_remote_address(stream, ip, sizeof(ip)))
    strcpy(ip, "UNKNOWN");
  if (!ssh_tcp_get_remote_port(stream, port, sizeof(port)))
    strcpy(port, "UNKNOWN");

#ifdef HAVE_LIBWRAP
  {
    struct request_info req;
    struct servent *serv;
    char fwdportname[32];
    void *old_handler;
    
    old_handler = signal(SIGCHLD, SIG_DFL);
    
    /* try to find port's name in /etc/services */
    serv = getservbyport(atoi(fwd->port), "tcp");
    if (serv == NULL)
      {
        /* not found (or faulty getservbyport) -
           use the number as a name */
        snprintf(fwdportname, sizeof(fwdportname), "sshdfwd-%s", fwd->port);
      }
    else
      {
        snprintf(fwdportname, sizeof(fwdportname), "sshdfwd-%.20s",
                 serv->s_name);
      }
    /* fill req struct with port name and fd number */
    request_init(&req, RQ_DAEMON, fwdportname,
                 RQ_FILE, ssh_stream_fd_get_readfd(stream), NULL);
    fromhost(&req);
    if (!hosts_access(&req))
      {
        ssh_conn_send_debug(fwd->common->conn, TRUE,
                            "Fwd connection from %.500s to local port %s "
                            "refused by tcp_wrappers.",
                            eval_client(&req), fwdportname);
        ssh_log_event(fwd->common->config->log_facility, SSH_LOG_WARNING,
                      "Fwd connection from %.500s to local port %s "
                      "refused by tcp_wrappers.",
                      eval_client(&req), fwdportname);
        ssh_stream_destroy(stream);
        signal(SIGCHLD, old_handler);

        return;
      }
    signal(SIGCHLD, old_handler);

    ssh_log_event(fwd->common->config->log_facility, SSH_LOG_INFORMATIONAL,
                  "direct fwd connect from %.500s to local port %s",
                  eval_client(&req), fwdportname);
  }
#endif /* HAVE_LIBWRAP */

  /* Send a request to open a channel and connect it to the given port. */
  ssh_channel_dtcp_open_to_remote(fwd->common, stream,
                                  fwd->connect_to_host,
                                  fwd->connect_to_port,
                                  ip, port);
}

/***********************************************************************
 * Starting local TCP/IP forwarding for a port
 ***********************************************************************/

/* Requests forwarding of the given local TCP/IP port.  Returns TRUE if
   forwarding was successfully started, FALSE otherwise. */

Boolean ssh_channel_start_local_tcp_forward(SshCommon common,
                                            const char *address_to_bind,
                                            const char *port,
                                            const char *connect_to_host,
                                            const char *connect_to_port)
{
  SshLocalTcpForward fwd;
  SshChannelTypeTcpDirect ct;
  long portnumber;
  SshUser user;
  
  SSH_DEBUG(5, ("requesting local forwarding for port %s to %s:%s",
                port, connect_to_host, connect_to_port));

  portnumber = atol(port);
  user = ssh_user_initialize(NULL, FALSE);
    /* If user is not logged in as a privileged user, don't allow
     forwarding of privileged ports. */
  if (portnumber < 1024)
    {
      if (ssh_user_uid(user))
        {
          ssh_warning("Tried to forward " \
                      "privileged port %d as an ordinary user.",
                      portnumber);
          return FALSE;
        }
    }

  if (portnumber >= 65536)
    {
      ssh_warning("Tried to forward " \
                  "port above 65535 (%d).",
                  portnumber);
      return FALSE;
    }
  
  ct = ssh_channel_dtcp_ct(common);

  fwd = ssh_xcalloc(1, sizeof(*fwd));
  fwd->common = common;
  fwd->listener = ssh_tcp_make_listener(address_to_bind, port,
                                        ssh_channel_dtcp_incoming_connection,
                                        (void *)fwd);
  if (!fwd->listener)
    {
      SSH_DEBUG(5, ("creating listener failed"));
      ssh_xfree(fwd);
      return FALSE;
    }

  fwd->port = ssh_xstrdup(port);
  fwd->connect_to_host = ssh_xstrdup(connect_to_host);
  fwd->connect_to_port = ssh_xstrdup(connect_to_port);

  fwd->next = ct->local_forwards;
  ct->local_forwards = fwd;

  return TRUE;
}

/***********************************************************************
 * Sending a direct open request to a TCP/IP port from the remote side.
 * This is direct forwarding, and is primarily used for local
 * forwardings.
 ***********************************************************************/

/* Opens a direct connection to the given TCP/IP port at the remote side.
   The originator values should be set to useful values and are passed
   to the other side.  ``stream'' will be used to transfer channel data.
   The stream will be closed when the channel is closed, or if opening
   the channel fails. */

void ssh_channel_dtcp_open_to_remote(SshCommon common, SshStream stream,
                                     const char *connect_to_host,
                                     const char *connect_to_port,
                                     const char *originator_ip,
                                     const char *originator_port)
{
  SshBuffer buffer;

  SSH_DEBUG(5, ("opening direct TCP/IP connection to %s:%s originator %s:%s",
                connect_to_host, connect_to_port,
                originator_ip, originator_port));

  /* Register that we have a new channel. */
  ssh_common_new_channel(common);

  /* Format the channel open request in a buffer. */
  ssh_buffer_init(&buffer);
  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_UINT32_STR,
                      connect_to_host, strlen(connect_to_host),
                    SSH_FORMAT_UINT32, (SshUInt32) atol(connect_to_port),
                    SSH_FORMAT_UINT32_STR,
                      originator_ip, strlen(originator_ip),
                    SSH_FORMAT_UINT32, (SshUInt32) atol(originator_port),
                    SSH_FORMAT_END);
  
  /* Send the channel open request. */
  ssh_conn_send_channel_open(common->conn, "direct-tcpip",
                             stream, TRUE, FALSE, SSH_TCPIP_WINDOW,
                             SSH_TCPIP_PACKET_SIZE,
                             ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer),
                             NULL, 
                             ssh_channel_tcp_connection_destroy,
                             (void *)common, NULL, NULL);

  ssh_buffer_uninit(&buffer);
}

#endif /* SSH_CHANNEL_TCPFWD */
