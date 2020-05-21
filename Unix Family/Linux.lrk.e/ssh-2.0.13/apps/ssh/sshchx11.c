/*

sshchx11.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Code for X11 forwarding channels for SSH2 servers and clients.

*/

#include "ssh2includes.h"
#include "sshfilterstream.h"
#include "sshtcp.h"
#include "sshencode.h"
#include "sshtrans.h"
#include "sshconn.h"
#include "sshmsgs.h"
#include "sshlocalstream.h"
#include "sshcommon.h"
#include "sshunixfdstream.h"

#ifdef SSH_CHANNEL_X11

#include "sshchx11.h"

/* These headers are needed for Unix domain sockets. */
#if defined(XAUTH_PATH) || defined(HPSUX_NONSTANDARD_X11_KLUDGE)
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#else /* Some old linux systems at least have in_system.h instead. */
#include <netinet/in_system.h>
#endif /* HAVE_NETINET_IN_SYSTM_H */
#if !defined(__PARAGON__)
#include <netinet/ip.h>
#endif /* !__PARAGON__ */
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */
#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif /* HAVE_SYS_UTSNAME_H */
#endif /* XAUTH_PATH || HPSUX_NONSTANDARD_X11_KLUDGE */
#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#include <syslog.h>
#ifdef NEED_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif /* NEED_SYS_SYSLOG_H */
#endif /* HAVE_LIBWRAP */

#define SSH_DEBUG_MODULE "Ssh2ChannelX11"

#define X11_WINDOW_SIZE          30000
#define X11_PACKET_SIZE           1024

/* Maximum number of fake X11 displays to try. */
#define X11_MAX_DISPLAYS  1000

/* Directory in which the fake unix-domain X11 displays reside.  The
   default value can be overriden by configure. */
#ifndef X11_DIR
#define X11_DIR "/tmp/.X11-unix"
#endif /* !X11_DIR */

#define X11_MAX_AUTH_PACKET_SIZE 10000

/* Context per session. */
typedef struct SshChannelX11SessionRec
{
  /* Controlling SshCommon object. */
  SshCommon common;
  
  /* X11-related data for the server. */
  Boolean forward_x11;          /* True if forwarding has been requested. */
  char *auth_protocol;          /* The received auth protocol. */
  char *auth_cookie;            /* The received auth cookie (hex string). */
  unsigned long screen_number;  /* Screen number. */
  char *display;                /* Value for DISPLAY variable. */
  SshTcpListener x11_listener;  /* Socket listening for X11 connections. */
  Boolean single_x11_connection; /* If true, close listener after first conn */
} *SshChannelX11Session;

/* Context per SshCommon object. */
typedef struct SshChannelTypeX11Rec
{
  /* X11-related data for the client. */
  Boolean x11_requested;
  unsigned char *x11_fake_proto;
  size_t x11_fake_proto_len;
  unsigned char *x11_fake_cookie;
  size_t x11_fake_cookie_len;
  unsigned char *x11_real_proto;
  size_t x11_real_proto_len;
  unsigned char *x11_real_cookie;
  size_t x11_real_cookie_len;
} *SshChannelTypeX11;



/***********************************************************************
 * Glue functions for creating/destroying channel type and session
 * contexts.
 ***********************************************************************/

/* This function is called once when a SshCommon object is created. */

void *ssh_channel_x11_create(SshCommon common)
{
  return ssh_xcalloc(1, sizeof(struct SshChannelTypeX11Rec));
}

/* This function is called once when an SshCommon object is being
   destroyed.  This should destroy all X11 channels and listeners and
   free the context. */
void ssh_channel_x11_destroy(void *context)
{
  SshChannelTypeX11 ct = (SshChannelTypeX11)context;

  /* Destroy all existing channels.
     XXX not implemented. */

  /* Free any data in the session context. */
  ssh_xfree(ct->x11_fake_proto);
  ssh_xfree(ct->x11_fake_cookie);
  ssh_xfree(ct->x11_real_proto);
  ssh_xfree(ct->x11_real_cookie);

  /* Destroy the channel type context. */
  ssh_xfree(ct);
}

/* This function is called once for each session channel that is created.
   This should initialize per-session state for X11 forwarding.  The
   argument points to a void pointer that will be given as argument to
   the following functions.  It can be used to store the per-session
   state. */

void ssh_channel_x11_session_create(SshCommon common,
                                    void **session_placeholder)
{
  SshChannelX11Session session;

  /* Allocate a session context. */
  session = ssh_xcalloc(1, sizeof(*session));
  session->common = common;

  *session_placeholder = (void *)session;
}
                                        
/* This function is called once whenever a session channel is destroyed.
   This should free any X11 forwarding state related to the session; however,
   this should typically not close forwarded X11 channels. */

void ssh_channel_x11_session_destroy(void *session_placeholder)
{
  SshChannelX11Session session = (SshChannelX11Session)session_placeholder;

  /* Destroy the listener if any. */
  if (session->x11_listener)
    ssh_tcp_destroy_listener(session->x11_listener);

  /* Free the session context. */
  ssh_xfree(session);
}

/* Returns the channel type context from the SshCommon object. */

SshChannelTypeX11 ssh_channel_x11_ct(SshCommon common)
{
  return (SshChannelTypeX11)ssh_common_get_channel_type_context(common, "x11");
}

/***********************************************************************
 * Sending a request to start forwarding.
 ***********************************************************************/

/* This function is called from within the context of a session channel
   in the client to request X11 forwarding for the session.
   Generates a fake authentication cookie and sends a request for X11
   forwarding. */

void ssh_channel_x11_send_request(SshCommon common, int session_channel_id)
{
  char line[512], proto[512], data[512];
  Boolean got_data = FALSE;
  FILE *f;
  unsigned int data_len;
  unsigned int value;
  char *new_data;
  int i;
  SshUInt32 screen_number;
  const char *cp;
  SshBuffer buffer;
  SshChannelTypeX11 ct;

  /* Find the channel type context. */
  ct = ssh_channel_x11_ct(common);
  
  /* If DISPLAY isn't set, no sense in requesting X11 forwarding. */
  if (getenv("DISPLAY") == NULL)
    {
      ssh_debug("DISPLAY not set; X11 forwarding disabled.");
      return;
    }
      
  /* Got local authentication reasonable information.  Request forwarding
     with authentication spoofing. */
  ssh_debug("Requesting X11 forwarding with authentication spoofing.");
      
  /* Extract screen number from the display. */
  cp = getenv("DISPLAY");
  if (cp)
    cp = strchr(cp, ':');
  if (cp)
    cp = strchr(cp, '.');
  if (cp)
    screen_number = atoi(cp + 1);
  else
    screen_number = 0;

  /* Generate a fake cookie only if this is the first X11 request in this
     connection. */
  if (!ct->x11_requested)
    {
#ifdef XAUTH_PATH
      /* Try to get Xauthority information for the display. */
      snprintf(line, sizeof(line), "%s list %s 2>/dev/null", 
               XAUTH_PATH, getenv("DISPLAY"));
      f = popen(line, "r");
      if (f && fgets(line, sizeof(line), f) && 
          sscanf(line, "%*s %s %s", proto, data) == 2)
        got_data = TRUE;
      else
        ssh_debug("Failed to get local xauth data.");
      if (f)
        pclose(f);
#else /* XAUTH_PATH */
      ssh_debug("No xauth program was found at configure time.");
#endif /* XAUTH_PATH */
      /* If we didn't get authentication data, just make up some data.  The
         forwarding code will check the validity of the response anyway, and
         substitute this data.  The X11 server, however, will ignore this
         fake data and use whatever authentication mechanisms it was using
         otherwise for the local connection. */
      if (!got_data)
        {
          strcpy(proto, "MIT-MAGIC-COOKIE-1");
          for (i = 0; i < 16; i++)
            snprintf(data + 2 * i, 3, "%02x",
                     ssh_random_get_byte(common->random_state));
        }
      
      /* Save protocol name. */
      ct->x11_real_proto = ssh_xstrdup(proto);
      ct->x11_real_proto_len = strlen(proto);
      ct->x11_fake_proto = ssh_xstrdup(proto);
      ct->x11_fake_proto_len = strlen(proto);

      /* Extract real authentication data and generate fake data of the same
         length. */
      data_len = strlen(data) / 2;
      ct->x11_real_cookie = ssh_xmalloc(data_len);
      ct->x11_real_cookie_len = data_len;
      ct->x11_fake_cookie = ssh_xmalloc(data_len);
      ct->x11_fake_cookie_len = data_len;

      /* Convert the real cookie into binary. */
      for (i = 0; i < data_len; i++)
        {
          if (sscanf(data + 2 * i, "%2x", &value) != 1)
            {
              ssh_warning("ssh_channel_x11_send_request: bad data: %s",
                          data);
              return;
            }
          ct->x11_real_cookie[i] = value;
        }

      /* Generate fake cookie. */
      for (i = 0; i < data_len; i++)
        ct->x11_fake_cookie[i] = ssh_random_get_byte(common->random_state);
    }
  
  /* Convert the fake data into hex for transmission. */
  new_data = ssh_xmalloc(2 * ct->x11_fake_cookie_len + 1);
  for (i = 0; i < ct->x11_fake_cookie_len; i++)
    snprintf(new_data + 2 * i, 3, "%02x",
             (unsigned char)ct->x11_fake_cookie[i]);

  ssh_buffer_init(&buffer);
  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_BOOLEAN, FALSE, /* XXX single-connection */
                    SSH_FORMAT_UINT32_STR,
                      ct->x11_fake_proto, ct->x11_fake_proto_len,
                    SSH_FORMAT_UINT32_STR, new_data, strlen(new_data),
                    SSH_FORMAT_UINT32, screen_number,
                    SSH_FORMAT_END);
  ssh_conn_send_channel_request(common->conn, session_channel_id,
                                "x11-req", ssh_buffer_ptr(&buffer),
                                ssh_buffer_len(&buffer), NULL, NULL);
  ssh_buffer_uninit(&buffer);
  ssh_xfree(new_data);

  ct->x11_requested = TRUE;
}

/***********************************************************************
 * Functions that are used in the SSH server end.  These receive
 * incoming X11 connections, and cause channel open requests to be
 * sent to the SSH client.
 ***********************************************************************/

/* Function to be called when a forwarded X11 connection is closed. */

void ssh_channel_x11_connection_destroy(void *context)
{
  SshCommon common = (SshCommon)context;

  /* Inform the common code that a channel has been destroyed. */
  ssh_common_destroy_channel(common);
}

/* This function is called whenever a new X11 connection is received. */

void ssh_channel_x11_connection(SshIpError error, SshStream stream,
                                void *context)
{
  SshChannelX11Session session = (SshChannelX11Session)context;
  SshBuffer buffer;
  char ip[50], port[50], msg[256];

  SSH_DEBUG(6, ("X11 connection from an X11 client"));
  
  /* We should only receive new connections. */
  if (error != SSH_IP_NEW_CONNECTION)
    ssh_fatal("ssh_channel_x11_connection: error %d", (int)error);

  /* If we only want to accept a single connection, close the listener now. */
  if (session->single_x11_connection)
    {
      ssh_tcp_destroy_listener(session->x11_listener);
      session->x11_listener = NULL;
    }
  
  /* Get remote IP address and port. */
  if (!ssh_tcp_get_remote_address(stream, ip, sizeof(ip)))
    strcpy(ip, "UNKNOWN");
  if (!ssh_tcp_get_remote_port(stream, port, sizeof(port)))
    strcpy(port, "UNKNOWN");

  /* Format the initiator string for describing where the connection
     came from. */
  snprintf(msg, sizeof(msg), "X11 connection from %s:%s", ip, port);

  /* Increase the number of open channels.  This will be decremented in
     the destroy function. */
  ssh_common_new_channel(session->common);

#ifdef HAVE_LIBWRAP
  {
    struct request_info req;
    void *old_handler;
    
    old_handler = signal(SIGCHLD, SIG_DFL);
                
    /* Fill req struct with port name and fd number */
    request_init(&req, RQ_DAEMON, "sshdfwd-X11",
                 RQ_FILE, ssh_stream_fd_get_readfd(stream), NULL);
    fromhost(&req);
    if (!hosts_access(&req))
      {
        ssh_conn_send_debug(session->common->conn, TRUE, "Fwd X11 connection "
                            "from %.500s refused by tcp_wrappers.",
                            eval_client(&req));
        ssh_log_event(session->common->config->log_facility, SSH_LOG_WARNING,
                      "Fwd X11 connection "
                      "from %.500s refused by tcp_wrappers.",
                      eval_client(&req));
        ssh_stream_destroy(stream);
        signal(SIGCHLD, old_handler);

        return;
      }

    signal(SIGCHLD, old_handler);

    ssh_log_event(session->common->config->log_facility, SSH_LOG_INFORMATIONAL,
                  "fwd X11 connect from %.500s",
                  eval_client(&req));
  }
#endif /* HAVE_LIBWRAP */
  /* XXX Logging*/

  /* Send a channel open request to the other side. */
  ssh_buffer_init(&buffer);
  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_UINT32_STR, msg, strlen(msg),
                    SSH_FORMAT_END);
  ssh_conn_send_channel_open(session->common->conn, "x11", stream, TRUE, TRUE,
                             X11_WINDOW_SIZE, X11_PACKET_SIZE,
                             ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer),
                             NULL,
                             ssh_channel_x11_connection_destroy,
                             (void *)session->common, NULL, NULL);
  ssh_buffer_uninit(&buffer);
}

/***********************************************************************
 * Processing a request to start X11 forwarding at server end.
 ***********************************************************************/

/* Processes an X11 forwarding request.  Returns TRUE if the request was
   accepted, FALSE otherwise. */

Boolean ssh_channel_x11_process_request(void *session_placeholder,
                                        const unsigned char *data,
                                        size_t len)
{
  int display_number;
  char buf[512], hostname[257];
  struct stat st;
  SshChannelX11Session session;
  SshChannelTypeX11 ct;
  SshUInt32 temp;
  
  SSH_DEBUG(6, ("request_x11"));

  session = (SshChannelX11Session)session_placeholder;
  ct = ssh_channel_x11_ct(session->common);

  /* If already forwarding X11, fail. */
  if (session->forward_x11)
    {
      SSH_DEBUG(1, ("request_x11: already forwarding"));
      return FALSE;
    }

  /* Parse the request. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_BOOLEAN, &session->single_x11_connection,
                       SSH_FORMAT_UINT32_STR,
                         &session->auth_protocol, NULL,
                       SSH_FORMAT_UINT32_STR,
                         &session->auth_cookie, NULL,
                       SSH_FORMAT_UINT32, &temp,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG(0, ("request_x11: bad data"));
      return FALSE;
    }

  session->screen_number = temp;
  
  /* Check whether we have xauth installed on this machine (in case
     the binary was moved from elsewhere). */
  if (stat(XAUTH_PATH, &st) < 0)
    {
      SSH_DEBUG(1, ("request_x11: no X11 installed"));
      return FALSE;
    }


  /* Open the first available display, starting at number 10. */
  for (display_number = 10; display_number < X11_MAX_DISPLAYS;
       display_number++)
    {
      /* Format a port number for the display. */
      snprintf(buf, sizeof(buf), "%d", 6000 + display_number);

      /* Open a TCP/IP socket for listening the port. */
      session->x11_listener =
        ssh_tcp_make_listener("0.0.0.0", buf, ssh_channel_x11_connection,
                              (void *)session);

      /* Break if we got the display number. */
      if (session->x11_listener != NULL)
        break;
    }

  /* If we failed to allocate a display number, fail. */
  if (session->x11_listener == NULL)
    {
      SSH_DEBUG(1, ("request_x11: failed to allocate display."));
      return FALSE;
    }

  /* Set up a suitable value for the DISPLAY variable. */
#ifdef HPSUX_NONSTANDARD_X11_KLUDGE
  /* HPSUX has some special shared memory stuff in their X server, which
     appears to be enabled if the host name matches that of the local machine.
     However, it can be circumvented by using the IP address of the local
     machine instead.  */
  if (gethostname(buf, sizeof(buf)) < 0)
    ssh_fatal("gethostname: %s", strerror(errno));
  {
    struct hostent *hp;
    struct in_addr addr;
    hp = gethostbyname(buf);
    if (hp == NULL || !hp->h_addr_list[0])
      {
        ssh_warning("Could not get server IP address for %.200s.", buf);
        ssh_tcp_destroy_listener(session->x11_listener);
        session->x11_listener = NULL;
        return FALSE;
      }
    memcpy(&addr, hp->h_addr_list[0], sizeof(addr));
    snprintf(buf, sizeof(buf), "%s:%d.%d",
             inet_ntoa(addr), display_number, session->screen_number);
  }
#else /* HPSUX_NONSTANDARD_X11_KLUDGE */
  /* Get the name of the local host. */
  ssh_tcp_get_host_name(hostname, sizeof(hostname));

  /* Format the DISPLAY value. */
  snprintf(buf, sizeof(buf), "%s:%d.%lu",
           hostname, display_number, session->screen_number);
#endif /* HPSUX_NONSTANDARD_X11_KLUDGE */
  
  /* Save the display name. */
  session->display = ssh_xstrdup(buf);

  /* Mark that we are forwarding X11. */
  session->forward_x11 = TRUE;
  return TRUE;
}

/***********************************************************************
 * Functions that are used at the SSH client end for connecting to the
 * real X11 display.
 ***********************************************************************/

typedef struct SshX11ConnectionRec
{
  SshCommon common;
  SshChannelTypeX11 ct;
  int channel_id;
  SshConnOpenCompletionProc completion;
  void *context;
  char *originator;
} *SshX11Connection;

/* Frees the X11 stream context. */

void ssh_channel_x11_x_destroy(SshX11Connection x)
{
  ssh_xfree(x->originator);
  memset(x, 'F', sizeof(*x));
  ssh_xfree(x);
}

/* Filter function for filtering data in the X11 data stream.  This function
   will keep data until the first packet (authentication packet) has
   been entirely received, at which point this will replace the authentication
   cookie in the packet by the real cookie, and shortcircuit the filter. */

int ssh_channel_x11_filter(SshBuffer *data,
                           size_t offset,
                           Boolean eof_received,
                           void *context)
{
  SshX11Connection x = (SshX11Connection)context;
  unsigned char *ucp;
  size_t received_len, data_len, proto_len, desired_len;

  SSH_DEBUG(6, ("filter: data len %d, offset %d",
                (int)ssh_buffer_len(data), (int)offset));
  
  /* Compute the start and length of data that we have in the filter. */
  ucp = ssh_buffer_ptr(data);
  ucp += offset;
  received_len = ssh_buffer_len(data) - offset;

  /* Check if we have received enough to have the fixed packet header. */
  if (received_len < 12)
    {
      /* Not yet...  Keep receiving, unless we've got EOF. */
      if (eof_received)
        return SSH_FILTER_DISCONNECT; /* Abort the connection. */
      else
        return SSH_FILTER_HOLD; /* Wait for more data. */
    }

  /* Parse the lengths of variable-length fields. */
  if (ucp[0] == 0x42)
    { /* Byte order MSB first. */
      proto_len = 256 * ucp[6] + ucp[7];
      data_len = 256 * ucp[8] + ucp[9];
    }
  else
    if (ucp[0] == 0x6c)
      { /* Byte order LSB first. */
        proto_len = ucp[6] + 256 * ucp[7];
        data_len = ucp[8] + 256 * ucp[9];
      }
    else
      {
        ssh_warning("Initial X11 packet contains bad byte order byte: 0x%x",
                    ucp[0]);
        return SSH_FILTER_DISCONNECT;
      }

  /* Compute the length of the packet we must receive. */
  desired_len = 12 + ((proto_len + 3) & ~3) + ((data_len + 3) & ~3);

  /* Sanity check: it must not be larger than we are willing to receive. */
  if (desired_len > X11_MAX_AUTH_PACKET_SIZE)
    return SSH_FILTER_DISCONNECT;
  
  /* Check if the whole packet is in buffer. */
  if (received_len < desired_len)
    {
      if (eof_received)
        return SSH_FILTER_DISCONNECT; /* Abort the connection. */
      else
        return SSH_FILTER_HOLD;
    }

  /* Check if authentication protocol matches. */
  if (proto_len != x->ct->x11_fake_proto_len ||
      memcmp(ucp + 12, x->ct->x11_fake_proto, proto_len) != 0)
    {
      if (proto_len > 100)
        proto_len = 100; /* Limit length of output. */
      ssh_warning("X11 connection requests different authentication protocol: '%.*s' vs. '%.*s'.",
                  x->ct->x11_fake_proto_len, x->ct->x11_fake_proto,
                  proto_len, (const char *)(ucp + 12));
      return SSH_FILTER_DISCONNECT;
    }

  /* Check if authentication data matches our fake data. */
  if (data_len != x->ct->x11_fake_cookie_len ||
      memcmp(ucp + 12 + ((proto_len + 3) & ~3),
             x->ct->x11_fake_cookie, x->ct->x11_fake_cookie_len) != 0)
    {
      ssh_warning("X11 auth data does not match fake data.");
      return SSH_FILTER_DISCONNECT;
    }

  /* Received authentication protocol and data match our fake data.
     Substitute the fake data with real data. */
  assert(x->ct->x11_fake_cookie_len == x->ct->x11_real_cookie_len);
  memcpy(ucp + 12 + ((proto_len + 3) & ~3),
         x->ct->x11_real_cookie, x->ct->x11_real_cookie_len);

  /* Otherwise, we accept and shortcircuit any further communications. */
  return SSH_FILTER_SHORTCIRCUIT;
}

/* This is called when the filter stream is being destroyed.  We free the
   context. */

void ssh_channel_x11_filter_destroy(void *context)
{
  SshX11Connection x = (SshX11Connection)context;

  ssh_channel_x11_x_destroy(x);
}

/* This function is called whenever connecting to an X11 display has
   completed successfully during processing of a received channel open
   request. */

void ssh_channel_x11_open_connected(SshStream stream,
                                    void *context)
{
  SshX11Connection x = (SshX11Connection)context;

  if (stream == NULL)
    {
      SSH_DEBUG(6, ("x11_open_connected: Connecting to the real "
                    "X server failed."));
      (*x->completion)(SSH_OPEN_CONNECT_FAILED,
                       NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                       x->context);
      ssh_channel_x11_x_destroy(x);
      return;
    }
  
  
  SSH_DEBUG(6, ("open_connected: %s", x->originator));

  /* Increment the number of channels. */
  ssh_common_new_channel(x->common);
  
  /* Wrap the stream to the X server into a filter stream that is used
     to replace the fake authentication cookie with the real one. */
  stream = ssh_stream_filter_create(stream, X11_MAX_AUTH_PACKET_SIZE,
                                    ssh_channel_x11_filter,
                                    NULL, ssh_channel_x11_filter_destroy,
                                    (void *)x);

  /* Call the open completion procedure. */
  (*x->completion)(SSH_OPEN_OK,
                   stream, TRUE, TRUE, X11_WINDOW_SIZE, NULL, 0,
                   NULL, ssh_channel_x11_connection_destroy,
                   (void *)x->common, x->context);
}

/* This function is called whenever connecting to a TCP/IP X11 display
   completes. */

void ssh_channel_x11_open_connected_tcp(SshIpError error,
                                        SshStream stream,
                                        void *context)
{
  SshX11Connection x = (SshX11Connection)context;
  if (error != SSH_IP_OK)
    {
      SSH_DEBUG(6, ("Connecting to the real X server failed."));
      (*x->completion)(SSH_OPEN_CONNECT_FAILED,
                       NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                       x->context);
      ssh_channel_x11_x_destroy(x);
      return;
    }
  
  /* Complete processing of the channel open request. */
  ssh_channel_x11_open_connected(stream, context);
}

/***********************************************************************
 * Receiving an open request for a X11 channel.  This call typically
 * happens in the SSH client, and this will contact the local real
 * X server.
 ***********************************************************************/

/* This function is called whenever an open request is received for an
   X11 channel.  This connects to the real X display and creates the
   channel. */

void ssh_channel_x11_open(const char *type, int channel_id,
                          const unsigned char *data, size_t len,
                          SshConnOpenCompletionProc completion,
                          void *completion_context, void *context)
{
  SshCommon common = (SshCommon)context;
  SshX11Connection x;
  char *originator;
  int display_number;
  const char *display;
  char buf[256], port[20], *cp;
  SshChannelTypeX11 ct;
  
  SSH_DEBUG(6, ("X11 channel open received"));

  ct = (SshChannelTypeX11)ssh_common_get_channel_type_context(common, "x11");
  
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR, &originator, NULL,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG(0, ("x11_open: bad data"));
      goto fail;
    }

  if (!ct->x11_requested)
    {
      ssh_warning("Received X11 connection without requesting forwarding!");
      ssh_warning("Originator string: '%s'", originator);
      ssh_xfree(originator);
      goto fail;
    }

  x = ssh_xcalloc(1, sizeof(*x));
  x->common = common;
  x->ct = ct;
  x->channel_id = channel_id;
  x->completion = completion;
  x->context = completion_context;
  x->originator = originator;

  /* Try to open a socket for the local X server. */
  display = getenv("DISPLAY");
  if (!display)
    ssh_fatal("ssh_channel_x11_open: DISPLAY not set.");
  
  /* Now we decode the value of the DISPLAY variable and make a connection
     to the real X server. */

  /* Check if it is a unix domain socket.  Unix domain displays are in one
     of the following formats: unix:d[.s], :d[.s], ::d[.s] */
  if (strncmp(display, "unix:", 5) == 0 ||
      display[0] == ':')
    {
      /* Connect to the unix domain socket. */
      if (sscanf(strrchr(display, ':') + 1, "%d", &display_number) != 1)
        {
          ssh_warning("Could not parse display number from DISPLAY: %.100s",
                      display);
          goto fail;
        }

      /* Determine the name to use for the socket. */
#ifdef HPSUX_NONSTANDARD_X11_KLUDGE
      {
        /* HPSUX release 10.X uses /var/spool/sockets/X11/0 for the
           unix-domain sockets, while earlier releases stores the
           socket in /usr/spool/sockets/X11/0 with soft-link from
           /tmp/.X11-unix/`uname -n`0 */

        struct stat st;

        if (stat("/var/spool/sockets/X11", &st) == 0)
          {
            snprintf(buf, sizeof(buf), "%s/%d",
                     "/var/spool/sockets/X11", display_number);
          }
        else
          {
            if (stat("/usr/spool/sockets/X11", &st) == 0)
              {
                snprintf(buf, sizeof(buf), "%s/%d",
                         "/usr/spool/sockets/X11", display_number);
              }
            else
              {
                struct utsname utsbuf;
                /* HPSUX stores unix-domain sockets in
                   /tmp/.X11-unix/`hostname`0 
                   instead of the normal /tmp/.X11-unix/X0. */
                if (uname(&utsbuf) < 0)
                  ssh_fatal("uname: %.100s", strerror(errno));
                snprintf(buf, sizeof(buf), "%.20s/%.64s%d",
                         X11_DIR, utsbuf.nodename, display_number);
              }
          }
      }
#else /* HPSUX_NONSTANDARD_X11_KLUDGE */
      snprintf(buf, sizeof(buf), "%.80s/X%d", X11_DIR, display_number);
#endif /* HPSUX_NONSTANDARD_X11_KLUDGE */

      /* Connect to the X11 socket. */
      ssh_local_connect(buf, ssh_channel_x11_open_connected, (void *)x);
      return;
    }
  
  /* Connect to an inet socket.  The DISPLAY value is supposedly
     hostname:d[.s], where hostname may also be numeric IP address. */
  strncpy(buf, display, sizeof(buf));
  buf[sizeof(buf) - 1] = 0;
  cp = strchr(buf, ':');
  if (!cp)
    {
      ssh_warning("Could not find ':' in DISPLAY: %.100s", display);
    free_x_and_fail:
      ssh_channel_x11_x_destroy(x);
    fail:
      (*completion)(SSH_OPEN_CONNECT_FAILED,
                    NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                    completion_context);
      return;
    }
  *cp = 0;
  /* buf now contains the host name.  But first we parse the display number. */
  if (sscanf(cp + 1, "%d", &display_number) != 1)
    {
      ssh_warning("Could not parse display number from DISPLAY: %.100s",
                  display);
      goto free_x_and_fail;
    }

  /* Host name is now in ``buf''.  Format port number in ``port''. */
  snprintf(port, sizeof(port), "%d", 6000 + display_number);

  ssh_tcp_connect_with_socks(buf, port, NULL, 1,
                             ssh_channel_x11_open_connected_tcp, 
                             (void *)x);
}

/* Returns the value of DISPLAY in the server. */

const char *ssh_channel_x11_get_display(void *session_placeholder)
{
  SshChannelX11Session session = (SshChannelX11Session)session_placeholder;

  return session->display;
}

/* Returns the value of the authentication protocol in the server. */

const char *ssh_channel_x11_get_auth_protocol(void *session_placeholder)
{
  SshChannelX11Session session = (SshChannelX11Session)session_placeholder;

  return session->auth_protocol;
}

/* Returns the value of the authentication cookie in the server. */

const char *ssh_channel_x11_get_auth_cookie(void *session_placeholder)
{
  SshChannelX11Session session = (SshChannelX11Session)session_placeholder;

  return session->auth_cookie;
}

#endif /* SSH_CHANNEL_X11 */
