/*

Author: Tatu Ylonen <ylo@ssh.fi>
        Antti Huima <huima@ssh.fi>

Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
All rights reserved.

Unix-specific code for sockets.

*/

/*
 * $Id: sshunixtcp.c,v 1.16 1999/04/28 13:20:05 tri Exp $
 * $Log: sshunixtcp.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshstream.h"
#include "sshtcp.h"
#include "sshunixfdstream.h"
#include "sshtimeouts.h"
#include "sshunixeloop.h"

#define MAX_IP_ADDR_LEN 16

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
#if !defined(HAVE_GETHOSTNAME) && defined(HAVE_UNAME) && defined(HAVE_SYS_UTSNAME_H)
#include <sys/utsname.h>
#endif

#define SSH_DEBUG_MODULE "SshUnixTcp"

typedef struct LowConnectRec
{
  int sock;
  char *address;
  unsigned int port;
  SshTcpCallback callback;
  void *context;
} *LowConnect;


void ssh_socket_set_reuseaddr(int sock)
{
  int on = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&on, 
             sizeof(on));
}

#ifdef NO_NONBLOCKING_CONNECT

void ssh_socket_low_connect_try_once(unsigned int events, void *context)
{
  LowConnect c = (LowConnect)context;
  int ret;
  struct sockaddr_in sinaddr;
  SshIpError error;
  
  memset(&sinaddr, 0, sizeof(sinaddr));
  sinaddr.sin_family = AF_INET;
  sinaddr.sin_port = htons(c->port);

#ifdef BROKEN_INET_ADDR
  sinaddr.sin_addr.s_addr = inet_network(c->address);
#else /* BROKEN_INET_ADDR */
  sinaddr.sin_addr.s_addr = inet_addr(c->address);
#endif /* BROKEN_INET_ADDR */
  if ((sinaddr.sin_addr.s_addr & 0xffffffff) == 0xffffffff)
    {
      close(c->sock);
      (*c->callback)(SSH_IP_NO_ADDRESS, NULL, c->context);
      ssh_xfree(c->address);
      ssh_xfree(c);
      return;
    }

  /* Make a blocking connect attempt. */
  ret = connect(c->sock, (struct sockaddr *)&sinaddr, sizeof(sinaddr));
  if (ret >= 0 || errno == EISCONN) /* Connection is ready. */
    {
      /* Successful connection. */
      (*c->callback)(SSH_IP_OK, ssh_stream_fd_wrap(c->sock, TRUE),
                     c->context);
      ssh_xfree(c->address);
      ssh_xfree(c);
      return;
    }

  /* Connection failed. */
  SSH_DEBUG(5, ("Connect failed: %s", strerror(errno)));
  error = SSH_IP_FAILURE;
#ifdef ENETUNREACH
  if (errno == ENETUNREACH)
    error = SSH_IP_UNREACHABLE;
#endif
#ifdef ECONNREFUSED
  if (errno == ECONNREFUSED)
    error = SSH_IP_REFUSED;
#endif
#ifdef EHOSTUNREACH
  if (errno == EHOSTUNREACH)
    error = SSH_IP_UNREACHABLE;
#endif
#ifdef ENETDOWN
  if (errno == ENETDOWN)
    error = SSH_IP_UNREACHABLE;
#endif
#ifdef ETIMEDOUT
  if (errno == ETIMEDOUT)
    error = SSH_IP_TIMEOUT;
#endif
    
  close(c->sock);
  ssh_xfree(c->address);
  (*c->callback)(error, NULL, c->context);
  ssh_xfree(c);
}

#else /* NO_NONBLOCKING_CONNECT */

void ssh_socket_low_connect_try(unsigned int events, void *context)
{
  LowConnect c = (LowConnect)context;
  int ret;
  struct sockaddr_in sinaddr;
  SshIpError error;
  
  memset(&sinaddr, 0, sizeof(sinaddr));
  sinaddr.sin_family = AF_INET;
  sinaddr.sin_port = htons(c->port);
  
#ifdef BROKEN_INET_ADDR
  sinaddr.sin_addr.s_addr = inet_network(c->address);
#else /* BROKEN_INET_ADDR */
  sinaddr.sin_addr.s_addr = inet_addr(c->address);
#endif /* BROKEN_INET_ADDR */
  if ((sinaddr.sin_addr.s_addr & 0xffffffff) == 0xffffffff)
    {
      ssh_io_unregister_fd(c->sock, FALSE);
      close(c->sock);
      (*c->callback)(SSH_IP_NO_ADDRESS, NULL, c->context);
      ssh_xfree(c->address);
      ssh_xfree(c);
      return;
    }

  /* Make a non-blocking connect attempt. */
  ret = connect(c->sock, (struct sockaddr *)&sinaddr, sizeof(sinaddr));
  if (ret >= 0 || errno == EISCONN) /* Connection is ready. */
    {
      /* Successful connection. */
      ssh_io_unregister_fd(c->sock, FALSE);
      (*c->callback)(SSH_IP_OK, ssh_stream_fd_wrap(c->sock, TRUE),
                     c->context);
      ssh_xfree(c->address);
      ssh_xfree(c);
      return;
    }
  if (errno == EINPROGRESS || errno == EWOULDBLOCK || errno == EALREADY)
    {
      /* Connection still in progress.  */
      ssh_io_set_fd_request(c->sock, SSH_IO_WRITE);
      return;
    }

  SSH_DEBUG(5, ("Connect failed: %s", strerror(errno)));
  /* Connection failed. */
  error = SSH_IP_FAILURE;
#ifdef ENETUNREACH
  if (errno == ENETUNREACH)
    error = SSH_IP_UNREACHABLE;
#endif
#ifdef ECONNREFUSED
  if (errno == ECONNREFUSED)
    error = SSH_IP_REFUSED;
#endif
#ifdef EHOSTUNREACH
  if (errno == EHOSTUNREACH)
    error = SSH_IP_UNREACHABLE;
#endif
#ifdef ENETDOWN
  if (errno == ENETDOWN)
    error = SSH_IP_UNREACHABLE;
#endif
#ifdef ETIMEDOUT
  if (errno == ETIMEDOUT)
    error = SSH_IP_TIMEOUT;
#endif
    
  ssh_io_unregister_fd(c->sock, FALSE);
  close(c->sock);
  ssh_xfree(c->address);

  (*c->callback)(error, NULL, c->context);
  ssh_xfree(c);
}

#endif /* NO_NONBLOCKING_CONNECT */

/* Connects to the given address/port, and makes a stream for it.
   The address to use is the first address from the list. */

void ssh_socket_low_connect(const char *address_list, unsigned int port,
                            SshTcpCallback callback, void *context)
{
  int sock, first_len;
  LowConnect c;

  /* Create a socket. */
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      (*callback)(SSH_IP_FAILURE, NULL, context);
      return;
    }

  /* Set SO_REUSEADDR. */
  ssh_socket_set_reuseaddr(sock);

  /* Compute the length of the first address on the list. */
  if (strchr(address_list, ','))
    first_len = strchr(address_list, ',') - address_list;
  else
    first_len = strlen(address_list);

  /* Save data in a context structure. */
  c = ssh_xmalloc(sizeof(*c));
  c->sock = sock;
  c->address = ssh_xmalloc(first_len + 1);
  memcpy(c->address, address_list, first_len);
  c->address[first_len] = '\0';
  c->port = port;
  c->callback = callback;
  c->context = context;

#ifdef NO_NONBLOCKING_CONNECT

  /* Try connect once.  Function calls user callback. */
  ssh_socket_low_connect_try_once(SSH_IO_WRITE, (void *)c);

#else /* NO_NONBLOCKING_CONNECT */

  /* Register it and request events. */
  ssh_io_register_fd(sock, ssh_socket_low_connect_try, (void *)c);
  ssh_io_set_fd_request(sock, SSH_IO_WRITE);

  /* Fake a callback to start asynchronous connect. */
  ssh_socket_low_connect_try(SSH_IO_WRITE, (void *)c);

#endif /* NO_NONBLOCKING_CONNECT */
}

/* --------- function for listening for connections ---------- */

struct SshTcpListenerRec
{
  int sock;
  char *path;
  SshTcpCallback callback;
  void *context;
};

/* This callback is called whenever a new connection is made to a listener
   socket. */

void ssh_tcp_listen_callback(unsigned int events, void *context)
{
  SshTcpListener listener = (SshTcpListener)context;
  int sock, addrlen;
  struct sockaddr_in sinaddr;

  if (events & SSH_IO_READ)
    {
      addrlen = sizeof(sinaddr);
      sock = accept(listener->sock, (struct sockaddr *)&sinaddr, &addrlen);
      if (sock < 0)
        {
          ssh_debug("ssh_tcp_listen_callback: accept failed");
          return;
        }

      /* Re-enable requests on the listener. */
      ssh_io_set_fd_request(listener->sock, SSH_IO_READ);
      
      /* Inform user callback of the new socket.  Note that this might
         destroy the listener. */
      (*listener->callback)(SSH_IP_NEW_CONNECTION,
                            ssh_stream_fd_wrap(sock, TRUE),
                            listener->context);
    }
}

/* Creates a socket that listens for new connections.  The address
   must be an ip-address in the form "nnn.nnn.nnn.nnn".  "0.0.0.0"
   indicates any host; otherwise it should be the address of some
   interface on the system.  The given callback will be called whenever
   a new connection is received at the socket.  This returns NULL on error. */

SshTcpListener ssh_tcp_make_listener(const char *local_address,
                                     const char *port_or_service,
                                     SshTcpCallback callback,
                                     void *context)
{
  int sock, port;
  struct sockaddr_in sinaddr;
  SshTcpListener listener;
  
  /* Parse port and address. */
  port = ssh_tcp_get_port_by_service(port_or_service, "tcp");
  memset(&sinaddr, 0, sizeof(sinaddr));
  sinaddr.sin_family = AF_INET;
  sinaddr.sin_port = htons(port);
  
#ifdef BROKEN_INET_ADDR
  sinaddr.sin_addr.s_addr = inet_network(local_address);
#else /* BROKEN_INET_ADDR */
  sinaddr.sin_addr.s_addr = inet_addr(local_address);
#endif /* BROKEN_INET_ADDR */
  if ((sinaddr.sin_addr.s_addr & 0xffffffff) == 0xffffffff)
    return NULL;

  /* Create a socket. */
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return NULL;

  ssh_socket_set_reuseaddr(sock);
  
  if (bind(sock, (struct sockaddr *)&sinaddr, sizeof(sinaddr)) < 0)
    {
      close(sock);
      return NULL;
    }

  if (listen(sock, 5) < 0)
    {
      close(sock);
      return NULL;
    }

  listener = ssh_xmalloc(sizeof(*listener));
  listener->sock = sock;
  listener->path = NULL;
  listener->callback = callback;
  listener->context = context;

  ssh_io_register_fd(sock, ssh_tcp_listen_callback, (void *)listener);
  ssh_io_set_fd_request(sock, SSH_IO_READ);

  return listener;
}

/* Destroys the socket.  It is safe to call this from a callback. */

void ssh_tcp_destroy_listener(SshTcpListener listener)
{
  ssh_io_unregister_fd(listener->sock, FALSE);
  close(listener->sock);
  if (listener->path)
    {
      /* Do not remove the listener here.  There are situations where we
         fork after creating a listener, and want to close it in one but not
         the other fork.  Thus, listeners should be removed by the application
         after they have been destroyed. */
      /* remove(listener->path); */
      ssh_xfree(listener->path);
    }
  ssh_xfree(listener);
}

/* Returns true (non-zero) if the socket behind the stream has IP options set.
   This returns FALSE if the stream is not a socket stream. */

Boolean ssh_tcp_has_ip_options(SshStream stream)
{
  int option_size, sock;
  char options[8192];

  sock = ssh_stream_fd_get_readfd(stream);
  if (sock == -1)
    return FALSE;
  option_size = sizeof(options);
  return getsockopt(sock, IPPROTO_IP, IP_OPTIONS, options,
                    &option_size) >= 0 && option_size != 0;
}

/* Returns the ip-address of the remote host, as string.  This returns
   FALSE if the stream is not a socket stream or buffer space is
   insufficient. */

Boolean ssh_tcp_get_remote_address(SshStream stream, char *buf, 
                                   size_t buflen)
{
  struct sockaddr_in saddr;
  int saddrlen, sock;

  sock = ssh_stream_fd_get_readfd(stream);
  if (sock == -1)
    return FALSE;

  saddrlen = sizeof(saddr);
  if (getpeername(sock, (struct sockaddr *)&saddr, &saddrlen) < 0)
    return 0;

  strncpy(buf, inet_ntoa(saddr.sin_addr), buflen);
  return TRUE;
}

/* Returns the remote port number, as a string.  This returns FALSE if the
   stream is not a socket stream or buffer space is insufficient. */

Boolean ssh_tcp_get_remote_port(SshStream stream, char *buf, 
                                size_t buflen)
{
  struct sockaddr_in saddr;
  int saddrlen, sock;

  sock = ssh_stream_fd_get_readfd(stream);
  if (sock == -1)
    return FALSE;

  saddrlen = sizeof(saddr);
  if (getpeername(sock, (struct sockaddr *)&saddr, &saddrlen) < 0)
    return 0;

  snprintf(buf, buflen, "%u", ntohs(saddr.sin_port));
  return TRUE;
}

/* Returns the ip-address of the local host, as string.  This returns FALSE
   if the stream is not a socket stream or buffer space is insufficient. */
Boolean ssh_tcp_get_local_address(SshStream stream, char *buf, 
                                  size_t buflen)
{
  struct sockaddr_in saddr;
  int saddrlen, sock;

  sock = ssh_stream_fd_get_readfd(stream);
  if (sock == -1)
    return FALSE;

  saddrlen = sizeof(saddr);
  if (getsockname(sock, (struct sockaddr *)&saddr, &saddrlen) < 0)
    return 0;

  strncpy(buf, inet_ntoa(saddr.sin_addr), buflen);
  return TRUE;
}

/* Returns the local port number, as a string.  This returns FALSE if the
   stream is not a socket stream or buffer space is insufficient. */
Boolean ssh_tcp_get_local_port(SshStream stream, char *buf, 
                               size_t buflen)
{
  struct sockaddr_in saddr;
  int saddrlen, sock;

  sock = ssh_stream_fd_get_readfd(stream);
  if (sock == -1)
    return FALSE;

  saddrlen = sizeof(saddr);
  if (getsockname(sock, (struct sockaddr *)&saddr, &saddrlen) < 0)
    return 0;

  snprintf(buf, buflen, "%u", ntohs(saddr.sin_port));
  return 1;
}

/* Sets/resets TCP options TCP_NODELAY for the socket.  */

Boolean ssh_socket_set_nodelay(SshStream stream, Boolean on)
{
#ifdef ENABLE_TCP_NODELAY
  int onoff = on, sock;

  sock = ssh_stream_fd_get_readfd(stream);
  if (sock == -1)
    return FALSE;

  return setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&onoff,
                    sizeof(onoff)) == 0;
#else /* ENABLE_TCP_NODELAY */
  return FALSE;
#endif /* ENABLE_TCP_NODELAY */
}  

Boolean ssh_socket_set_keepalive(SshStream stream, Boolean on)
{
  int onoff = on, sock;

  sock = ssh_stream_fd_get_readfd(stream);
  if (sock == -1)
    return FALSE;

#if defined (SOL_SOCKET) && defined (SO_KEEPALIVE)
  return setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&onoff,
                    sizeof(onoff)) == 0;
#else /* defined (SOL_SOCKET) && defined (SO_KEEPALIVE) */
  return FALSE;
#endif /* defined (SOL_SOCKET) && defined (SO_KEEPALIVE) */
}  

/* -------------- functions for name server lookups ------------------ */

/* Gets the name of the host we are running on.  To get the corresponding IP
   address(es), a name server lookup must be done using the functions below. */

void ssh_tcp_get_host_name(char *buf, size_t buflen)
{
#if !defined(HAVE_GETHOSTNAME) && defined(HAVE_UNAME)
  struct utsname uts;
#endif

#ifdef HAVE_GETHOSTNAME
  if (gethostname(buf, buflen) < 0)
    {
      ssh_debug("gethostname failed, buflen %u, errno %d", buflen, errno);
      strncpy(buf, "UNKNOWN", buflen);
    }
#else /* HAVE_GETHOSTNAME */
# ifdef HAVE_UNAME
  if (uname(&uts) < 0)
    {
      ssh_debug("uname failed: %s", strerror(errno));
      strncpy(buf, "UNKNOWN", buflen);
    }
  else
    strncpy(buf, uts.nodename, buflen);
# else /* HAVE_UNAME */
  strncpy(buf, "UNKNOWN", buflen);
# endif /* HAVE_UNAME */
#endif /* HAVE_GETHOSTNAME */
}

/* Looks up all ip-addresses of the host, returning them as a
   comma-separated list. The host name may already be an ip address,
   in which case it is returned directly. This is an simplification
   of function ssh_tcp_get_host_addrs_by_name for situations when
   the operation may block. 

   The function returns NULL if the name can not be resolved. When the
   return value is non null, it is a pointer to a string allocated by
   this function, and must be freed by the caller when no longer
   needed. */
char *ssh_tcp_get_host_addrs_by_name_sync(const char *name)
{
  char addresses[1024], *cp;
  unsigned char outbuf[16];
  struct in_addr in_addr;
  struct hostent *hp;
  size_t outbuflen = 4;
  int i;

  /* First check if it is already an ip address. */
  if (ssh_inet_strtobin(name, outbuf, &outbuflen))
    return ssh_xstrdup(name);

  /* Look up the host from the name servers. */
  hp = gethostbyname(name);
  if (!hp)
    return NULL;

  if (!hp->h_addr_list[0])
    return NULL;

  /* Format the addresses into a comma-separated string. */
  strcpy(addresses, "");
  for (i = 0; hp->h_addr_list[i]; i++)
    {
      memcpy(&in_addr, hp->h_addr_list[i], sizeof(in_addr));
      cp = inet_ntoa(in_addr);
      if (strlen(addresses) + strlen(cp) + 2 >= sizeof(addresses))
        break;
      if (i > 0)
        strcat(addresses, ",");
      strcat(addresses, cp);
    }
  return ssh_xstrdup(addresses);
}

/* Looks up all ip-addresses of the host, returning them as a
   comma-separated list when calling the callback.  The host name may
   already be an ip address, in which case it is returned directly. */

void ssh_tcp_get_host_addrs_by_name(const char *name, 
                                    SshLookupCallback callback,
                                    void *context)
{
  char *addrs; 

  addrs = ssh_tcp_get_host_addrs_by_name_sync(name);
  if (addrs)
    {
      (*callback)(SSH_IP_OK, addrs, context);
      ssh_xfree(addrs);
    }
  else
    (*callback)(SSH_IP_NO_ADDRESS, NULL, context);
}


/* Looks up the name of the host by its ip-address.  Verifies that the
   address returned by the name servers also has the original ip
   address. This is an simplification of function
   ssh_tcp_get_host_by_addr for situations when the operation may
   block.

   Function returns NULL, if the reverse lookup fails for some reason,
   or pointer to dynamically allocated memory containing the host
   name.  The memory should be deallocated by the caller when no
   longer needed.  */

char *ssh_tcp_get_host_by_addr_sync(const char *addr)
{
  char name[1024];
  size_t outbuflen = 4;
  struct hostent *hp;
  struct in_addr in_addr;
  unsigned char outbuf[16];
  int i;

  if (!ssh_inet_strtobin(addr, outbuf, &outbuflen))
    return NULL;

  memmove(&in_addr.s_addr, outbuf, outbuflen);
  hp = gethostbyaddr((char *)&in_addr, sizeof(struct in_addr), AF_INET);
  if (!hp)
    return NULL;

  /* Got host name. */
  strncpy(name, hp->h_name, sizeof(name));
  name[sizeof(name) - 1] = '\0';
  
  /* Map it back to an IP address and check that the given address
     actually is an address of this host.  This is necessary because
     anyone with access to a name server can define arbitrary names
     for an IP address.  Mapping from name to IP address can be
     trusted better (but can still be fooled if the intruder has
     access to the name server of the domain). */
  hp = gethostbyname(name);
  if (!hp)
    return NULL;
  
  /* Look for the address from the list of addresses. */
  for (i = 0; hp->h_addr_list[i]; i++)
    if (memcmp(hp->h_addr_list[i], &in_addr, sizeof(in_addr)) == 0)
      break;
  /* If we reached the end of the list, the address was not there. */
  if (!hp->h_addr_list[i])
    return NULL;

  /* Address was found for the host name.  We accept the host name. */
  return ssh_xstrdup(name);
} 

/* Looks up the name of the host by its ip-address.  Verifies that the
   address returned by the name servers also has the original ip address.
   Calls the callback with either error or success.  The callback should
   copy the returned name. */

void ssh_tcp_get_host_by_addr(const char *addr, 
                              SshLookupCallback callback,
                              void *context)
{
  char *name; 

  name = ssh_tcp_get_host_by_addr_sync(addr);
  if (name)
    {
      (*callback)(SSH_IP_OK, name, context);
      ssh_xfree(name);
    }
  else
    (*callback)(SSH_IP_NO_ADDRESS, NULL, context);
}

/* Looks up the service (port number) by name and protocol.  `protocol' must
   be either "tcp" or "udp".  Returns -1 if the service could not be found. */

int ssh_tcp_get_port_by_service(const char *name, const char *proto)
{
#ifdef HAVE_GETSERVBYNAME
  const char *cp;
  struct servent *se;
  int port;
  
  for (cp = name; isdigit(*cp); cp++)
    ;
  if (!*cp && *name)
    return atoi(name);
  se = getservbyname(name, proto);
  if (!se)
    return -1;
  port = ntohs(se->s_port);
  endservent();
  return port;
#else  /* HAVE_GETSERVBYNAME */
  return -1;
#endif /* HAVE_GETSERVBYNAME */
}

/* Looks up the name of the service based on port number and protocol.
   `protocol' must be either "tcp" or "udp".  The name is stored in the
   given buffer; is the service is not found, the port number is stored
   instead (without the protocol specification).  The name will be
   truncated if it is too long. */

void ssh_tcp_get_service_by_port(unsigned int port, const char *proto,
                                 char *buf, size_t buflen)
{
#ifdef HAVE_GETSERVBYPORT
  struct servent *se;

  se = getservbyport(htons(port), proto);
  if (!se)
    snprintf(buf, buflen, "%u", port);
  else
    strncpy(buf, se->s_name, buflen);
  endservent();
#else /* HAVE_GETSERVBYPORT */
  snprintf(buf, buflen, "%u", port);
#endif /* HAVE_GETSERVBYPORT */
}

/* --------------------- auxiliary functions -------------------------*/



/* Compares two port number addresses, and returns <0 if port1 is smaller,
   0 if they denote the same number (though possibly written differently),
   and >0 if port2 is smaller.  The result is zero if either address is
   invalid. */
int ssh_socket_port_number_compare(const char *port1, const char *port2,
                                   const char *proto)
{
  int nport1, nport2;
  
  nport1 = ssh_tcp_get_port_by_service(port1, proto);
  nport2 = ssh_tcp_get_port_by_service(port2, proto);
  
  if (nport1 == -1 || nport2 == -1)
    return 0;
  if (nport1 == nport2)
    return 0;
  else
    if (nport1 < nport2)
      return -1;
    else
      return 1;
}
