/*

Author: Tatu Ylonen <ylo@ssh.fi>
        Antti Huima <huima@ssh.fi>

Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
All rights reserved.

Interface to sockets.

*/

/*
 * $Id: sshtcp.h,v 1.18 1999/04/28 13:20:03 tri Exp $
 * $Log: sshtcp.h,v $
 * $EndLog$
 */

#ifndef SSHTCP_H
#define SSHTCP_H

#include "sshinet.h"
#include "sshstream.h"

typedef enum {
  /* The connection or lookup was successful. */
  SSH_IP_OK = 0,

  /* A new connection has been received.  This result code is only given
     to listeners. */
  SSH_IP_NEW_CONNECTION,

  /* No address could be found the host. */
  SSH_IP_NO_ADDRESS,

  /* The address has no name. */
  SSH_IP_NO_NAME,

  /* The destination is unreachable; this could indicate a routing problem,
     the host being off, or something similar. */
  SSH_IP_UNREACHABLE,

  /* The destination refused the connection (i.e., is not listening on
     the specified port). */
  SSH_IP_REFUSED,

  /* A timeout occurred.  This could indicate a network problem. */
  SSH_IP_TIMEOUT,

  /* An operation has failed.  This is a catch-all error used when none of the
     other codes is appropriate. */
  SSH_IP_FAILURE
} SshIpError;

/* Convert TCP error to string */
DLLEXPORT char * DLLCALLCONV
ssh_tcp_error_string(SshIpError error);

/* Callback function for socket creation.  The given function is called when
   a connection is ready. */
typedef void (*SshTcpCallback)(SshIpError error,
                               SshStream stream,
                               void *context);
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
   `socks_server_url' specifies the SOCKS host, port, username and socks
   network exceptions. If `socks_server_url' is NULL or
   empty, the connection will be made without SOCKS.  If port is not given in
   the url, the default SOCKS port (1080) will be used.  

   `connection_attempts' specifies the number of times to attempt the
   connection before giving up.  (Some systems appear to spuriously fail
   connections without apparent reason, and retrying usually succeeds in
   those cases). */
DLLEXPORT void DLLCALLCONV
ssh_tcp_connect_with_socks(const char *host_name_or_address,
                           const char *port_or_service,
                           const char *socks_server_url,
                           unsigned int connection_attempts,
                           SshTcpCallback callback,
                           void *context);

/* Opens a connection to the specified host, and calls the callback
   when the connection has been established or has failed.  If
   connecting is successful, the callback will be called with error
   set to SSH_TCP_OK and an SshStream object for the connection passed
   in in the stream argument.  Otherwise, error will indicate the
   reason for the connection failing, and the stream will be NULL. */
DLLEXPORT void DLLCALLCONV
ssh_tcp_connect(const char *host_name_or_address,
                const char *port_or_service,
                SshTcpCallback callback,
                void *context);

/* --------- function for listening for connections ---------- */

typedef struct SshTcpListenerRec *SshTcpListener;

/* Creates a socket that listens for new connections.  The address
   must be an ip-address in the form "nnn.nnn.nnn.nnn".  "0.0.0.0"
   indicates any host; otherwise it should be the address of some
   interface on the system.  The given callback will be called whenever
   a new connection is received at the socket.  This returns NULL on error. */
DLLEXPORT SshTcpListener DLLCALLCONV
ssh_tcp_make_listener(const char *local_address,
                      const char *port_or_service,
                      SshTcpCallback callback,
                      void *context);

/* Destroys the socket.  It is safe to call this from a callback.  If
   the listener was local, and a socket was created in the file system, this
   does not automatically remove the socket (so that it is possible to close
   the other copy after a fork).  The application should call remove() for the
   socket path when no longer needed. */
DLLEXPORT void DLLCALLCONV
ssh_tcp_destroy_listener(SshTcpListener listener);

/* Returns true (non-zero) if the socket behind the stream has IP options set.
   This returns FALSE if the stream is not a socket stream. */
DLLEXPORT Boolean DLLCALLCONV
ssh_tcp_has_ip_options(SshStream stream);

/* Returns the ip-address of the remote host, as string.  This returns
   FALSE if the stream is not a socket stream or buffer space is
   insufficient. */
DLLEXPORT Boolean DLLCALLCONV
ssh_tcp_get_remote_address(SshStream stream, char *buf, size_t buflen);

/* Returns the remote port number, as a string.  This returns FALSE if the
   stream is not a socket stream or buffer space is insufficient. */
DLLEXPORT Boolean DLLCALLCONV
ssh_tcp_get_remote_port(SshStream stream, char *buf, size_t buflen);

/* Returns the ip-address of the local host, as string.  This returns FALSE
   if the stream is not a socket stream or buffer space is insufficient. */
DLLEXPORT Boolean DLLCALLCONV
ssh_tcp_get_local_address(SshStream stream, char *buf, size_t buflen);

/* Returns the local port number, as a string.  This returns FALSE if the
   stream is not a socket stream or buffer space is insufficient. */
DLLEXPORT Boolean DLLCALLCONV
ssh_tcp_get_local_port(SshStream stream, char *buf, size_t buflen);

/* -------------- functions for name server lookups ------------------ */

/* Gets the name of the host we are running on.  To get the corresponding IP
   address(es), a name server lookup must be done using the functions below. */
DLLEXPORT void DLLCALLCONV
ssh_tcp_get_host_name(char *buf, size_t buflen);

/* Callback function for name server lookups.  The function
   should copy the result; the argument string is only valid until this
   call returns.  The result is only valid if error is SSH_IP_OK. */
typedef void (*SshLookupCallback)(SshIpError error,
                                  const char *result,
                                  void *context);



/* Looks up all ip-addresses of the host, returning them as a
   comma-separated list. The host name may already be an ip address,
   in which case it is returned directly. This is an simplification
   of function ssh_tcp_get_host_addrs_by_name for situations when
   the operation may block. 

   The function returns NULL if the name can not be resolved. When the
   return value is non null, it is a pointer to a string allocated by
   this function, and must be freed by the caller when no longer
   needed. */
DLLEXPORT char * DLLCALLCONV
ssh_tcp_get_host_addrs_by_name_sync(const char *name);

/* Looks up all ip-addresses of the host, returning them as a comma-separated
   list when calling the callback.  The host name may already be an ip
   address, in which case it is returned directly. */
DLLEXPORT void DLLCALLCONV
ssh_tcp_get_host_addrs_by_name(const char *name, 
                               SshLookupCallback callback,
                               void *context);

/* Looks up the name of the host by its ip-address.  Verifies that the
   address returned by the name servers also has the original ip
   address. This is an simplification of function
   ssh_tcp_get_host_by_addr for situations when the operation may
   block.

   Function returns NULL, if the reverse lookup fails for some reason,
   or pointer to dynamically allocated memory containing the host
   name.  The memory should be deallocated by the caller when no
   longer needed.  */
DLLEXPORT char * DLLCALLCONV
ssh_tcp_get_host_by_addr_sync(const char *addr);

/* Looks up the name of the host by its ip-address.  Verifies that the
   address returned by the name servers also has the original ip address.
   Calls the callback with either error or success.  The callback should
   copy the returned name. */
DLLEXPORT void DLLCALLCONV
ssh_tcp_get_host_by_addr(const char *addr, SshLookupCallback callback,
                         void *context);

/* Looks up the service (port number) by name and protocol.  `protocol' must
   be either "tcp" or "udp".  Returns -1 if the service could not be found. */
DLLEXPORT int DLLCALLCONV
ssh_tcp_get_port_by_service(const char *name, const char *proto);

/* Looks up the name of the service based on port number and protocol.
   `protocol' must be either "tcp" or "udp".  The name is stored in the
   given buffer; is the service is not found, the port number is stored
   instead (without the protocol specification).  The name will be
   truncated if it is too long. */
DLLEXPORT void DLLCALLCONV
ssh_tcp_get_service_by_port(unsigned int port, const char *protocol,
                            char *buf, size_t buflen);

/* --------------------- functions for socket options ----------------*/

/* Sets/resets TCP options TCP_NODELAY for the socket.  This returns TRUE on
   success. */
DLLEXPORT Boolean DLLCALLCONV
ssh_socket_set_nodelay(SshStream stream, Boolean on);

/* Sets/resets TCP options SO_KEEPALIVE for the socket.  This returns TRUE on
   success. */
DLLEXPORT Boolean DLLCALLCONV
ssh_socket_set_keepalive(SshStream stream, Boolean on);

/* Compares two port number addresses, and returns <0 if port1 is smaller,
   0 if they denote the same number (though possibly written differently),
   and >0 if port2 is smaller.  The result is zero if either address is
   invalid. */
DLLEXPORT int DLLCALLCONV
ssh_socket_port_number_compare(const char *port1, const char *port2,
                               const char *proto);

#endif /* SSHTCP_H */
