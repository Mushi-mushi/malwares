/*

sshunixunlocalstream.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Implementation of local streams for Unix.

*/

#include "sshincludes.h"

#ifdef HAVE_SYS_UN_H

#include "sshlocalstream.h"
#include "sshunixeloop.h"
#include "sshunixfdstream.h"

#include <sys/socket.h>
#include <sys/un.h>

struct SshLocalListenerRec {
  int sock;
  char *path;
  SshLocalCallback callback;
  void *context;
};


/* This callback is called whenever a new connection is made to a listener
   socket. */

void ssh_local_listen_callback(unsigned int events, void *context)
{
  SshLocalListener listener = (SshLocalListener)context;
  int sock, addrlen;
  struct sockaddr_un sunaddr;

  if (events & SSH_IO_READ)
    {
      addrlen = sizeof(sunaddr);
      sock = accept(listener->sock, (struct sockaddr *)&sunaddr, &addrlen);
      if (sock < 0)
	{
	  ssh_debug("ssh_local_listen_callback: accept failed");
	  return;
	}

      /* Re-enable requests on the listener. */
      ssh_io_set_fd_request(listener->sock, SSH_IO_READ);
      
      /* Inform user callback of the new socket.  Note that this might
         destroy the listener. */
      (*listener->callback)(ssh_stream_fd_wrap(sock, TRUE), listener->context);
    }
}

/* Creates a local listener for receiving connections to the supplied
   path.  If there already is a listener for the specified path, this
   fails.  Otherwise, this reserves the given pathname, and any
   connect requests with the same path will result in a call to the
   supplied callback.  The listener created by this is only accessible
   from within the local machine.  The implementation must provide the
   necessary access control mechanisms to guarantee that connections
   cannot be made from outside the local machine. */

SshLocalListener ssh_local_make_listener(const char *path,
					 SshLocalCallback callback,
					 void *context)
{
  int sock;
  struct sockaddr_un sunaddr;
  SshLocalListener listener;

  /* Create a socket for the listener. */
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
      ssh_warning("Can not create local domain socket: %.200s", 
		  strerror(errno));
      return NULL;

    }

  /* Initialize a unix-domain address structure. */
  memset(&sunaddr, 0, sizeof(sunaddr));
  sunaddr.sun_family = AF_UNIX;
  strncpy(sunaddr.sun_path, path, sizeof(sunaddr.sun_path));

  /* Bind the socket to the address.  This will create the socket in the file
     system, and will fail if the socket already exists. */
  if (bind(sock, (struct sockaddr *)&sunaddr, AF_UNIX_SIZE(sunaddr)) < 0)
    {
      close(sock);
      ssh_warning("Can not bind local address %.200s: %.200s", 
		  path, strerror(errno));
      return NULL;
    }
  
  /* Start listening for connections to the socket. */
  if (listen(sock, 5) < 0)
    {
      close(sock);
      ssh_warning("Can not listen to local address %.200s: %.200s", 
		  path, strerror(errno));
      return NULL;
    }

  /* Allocate and initialize the listener structure. */
  listener = ssh_xmalloc(sizeof(*listener));
  listener->sock = sock;
  listener->path = ssh_xstrdup(path);
  listener->callback = callback;
  listener->context = context;  

  /* ssh_local_listen_callback will call the user supplied callback
     when after new connection is accepted. It also creates stream
     object for the new connection and calls callback. */
  ssh_io_register_fd(sock, ssh_local_listen_callback, (void *)listener);
  ssh_io_set_fd_request(sock, SSH_IO_READ);
  
  return listener;
}

/* Context structure for connecting to the listener. */

typedef struct SshLocalConnectRec
{
  int sock;
  char *path;
  SshLocalCallback callback;
  void *context;
} *SshLocalConnect;

/* This function is called whenever something happens with our asynchronous
   connect attempt.  This is also used for the starting the operation
   initially. */

void ssh_local_connect_try(unsigned int events, void *context)
{
  SshLocalConnect c = (SshLocalConnect)context;
  int ret;
  struct sockaddr_un sunaddr;
  
  /* Initialize the address to connect to. */
  memset(&sunaddr, 0, sizeof(sunaddr));
  sunaddr.sun_family = AF_UNIX;
  strncpy(sunaddr.sun_path, c->path, sizeof(sunaddr.sun_path));

  /* Make a non-blocking connect attempt. */
  ret = connect(c->sock, (struct sockaddr *)&sunaddr, AF_UNIX_SIZE(sunaddr));
  if (ret >= 0 || errno == EISCONN) /* Connection is ready. */
    {
      /* Successful connection. */
      ssh_io_unregister_fd(c->sock, FALSE);
      (*c->callback)(ssh_stream_fd_wrap(c->sock, TRUE), c->context);
      ssh_xfree(c->path);
      ssh_xfree(c);
      return;
    }
  if (errno == EINPROGRESS || errno == EWOULDBLOCK || errno == EALREADY)
    {
      /* Connection still in progress.  */
      ssh_io_set_fd_request(c->sock, SSH_IO_WRITE);
      return;
    }

  /* Connection failed. */
  ssh_io_unregister_fd(c->sock, FALSE);
  close(c->sock);
  (*c->callback)(NULL, c->context);
  ssh_xfree(c->path);
  ssh_xfree(c);
}

/* Destroys the local listener.  However, this might leave entries in
   the file system on some systems.  (For example, in Unix this does
   not remove the unix-domain socket, as this might be called after a
   fork, and we might wish to continue receiving connections in the
   other fork.)  Thus, it is recommended that remove() be called for
   the path to ensure that any garbage has been removed.  (The remove
   call should probably be made just before creating a new listener,
   in case the application has previously crashed before destroying
   the listener). */

void ssh_local_destroy_listener(SshLocalListener listener)
{
  ssh_io_unregister_fd(listener->sock, FALSE);
  close(listener->sock);
  ssh_xfree(listener->path);
  ssh_xfree(listener);
}

/* Connects to the local listener with the given path.  The callback
   will be colled when the connection is complete or has failed. If
   the connection is successful, an SshStream object is created and
   passed to the callback.  If connecting fails, NULL is passed to the
   callback as the stream. */

void ssh_local_connect(const char *path,
		       SshLocalCallback callback,
		       void *context)
{
  int sock;
  SshLocalConnect c;

  /* Create a unix-domain socket. */
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
      /* Failed to create the socket. */
      (*callback)(NULL, context);
      return;
    }

  /* Allocate and initialize a context structure. */
  c = ssh_xmalloc(sizeof(*c));
  c->path = ssh_xstrdup(path);
  c->sock = sock;
  c->callback = callback;
  c->context = context;
  
  /* Register the file descriptor.  Note that this also makes it
     non-blocking. */
  ssh_io_register_fd(sock, ssh_local_connect_try, c);

  /* Fake a callback to start asynchronous connect. This connect could be
     done on this current routine, but we want this to be similar with 
     tcp/ip socket code, so we use the try-routines */
  ssh_local_connect_try(SSH_IO_WRITE, (void *)c);
}

#endif /* HAVE_SYS_UN_H */
