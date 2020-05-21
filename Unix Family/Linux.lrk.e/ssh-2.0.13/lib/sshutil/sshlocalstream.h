/*

sshlocalstream.h

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Local streams between two processes running on the same machine.
These may correspond to e.g. named pipes, unix-domain sockets, or some
other form of inter-process communication, depending on the system.
Listeners with these streams are identified with file names.

*/

#ifndef SSHLOCALSTREAM_H
#define SSHLOCALSTREAM_H

#include "sshstream.h"

/* Data type for a local listener. */
typedef struct SshLocalListenerRec *SshLocalListener;

/* Type for a callback function to be called when a local listener receives
   a connection or when connecting to a local listener is complete. */
typedef void (*SshLocalCallback)(SshStream stream, void *context);

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
					 void *context);

/* Destroys the local listener.  However, this might leave entries in
   the file system on some systems.  (For example, in Unix this does
   not remove the unix-domain socket, as this might be called after a
   fork, and we might wish to continue receiving connections in the
   other fork.)  Thus, it is recommended that remove() be called for
   the path to ensure that any garbage has been removed.  (The remove
   call should probably be made just before creating a new listener,
   in case the application has previously crashed before destroying
   the listener). */
void ssh_local_destroy_listener(SshLocalListener listener);

/* Connects to the local listener with the given path.  The callback
   will be colled when the connection is complete or has failed. If
   the connection is successful, an SshStream object is created and
   passed to the callback.  If connecting fails, NULL is passed to the
   callback as the stream. */
void ssh_local_connect(const char *path,
		       SshLocalCallback callback,
		       void *context);

#endif /* SSHLOCALSTREAM_H */
