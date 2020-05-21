/*

sshfilexfer.h

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

This interface implements a simple file sharing protocol across a
SshStream channel.  It can be used in implementing file transfer, file
sharing, or other data copying over any stream.

*/

#ifndef SSHFILEXFER_H
#define SSHFILEXFER_H

#include "sshstream.h"

/* Data type for the file transfer client. */
typedef struct SshFileClientRec *SshFileClient;

/* Attribute flags.  These are used to specify which attributes are
   present. */
#define SSH_FILEXFER_ATTR_SIZE          0x01
#define SSH_FILEXFER_ATTR_UIDGID        0x02
#define SSH_FILEXFER_ATTR_PERMISSIONS   0x04
#define SSH_FILEXFER_ATTR_ACMODTIME     0x08

/* Data structure for representing file attributes. */

typedef struct SshFileAttributesRec {
  /* Flags that specify which attributes are present. */
  unsigned int flags;

  /* Size of the file. */
  off_t size;

  /* User id owning the file. */
  uid_t uid;

  /* Group id owning the file. */
  gid_t gid;

  /* Time of last modification. */
  SshTime mtime;

  /* Time of last access. */
  SshTime atime;
  
  /* Permissions of the file.  This is in unix format. */
  unsigned long permissions;
} *SshFileAttributes;

/* Data type for a file handle. */
typedef struct SshFileHandleRec *SshFileHandle;

/* Data type for status returns by various functions in this module.
   These values are typically passed to the callback when the operation
   completes. */
typedef enum {
  /* The operation completed successfully. */
  SSH_FX_OK,

  /* The operation failed because of trying to read at end of file. */
  SSH_FX_EOF,
  
  /* The requested file does not exist. */
  SSH_FX_NO_SUCH_FILE,

  /* Insufficient privileges to perform the operation. */
  SSH_FX_PERMISSION_DENIED,

  /* The requested operation failed for some other reason. */
  SSH_FX_FAILURE,
  
  /* A badly formatted message was received.  This indicates an error or
     incompatibility in the protocol implementation. */
  SSH_FX_BAD_MESSAGE,

  /* Connection has not been established (yet) */
  SSH_FX_NO_CONNECTION,
  
  /* Connection to the server was lost, and the operation could not be
     performed. */
  SSH_FX_CONNECTION_LOST
} SshFileClientError;

/***********************************************************************
 * Common functions for client and server
 ***********************************************************************/

/* Duplicate a SshFileAttributes-structure.
 */
SshFileAttributes ssh_file_attributes_dup(SshFileAttributes attributes);

/***********************************************************************
 * Client-side functions
 ***********************************************************************/

/* Callback function for returning only the status of the command. */
typedef void (*SshFileStatusCallback)(SshFileClientError error,
                                      void *context);

/* Callback function for returning file handles. */
typedef void (*SshFileHandleCallback)(SshFileClientError error,
                                      SshFileHandle handle,
                                      void *context);

/* Callback function for returning data. */
typedef void (*SshFileDataCallback)(SshFileClientError error,
                                    const unsigned char *data,
                                    size_t len,
                                    void *context);

/*
 * Callback function for returning file names. 
 * 
 * long_name      "long" description of the file.. intepretation
 *                is host specific. 
 */

typedef void (*SshFileNameCallback)(SshFileClientError error,
                                    const char *name,
                                    const char *long_name,
                                    SshFileAttributes attrs,
                                    void *context);

/* Callback function for returning file attributes. */
typedef void (*SshFileAttributeCallback)(SshFileClientError error,
                                         SshFileAttributes attributes,
                                         void *context);

/* This function wraps a communications channel into a file transfer client.
   This takes over the stream, and it should no longer be used directly.
   This returns an object that represents the file transfer client. */
SshFileClient ssh_file_client_wrap(SshStream stream);

/* Closes the file transfer client.  Any outstanding requests are silently
   terminated without calling their callbacks. */
void ssh_file_client_destroy(SshFileClient client);

/* Sends a request to open a file, and calls the given callback when
   complete.  The callback will be called either during this call or
   any time later.  Attributes may be NULL to use default values. */
void ssh_file_client_open(SshFileClient client,
                          const char *name,
                          unsigned int flags,
                          SshFileAttributes attributes,
                          SshFileHandleCallback callback,
                          void *context);

/* Sends a read request, and calls the given callback when complete.  The
   callback will be called either during this call or any time later. */
void ssh_file_client_read(SshFileHandle handle,
                          off_t offset,
                          size_t len,
                          SshFileDataCallback callback,
                          void *context);

/* Sends a write request, and calls the given callback when complete.  The
   callback will be called either during this call or any time later. */
void ssh_file_client_write(SshFileHandle handle,
                           off_t offset,
                           const unsigned char *buf,
                           size_t len,
                           SshFileStatusCallback callback,
                           void *context);

/* Sends a close request, and calls the given callback when complete.  The
   callback will be called either during this call or any time later. */
void ssh_file_client_close(SshFileHandle handle,
                           SshFileStatusCallback callback,
                           void *context);

/* Sends a stat request, and calls the given callback when complete.  The
   callback will be called either during this call or any time later. */
void ssh_file_client_stat(SshFileClient client,
                          const char *name,
                          SshFileAttributeCallback callback,
                          void *context);

/* Sends a lstat request, and calls the given callback when complete.  The
   callback will be called either during this call or any time later. */
void ssh_file_client_lstat(SshFileClient client,
                          const char *name,
                          SshFileAttributeCallback callback,
                           void *context);

/* Sends an fstat request, and calls the given callback when complete.  The
   callback will be called either during this call or any time later. */
void ssh_file_client_fstat(SshFileHandle handle,
                           SshFileAttributeCallback callback,
                           void *context);

/* Sends a setstat request, and calls the given callback when complete.  The
   callback will be called either during this call or any time later.
   Setstat requests can be used to implement e.g. chown and chmod. */
void ssh_file_client_setstat(SshFileClient client,
                             const char *name,
                             SshFileAttributes attributes,
                             SshFileStatusCallback callback,
                             void *context);

/* Sends an fsetstat request, and calls the given callback when complete.  The
   callback will be called either during this call or any time later.
   Fsetstat requests can be used to implement e.g. fchown and fchmod. */
void ssh_file_client_fsetstat(SshFileHandle handle,
                              SshFileAttributes attributes,
                              SshFileStatusCallback callback,
                              void *context);

/* Sends an opendir request, and calls the given callback when complete.  The
   callback will be called either during this call or any time later.
   The path should point to a directory.  An empty string refers to the
   current directory. */
void ssh_file_client_opendir(SshFileClient client,
                             const char *name,
                             SshFileHandleCallback callback,
                             void *context);

/* Sends a readdir request, and calls the given callback when
   complete.  The callback will be called either during this call or
   any time later.  This returns one name at a time.  Only the last
   component of the name is returned (i.e., the name stored in the
   directory). */
void ssh_file_client_readdir(SshFileHandle handle,
                             SshFileNameCallback callback,
                             void *context);

/* Sends a request to remove the given file.  This cannot be used to
   remove directories.  The callback will be called either during this call
   or any time later. */
void ssh_file_client_remove(SshFileClient client,
                            const char *name,
                            SshFileStatusCallback callback,
                            void *context);

/* Sends a requst to create the named directory, and calls the given callback
   when complete.  The callback will be called either during this call
   or any time later.  Attrs may be NULL to use default values. */
void ssh_file_client_mkdir(SshFileClient client,
                           const char *name,
                           SshFileAttributes attrs,
                           SshFileStatusCallback callback,
                           void *context);

/* Sends a request to remove the given directory.  This cannot be used to
   remove normal files.  The callback will be called either during this
   call or any time later. */
void ssh_file_client_rmdir(SshFileClient client,
                           const char *name,
                           SshFileStatusCallback callback,
                           void *context);

/* Asks the server side to resolve a path */

void ssh_file_client_realpath(SshFileClient client,
                              const char *path,
                              SshFileNameCallback callback,
                              void *context);

/***********************************************************************
 * Server-side functions
 ***********************************************************************/

/* Data type representing the server object. */
typedef struct SshFileServerRec *SshFileServer;

/* Wraps the given communications channel into a file transfer server.
   The server is automatically destroyed when the connection is closed. */
SshFileServer ssh_file_server_wrap(SshStream stream);


/* Internal definitions */

#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif

char *ssh_realpath(const char *path, char *resolved);



#endif /* SSHFILEXFER_H */
