/*

sshfilexferc.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Generic file transfer module, client side.

*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshpacketstream.h"
#include "sshfilexfer.h"
#include "sshfilexferi.h"

/* Enumerated type for indicating what kind of a reply we are
   expecting for a server. */

typedef enum {
  /* Expecting SSH_FXP_HANDLE or SSH_FXP_STATUS reply. */
  SSH_FILEXFER_HANDLE_REPLY,

  /* Expecting SSH_FXP_STATUS reply. */
  SSH_FILEXFER_STATUS_REPLY,

  /* Expecting SSH_FXP_DATA or SSH_FXP_STATUS reply. */
  SSH_FILEXFER_DATA_REPLY,

  /* Expecting SSH_FXP_NAME or SSH_FXP_STATUS reply. */
  SSH_FILEXFER_NAME_REPLY,

  /* Expecting SSH_FXP_ATTRS or SSH_FXP_STATUS reply. */
  SSH_FILEXFER_ATTRS_REPLY
} SshFileClientExpect;

/* Internal data structure for a file handle.  File handles are essentially
   binary strings. */

struct SshFileHandleRec
{
  /* Value of the handle.  The value is not null-terminated.  The value is
     allocated with ssh_xmalloc. */
  unsigned char *value;

  /* Length of the value in bytes. */
  size_t len;

  /* Back-pointer to the client object. */
  SshFileClient client;
  
  /* An array of cached names during readdir. */
  unsigned int num_names;
  unsigned int next_name;
  char **names;
  char **long_names;
  SshFileAttributes *attrs;
};

/* Data structure for an outstanding request.  Some requests have already been
   sent to the server, some may be waiting to be sent, as determined by
   the list that the request is on. */

typedef struct SshFileClientRequestRec
{
  /* Pointer to next request in the list.  The 'next' field of the last
     request in the list is NULL. */
  struct SshFileClientRequestRec *next;

  /* Identifier for this request.  The identifier is effectively a
     monotonically increasing sequence number.  Replies from the server
     will carry the same identifier, and it is used to find the corresponding
     request. */
  SshUInt32 id;

  /* Pointer to the encoded request message that should be or has been sent
     to the server.  This value has been allocated with ssh_xmalloc. */
  unsigned char *request;

  /* Length of the encoded request in bytes. */
  size_t request_len;

  /* Type of the packet for the request. */
  unsigned int packet_type;

  /* Type of the expected reply packet. */
  SshFileClientExpect expected_reply;

  /* Various types of callback functions.  Only one of these will be set,
     as determined by `expected_reply'.  The others will be set to NULL.
     The callback might be called either during the initial request function,
     or later from the bottom of the event loop. */
  SshFileHandleCallback handle_callback;
  SshFileStatusCallback status_callback;
  SshFileDataCallback data_callback;
  SshFileNameCallback name_callback;
  SshFileAttributeCallback attribute_callback;

  /* Context argument for the callback function. */
  void *context;

  /* File handle related to this request (for readdir only). */
  SshFileHandle handle;
} *SshFileClientRequest;

/* Internal data structure for the file transfer protocol client side. */

struct SshFileClientRec
{
  /* The packet stream object that is used for communication.  This hides
     the actual SshStream used for communication. */
  SshPacketWrapper conn;

  /* Boolean value indicating whether a version number has been received from
     the remote side.  This is set to TRUE when the version number has been
     received and `version' field has been set.  No other processing can
     take place before the version number has been received. */
  Boolean version_received;

  /* Negotiated version number for the connection.  This is the lower of the
     version numbers of the server and the client.  This is only valid
     after version_received has been set. */
  SshUInt32 version;

  /* The next unused request id.  This is used to generate request identifiers,
     and is incremented by one every time a new identifier is allocated.
     There is currently no check for this wrapping around; it is simply
     assumed that if it ever happens, the old requests will have been
     completed by then. */
  SshUInt32 next_id;

  /* Linked list of requests that have been sent but for which no answer
     has been received yet. */
  SshFileClientRequest sent_requests;

  /* Linked list of requests that have been issued but that have not yet been
     sent for one reason or another (typically because the link is saturated
     and cannot receive more requests at this time). */
  SshFileClientRequest queued_requests;

  /* Flag indicating that EOF has been received from the other end.  When this
     happens, all outstanding requests are immediately completed with an
     error, and this flag is set.  This flag causes all future requests
     to fail immediately. */
  Boolean eof_received;
};

/* Frees the given request data structure. */

void ssh_file_client_free_request(SshFileClientRequest request)
{
  if (request->request)
    ssh_xfree(request->request);
  ssh_xfree(request);
}

/* Tries to send queued requests to the server. */

void ssh_file_client_try_send(SshFileClient client)
{
  SshFileClientRequest request;

  /* If we haven't yet received the version number from the client,
     keep everything in the queue.  XXX Actually, the request should be
     recomputed after the version is received, as the packet layout
     might depend on the version. */
  if (!client->version_received)
    return;
  
  /* Loop as long as we have requests to send. */
  while (client->queued_requests != NULL)
    {
      /* If buffers are full, stop sending.  We will be called again
         from a callback when sending is again possible. */
      if (!ssh_packet_wrapper_can_send(client->conn))
        return;

      /* Take a request from the queue. */
      request = client->queued_requests;
      client->queued_requests = request->next;

      /* Send the request to the other side. */
      ssh_packet_wrapper_send(client->conn, request->packet_type,
                              request->request, request->request_len);

      /* Put the request in the waiting queue. */
      request->next = client->sent_requests;
      client->sent_requests = request;
    }
}

/* Looks up a request with the specified id from the client's sent_requests
   list.  Removes the request from the list and returns it. */

SshFileClientRequest ssh_file_client_find_request(SshFileClient client,
                                                  unsigned int id)
{
  SshFileClientRequest request, *requestp;

  /* Look for a request with the given id. */
  for (requestp = &client->sent_requests; *requestp;
       requestp = &(*requestp)->next)
    if ((*requestp)->id == id)
      break;

  /* Remove the matching request from the list. */
  request = *requestp;
  *requestp = request->next;

  return request;
}
  
/* Call the callback of the request, returning the specified status.  This
   is typically used for status replies. */
  
void ssh_file_client_return_status(SshFileClient client,
                                   unsigned int id,
                                   SshFileClientError error)
{
  SshFileClientRequest request;

  /* Look up a matching request. */
  request = ssh_file_client_find_request(client, id);

  /* Check if a request was found. */
  if (request == NULL)
    {
      ssh_warning("ssh_file_client_return_status: id %d not found, error %d",
                  id, (int)error);
      return;
    }
  
  /* Call the callback with the appropriate status. */
  switch (request->expected_reply)
    {
    case SSH_FILEXFER_HANDLE_REPLY:
      if (request->handle_callback)
        (*request->handle_callback)(error, NULL, request->context);
      break;
      
    case SSH_FILEXFER_STATUS_REPLY:
      if (request->status_callback)
        (*request->status_callback)(error, request->context);
      break;
      
    case SSH_FILEXFER_DATA_REPLY:
      if (request->data_callback)
        (*request->data_callback)(error, NULL, (size_t)0, request->context);
      break;
      
    case SSH_FILEXFER_NAME_REPLY:
      if (request->name_callback)
        (*request->name_callback)(error, NULL, NULL, NULL, request->context);
      break;
      
    case SSH_FILEXFER_ATTRS_REPLY:
      if (request->attribute_callback)
        (*request->attribute_callback)(error, NULL, request->context);
      break;
      
    default:
      ssh_fatal("ssh_file_client_eof_proc: bad expect %d",
                (int)request->expected_reply);
    }

  /* Free the request. */
  ssh_file_client_free_request(request);
}

/* Creates a file handle out of the specified value.  The value is made
   part of the handle, and will be freed automatically when the handle
   is freed. */

SshFileHandle ssh_file_client_make_handle(SshFileClient client,
                                          unsigned char *value,
                                          size_t len)
{
  SshFileHandle handle;

  handle = ssh_xmalloc(sizeof(*handle));
  memset(handle, 0, sizeof(*handle));
  handle->client = client;
  handle->value = value;
  handle->len = len;
  handle->num_names = 0;
  handle->next_name = 0;
  handle->names = NULL;
  handle->long_names = NULL;
  handle->attrs = NULL;
  return handle;
}

/* Frees the given file handle object. */

void ssh_file_client_free_handle(SshFileHandle handle)
{
  unsigned int i;
  
  ssh_xfree(handle->value);
  for (i = 0; i < handle->num_names; i++)
    {
      ssh_xfree(handle->names[i]);
      ssh_xfree(handle->long_names[i]);
      ssh_xfree(handle->attrs[i]);
    }
  ssh_xfree(handle->names);
  ssh_xfree(handle->long_names);
  ssh_xfree(handle->attrs);
  memset(handle, 'F', sizeof(*handle));
  ssh_xfree(handle);
}

/* Allocates a new request structure and adds it on the queued list. */

SshFileClientRequest ssh_file_request(SshFileClient client,
                                      unsigned int packet_type,
                                      SshFileClientExpect reply_type, ...)
{
  SshFileClientRequest request;
  va_list va;
  SshBuffer buffer;

  assert(!client->eof_received);

  /* Format the request packet in the buffer. */
  va_start(va, reply_type);
  ssh_buffer_init(&buffer);
  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_UINT32, client->next_id,
                    SSH_FORMAT_END);
  ssh_encode_va(&buffer, va);

  /* Allocate and initialize the request data structure. */
  request = ssh_xmalloc(sizeof(*request));
  memset(request, 0, sizeof(*request));
  request->id = client->next_id++;
  request->request = ssh_xmemdup(ssh_buffer_ptr(&buffer),
                                 ssh_buffer_len(&buffer));
  request->request_len = ssh_buffer_len(&buffer);
  request->packet_type = packet_type;
  request->expected_reply = reply_type;

  /* Free the buffer. */
  ssh_buffer_uninit(&buffer);

  /* Add the request to the list of queued requests. */
  request->next = client->queued_requests;
  client->queued_requests = request;
  
  /* Try to send the request.  If we must wait, the request is left in
     a queue. */
  ssh_file_client_try_send(client);
  
  return request;
}

/* Sends a request to open a file, and calls the given callback when
   complete. */

void ssh_file_client_open(SshFileClient client,
                          const char *name,
                          unsigned int flags,
                          SshFileAttributes attributes,
                          SshFileHandleCallback callback,
                          void *context)
{
  SshFileClientRequest request;
  struct SshFileAttributesRec default_attrs;
  unsigned long pflags;

  if (attributes == NULL)
    {
      memset(&default_attrs, 0, sizeof(default_attrs));
      default_attrs.flags = 0;
      attributes = &default_attrs;
    }

  switch (flags & (O_RDWR|O_WRONLY|O_RDONLY))
    {
    case O_RDWR:
      pflags = SSH_FXF_READ | SSH_FXF_WRITE;
      break;
    case O_WRONLY:
      pflags = SSH_FXF_WRITE;
      break;
    case O_RDONLY:
      pflags = SSH_FXF_READ;
      break;
    default:
      ssh_fatal("ssh_file_client_open: internal error converting flags");
    }
  if (flags & O_APPEND)
    pflags |= SSH_FXF_APPEND;
  if (flags & O_CREAT)
    pflags |= SSH_FXF_CREAT;
  if (flags & O_TRUNC)
    pflags |= SSH_FXF_TRUNC;
  if (flags & O_EXCL)
    pflags |= SSH_FXF_EXCL;

  if (client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, NULL, context);
      return;
    }
  
  request = ssh_file_request(client, SSH_FXP_OPEN, SSH_FILEXFER_HANDLE_REPLY,
                             SSH_FORMAT_UINT32_STR, name, strlen(name),
                             SSH_FORMAT_UINT32, (SshUInt32) pflags,
                             SSH_FORMAT_EXTENDED, 
                               ssh_file_attrs_encoder, attributes,
                             SSH_FORMAT_END);
  
  /* Note that the callback will not be delivered until from the bottom
     of the event loop, and thus it is safe to set the callback here. */
  request->handle_callback = callback;
  request->context = context;
}

/* Sends a read request. */

void ssh_file_client_read(SshFileHandle handle,
                          off_t offset,
                          size_t len,
                          SshFileDataCallback callback,
                          void *context)
{
  SshUInt64 seek_offset = 0L;
  
  SshFileClientRequest request;
  
  if (handle->client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, NULL, (size_t)0, context);
      return;
    }

  seek_offset = (SshUInt64)offset;
  request = ssh_file_request(handle->client, SSH_FXP_READ,
                             SSH_FILEXFER_DATA_REPLY,
                             SSH_FORMAT_UINT32_STR, handle->value, handle->len,
                             SSH_FORMAT_UINT64, seek_offset,
                             SSH_FORMAT_UINT32, (SshUInt32) len,
                             SSH_FORMAT_END);
  request->data_callback = callback;
  request->context = context;
}

/* Sends a write request. */

void ssh_file_client_write(SshFileHandle handle,
                           off_t offset,
                           const unsigned char *buf,
                           size_t len,
                           SshFileStatusCallback callback,
                           void *context)
{
  SshUInt64 seek_offset = 0L;
  SshFileClientRequest request;
  
  if (handle->client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, context);
      return;
    }

  seek_offset = (SshUInt64)offset;
  request = ssh_file_request(handle->client, SSH_FXP_WRITE,
                             SSH_FILEXFER_STATUS_REPLY,
                             SSH_FORMAT_UINT32_STR, 
                               handle->value, handle->len,
                             SSH_FORMAT_UINT64, seek_offset,
                             SSH_FORMAT_UINT32_STR, 
                               buf, len,
                             SSH_FORMAT_END);
  request->status_callback = callback;
  request->context = context;
}

/* Sends a close request. */

void ssh_file_client_close(SshFileHandle handle,
                           SshFileStatusCallback callback,
                           void *context)
{
  SshFileClientRequest request;

  if (handle->client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, context);
      ssh_file_client_free_handle(handle);
      return;
    }

  request = ssh_file_request(handle->client, SSH_FXP_CLOSE,
                             SSH_FILEXFER_STATUS_REPLY,
                             SSH_FORMAT_UINT32_STR, 
                               handle->value, handle->len,
                             SSH_FORMAT_END);
  request->status_callback = callback;
  request->context = context;

  /* Free the file handle. */
  ssh_file_client_free_handle(handle);
}

/* Sends a stat request. */

void ssh_file_client_stat(SshFileClient client,
                          const char *name,
                          SshFileAttributeCallback callback,
                          void *context)
{
  SshFileClientRequest request;

  if (!client->version_received)
    {
      (*callback)(SSH_FX_NO_CONNECTION, NULL, context);
      return;      
    }
    
  if (client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, NULL, context);
      return;
    }

  request = ssh_file_request(client, SSH_FXP_STAT,
                             SSH_FILEXFER_ATTRS_REPLY,
                             SSH_FORMAT_UINT32_STR, 
                               name, strlen(name),
                             SSH_FORMAT_END);
  request->attribute_callback = callback;
  request->context = context;
}

/* Sends a lstat request. */

void ssh_file_client_lstat(SshFileClient client,
                          const char *name,
                          SshFileAttributeCallback callback,
                          void *context)
{
  SshFileClientRequest request;

  if (!client->version_received)
    {
      (*callback)(SSH_FX_NO_CONNECTION, NULL, context);
      return;      
    }
    
  if (client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, NULL, context);
      return;
    }

  request = ssh_file_request(client, SSH_FXP_LSTAT,
                             SSH_FILEXFER_ATTRS_REPLY,
                             SSH_FORMAT_UINT32_STR, 
                               name, strlen(name),
                             SSH_FORMAT_END);
  request->attribute_callback = callback;
  request->context = context;
}

/* Sends an fstat request. */

void ssh_file_client_fstat(SshFileHandle handle,
                           SshFileAttributeCallback callback,
                           void *context)
{
  SshFileClientRequest request;

  if (handle->client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, NULL, context);
      return;
    }

  request = ssh_file_request(handle->client, SSH_FXP_FSTAT,
                             SSH_FILEXFER_ATTRS_REPLY,
                             SSH_FORMAT_UINT32_STR, 
                               handle->value, handle->len,
                             SSH_FORMAT_END);
  request->attribute_callback = callback;
  request->context = context;
}

/* Sends a setstat request (i.e., chown, chmod, or truncate). */

void ssh_file_client_setstat(SshFileClient client,
                             const char *name,
                             SshFileAttributes attributes,
                             SshFileStatusCallback callback,
                             void *context)
{
  SshFileClientRequest request;

  if (client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, context);
      return;
    }

  request = ssh_file_request(client, SSH_FXP_SETSTAT,
                             SSH_FILEXFER_STATUS_REPLY,
                             SSH_FORMAT_UINT32_STR, name, strlen(name),
                             SSH_FORMAT_EXTENDED, 
                               ssh_file_attrs_encoder, attributes,
                             SSH_FORMAT_END);
  request->status_callback = callback;
  request->context = context;
}

/* Sends an fsetstat request (i.e., fchmod, fchown, or ftruncate). */

void ssh_file_client_fsetstat(SshFileHandle handle,
                              SshFileAttributes attributes,
                              SshFileStatusCallback callback,
                              void *context)
{
  SshFileClientRequest request;

  if (handle->client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, context);
      return;
    }

  request = ssh_file_request(handle->client, SSH_FXP_FSETSTAT,
                             SSH_FILEXFER_STATUS_REPLY,
                             SSH_FORMAT_UINT32_STR, handle->value, handle->len,
                             SSH_FORMAT_EXTENDED, 
                               ssh_file_attrs_encoder, attributes,
                             SSH_FORMAT_END);
  request->status_callback = callback;
  request->context = context;
}

/* Glob the remote file names.  This is used for purposes similar to
   readdir. */

void ssh_file_client_opendir(SshFileClient client,
                             const char *name,
                             SshFileHandleCallback callback,
                             void *context)
{
  SshFileClientRequest request;

  if (client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, NULL, context);
      return;
    }

  request = ssh_file_request(client, SSH_FXP_OPENDIR,
                             SSH_FILEXFER_HANDLE_REPLY,
                             SSH_FORMAT_UINT32_STR, name, strlen(name),
                             SSH_FORMAT_END);
  request->handle_callback = callback;
  request->context = context;
}

/* Read the next directory entry. */

void ssh_file_client_readdir(SshFileHandle handle,
                             SshFileNameCallback callback,
                             void *context)
{
  SshFileClientRequest request;
  unsigned int a;
  
  /* If we already have a cached name, return it immediately. */
  if (handle->next_name < handle->num_names)
    {
      a = handle->next_name++;
      (*callback)(SSH_FX_OK, 
                  handle->names[a], 
                  handle->long_names[a], 
                  handle->attrs[a],               
                  context);
      return;
    }

  /* If we have received EOF, fail immediately. */
  if (handle->client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, NULL, NULL, NULL, context);
      return;
    }
  
  /* Otherwise, request more names from the server. */
  request = ssh_file_request(handle->client, SSH_FXP_READDIR,
                             SSH_FILEXFER_NAME_REPLY,
                             SSH_FORMAT_UINT32_STR, 
                               handle->value, handle->len,
                             SSH_FORMAT_END);
  request->name_callback = callback;
  request->context = context;
  request->handle = handle;
}

/* Remove a file */

void ssh_file_client_remove(SshFileClient client,
                            const char *name,
                            SshFileStatusCallback callback,
                            void *context)
{
  SshFileClientRequest request;

  if (client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, context);
      return;
    }

  request = ssh_file_request(client, SSH_FXP_REMOVE,
                             SSH_FILEXFER_STATUS_REPLY,
                             SSH_FORMAT_UINT32_STR, 
                               name, strlen(name),
                             SSH_FORMAT_END);
  request->status_callback = callback;
  request->context = context;
}

/* Make directory */

void ssh_file_client_mkdir(SshFileClient client,
                           const char *name,
                           SshFileAttributes attributes,
                           SshFileStatusCallback callback,
                           void *context)
{
  SshFileClientRequest request;
  struct SshFileAttributesRec default_attrs;

  if (attributes == NULL)
    {
      memset(&default_attrs, 0, sizeof(default_attrs));
      default_attrs.flags = 0;
      attributes = &default_attrs;
    }

  if (client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, context);
      return;
    }

  request = ssh_file_request(client, SSH_FXP_MKDIR,
                             SSH_FILEXFER_STATUS_REPLY,
                             SSH_FORMAT_UINT32_STR, name, strlen(name),
                             SSH_FORMAT_EXTENDED, ssh_file_attrs_encoder,
                               attributes,
                             SSH_FORMAT_END);
  request->status_callback = callback;
  request->context = context;
}

/* Remove a directory */

void ssh_file_client_rmdir(SshFileClient client,
                           const char *name,
                           SshFileStatusCallback callback,
                           void *context)
{
  SshFileClientRequest request;

  if (client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, context);
      return;
    }

  request = ssh_file_request(client, SSH_FXP_RMDIR,
                             SSH_FILEXFER_STATUS_REPLY,
                             SSH_FORMAT_UINT32_STR, 
                               name, strlen(name),
                             SSH_FORMAT_END);
  request->status_callback = callback;
  request->context = context;
}

/* realpath */

void ssh_file_client_realpath(SshFileClient client,
                              const char *name,
                              SshFileNameCallback callback,
                              void *context)
{
  SshFileClientRequest request;

  if (client->eof_received)
    {
      (*callback)(SSH_FX_CONNECTION_LOST, NULL, NULL, NULL, context);
      return;
    }

  request = ssh_file_request(client, SSH_FXP_REALPATH,
                             SSH_FILEXFER_NAME_REPLY,
                             SSH_FORMAT_UINT32_STR, 
                               name, strlen(name),
                             SSH_FORMAT_END);
  request->name_callback = callback;
  request->context = context;
  request->handle = NULL;
}

/* This function is called whenever a packet is received from the server. */

void ssh_file_client_receive_proc(SshPacketType type,
                                  const unsigned char *data, size_t len,
                                  void *context)
{
  SshFileClient client = (SshFileClient)context;
  SshFileClientRequest request;
  SshFileHandle handle;
  size_t bytes, slen, offset;
  SshUInt32 u, id;
  unsigned int i, a;
  unsigned char *s, *name, *long_name;
  SshFileAttributes attrs;
  
  switch (type)
    {
    case SSH_FXP_VERSION:
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &u,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_client_receive_proc: bad VERSION");
          return;
        }
      client->version = (u < SSH_FILEXFER_VERSION) ? u : SSH_FILEXFER_VERSION;
      client->version_received = TRUE;
      ssh_file_client_try_send(client);
      break;

    case SSH_FXP_STATUS:
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32, &u,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_client_receive_proc: bad STATUS");
          return;
        }
      ssh_file_client_return_status(client, id, (SshFileClientError)u);
      break;

    case SSH_FXP_HANDLE:
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR, &s, &slen,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_client_receive_proc: bad HANDLE");
          return;
        }

      /* Try to find a matching request. */
      request = ssh_file_client_find_request(client, id);
      if (!request)
        {
          /* No such request found. */
          ssh_warning("ssh_file_client_receive_proc: unknown HANDLE");
          return;
        }

      /* Check that the request really expects a reply of this type. */
      if (request->expected_reply != SSH_FILEXFER_HANDLE_REPLY)
        {
          ssh_warning("ssh_file_client_receive_proc: unexpected HANDLE");
          return;
        }

      /* Call the callback.  If none was supplied, free the handle. */
      if (request->handle_callback)
        (*request->handle_callback)(SSH_FX_OK,
                                    ssh_file_client_make_handle(client, s,
                                                                slen),
                                    request->context);
      else
        ssh_xfree(s);
      break;
      
    case SSH_FXP_DATA:
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &s, &slen,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_client_receive_proc: bad DATA");
          return;
        }

      /* Try to find a matching request. */
      request = ssh_file_client_find_request(client, id);
      if (!request)
        {
          /* No such request found. */
          ssh_warning("ssh_file_client_receive_proc: unknown DATA");
          return;
        }

      /* Check that the request really expects a reply of this type. */
      if (request->expected_reply != SSH_FILEXFER_DATA_REPLY)
        {
          ssh_warning("ssh_file_client_receive_proc: unexpected DATA");
          return;
        }

      /* Call the callback.  If none was supplied, free the handle. */
      if (request->data_callback)
        (*request->data_callback)(SSH_FX_OK, s, slen, request->context);
      break;

    case SSH_FXP_NAME:
      bytes = ssh_decode_array(data, len,
                               SSH_FORMAT_UINT32, &id,
                               SSH_FORMAT_UINT32, &u,
                               SSH_FORMAT_END);
      if (bytes == 0)
        {
          ssh_warning("ssh_file_client_receive_proc: bad NAME");
          return;
        }

      /* Try to find a matching request. */
      request = ssh_file_client_find_request(client, id);
      if (!request)
        {
          /* No such request found. */
          ssh_warning("ssh_file_client_receive_proc: unknown NAME");
          return;
        }

      /* Check that the request really expects a reply of this type. */
      if (request->expected_reply != SSH_FILEXFER_NAME_REPLY)
        {
          ssh_warning("ssh_file_client_receive_proc: unexpected NAME");
          return;
        }

      /* Get the file handle. */
      handle = request->handle;
      
      /* If the handle is NULL, u should be 1 and the message consists
       * of a single name */
      
      if (handle == NULL)
        {         
          if (u != 1)
            {
              ssh_warning("ssh_file_client_receive_proc: null handle and "
                          "%lu names.", u);
              return;
            }
          
          offset = bytes;         
          bytes = ssh_decode_array(data + offset, len - offset,
                                   SSH_FORMAT_UINT32_STR,
                                     &name, NULL,
                                   SSH_FORMAT_UINT32_STR,
                                     &long_name, NULL,
                                   SSH_FORMAT_EXTENDED, 
                                     ssh_file_attrs_decoder, 
                                     &attrs,
                                   SSH_FORMAT_END);
          
           if (bytes == 0)
            {
              ssh_warning("ssh_file_client_receive_proc: bad NAME");
              return;
            }
         
          /* Call the context */

          (*request->name_callback)(SSH_FX_OK,
                                    (char *) name, (char *) long_name, attrs,
                                    request->context);    
          ssh_xfree(name);
          ssh_xfree(long_name);
          ssh_xfree(attrs);       
          
          return;
        }
      
      /* Sanity check: should not have any unprocessed names left. */
      if (handle->next_name < handle->num_names)
        ssh_warning("ssh_file_client_receive_proc: names still left");

      /* Free any previous names. */
      for (i = 0; i < handle->num_names; i++)
        {
          ssh_xfree(handle->names[i]);
          ssh_xfree(handle->long_names[i]);
          ssh_xfree(handle->attrs[i]);
        }
      ssh_xfree(handle->names);
      ssh_xfree(handle->long_names);
      ssh_xfree(handle->attrs);
      
      /* Parse the names from the message. */
      handle->names = ssh_xcalloc(u, sizeof(handle->names[0]));
      handle->long_names = ssh_xcalloc(u, sizeof(handle->long_names[0]));
      handle->attrs = ssh_xcalloc(u, sizeof(handle->attrs[0]));
      offset = bytes;

      for (i = 0; i < u; i++)
        {
          bytes = ssh_decode_array(data + offset, len - offset,
                                   SSH_FORMAT_UINT32_STR,
                                     &handle->names[i], NULL,
                                   SSH_FORMAT_UINT32_STR,
                                     &handle->long_names[i], NULL,
                                   SSH_FORMAT_EXTENDED, 
                                     ssh_file_attrs_decoder, 
                                     &handle->attrs[i],
                                   SSH_FORMAT_END);
          if (bytes == 0)
            {
              ssh_warning("ssh_file_client_receive_proc: bad NAME %d", i);
              for (; i > 0; i--)
                {
                  ssh_xfree(handle->names[i - 1]);
                  ssh_xfree(handle->long_names[i - 1]);
                  ssh_xfree(handle->attrs[i - 1]);
                }
              ssh_xfree(handle->names);
              ssh_xfree(handle->long_names);
              ssh_xfree(handle->attrs);       
              handle->names = NULL;
              handle->long_names = NULL;
              handle->attrs = NULL;
              handle->num_names = 0;
              handle->next_name = 0;
              return;
            }

          /* Move to next name. */
          offset += bytes;
        }
      handle->num_names = u;
      handle->next_name = 0;

      /* Should have consumed all data. */
      if (offset != len)
        {
          ssh_warning("ssh_file_client_receive_proc: bad NAME %d", i);
          return;
        }

      /* Call the callback.  If none was supplied, free the handle. */
      if (request->name_callback)
        {
          if (handle->next_name < handle->num_names)
            {
              a = handle->next_name++;        
              (*request->name_callback)(SSH_FX_OK,
                                        handle->names[a],
                                        handle->long_names[a],
                                        handle->attrs[a],
                                        request->context);
            }
          else
            (*request->name_callback)(SSH_FX_EOF, NULL, NULL, NULL,
                                      request->context);
        }
      break;

    case SSH_FXP_ATTRS:
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_EXTENDED, 
                             ssh_file_attrs_decoder, &attrs,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_client_receive_proc: bad ATTRS");
          return;
        }

      /* Try to find matching request. */
      request = ssh_file_client_find_request(client, id);
      if (!request)
        {
          /* No such request found. */
          ssh_warning("ssh_file_client_receive_proc: unknown ATTRS");
          return;
        }

      /* Check that the request really expects a reply of this type. */
      if (request->expected_reply != SSH_FILEXFER_ATTRS_REPLY)
        {
          ssh_warning("ssh_file_client_receive_proc: unexpected ATTRS");
          return;
        }

      /* Call the callback.  If none was supplied, free the handle. */
      if (request->attribute_callback)
        (*request->attribute_callback)(SSH_FX_OK, attrs, request->context);
      ssh_xfree(attrs);
      break;

    default:
      ssh_warning("ssh_file_client_receive_proc: unexpected packet %d",
                  (int)type);
    }
}

/* This function is called whenever EOF is received from the server. */

void ssh_file_client_eof_proc(void *context)
{
  SshFileClient client = (SshFileClient)context;

  /* Mark that we have received EOF. */
  client->eof_received = TRUE;

  /* Complete all sent requests with an error. */
  while (client->sent_requests)
    ssh_file_client_return_status(client, client->sent_requests->id,
                                  SSH_FX_CONNECTION_LOST);

  /* Fake sending of queued requests. */
  client->sent_requests = client->queued_requests;
  client->queued_requests = NULL;

  /* Then complete them all with an error. */
  while (client->sent_requests)
    ssh_file_client_return_status(client, client->sent_requests->id,
                                  SSH_FX_CONNECTION_LOST);
}

/* This function is called whenever we can send again after can_send
   having returned FALSE.  */

void ssh_file_client_can_send_proc(void *context)
{
  SshFileClient client = (SshFileClient)context;

  ssh_file_client_try_send(client);
}

/* Turns the given stream into a file transfer client.  This takes over
   the stream; the stream will be automatically freed when the file transfer
   client is freed. */

SshFileClient ssh_file_client_wrap(SshStream stream)
{
  SshFileClient client;

  /* Allocate a context for the client. */
  client = ssh_xmalloc(sizeof(*client));
  memset(client, 0, sizeof(*client));
  client->next_id = 0;
  client->sent_requests = NULL;
  client->queued_requests = NULL;
  client->version_received = FALSE;
  client->eof_received = FALSE;

  /* Turn the stream into a packet stream. */
  client->conn = ssh_packet_wrap(stream,
                                 ssh_file_client_receive_proc,
                                 ssh_file_client_eof_proc,
                                 ssh_file_client_can_send_proc,
                                 (void *)client);

  /* Send initialization packet. */
  ssh_packet_wrapper_send_encode(client->conn, SSH_FXP_INIT,
                                 SSH_FORMAT_UINT32, (SshUInt32) 0,
                                 SSH_FORMAT_END);

  return client;
}

/* Closes the file transfer client.  Any outstanding requests are silently
   terminated without calling their callbacks. */

void ssh_file_client_destroy(SshFileClient client)
{
  SshFileClientRequest request, next_request;

  ssh_packet_wrapper_destroy(client->conn);
  for (request = client->sent_requests; request; request = next_request)
    {
      next_request = request->next;
      ssh_file_client_free_request(request);
    }
  for (request = client->queued_requests; request; request = next_request)
    {
      next_request = request->next;
      ssh_file_client_free_request(request);
    }
  memset(client, 'F', sizeof(*client));
  ssh_xfree(client);
}

/* XXX should we handle timeouts here? */
/* XXX check sending requests before version number received. */
