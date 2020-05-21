/*

sshfilexferi.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Internal functions for file transfer that are used by both the server
and the client.

*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshfilexfer.h"
#include "sshfilexferi.h"


/* Encodes a SshFileAttributes object supplied as the next argument.
   The next argument should be of type SshFileAttributes. */

void ssh_file_attrs_encoder(SshBuffer *buffer, va_list *app)
{
  SshFileAttributes attrs;
  /*  unsigned long size_high, size_low;*/
  SshUInt64 size;
  
  /* Get the next argument from the list. */
  attrs = va_arg(*app, SshFileAttributes);

  /* Encode flags. */
  ssh_encode_buffer(buffer,
                    SSH_FORMAT_UINT32, (SshUInt32) attrs->flags,
                    SSH_FORMAT_END);

  /* Encode size if flags indicate it should be present. */
  if (attrs->flags & SSH_FILEXFER_ATTR_SIZE)
    {
      /*size_low = attrs->size & 0xffffffffL;
      size_high = (sizeof(off_t) > 4) ? (attrs->size >> 32) : 0; */
      size = (SshUInt64) attrs->size;
      
      ssh_encode_buffer(buffer,
                        SSH_FORMAT_UINT64, size,
                        /*_high,
                        SSH_FORMAT_UINT32, size_low,*/
                        SSH_FORMAT_END);
    }

  /* Encode uid and gid if flags indicate they should be present. */
  if (attrs->flags & SSH_FILEXFER_ATTR_UIDGID)
    ssh_encode_buffer(buffer,
                      SSH_FORMAT_UINT32, (SshUInt32) attrs->uid,
                      SSH_FORMAT_UINT32, (SshUInt32) attrs->gid,
                      SSH_FORMAT_END);

  /* Encode permissions if flags indicate they should be present. */
  if (attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    ssh_encode_buffer(buffer,
                      SSH_FORMAT_UINT32, (SshUInt32) attrs->permissions,
                      SSH_FORMAT_END);
  /* Encode access and modification times if flags indicate they should be
     present. */
  if (attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME)
    ssh_encode_buffer(buffer,
                      SSH_FORMAT_UINT32, (SshUInt32) attrs->atime,
                      SSH_FORMAT_UINT32, (SshUInt32) attrs->mtime,
                      SSH_FORMAT_END);

}

/* Decodes a SshFileAttributes object.  The next argument should be of type
   SshFileAttributes *.  This allocates an attributes object and copies data
   to it. */

size_t ssh_file_attrs_decoder(const unsigned char *buf, size_t len,
                              va_list *app)
{
  SshFileAttributes attrs, *attrsp;
  size_t offset, bytes;
  SshUInt32 u1, u2;
  SshUInt64 size;

  /* Get the next argument. */
  attrsp = va_arg(*app, SshFileAttributes *);

  /* Check if we were called to free allocated space. */
  if (buf == SSH_DECODE_FREE)
    {
      /* Free allocated space. */
      ssh_xfree(*attrsp);
      return 0;
    }

  /* Allocate space for the attributes. */
  attrs = ssh_xmalloc(sizeof(*attrs));
  memset(attrs, 0, sizeof(*attrs));
  *attrsp = attrs;
  
  /* Decode flags. */
  bytes = ssh_decode_array(buf, len, SSH_FORMAT_UINT32, &u1, SSH_FORMAT_END);
  if (bytes == 0)
    return 0;
  attrs->flags = u1;
  offset = bytes;

  /* Decode size if flags indicate it should be present. */
  if (attrs->flags & SSH_FILEXFER_ATTR_SIZE)
    {
      bytes = ssh_decode_array(buf + offset, len - offset,
                               SSH_FORMAT_UINT64, &size,
                               SSH_FORMAT_END);
      if (bytes == 0)
        return 0;
      offset += bytes;
      attrs->size = (off_t)size;
    }

  /* Decode uid and gid if flags indicate they should be present. */
  if (attrs->flags & SSH_FILEXFER_ATTR_UIDGID)
    {
      bytes = ssh_decode_array(buf + offset, len - offset,
                               SSH_FORMAT_UINT32, &u1,
                               SSH_FORMAT_UINT32, &u2,
                               SSH_FORMAT_END);
      if (bytes == 0)
        return 0;
      offset += bytes;
      attrs->uid = u1;
      attrs->gid = u2;
    }

  /* Decode permissions if flags indicate it should be present. */
  if (attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    {
      bytes = ssh_decode_array(buf + offset, len - offset,
                               SSH_FORMAT_UINT32, &u1,
                               SSH_FORMAT_END);
      if (bytes == 0)
        return 0;
      offset += bytes;
      attrs->permissions = u1;
    }

  /* Decode access and modification times if flags indicate they should be
     present. */
  if (attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME)
    {
      bytes = ssh_decode_array(buf + offset, len - offset,
                               SSH_FORMAT_UINT32, &u1,
                               SSH_FORMAT_UINT32, &u2,
                               SSH_FORMAT_END);
      if (bytes == 0)
        return 0;
      offset += bytes;
      attrs->atime = u1;
      attrs->mtime = u2;
    }

  /* Return the number of bytes consumed. */
  return offset;
}
