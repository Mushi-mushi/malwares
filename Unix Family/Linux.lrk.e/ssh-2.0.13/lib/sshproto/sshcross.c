/*

sshcross.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Functions for encoding cross-layer packets.

*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshgetput.h"
#include "sshcross.h"

/* Appends a cross-layer packet at the end of the buffer as specified
   by the variable-length argument list.  The packet will have the
   given type.  Each element in the variable-length part of the
   argument list must start with a SshEncodingFormat type, be followed
   by arguments of the appropriate type, and the list must end with
   SSH_FORMAT_END.  This returns the number of bytes added to the buffer. */

size_t ssh_cross_encode_packet(SshBuffer *buffer, SshCrossPacketType type, ...)
{
  va_list ap;

  va_start(ap, type);

  return ssh_cross_encode_packet_va(buffer, type, ap);
}

/* Appends a cross-layer packet at the end of the buffer as specified
   by the variable-length argument list.  The packet will have the
   given type.  Each element in the variable-length part of the
   argument list must start with a SshEncodingFormat type, be followed
   by arguments of the appropriate type, and the list must end with
   SSH_FORMAT_END.  This returns the number of bytes added to the buffer. */

size_t ssh_cross_encode_packet_va(SshBuffer *buffer,
                                  SshCrossPacketType type,
                                  va_list ap)
{
  size_t payload_size, original_len;
  unsigned char *p;

  /* Save the original length so we can later find where the packet header
     starts. */
  original_len = ssh_buffer_len(buffer);

  /* Construct the cross-layer packet header with dummy length. */
  ssh_encode_buffer(buffer,
                    SSH_FORMAT_UINT32, (SshUInt32) 0,
                    SSH_FORMAT_CHAR, (unsigned int)type,
                    SSH_FORMAT_END);

  /* Encode the packet payload. */
  payload_size = ssh_encode_va(buffer, ap);

  /* Update the packet header to contain the correct payload size. */
  p = ssh_buffer_ptr(buffer);
  p += original_len;
  SSH_PUT_32BIT(p, payload_size + 1);
  
  /* Return the total number of bytes added to the buffer. */
  return ssh_buffer_len(buffer) - original_len;
}
