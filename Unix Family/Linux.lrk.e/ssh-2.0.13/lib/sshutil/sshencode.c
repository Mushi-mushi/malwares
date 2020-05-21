/*

sshencode.c

Author: Tero Kivinen <kivinen@ssh.fi>
        Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

Functions for encoding/decoding binary data.

*/

#include "sshincludes.h"
#include "sshvlint32.h"
#include "sshbuffer.h"
#include "sshbufaux.h"
#include "sshmpaux.h"
#include "sshgetput.h"
#include "sshstream.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "SshEncode"

/* Appends data at the end of the buffer as specified by the
   variable-length argument list.  Each element must start with a
   SshEncodingFormat type, be followed by arguments of the appropriate
   type, and the list must end with SSH_FORMAT_END.  This returns the
   number of bytes added to the buffer. */

size_t ssh_encode_va(SshBuffer *buffer, va_list ap)
{
  SshEncodingFormat format;
  unsigned long longvalue;
  unsigned int intvalue;
  SshUInt64 u64;
  SshUInt32 u32;
  size_t i;
  Boolean b;
  const unsigned char *p;
  size_t original_bytes;
  SshInt *mp;
  SshEncoder encoder;
  unsigned char buf[8];
  
  original_bytes = ssh_buffer_len(buffer);
  for (;;)
    {
      format = va_arg(ap, SshEncodingFormat);
      switch (format)
        {
        case SSH_FORMAT_VLINT32_STR:
          p = va_arg(ap, unsigned char *);
          i = va_arg(ap, size_t);
          buffer_put_vlint32_string(buffer, p, i);
          break;

        case SSH_FORMAT_UINT32_STR:
          p = va_arg(ap, unsigned char *);
          i = va_arg(ap, size_t);
          buffer_put_uint32_string(buffer, p, i);
          break;

        case SSH_FORMAT_VLINT32:
          u32 = va_arg(ap, SshUInt32);
          buffer_put_vlint32(buffer, u32);
          break;

        case SSH_FORMAT_BOOLEAN:
          b = va_arg(ap, unsigned int);
          buffer_put_boolean(buffer, b);
          break;

        case SSH_FORMAT_MP_INT:
          mp = va_arg(ap, SshInt *);
          buffer_put_mp_int(buffer, mp);
          break;

        case SSH_FORMAT_UINT32:
          u32 = va_arg(ap, SshUInt32);
          buffer_put_int(buffer, u32);
          break;

        case SSH_FORMAT_CHAR:
          intvalue = va_arg(ap, unsigned int);
          buffer_put_char(buffer, intvalue);
          break;

        case SSH_FORMAT_DATA:
          p = va_arg(ap, unsigned char *);
          i = va_arg(ap, size_t);
          ssh_buffer_append(buffer, p, i);
          break;

        case SSH_FORMAT_EXTENDED:
          encoder = va_arg(ap, SshEncoder);
          (*encoder)(buffer, &ap);
          break;

        case SSH_FORMAT_UINT64:
          u64 = va_arg(ap, SshUInt64);
          SSH_PUT_64BIT(buf, u64);
          ssh_buffer_append(buffer, buf, 8);
          break;
          
        case SSH_FORMAT_END:
          /* Return the number of bytes added. */
          return ssh_buffer_len(buffer) - original_bytes;

        default:
          ssh_fatal("ssh_encode_va: invalid format code %d "
                    "(check arguments and SSH_FORMAT_END)", 
                    (int)format);
        }
    }
  /*NOTREACHED*/
}

/* Appends data at the end of the buffer as specified by the variable-length
   argument list.  Each element must start with a SshEncodingFormat type,
   be followed by arguments of the appropriate type, and the list must end
   with SSH_FORMAT_END.  This returns the number of bytes added to the
   buffer. */

size_t ssh_encode_buffer(SshBuffer *buffer, ...)
{
  size_t bytes;
  va_list ap;
  
  va_start(ap, buffer);
  bytes = ssh_encode_va(buffer, ap);
  va_end(ap);
  return bytes;
}

/* Encodes the given data.  Returns the length of encoded data in bytes, and
   if `buf_return' is non-NULL, it is set to a memory area allocated by
   ssh_xmalloc that contains the data.  The caller should free the data when
   no longer needed. */

size_t ssh_encode_alloc(unsigned char **buf_return, ...)
{
  size_t bytes;
  SshBuffer buffer;
  va_list ap;
  
  va_start(ap, buf_return);
  ssh_buffer_init(&buffer);
  bytes = ssh_encode_va(&buffer, ap);
  va_end(ap);
  SSH_ASSERT(bytes == ssh_buffer_len(&buffer));

  if (buf_return != NULL)
    {
      *buf_return = ssh_xmalloc(bytes);
      memcpy(*buf_return, ssh_buffer_ptr(&buffer), bytes);
    }
  ssh_buffer_uninit(&buffer);

  return bytes;
}

/* Encodes the given data.  Returns the length of encoded data in bytes, and
   if `buf_return' is non-NULL, it is set to a memory area allocated by
   ssh_xmalloc that contains the data.  The caller should free the data when
   no longer needed. */

size_t ssh_encode_alloc_va(unsigned char **buf_return, va_list ap)
{
  size_t bytes;
  SshBuffer buffer;
  
  ssh_buffer_init(&buffer);
  bytes = ssh_encode_va(&buffer, ap);
  SSH_ASSERT(bytes == ssh_buffer_len(&buffer));

  if (buf_return != NULL)
    {
      *buf_return = ssh_xmalloc(bytes);
      memcpy(*buf_return, ssh_buffer_ptr(&buffer), bytes);
    }
  ssh_buffer_uninit(&buffer);

  return bytes;
}

/* Decodes a vlint32 from the buffer.  Returns the number of bytes consumed,
   or 0 if an error was encountered.  The value is returned in *valuep. */

size_t ssh_decode_vlint32(const unsigned char *buf, size_t len,
                          unsigned long *valuep)
{
  size_t itemlen;

  /* The integer cannot possibly be valid if length is zero. */
  if (len == 0)
    return 0;

  /* Parse the length of the integer. */
  itemlen = ssh_ssh_vlint32_parse_length(buf);
  
  /* Check that there is enough data in the buffer. */
  if (len < itemlen)
    return 0;

  /* Get the value of the integer. */
  *valuep = ssh_vlint32_parse(buf, NULL);
  
  /* Return its length. */
  return itemlen;
}

/* Allocates a buffer of the given size with ssh_xmalloc.  However, the buffer is
   also recorded in *num_allocs_p and *allocs_p, so that they can all be
   easily freed later if necessary. */

unsigned char *ssh_decode_alloc(unsigned int *num_allocs_p,
                                unsigned char ***allocsp,
                                size_t size)
{
  unsigned char *p;

  /* Check if we need to enlarge the pointer array.  We enlarge it in chunks
     of 16 pointers. */
  if (*num_allocs_p == 0)
    *allocsp = ssh_xmalloc(16 * sizeof(unsigned char *));
  else
    if (*num_allocs_p % 16 == 0)
      *allocsp = ssh_xrealloc(*allocsp,
                              (*num_allocs_p + 16) * sizeof(unsigned char *));

  /* Allocate the memory block. */
  p = ssh_xmalloc(size);

  /* Store it in the array. */
  (*allocsp)[*num_allocs_p] = p;
  (*num_allocs_p)++;
  
  return p;
}

/* Decodes an mp-int from the buffer.  The value is stored in mp (which must
   already be initialized).  mp may be NULL, in which case the value is not
   stored.  This returns the number of bytes processed, or 0 if an error
   is encountered (the buffer ends too soon). */

size_t ssh_decode_mp_int(const unsigned char *buf, size_t len,
                         SshInt *mp)
{
  unsigned int bits;
  size_t bytes;

  /* Check that there is enough data left for length. */
  if (len < 4)
    return 0;

  /* Get the number of bits, and convert it to bytes. */
  bits = SSH_GET_32BIT(buf);
  bytes = (bits + 7) / 8;

  /* Check that there is enough data in the buffer. */
  if (len < 4 + bytes)
    return 0;

  /* If not storing the value, just return its length. */
  if (mp == NULL)
    return 4 + bytes;

  /* Convert the binary representation of the integer into a hex string. */
  mp_unlinearize_msb_first(mp, buf + 4, bytes);
  
  /* Return its length. */
  return 4 + bytes;
}

/* Decodes data from the given byte array as specified by the
   variable-length argument list.  If all specified arguments could be
   successfully parsed, returns the number of bytes parsed (any
   remaining data can be parsed by first skipping this many bytes).
   If parsing any element results in an error, this returns 0 (and
   frees any already allocated data).  Zero is also returned if the
   specified length would be exceeded. */

size_t ssh_decode_array_va(const unsigned char *buf, size_t len,
                           va_list ap)
{
  SshEncodingFormat format;
  unsigned long *longp, longvalue;
  SshUInt64 *u64p;
  SshUInt32 *u32p;
  Boolean *bp;
  size_t size, *sizep;
  unsigned int *uip;
  unsigned char *p, **pp;
  const unsigned char **cpp;
  size_t offset, itemlen;
  unsigned int i, num_allocs;
  unsigned char **allocs;
  SshInt *mp;
  SshDecoder decoder;
  va_list start_of_ap;
  struct {
    SshDecoder decoder;
    va_list ap;
  } *decoders;
  unsigned int num_decoders;

  offset = 0;
  num_allocs = 0;
  num_decoders = 0;
  decoders = NULL;
  
  for (;;)
    {
      /* Get the next format code. */
      format = va_arg(ap, SshEncodingFormat);
      switch (format)
        {
        case SSH_FORMAT_VLINT32_STR:
          /* Get length and data pointers. */
          pp = va_arg(ap, unsigned char **);
          sizep = va_arg(ap, size_t *);

          /* Decode string length, check errors, and skip the length. */
          itemlen = ssh_decode_vlint32(buf + offset, len - offset,
                                       &longvalue);
          if (itemlen == 0)
            goto fail;
          offset += itemlen;

          /* Check that the string is all in the buffer. */
          if (longvalue > len - offset)
            goto fail;

          /* Store length if requested. */
          if (sizep != NULL)
            *sizep = longvalue;

          /* Retrieve the data if requested. */
          if (pp != NULL)
            {
              *pp = ssh_decode_alloc(&num_allocs, &allocs,
                                     (size_t)longvalue + 1);
              memcpy(*pp, buf + offset, (size_t)longvalue);
              (*pp)[longvalue] = '\0';
            }

          /* Consume the data. */
          offset += longvalue;
          break;

        case SSH_FORMAT_VLINT32_STR_NOCOPY:
          /* Get length and data pointers. */
          cpp = va_arg(ap, const unsigned char **);
          sizep = va_arg(ap, size_t *);

          /* Decode string length, check errors, and skip the length. */
          itemlen = ssh_decode_vlint32(buf + offset, len - offset,
                                       &longvalue);
          if (itemlen == 0)
            goto fail;
          offset += itemlen;

          /* Check that the string is all in the buffer. */
          if (longvalue > len - offset)
            goto fail;

          /* Store length if requested. */
          if (sizep != NULL)
            *sizep = longvalue;

          /* Retrieve the data if requested. */
          if (cpp != NULL)
            *cpp = buf + offset;

          /* Consume the data. */
          offset += longvalue;
          break;
          
        case SSH_FORMAT_UINT32_STR:
          /* Get length and data pointers. */
          pp = va_arg(ap, unsigned char **);
          sizep = va_arg(ap, size_t *);

          /* Check if the length of the string is there. */
          if (len - offset < 4)
            goto fail;

          /* Get the length of the string. */
          longvalue = SSH_GET_32BIT(buf + offset);
          offset += 4;

          /* Check that the string is all in the buffer. */
          if (longvalue > len - offset)
            goto fail;

          /* Store length if requested. */
          if (sizep != NULL)
            *sizep = longvalue;

          /* Retrieve the data if requested. */
          if (pp != NULL)
            {
              *pp = ssh_decode_alloc(&num_allocs, &allocs,
                                     (size_t)longvalue + 1);
              memcpy(*pp, buf + offset, (size_t)longvalue);
              (*pp)[longvalue] = '\0';
            }

          /* Consume the data. */
          offset += longvalue;
          break;

        case SSH_FORMAT_UINT32_STR_NOCOPY:

          /* Get length and data pointers. */
          cpp = va_arg(ap, const unsigned char **);
          sizep = va_arg(ap, size_t *);

          /* Decode string length and skip the length. */

          if (len - offset < 4)
            goto fail;

          longvalue = SSH_GET_32BIT(buf + offset);
          offset += 4;

          /* Check that the string is all in the buffer. */
          if (longvalue > len - offset)
            goto fail;

          /* Store length if requested. */
          if (sizep != NULL)
            *sizep = longvalue;

          /* Retrieve the data if requested. */
          if (cpp != NULL)
            *cpp = buf + offset;

          /* Consume the data. */
          offset += longvalue;
          break;
          

        case SSH_FORMAT_VLINT32:
          u32p = va_arg(ap, SshUInt32 *);

          /* Decode the value, and check errors, and skip the value. */
          itemlen = ssh_decode_vlint32(buf + offset, len - offset,
                                       &longvalue);
          if (itemlen == 0)
            goto fail;
          offset += itemlen;

          /* Store the value if requested. */
          if (u32p != NULL)
            *u32p = longvalue;
          break;

        case SSH_FORMAT_BOOLEAN:
          bp = va_arg(ap, Boolean *);
          if (len - offset < 1)
            goto fail;
          if (bp != NULL)
            *bp = buf[offset] != 0;
          offset++;
          break;

        case SSH_FORMAT_MP_INT:
          /* Note: there is no need to free mp-ints on error, as they are
             already initialized, and thus the caller will eventually
             free them. */
          mp = va_arg(ap, SshInt *);
          /* Decode the value (note: mp may be NULL). */
          itemlen = ssh_decode_mp_int(buf + offset, len - offset, mp);
          if (itemlen == 0)
            goto fail;
          offset += itemlen;
          break;

        case SSH_FORMAT_UINT32:
          u32p = va_arg(ap, SshUInt32 *);
          if (len - offset < 4)
            goto fail;
          if (u32p)
            *u32p = SSH_GET_32BIT(buf + offset);
          offset += 4;
          break;

        case SSH_FORMAT_CHAR:
          uip = va_arg(ap, unsigned int *);
          if (len - offset < 1)
            goto fail;
          if (uip)
            *uip = buf[offset];
          offset++;
          break;

        case SSH_FORMAT_DATA:
          p = va_arg(ap, unsigned char *);
          size = va_arg(ap, size_t);
          if (len - offset < size)
            goto fail;
          if (p)
            memcpy(p, buf + offset, size);
          offset += size;
          break;

        case SSH_FORMAT_EXTENDED:
          /* Get the decoder from the argument list. */
          decoder = va_arg(ap, SshDecoder);

          /* Try decoding. */
          start_of_ap = ap;
          size = (*decoder)(buf + offset, len - offset, &ap);
          if (size == 0)
            goto fail;

          /* Save the decoder in case we fail later. */
          if (num_decoders == 0)
            decoders = ssh_xmalloc(sizeof(*decoders));
          else
            decoders = ssh_xrealloc(decoders,
                                    (num_decoders + 1) * sizeof(*decoders));
          decoders[num_decoders].decoder = decoder;
          decoders[num_decoders].ap = start_of_ap;
          num_decoders++;

          /* Move over parsed data. */
          offset += size;
          break;

        case SSH_FORMAT_UINT64:
          u64p = va_arg(ap, SshUInt64 *);
          if (len - offset < 8)
            goto fail;
          if (u64p)
            *u64p = SSH_GET_64BIT(buf + offset);
          offset += 8;
          break;
          
        case SSH_FORMAT_END:
          /* Free the allocs array. */
          if (num_allocs > 0)
            ssh_xfree(allocs);
          /* Return the number of bytes consumed. */
          return offset;

        default:
          ssh_fatal("ssh_decode_array_va: invalid format code %d (check arguments and SSH_FORMAT_END)", 
                    (int)format);
        }
    }
  /*NOTREACHED*/
  ssh_fatal("ssh_decode_array_va: at end of loop");
  
fail:
  /* An error was encountered.  Free all allocated memory and return zero. */
  for (i = 0; i < num_allocs; i++)
    ssh_xfree(allocs[i]);
  if (i > 0)
    ssh_xfree(allocs);
  if (num_decoders > 0)
    {
      for (i = 0; i < num_decoders; i++)
        (*decoders[i].decoder)(SSH_DECODE_FREE, 0, &decoders[i].ap);
      ssh_xfree(decoders);
    }
  return 0;
}

/* Decodes data from the given byte array as specified by the
   variable-length argument list.  If all specified arguments could be
   successfully parsed, returns the number of bytes parsed (any
   remaining data can be parsed by first skipping this many bytes).
   If parsing any element results in an error, this returns 0 (and
   frees any already allocates data).  Zero is also returned if the
   specified length would be exceeded. */

size_t ssh_decode_array(const unsigned char *buf, size_t len, ...)
{
  va_list ap;
  size_t bytes;

  va_start(ap, len);
  bytes = ssh_decode_array_va(buf, len, ap);
  va_end(ap);

  return bytes;
}

/* Decodes and consumes data from the given buffer as specified by the
   variable-length argument list.  If all the specified arguments could he
   successfully parsed, returns the number of bytes parsed and consumes the
   parsed data from the buffer.  If parsing results in an error, or the buffer
   does not contain enough data, 0 is returned and nothing is consumed from
   the buffer. */

size_t ssh_decode_buffer(SshBuffer *buffer, ...)
{
  va_list ap;
  size_t bytes;
  
  va_start(ap, buffer);
  bytes = ssh_decode_array_va(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer), ap);
  va_end(ap);
  
  ssh_buffer_consume(buffer, bytes);
  return bytes;
}
