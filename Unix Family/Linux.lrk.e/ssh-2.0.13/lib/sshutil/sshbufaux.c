/*

bufaux.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Wed Mar 29 02:24:47 1995 ylo

Auxiliary functions for storing and retrieving various data types to/from
Buffers.

*/

/*
 * $Id: sshbufaux.c,v 1.2 1999/04/29 13:38:55 huima Exp $
 * $Log: sshbufaux.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmp.h" /* was "gmp.h" */
#include "sshbufaux.h"
#include "sshmpaux.h"
#include "sshgetput.h"
#include "sshvlint32.h"


/* Returns a hex value of the specified length from the buffer. */
unsigned int hex2int(const char *buf, size_t len)
{
  unsigned int ch;
  unsigned int value;
  size_t i;

  value = 0;

  for (i = 0; i < len; i++)
    {
      ch = (unsigned int) buf[i];
      if (ch >= '0' && ch <= '9')
        ch = ch - '0';
      else 
        {
          if (ch >= 'A' && ch <= 'F')
            {
              ch = ch + (10 - 'A');
            } 
          else 
            {
              if (ch >= 'a' && ch <= 'f')
                ch = ch + (10 - 'a');
              else
                return value;  /* terminate early if not a hex char */
            }
        }
      value = (value << 4) + ch;
    }

  return value;
}

/* Outputs a hex value of the specified length to the buffer. */
void int2hex(char *buf, size_t len, unsigned int value)
{
  const char *hex = "0123456789ABCDEF";
  size_t i;

  for (i = 0; i < len; i++)
    {
      buf[len - i - 1] = hex[value & 0xf];
      value = value >> 4;
    }
}

/* Returns an integer from the buffer (4 bytes, msb first). */

unsigned long buffer_get_int(SshBuffer *buffer)
{
  unsigned char buf[4];

  ssh_buffer_get(buffer, buf, 4);
  return SSH_GET_32BIT(buf);
}

/* Stores an integer in the buffer in 4 bytes, msb first. */

void buffer_put_int(SshBuffer *buffer, unsigned long value)
{
  unsigned char buf[4];
  SSH_PUT_32BIT(buf, value);
  ssh_buffer_append(buffer, buf, 4);
}

/* Stores an SshInt in the buffer in ssh2 style 
   (XXX only positive integers for now !) */

void buffer_put_mp_int_ssh2style(SshBuffer *buffer, SshInt *value)
{
  SshInt temp;
  unsigned int i;
  unsigned char four[4], *buf;
  size_t buf_len;

  /* This code is written along the lines of the code in ber.c */
  switch (ssh_mp_cmp_ui(value, 0))
    {
    case 0:
      four[0] = four[1] = four[2] = four[3] = 0;
      ssh_buffer_append(buffer, four, 4);
      break;
    case 1:
      /* Handle the positive case. */
      buf_len = ssh_mp_get_size(value, 2);
      /* If highest bit set add one empty octet. */
      if ((buf_len & 7) == 0)
        buf_len += 8;
      /* The correct octet count. */
      buf_len = (buf_len + 7)/8;
      /* Allocate enough space. */
      buf = ssh_xmalloc(buf_len + 4);
      /* Put the length. */
      SSH_PUT_32BIT(buf, buf_len);
      /* Put the integer in quickly. */
      ssh_mp_to_buf(buf + 4, buf_len, value);

      /* Copy into buffer. */
      ssh_buffer_append(buffer, buf, buf_len + 4);
      ssh_xfree(buf);
      break;
    case -1:
      /* We need some additional arithmetic. */
      ssh_mp_init(&temp);
      /* Compute temp = (-value - 1) = -(value + 1). E.g. -1 -> 0, which
         then can be complemented. */
      ssh_mp_set_ui(&temp, 0);
      ssh_mp_sub(&temp, &temp, value);
      ssh_mp_sub_ui(&temp, &temp, 1);
      /* Compute the correct length in base 2. */
      buf_len = ssh_mp_get_size(&temp, 2);
      /* Check the highest bit case. Note that here we actually want the
         highest bit be set (after complementing). */
      if ((buf_len & 7) == 0)
        buf_len += 8;
      buf_len = (buf_len + 7)/8;
      buf = ssh_xmalloc(buf_len + 4);
      SSH_PUT_32BIT(buf, buf_len);
      ssh_mp_to_buf(buf + 4, buf_len, &temp);
      /* XXX Doing the complementing. Currently the ssh_mp_to_buf doesn't know
         how to do it. */
      for (i = 0; i < buf_len; i++)
        buf[i + 4] ^= 0xff;
      
      ssh_buffer_append(buffer, buf, buf_len + 4);
      ssh_xfree(buf);
      ssh_mp_clear(&temp);
      break;
    default:
      break;
    }
#if 0
  size_t i, j, hex_size;
  unsigned int first;
  char *buf;
    
  
  hex_size = ssh_mp_get_size(value, 16);
  
  buf = ssh_xmalloc(hex_size + 8);
  ssh_mp_get_str(&buf[6], 16, value);
  i = 6;
  j = 4;

  if ((hex_size & 1) != 0)
    {
      first = hex2int(&buf[i++], 1);
      if (first != 0)
        buf[j++] = first;
    }
  else
    {
      if (hex2int(&buf[i], 2) >= 0x80)
        buf[j++] = 0;
    }

  for (; i < (hex_size + 6); i += 2)
    buf[j++] = hex2int(&buf[i], 2);

  SSH_PUT_32BIT(buf, j - 4);
  ssh_buffer_append(buffer, (unsigned char *)buf, j);

  memset(buf, 0, hex_size + 8);
  ssh_xfree(buf);
#endif
}

/* Get an SshInt from a buffer in ssh2 style */

void buffer_get_mp_int_ssh2style(SshBuffer *buffer, SshInt *value)
{
  size_t byte_size;
  unsigned int i;
  unsigned char *buf;
  
  byte_size = buffer_get_int(buffer);
  /* Trivial case. */
  if (byte_size == 0)
    {
      ssh_mp_set_ui(value, 0);
      return;
    }
  /* Handling of the more complex cases. */
  buf = ssh_xmalloc(byte_size);
  ssh_buffer_get(buffer, buf, byte_size);

  if (buf[0] & 0x80)
    {
      for (i = 0; i < byte_size; i++)
        buf[i] ^= 0xff;
      ssh_buf_to_mp(value, buf, byte_size);
      ssh_mp_add_ui(value, value, 1);
      ssh_mp_neg(value, value);
    }
  else
    ssh_buf_to_mp(value, buf, byte_size);
  
  ssh_xfree(buf);
#if 0
  size_t byte_size;
  int i;
  unsigned char *buf;

  byte_size = buffer_get_int(buffer);
  buf = ssh_xmalloc(byte_size * 2 + 2);
  ssh_buffer_get(buffer, buf, byte_size);

  /* convert to hex */
  for (i = byte_size; i >= 0; i--)
    int2hex(&buf[i * 2], 2, (unsigned int) buf[i]);
  buf[byte_size * 2] = 0;

  /* Read the hex string into a mp-int. */
  ssh_mp_set_str(value, buf, 16);

  /* Free the string. */
  memset(buf, 0, 2 * byte_size + 1);
  ssh_xfree(buf);
#endif
}


/* Stores an SshInt in the buffer with a 4-byte msb first bit count, followed
   by (bits+7)/8 bytes of binary data, msb first. */

void buffer_put_mp_int(SshBuffer *buffer, SshInt *value)
{
  unsigned int bits = ssh_mp_get_size(value, 2);
  size_t buf_len = (bits + 7)/8;
  unsigned char *buf;

  /* Special case. Unnecessary, but funny. */
  if (bits == 0)
    {
      unsigned char four[4];
      four[0] = four[1] = four[2] = four[3] = 0;
      ssh_buffer_append(buffer, four, 4);
      return;
    }
  buf = ssh_xmalloc(buf_len + 4);
  SSH_PUT_32BIT(buf, bits);
  ssh_mp_to_buf(buf + 4, buf_len, value);
  ssh_buffer_append(buffer, buf, buf_len + 4);
  ssh_xfree(buf);

#if 0
  
  unsigned long bits = ssh_mp_get_size(value, 2);
  size_t hex_size = ssh_mp_get_size(value, 16);
  char *buf = ssh_xmalloc(hex_size + 2);
  size_t i, oi;
  unsigned char msg[4];
  
  /* Get the value of the number in hex.  Too bad that gmp does not allow
     us to get it in binary. */
  ssh_mp_get_str(buf, 16, value);

  /* i is "input index", oi is "output index".  Both point to the same array,
     and start from the beginning.  "input index" moves twice as fast. */
  i = 0;
  oi = 0;
  /* Check for an odd number of hex digits.  Process the odd digit 
     separately. */
  if (hex_size & 1)
    {
      buf[oi++] = hex2int(buf, 1);
      i = 1;
    }

  /* Convert the hex number into binary representation. */
  for (; i < hex_size; i += 2)
    buf[oi++] = hex2int(buf + i, 2);
  
  assert(oi == ((bits + 7) / 8));
  /* Store the number of bits in the buffer in four bytes, msb first. */
  SSH_PUT_32BIT(msg, bits);
  ssh_buffer_append(buffer, msg, 4);
  /* Store the binary data. */
  ssh_buffer_append(buffer, (unsigned char *)buf, oi);
  /* Clear the temporary data. */
  memset(buf, 0, hex_size);
  ssh_xfree(buf);
#endif
}

/* Retrieves an SshInt from the buffer. */
void buffer_get_mp_int(SshBuffer *buffer, SshInt *value)
{
  unsigned int bits;
  size_t bytes;
  unsigned char *buf;

  bits = buffer_get_int(buffer);
  if (bits == 0)
    {
      ssh_mp_set_ui(value, 0);
      return;
    }
  bytes = (bits + 7)/8;
  buf = ssh_xmalloc(bytes);
  ssh_buffer_get(buffer, buf, bytes);
  ssh_buf_to_mp(value, buf, bytes);
  ssh_xfree(buf);

#if 0  
  size_t bits, bytes, i;
  char *hex;
  unsigned char buf[4];
  unsigned char byte;

  /* Get the number for bits. */
  ssh_buffer_get(buffer, buf, 4);
  bits = SSH_GET_32BIT(buf);
  /* Compute the number of binary bytes that follow. */
  bytes = (bits + 7) / 8;
  /* Allocate space for a corresponding hex string. */
  hex = ssh_xmalloc(2 * bytes + 1);
  
  /* Read and convert the binary bytes into a hex string. */
  for (i = 0; i < bytes; i++)
    {
      ssh_buffer_get(buffer, &byte, 1);
      int2hex(hex + 2 * i, 2, byte);
    }
  hex[2 * i] = '\0';
  /* Read the hex string into a mp-int. */
  ssh_mp_set_str(value, hex, 16);
  /* Free the string. */
  memset(hex, 0, 2 * bytes + 1);
  ssh_xfree(hex);
#endif
}


/* Stores an vlint32 in the buffer. */

void buffer_put_vlint32(SshBuffer *buffer, unsigned long value)
{
  unsigned char temp[5];
  size_t length;

  length = ssh_vlint32_write(value, temp);
  ssh_buffer_append(buffer, temp, length);
}

/* Returns an vlint32 from the buffer. */

unsigned long buffer_get_vlint32(SshBuffer *buffer)
{
  size_t length;
  unsigned char temp[5];

  if (ssh_buffer_len(buffer) < 1)
    ssh_fatal("SshBuffer empty, cannot get vlint32 from it.");

  length = ssh_ssh_vlint32_parse_length(ssh_buffer_ptr(buffer));
  if (length > ssh_buffer_len(buffer))
    ssh_fatal("SshBuffer too short, cannot get vlint32 from it.");

  ssh_buffer_get(buffer, temp, length);
  return ssh_vlint32_parse(temp, NULL);
}

/* Return an arbitrary binary string, prefixed with vlint32, from the
   buffer. */

void *buffer_get_vlint32_string(SshBuffer *buffer, size_t *length_ptr)
{
  unsigned long length;
  unsigned char *value;

  length = buffer_get_vlint32(buffer);
  if (length > XMALLOC_MAX_SIZE)
    ssh_fatal("Bad string length %d.", length);

  value = ssh_xmalloc(length + 1);
  ssh_buffer_get(buffer, value, (size_t)length);
  value[length] = '\0';
  if (length_ptr)
    *length_ptr = length;
  return (void *)value;
}

void buffer_put_vlint32_string(SshBuffer *buffer,
                               const void *buf,
                               size_t len)
{
  buffer_put_vlint32(buffer, len);
  ssh_buffer_append(buffer, buf, len);
}


/* Returns an arbitrary binary string from the buffer.  The string cannot
   be longer than 256k.  The returned value points to memory allocated
   with ssh_xmalloc; it is the responsibility of the calling function to free
   the data.  If length_ptr is non-NULL, the length of the returned data
   will be stored there.  A null character will be automatically appended
   to the returned string, and is not counted in length. */

void *buffer_get_uint32_string(SshBuffer *buffer, size_t *length_ptr)
{
  size_t len;
  unsigned char *value;

  /* Get the length. */
  len = buffer_get_int(buffer);
  if (len > XMALLOC_MAX_SIZE)
    ssh_fatal("Received packet with bad string length %d", len);
  /* Allocate space for the string.  Add one byte for a null character. */
  value = ssh_xmalloc(len + 1);
  /* Get the string. */
  ssh_buffer_get(buffer, value, len);
  /* Append a null character to make processing easier. */
  value[len] = 0;
  /* Optionally return the length of the string. */
  if (length_ptr)
    *length_ptr = len;
  
  return value;
}

/* Stores and arbitrary binary string in the buffer. */

void buffer_put_uint32_string(SshBuffer *buffer, const void *buf, size_t len)
{
  buffer_put_int(buffer, len);
  ssh_buffer_append(buffer, buf, len);
}

/* Returns a character from the buffer (0 - 255). */

unsigned int buffer_get_char(SshBuffer *buffer)
{
  unsigned char ch;

  ssh_buffer_get(buffer, &ch, 1);
  return ch;
}

/* Stores a character in the buffer. */

void buffer_put_char(SshBuffer *buffer, unsigned int value)
{
  unsigned char ch = value;
  ssh_buffer_append(buffer, &ch, 1);
}

void buffer_put_boolean(SshBuffer *buffer, Boolean value)
{
  if (value)
    buffer_put_char(buffer, 1);
  else
    buffer_put_char(buffer, 0);
}

Boolean buffer_get_boolean(SshBuffer *buffer)
{
  int value = buffer_get_char(buffer);
  if (value == 0)
    return FALSE;
  return TRUE;
}
