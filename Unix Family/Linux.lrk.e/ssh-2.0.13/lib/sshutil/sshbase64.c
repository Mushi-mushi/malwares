/*

  base64.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sun Dec  8 08:10:59 1996 [mkojo]

  Converting buffers to and from base64.

  */

/*
 * $Id: sshbase64.c,v 1.2 1999/04/09 00:44:26 kivinen Exp $
 * $Log: sshbase64.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshbase64.h"

/* Convert from buffer of base 256 to base 64. */

const unsigned char ssh_base64[64] =
{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };

const unsigned char ssh_inv_base64[128] =
{
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255,  62, 255, 255, 255,  63, 
   52,  53,  54,  55,  56,  57,  58,  59,
   60,  61, 255, 255, 255, 255, 255, 255, 
  255,   0,   1,   2,   3,   4,   5,   6,
    7,   8,   9,  10,  11,  12,  13,  14, 
   15,  16,  17,  18,  19,  20,  21,  22,
   23,  24,  25, 255, 255, 255, 255, 255, 
  255,  26,  27,  28,  29,  30,  31,  32,
   33,  34,  35,  36,  37,  38,  39,  40, 
   41,  42,  43,  44,  45,  46,  47,  48,
   49,  50,  51, 255, 255, 255, 255, 255,
};

size_t ssh_is_base64_buf(unsigned char *buf, size_t buf_len)
{
  size_t i;

  for (i = 0; i < buf_len; i++)
    {
      /* Accept equal sign. */
      if (buf[i] == '=')
        continue;
      /* Don't accept anything else which isn't in base64. */
      if (buf[i] > 127)
        break;
      if (ssh_inv_base64[buf[i]] == 255)
        break;
    }
  return i;
}

unsigned char *ssh_buf_to_base64(const unsigned char *buf, size_t buf_len)
{
  unsigned char *out;
  size_t i, j;
  SshUInt32 limb;

  out = ssh_xmalloc(((buf_len * 8 + 5) / 6) + 5);

  for (i = 0, j = 0, limb = 0; i + 2 < buf_len; i += 3, j += 4)
    {
      limb =
        ((SshUInt32)buf[i] << 16) |
        ((SshUInt32)buf[i + 1] << 8) |
        ((SshUInt32)buf[i + 2]);

      out[j] = ssh_base64[(limb >> 18) & 63];
      out[j + 1] = ssh_base64[(limb >> 12) & 63];
      out[j + 2] = ssh_base64[(limb >> 6) & 63];
      out[j + 3] = ssh_base64[(limb) & 63];
    }
  
  switch (buf_len - i)
    {
    case 0:
      break;
    case 1:
      limb = ((SshUInt32)buf[i]);
      out[j++] = ssh_base64[(limb >> 2) & 63];
      out[j++] = ssh_base64[(limb << 4) & 63];
      out[j++] = '=';
      out[j++] = '=';
      break;
    case 2:
      limb = ((SshUInt32)buf[i] << 8) | ((SshUInt32)buf[i + 1]);
      out[j++] = ssh_base64[(limb >> 10) & 63];
      out[j++] = ssh_base64[(limb >> 4) & 63];
      out[j++] = ssh_base64[(limb << 2) & 63];
      out[j++] = '=';
      break;
    default:
      ssh_fatal("ssh_buf_to_base64: internal error.");
      break;
    }
  out[j] = '\0';

  return out;
}
      
unsigned char *ssh_base64_to_buf(unsigned char *str, size_t *buf_len)
{
  unsigned char *buf;
  int i, j, len;
  SshUInt32 limb;

  len = strlen((char *) str);
  *buf_len = (len * 6 + 7) / 8;
  buf = ssh_xmalloc(*buf_len);
  
  for (i = 0, j = 0, limb = 0; i + 3 < len; i += 4)
    {
      if (str[i] == '=' || str[i + 1] == '=' ||
          str[i + 2] == '=' || str[i + 3] == '=')
        {
          if (str[i] == '=' || str[i + 1] == '=')
            break;
          
          if (str[i + 2] == '=')
            {
              limb =
                ((SshUInt32)ssh_inv_base64[str[i]] << 6) |
                ((SshUInt32)ssh_inv_base64[str[i + 1]]);
              buf[j] =(unsigned char)(limb >> 4) & 0xff;
              j++;
            }
          else
            {
              limb =
                ((SshUInt32)ssh_inv_base64[str[i]] << 12) |
                ((SshUInt32)ssh_inv_base64[str[i + 1]] << 6) |
                ((SshUInt32)ssh_inv_base64[str[i + 2]]);
              buf[j] = (unsigned char)(limb >> 10) & 0xff;
              buf[j + 1] = (unsigned char)(limb >> 2) & 0xff;
              j += 2;
            }
        }
      else
        {
          limb =
            ((SshUInt32)ssh_inv_base64[str[i]] << 18) |
            ((SshUInt32)ssh_inv_base64[str[i + 1]] << 12) |
            ((SshUInt32)ssh_inv_base64[str[i + 2]] << 6) |
            ((SshUInt32)ssh_inv_base64[str[i + 3]]);
          
          buf[j] = (unsigned char)(limb >> 16) & 0xff;
          buf[j + 1] = (unsigned char)(limb >> 8) & 0xff;
          buf[j + 2] = (unsigned char)(limb) & 0xff;
          j += 3;
        }
    }

  *buf_len = j;
  
  return buf;
}

/* Remove unneeded whitespace (everything that is not in base64!).
 * Returns new xmallocated string containing the string. If len is 0
 * use strlen(str) to get length of data. */

unsigned char *ssh_base64_remove_whitespace(const unsigned char *str,
                                            size_t len)
{
  unsigned char *cp;
  size_t i, j;

  if (len == 0)
    len = strlen((char *) str);
  cp = ssh_xmalloc(len + 1);

  for (i = 0, j = 0; i < len; i++)
    {
      if (!(str[i] & 128))
        {
          if (ssh_inv_base64[str[i]] != 255 || str[i] == '=')
            cp[j++] = str[i];
        }
    }

  cp[j] = '\0';
  
  return cp;
}
