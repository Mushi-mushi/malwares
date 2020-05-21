/*

  Author: Antti Huima <huima@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat May 25 13:02:50 1996 [huima]

  Vlint32 utilites -- part of the protocol.
  Implementation.

  */

/*
 * $Id: sshvlint32.c,v 1.1 1999/03/15 13:54:45 tri Exp $
 * $Log: sshvlint32.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshvlint32.h"

unsigned long ssh_vlint32_parse(const unsigned char *data,
                           size_t *length_return)
{
  size_t temp;

  if (length_return == NULL)
    length_return = &temp;

  switch (data[0] & 0xc0)
    {
    case 0x00:
      *length_return = 1;
      return (data[0] & 0x3f);
    case 0x40:
      *length_return = 2;
      return (((unsigned long)(data[0] & 0x3f)) << 8) +
        data[1];
    case 0x80:
      *length_return = 3;
      return (((unsigned long)(data[0] & 0x3f)) << 16) +
        (((unsigned long)(data[1])) << 8) +
        data[2];
    case 0xc0:
      *length_return = 5;
      return (((unsigned long)(data[1])) << 24) +
        (((unsigned long)(data[2])) << 16) +
        (((unsigned long)(data[3])) << 8) +
        (((unsigned long)(data[4])));
    }
  /* NOTREACHED */
  ssh_fatal("ssh_vlint32_parse: internal error");
  return 0L;
}

size_t ssh_vlint32_write(unsigned long number,
                           unsigned char *data)
{
  if (number < 0x40)
    {
      data[0] = number;
      return 1;
    }
  if (number < 0x4000)
    {
      data[0] = (number >> 8) | 0x40;
      data[1] = (number & 0xff);
      return 2;
    }
  if (number < 0x400000L)
    {
      data[0] = (number >> 16) | 0x80;
      data[1] = ((number >> 8) & 0xff);
      data[2] = (number & 0xff);
      return 3;
    }
  data[0] = 0xc0;
  data[1] = (number >> 24) & 0xff;
  data[2] = (number >> 16) & 0xff;
  data[3] = (number >>  8) & 0xff;
  data[4] = (number      ) & 0xff;
  return 5;
}

size_t ssh_vlint32_length(unsigned long number)
{
  if (number < 0x40)
    return 1;
  if (number < 0x4000)
    return 2;
  if (number < 0x400000L)
    return 3;
  return 5;
}

size_t ssh_ssh_vlint32_parse_length(const unsigned char *data)
{
  switch (data[0] & 0xc0)
    {
    case 0x00:
      return 1;
    case 0x40:
      return 2;
    case 0x80:
      return 3;
    case 0xc0:
      return 5;
    }
  /*NOTREACHED*/
  return 0;
}
