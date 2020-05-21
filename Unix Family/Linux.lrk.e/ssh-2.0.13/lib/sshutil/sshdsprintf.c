/*

  sshdsprintf.c

  Author:
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
*/

#include "sshincludes.h"

#define SSH_DEBUG_MODULE "SshDSprintf"

int ssh_dsprintf(char **str, const char *format, ...)
{
  int ret;
  va_list ap;
  char *buffer;
  unsigned long size = 100L;

  SSH_PRECOND(str != NULL);
  SSH_PRECOND(format != NULL);
  
  /* Guess 100 characters length. */
  buffer = ssh_xcalloc(size, sizeof(char));
  
  do
    {
      va_start(ap, format);
      ret = vsnprintf(buffer, size, format, ap);
      va_end(ap);

      /* ret > size is for broken vsnprintf-implementations. If the
         output is truncated by vsnprintf, it should return -1. At
         least my linux glibc 2.1.1 system didn't return this. */
      if (ret < 0 || ret > size || ret == size)
        {
          if (ret > size)
            {
              SSH_DEBUG(4, ("vsnprintf gave return value %d, when given " \
                            "buffer size is only %d.", ret, size));
              ret = -1;
            }

          /* BSD style vsnprintf */
          if (ret == size)
            {
              /* buffer wasn't long enough. */
              ret = -1;
            }
          
          
          /* If it wasn't enough, double the buffer's size. */
          size *= 2L;
          buffer = ssh_xrealloc(buffer, size);
        }   
    }
  while(ret < 0);
  
  *str = buffer;
  return ret;
}
