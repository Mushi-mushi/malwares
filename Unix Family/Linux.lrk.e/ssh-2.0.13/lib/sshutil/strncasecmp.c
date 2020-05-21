/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 * 
 * Copyright (c) 1996 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *        Program: sshutil
 *        $Source: /ssh/CVS/src/lib/sshutil/strncasecmp.c,v $
 *        $Author: ylo $
 *
 *        Creation          : 06:56 Aug 20 1996 kivinen
 *        Last Modification : 07:00 Aug 20 1996 kivinen
 *        Last check in     : $Date: 1998/01/28 10:15:13 $
 *        Revision number   : $Revision: 1.2 $
 *        State             : $State: Exp $
 *        Version           : 1.5
 *
 *        Description       : Replacement functions for strncasecmp
 *
 *
 *        $Log: strncasecmp.c,v $
 *        $EndLog$
 */

#include "sshincludes.h"

int strncasecmp(const char *s1, const char *s2, size_t len)
{
  while (len-- > 1 && *s1 && (*s1 == *s2 || tolower(*s1) == tolower(*s2)))
    {
      s1++;
      s2++;
    }
  return (int) *(unsigned char *)s1 - (int) *(unsigned char *)s2;
}
