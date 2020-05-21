/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 * 
 * Copyright (c) 1996 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *        Program: sshutil
 *        $Source: /ssh/CVS/src/lib/sshutil/strcasecmp.c,v $
 *        $Author: ylo $
 *
 *        Creation          : 06:49 Aug 20 1996 kivinen
 *        Last Modification : 07:00 Aug 20 1996 kivinen
 *        Last check in     : $Date: 1998/01/28 10:15:09 $
 *        Revision number   : $Revision: 1.2 $
 *        State             : $State: Exp $
 *        Version           : 1.7
 *
 *        Description       : Replacement functions for strcasecmp
 *
 *
 *        $Log: strcasecmp.c,v $
 *        $EndLog$
 */

#include "sshincludes.h"

int strcasecmp(const char *s1, const char *s2)
{
  while (*s1 && (*s1 == *s2 || tolower(*s1) == tolower(*s2)))
    {
      s1++;
      s2++;
    }
  return (int) *(unsigned char *)s1 - (int) *(unsigned char *)s2;
}
