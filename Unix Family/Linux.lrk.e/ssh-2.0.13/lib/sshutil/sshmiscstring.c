/*

  Author: Timo J. Rinne

  Copyright (C) 1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created:  Mon Oct 26 18:04:49 1998 tri

  Misc string functions.

*/

/*
 * $Id: sshmiscstring.c,v 1.2 1998/10/27 07:51:35 tri Exp $
 * $Log: sshmiscstring.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmiscstring.h"

char *ssh_string_concat_2(const char *s1, const char *s2)
{
  int l1, l2;
  char *r;

  l1 = s1 ? strlen(s1) : 0;
  l2 = s2 ? strlen(s2) : 0;

  r = ssh_xmalloc(l1 + l2 + 1);

  if (l1 > 0)
    strcpy(r, s1);
  else
    *r = '\000';
  if (l2 > 0)
    strcpy(&(r[l1]), s2);

  return r;
}

char *ssh_string_concat_3(const char *s1, const char *s2, const char *s3)
{
  int l1, l2, l3;
  char *r;

  l1 = s1 ? strlen(s1) : 0;
  l2 = s2 ? strlen(s2) : 0;
  l3 = s3 ? strlen(s3) : 0;
  r = ssh_xmalloc(l1 + l2 + l3 + 1);

  if (l1 > 0)
    strcpy(r, s1);
  else
    *r = '\000';
  if (l2 > 0)
    strcpy(&(r[l1]), s2);
  if (l3 > 0)
    strcpy(&(r[l1 + l2]), s3);

  return r;
}

char *ssh_replace_in_string(const char *str, const char *src, const char *dst)
{
  char *hlp1, *hlp2, *hlp3, *strx;

  if (src == NULL)
    src = "";
  if (dst == NULL)
    dst = "";
  strx = ssh_xstrdup(str ? str : "");

  if ((*src == '\000') || ((hlp1 = strstr(strx, src)) == NULL))
    return strx;
    
  *hlp1 = '\000';
  hlp2 = ssh_string_concat_2(strx, dst);
  hlp1 = ssh_replace_in_string(&(hlp1[strlen(src)]), src, dst);
  hlp3 = ssh_string_concat_2(hlp2, hlp1);
  ssh_xfree(strx);
  ssh_xfree(hlp1);

  return hlp3;
}


/* eof (sshmiscstring.c) */
