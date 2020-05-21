/*

  Author: Timo J. Rinne

  Copyright (C) 1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created:  Mon Oct 26 18:04:49 1998 tri

  Misc string functions.

*/

/*
 * $Id: sshmiscstring.h,v 1.3 1998/10/29 14:22:51 tri Exp $
 * $Log: sshmiscstring.h,v $
 * $EndLog$
 */

#ifndef SSHMISCSTRING_H
#define SSHMISCSTRING_H
/*
 * Allocates (ssh_xmalloc) a new string concatenating the NULL 
 * terminated strings s1 and s2.  NULL pointer is translated to
 * empty string.
 */
char *ssh_string_concat_2(const char *s1, const char *s2);

/*
 * Allocates (ssh_xmalloc) a new string concatenating the NULL 
 * terminated strings s1, s2 and s3.  NULL pointer is translated to
 * empty string.
 */
char *ssh_string_concat_3(const char *s1, const char *s2, const char *s3);

/*
 * Allocates (ssh_xmalloc) a new string where all instances of
 * substring src in string str are replaced with substring dst.
 */
char *ssh_replace_in_string(const char *str, const char *src, const char *dst);

#endif /* SSHMISCSTRING_H */
/* eof (sshmiscstring.h) */
