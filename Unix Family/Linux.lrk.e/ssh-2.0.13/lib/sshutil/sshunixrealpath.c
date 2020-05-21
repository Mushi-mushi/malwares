/*

sshunixrealpath.c

Author: Timo J. Rinne <tri@ssh.fi>

Created: Fri Mar 27 17:22:06 1998 tri

Modified from NetBSD 1.3 source by Timo J. Rinne <tri@ssh.fi>.
Original function realpath renamed to ssh_realpath.
Added compatibility with systems with no fchdir(2).

*/

/*
 * $Id: sshunixrealpath.c,v 1.5 1998/06/24 13:38:22 kivinen Exp $
 * $Log: sshunixrealpath.c,v $
 * $EndLog$
 *
 */

/*
 * Copyright (c) 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Jan-Simon Pendry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "sshincludes.h"
#include "sshfilexfer.h"

#if 0
#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#endif

/*
 * char *ssh_realpath(const char *path, char resolved_path[MAXPATHLEN]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 * 
 */
char *ssh_realpath(const char *path, char *resolved)
{
  struct stat sb;
  int n, rootd, serrno;
#ifdef HAVE_FCHDIR
  int fd;
#else
  char starting_point[MAXPATHLEN];
#endif
  char *p, *q, wbuf[MAXPATHLEN];
  
  /* Save the starting point. */
#ifdef HAVE_FCHDIR
  if ((fd = open(".", O_RDONLY)) < 0) 
    {
      (void)strncpy(resolved, ".", MAXPATHLEN - 1);
      return (NULL);
    }
#else
  if (getcwd(starting_point, sizeof (starting_point) - 1) == NULL) 
    {
      (void)strncpy(resolved, ".", MAXPATHLEN - 1);
      return (NULL);
    }
#endif

  /*
   * Find the dirname and basename from the path to be resolved.
   * Change directory to the dirname component.
   * lstat the basename part.
   *     if it is a symlink, read in the value and loop.
   *     if it is a directory, then change to that directory.
   * get the current directory name and append the basename.
   */
  (void)strncpy(resolved, path, MAXPATHLEN - 1);
  resolved[MAXPATHLEN - 1] = '\0';
  loop:
  q = strrchr(resolved, '/');
  if (q != NULL) 
    {
      p = q + 1;
      if (q == resolved)
	q = "/";
      else 
	{
	  do 
	    {
	    --q;
	    } while (q > resolved && *q == '/');
	  q[1] = '\0';
	  q = resolved;
	}
      if (chdir(q) < 0)
	goto err1;
    } 
  else
    p = resolved;

  /* Deal with the last component. */
  if (lstat(p, &sb) == 0) 
    {
      if (S_ISLNK(sb.st_mode)) 
	{
	  n = readlink(p, resolved, MAXPATHLEN);
	  if (n < 0)
	    goto err1;
	  resolved[n] = '\0';
	  goto loop;
	}
      if (S_ISDIR(sb.st_mode)) 
	{
	  if (chdir(p) < 0)
	    goto err1;
	  p = "";
	}
    }
  
  /*
   * Save the last component name and get the full pathname of
   * the current directory.
   */
  (void)strncpy(wbuf, p, sizeof wbuf - 1);
  if (getcwd(resolved, MAXPATHLEN) == 0)
    goto err1;
  
  /*
   * Join the two strings together, ensuring that the right thing
   * happens if the last component is empty, or the dirname is root.
   */
  if (resolved[0] == '/' && resolved[1] == '\0')
    rootd = 1;
  else
    rootd = 0;
  
  if (*wbuf) 
    {
      if (strlen(resolved) + strlen(wbuf) + rootd + 1 > MAXPATHLEN) 
	{
	  errno = ENAMETOOLONG;
	  goto err1;
	}
      if (rootd == 0)
	(void)strcat(resolved, "/"); /* XXX: strcat is safe */
      (void)strcat(resolved, wbuf);	/* XXX: strcat is safe */
    }
  
#ifdef HAVE_FCHDIR
  /* Go back to where we came from. */
  if (fchdir(fd) < 0) 
    {
      serrno = errno;
      goto err2;
    }

  /* It's okay if the close fails, what's an fd more or less? */
  (void)close(fd);
#else
  if (chdir(starting_point) < 0) 
    {
      serrno = errno;
      goto err2;
    }
#endif
  return (resolved);
  
  err1:	
  serrno = errno;
#ifdef HAVE_FCHDIR
  (void)fchdir(fd);
#else
  (void)chdir(starting_point);
#endif
  err2:	
#ifdef HAVE_FCHDIR
  (void)close(fd);
#endif
  errno = serrno;
  return (NULL);
}
