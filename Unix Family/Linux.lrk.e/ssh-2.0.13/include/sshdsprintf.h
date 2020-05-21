/*

  sshdsprintf.h

  Author:
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
*/

#ifndef SSHDSPRINTF_H
#define SSHDSPRINTF_H

/* This function is similar to snprintf (indeed, this function, too,
   uses vsnprintf()); it takes a format argument which specifies the
   subsequent arguments, and writes them to a string using the
   format-string. This function differs from snprintf in that this
   allocates the buffer itself, and returns a pointer to the allocated
   string (in str). This function never fails.  (if there is not
   enough memory, ssh_xrealloc() calls ssh_fatal())

   The returned string must be freed by the caller. Returns the number
   of characters written.  */
int ssh_dsprintf(char **str, const char *format, ...);

#endif /* SSHDSPRINTF_H */
