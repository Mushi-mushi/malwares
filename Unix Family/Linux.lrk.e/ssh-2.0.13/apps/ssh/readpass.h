/*

readpass.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Functions for reading a passphrase from the user.  The terminal must be
in normal, blocking and cooked mode.

*/

#ifndef READPASS_H
#define READPASS_H

/* Reads a passphrase from /dev/tty with echo turned off.  Returns the 
   passphrase (allocated with ssh_xmalloc).  Exits if EOF is encountered. 
   The passphrase if read from stdin if from_stdin is true (as is the
   case with ssh-keygen).  */
char *ssh_read_passphrase(const char *prompt, int from_stdin);

/* Reads a yes/no confirmation from /dev/tty.  Returns TRUE if "yes" is
   received.  Otherwise returns FALSE (also if EOF is encountered). */
Boolean ssh_read_confirmation(const char *prompt);

#endif /* READPASS_H */
