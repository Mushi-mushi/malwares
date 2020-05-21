/*

sshsia.c

Author: Tom Woodburn <woodburn@zk3.dec.com>

Helper functions for using the SIA (Security Integration Architecture)
functions of Tru64 UNIX.

Copyright (c) 1999 SSH Communications Security Oy, Espoo, Finland
                   and Compaq Computer Corporation

*/

/*
 * $Id: sshsia.c,v 1.2 1999/04/30 06:45:46 tri Exp $
 * $Log: sshsia.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshsia.h"

static int argc = 0;
static char **argv = NULL;

void
initialize_sia(int ac, char **av)
{
  argc = ac;
  argv = av;
}

/* get_sia_args() returns the arguments passed to initialize_sia(), which
   typically are the arguments from main(). */

void
get_sia_args(int *ac, char ***av)
{
  *ac = argc;
  *av = argv;
}

/* The only reason we have our own version of sia_validate_user()
   is that we need to authenticate the user through sia_ses_authent().
   sia_validate_user() uses sia_ses_reauthent().

   We need sia_ses_authent() because it logs unsuccessful logins.
   sia_ses_reauthent() doesn't (at least not yet). */

/*
 * NAME:  my_sia_validate_user
 *
 * FUNCTION:  Verify a user/passphrase combination.
 *
 * RETURNS:
 *      SIASUCCESS on success,
 *      SIAFAIL on failure.
 *
 */

int
my_sia_validate_user(sia_collect_func_t *collect, /* communication routine */
                     int argc,
                     char **argv,
                     char *hostname,    /* remote host (or user@host) info */
                     char *username,
                     char *tty,         /* ttyname() or X display (if any) */
                     int colinput,      /* can call collect() for input */
                     char *gssapi,
                     char *passphrase)  /* pre-gathered passphrase (bad) */
{
  SIAENTITY *ent = NULL;
  int status;

  status = sia_ses_init(&ent, argc, argv,
                        hostname, username, tty, colinput, gssapi);
  if (status != SIASUCCESS || !ent)
    return SIAFAIL;

  status = sia_ses_authent(collect, passphrase, ent);
  (void) sia_ses_release(&ent);
  return status;
}
