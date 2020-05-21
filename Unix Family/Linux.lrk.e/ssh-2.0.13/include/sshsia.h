/*

sshsia.h

Author: Tom Woodburn <woodburn@zk3.dec.com>

Helper functions for using the SIA (Security Integration Architecture)
functions of Tru64 UNIX.

Copyright (c) 1999 SSH Communications Security Oy, Espoo, Finland
                   and Compaq Computer Corporation

*/

#ifndef SSHSIA_H
#define SSHSIA_H

#include <sia.h>

void initialize_sia(int ac, char **av);
void get_sia_args(int *ac, char ***av);
int my_sia_validate_user(sia_collect_func_t *collect, int argc, char *argv[],
                         char *hostname, char *username, char *tty,
                         int colinput, char *gssapi, char *passphrase);

#endif /* SSHSIA_H */
