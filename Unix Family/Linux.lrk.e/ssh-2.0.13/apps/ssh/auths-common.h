/*

  auths-common.h

  Author: Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Common functions for both pubkey- and password-authentication on the
  server side.

*/

#ifndef AUTHS_COMMON_H
#define AUTHS_COMMON_H

#include "sshincludes.h"
#include "sshuser.h"
#include "sshcommon.h"
#include "sshdllist.h"

/* Use this to check whether specified user is allowed to
   connect. Returns FALSE if allowed.*/
Boolean ssh_server_auth_check_user(SshUser *ucp, const char *user,
                                   SshConfig config);

/* Use this to check whether connects from specified host are
   allowed. Returns FALSE if connects are allowed.*/
Boolean ssh_server_auth_check_host(SshCommon common);

/* Checks whether given host name or ip-address is found in
   list. Returns FALSE if a match is found, and TRUE otherwise. */
Boolean ssh_match_host_in_list(char *host_name, char *host_ip,
                               SshDlList list);
#endif /* AUTHS_COMMON_H */
