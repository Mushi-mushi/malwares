/*
  auths-hostbased.h

  Authors: Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Hostbased authentication, server-side.
*/

#ifndef AUTHS_HOSTBASED_H
#define AUTHS_HOSTBASED_H

#include "ssh2includes.h"
#include "sshuser.h"

/*   Hostbased authentication, server-side. */

SshAuthServerResult ssh_server_auth_hostbased(SshAuthServerOperation op,
                                              const char *user,
                                              SshBuffer *packet,
                                              const unsigned char *session_id,
                                              size_t session_id_len,
                                              void **state_placeholder,
                                              void **longtime_placeholder,
                                              void *method_context);

/* Returns TRUE if hostbased authentication can continue (by checking
   /etc/hosts.equiv, /etc/shosts.equiv and $HOME/.[rs]hosts). */
Boolean ssh_server_auth_hostbased_rhosts(SshUser user_data,
                                         const char *client_user,
                                         void *context);

#endif /* AUTHS_HOSTBASED_H */
