/*
  authc-hostbased.h

  Authors: Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Hostbased authentication, client-side.
*/

#ifndef AUTHC_HOSTBASED_H
#define AUTHC_HOSTBASED_H

#include "ssh2includes.h"
#include "ssh-signer2.h"

/*   Hostbased authentication, client-side. */

void ssh_client_auth_hostbased(SshAuthClientOperation op,
                               const char *user,
                               unsigned int packet_type,
                               SshBuffer *packet_in,
                               const unsigned char *session_id,
                               size_t session_id_len,
                               void **state_placeholder,
                               SshAuthClientCompletionProc completion,
                               void *completion_context,
                               void *method_context);

#endif /* AUTHC_HOSTBASED_H */
