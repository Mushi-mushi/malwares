/*
  auths-pubkey.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Public key authentication, server-side.
*/

#ifndef AUTHS_PUBKEY_H
#define AUTHS_PUBKEY_H

#include "ssh2includes.h"

/* Public key authentication for the server side. */

SshAuthServerResult ssh_server_auth_pubkey(SshAuthServerOperation op,
                                           const char *user,
                                           SshBuffer *packet,
                                           const unsigned char *session_id,
                                           size_t session_id_len,
                                           void **state_placeholder,
                                           void **longtime_placeholder,
                                           void *method_context);

#endif /* AUTHS_PUBKEY_H */
