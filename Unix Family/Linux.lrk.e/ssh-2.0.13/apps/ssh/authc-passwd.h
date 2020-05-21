/*
  
  authc-passwd.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Password authentication, client side.
  
*/

#ifndef AUTHC_PASSWD_H
#define AUTHC_PASSWD_H

/* Password authentication, client-side. */

void ssh_client_auth_passwd(SshAuthClientOperation op,
                            const char *user,
                            unsigned int packet_type,
                            SshBuffer *packet_in,
                            const unsigned char *session_id,
                            size_t session_id_len,
                            void **state_placeholder,
                            SshAuthClientCompletionProc completion,
                            void *completion_context,
                            void *method_context);

#endif /* AUTHC_PASSWD_H */

