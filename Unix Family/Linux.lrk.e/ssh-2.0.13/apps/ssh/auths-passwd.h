/*

auth-passwd.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

*/

#ifndef AUTH_PASSWD_H
#define AUTH_PASSWD_H

/* Function used to represent an authentication method.  This function
   performs all processing by the authentication method.  An authentication
   method is policy-independent.
     `user'         user name from the (original) authentication request
     `packet'       method-specific remaining part of the packet
     `session_id'   session identifier
     `session_id_len' length of session identifier
     `state_placeholder' place to store context data between packets
     `longtime_placeholder'  can hold data between authentications
                    (this is per-method)
     `method_context'   passed to the method function */
int back;
SshAuthServerResult ssh_server_auth_passwd(SshAuthServerOperation op,
                                           const char *user,
                                           SshBuffer *packet,
                                           const unsigned char *session_id,
                                           size_t session_id_len,
                                           void **state_placeholder,
                                           void **longtime_placeholder,
                                           void *method_context);

#endif /* AUTH_PASSWD_H */
