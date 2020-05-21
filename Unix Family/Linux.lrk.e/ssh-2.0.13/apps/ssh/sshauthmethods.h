/*

sshauthmethods.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

This file defines the interfaces for authentication method handling for
ssh2.

*/

#ifndef SSHAUTHMETHODS_H
#define SSHAUTHMETHODS_H

#include "sshauth.h"

/* Array of authentication methods for the server. */
extern const SshAuthServerMethod *ssh_server_authentication_methods;

/* Array of authentication methods for the client. */
extern const SshAuthClientMethod *ssh_client_authentication_methods;

/* Initializes the authentication methods array for the server. */
SshAuthServerMethod *ssh_server_authentication_initialize(void);

/* Frees the returned authentication method array. */
void ssh_server_authentication_uninitialize(SshAuthServerMethod *methods);

/* Initializes the authentication methods array for the client. */
SshAuthClientMethod *ssh_client_authentication_initialize(void);

/* Frees the returned authentication method array. */
void ssh_client_authentication_uninitialize(SshAuthClientMethod *methods);

#endif /* SSHAUTHMETHODS_H */
