/*

  sshauthmethodc.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  SSH2 authentication methods for the client.

*/

#include "ssh2includes.h"
#include "sshencode.h"
#include "sshauth.h"
#include "readpass.h"
#include "authc-pubkey.h"
#include "authc-passwd.h"
#include "authc-hostbased.h"

#define SSH_DEBUG_MODULE "SshAuthMethodClient"

/* table of the supported authentication methods */

SshAuthClientMethod ssh_client_auth_methods[] =
{
  { SSH_AUTH_PUBKEY, ssh_client_auth_pubkey }, 
  { SSH_AUTH_PASSWD, ssh_client_auth_passwd },
  { SSH_AUTH_HOSTBASED, ssh_client_auth_hostbased },
  { NULL, NULL }
};

/* Initializes the authentication methods array for the client. */

SshAuthClientMethod *ssh_client_authentication_initialize()
{
  return ssh_client_auth_methods;
}

/* Frees the returned authentication method array. */

void ssh_client_authentication_uninitialize(SshAuthClientMethod *methods)
{
  /* We returned a static array, nothing to do here for now. */
}
