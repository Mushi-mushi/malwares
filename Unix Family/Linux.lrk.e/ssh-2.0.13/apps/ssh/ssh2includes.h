/*

ssh2includes.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

*/

#ifndef SSH2INCLUDES_H
#define SSH2INCLUDES_H

#include "sshincludes.h"
#include "sshsessionincludes.h"
#include "ssh2version.h"

/* File executed in user's home directory during login. */
#define SSH_USER_RC             "rc"
#define SSH_USER_ENV_FILE       "environment"
#define SSH_SYSTEM_RC           ETCDIR "/sshrc"

/* Definitions for authentication method names. */
#define SSH_AUTH_PUBKEY "publickey"
#define SSH_AUTH_PASSWD "password"
#define SSH_AUTH_HOSTBASED "hostbased"

/* Path to sshsigner2 */
#define SSH_SIGNER_PATH "ssh-signer2"

/* arguments to ssh2 */
#define SSH2_GETOPT_ARGUMENTS "ac:Cvd:e:fF:hi:l:L:no:p:PqR:s:Stx8gV"


#define SSH2_VERSION_STRING "SSH-" SSH2_VERSION
#define SSH2_PROTOCOL_VERSION_STRING SSH2_VERSION " (non-commercial)"


#endif /* SSH2INCLUDES_H */
