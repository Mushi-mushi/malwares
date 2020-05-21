/*

genaux.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

*/

/*
 * $Id: genaux.c,v 1.5 1998/02/08 18:51:57 ylo Exp $
 * $Log: genaux.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshcrypt.h"

/* Returns the string representation of the error returned (in English). */

DLLEXPORT const char * DLLCALLCONV
ssh_crypto_status_message(SshCryptoStatus status)
{
  switch (status)
    {
    case SSH_CRYPTO_OK:
      return "Operation was successful";
    case SSH_CRYPTO_UNSUPPORTED:
      return "Algorithm or key not supported";
    case SSH_CRYPTO_DATA_TOO_LONG:
      return "Data is too long";
    case SSH_CRYPTO_INVALID_PASSPHRASE:
      return "Invalid passphrase";
    case SSH_CRYPTO_BLOCK_SIZE_ERROR:
      return "Block cipher block size constraint violation";
    case SSH_CRYPTO_KEY_TOO_SHORT:
      return "Key is too short for the algorithm";
    case SSH_CRYPTO_OPERATION_FAILED:
      return "Operation failed";
    case SSH_CRYPTO_UNSUPPORTED_IDENTIFIER:
      return "Identifier not supported";
    case SSH_CRYPTO_SCHEME_UNKNOWN:
      return "Scheme not supported";
    case SSH_CRYPTO_UNKNOWN_GROUP_TYPE:
      return "Group type given not recognized";
    case SSH_CRYPTO_UNKNOWN_KEY_TYPE:
      return "Key type given not recognized";
    case SSH_CRYPTO_KEY_UNINITIALIZED:
      return "Key should have been initialized";
    case SSH_CRYPTO_CORRUPTED_KEY_FORMAT:
      return "Key format was corrupted";
    case SSH_CRYPTO_LIBRARY_CORRUPTED:
      return "Internal error"; 
    default:
      return "Unknown error code";
    }
}

