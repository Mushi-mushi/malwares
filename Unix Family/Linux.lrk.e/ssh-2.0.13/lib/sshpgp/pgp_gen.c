/*

pgp_gen.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Generic stuff for OpenPGP.

*/
/*
 * $Id: pgp_gen.c,v 1.5 1999/04/05 18:37:47 tri Exp $
 * $Log: pgp_gen.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef WITH_PGP
#include "sshcrypt.h"
#include "sshpgp.h"

#define SSH_DEBUG_MODULE "SshPgpGen"

const char *ssh_pgp_canonical_cipher_name(int cipher)
{
  switch (cipher) 
    {
    case SSH_PGP_SK_ALGORITHM_PLAIN:
      return "none";
    case SSH_PGP_SK_ALGORITHM_IDEA:
      return "idea-ecb";
    case SSH_PGP_SK_ALGORITHM_3DES:
      return "3des-ecb";
    case SSH_PGP_SK_ALGORITHM_CAST:
      return "cast128-ecb";
    case SSH_PGP_SK_ALGORITHM_BLOWFISH:
      return "blowfish-ecb";
    case SSH_PGP_SK_ALGORITHM_SAFER:
      return "safersk128-ecb";
    default:
      return NULL;
    }
}

const char *ssh_pgp_canonical_hash_name(int hash)
{
  switch (hash) 
    {
    case SSH_PGP_HASH_ALGORITHM_MD5:
      return "md5";
    case SSH_PGP_HASH_ALGORITHM_SHA1:
      return "sha1";
    case SSH_PGP_HASH_ALGORITHM_RIPEMD160:
      return "ripemd160";
    case SSH_PGP_HASH_ALGORITHM_MD2:
      return "md2";
    case SSH_PGP_HASH_ALGORITHM_TIGER192:
      return NULL;
    case SSH_PGP_HASH_ALGORITHM_HAVAL_5_160:
      return NULL;
    default:
      return NULL;
    }
}


const char *ssh_pgp_packet_type_str(int type)
{
  static char buf[32];

  if (type == SSH_PGP_PACKET_TYPE_ESK)
    return "PGP_PACKET_TYPE_ESK";
  else if (type == SSH_PGP_PACKET_TYPE_SIG)
    return "PGP_PACKET_TYPE_SIG";
  else if (type == SSH_PGP_PACKET_TYPE_CONVESK)
    return "PGP_PACKET_TYPE_CONVESK";
  else if (type == SSH_PGP_PACKET_TYPE_1PASSSIG)
    return "PGP_PACKET_TYPE_1PASSSIG";
  else if (type == SSH_PGP_PACKET_TYPE_SECKEY)
    return "PGP_PACKET_TYPE_SECKEY";
  else if (type == SSH_PGP_PACKET_TYPE_PUBKEY)
    return "PGP_PACKET_TYPE_PUBKEY";
  else if (type == SSH_PGP_PACKET_TYPE_SECSUBKEY)
    return "PGP_PACKET_TYPE_SECSUBKEY";
  else if (type == SSH_PGP_PACKET_TYPE_COMPRESSED)
    return "PGP_PACKET_TYPE_COMPRESSED";
  else if (type == SSH_PGP_PACKET_TYPE_CONVENTIONAL)
    return "PGP_PACKET_TYPE_CONVENTIONAL";
  else if (type == SSH_PGP_PACKET_TYPE_MARKER)
    return "PGP_PACKET_TYPE_MARKER";
  else if (type == SSH_PGP_PACKET_TYPE_LITERAL)
    return "PGP_PACKET_TYPE_LITERAL";
  else if (type == SSH_PGP_PACKET_TYPE_TRUST)
    return "PGP_PACKET_TYPE_TRUST";
  else if (type == SSH_PGP_PACKET_TYPE_NAME)
    return "PGP_PACKET_TYPE_NAME";
  else if (type == SSH_PGP_PACKET_TYPE_PUBSUBKEY)
    return "PGP_PACKET_TYPE_PUBSUBKEY";
  else if (type == SSH_PGP_PACKET_TYPE_COMMENT)
    return "PGP_PACKET_TYPE_COMMENT";

  snprintf(buf, sizeof (buf), "PGP_PACKET_TYPE_UNKNOWN (%d)", type);
  return buf;
}

void ssh_pgp_packet_free(SshPgpPacket packet)
{
  if (packet)
    {
      if (packet->data)
        ssh_xfree(packet->data);
      ssh_xfree(packet);
    }
  return;
}

#else /* WITH_PGP */

int ssh_pgp_library_not_configured(void);

int ssh_pgp_library_not_configured(void)
{
  return 1;
}

#endif /* WITH_PGP */
/* eof (pgp_gen.c) */
