/*

pgp_packet.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1999 SSH Communications Security, Finland
                   All rights reserved

PGP packet parsing utilities.

*/
/*
 * $Id: pgp_packet.c,v 1.2 1999/04/05 18:01:29 tri Exp $
 * $Log: pgp_packet.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef WITH_PGP
#include "sshpgp.h"

#define SSH_DEBUG_MODULE "SshPgpPacket"

/* Extract a name string from a name packet.  Returned string is allocated
   with ssh_xmalloc and is to be freed by the user. */
char *ssh_pgp_packet_name(SshPgpPacket packet)
{
  char *r;
  
  if ((packet == NULL) || (packet->type != SSH_PGP_PACKET_TYPE_NAME))
    return NULL;
  r = ssh_xmalloc(packet->len + 1);
  memcpy(r, packet->data, packet->len);
  r[packet->len] = '\0';
  return r;
}

#endif /* WITH_PGP */
/* eof (pgp_packet.c) */
