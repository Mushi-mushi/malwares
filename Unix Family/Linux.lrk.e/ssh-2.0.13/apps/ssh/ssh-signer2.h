/*
  ssh-signer2.h

  Authors: Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Hostbased authentication, client-side. This program is supposed to
  be suid, as it should have access to the private part of the host
  key.
*/

#ifndef SSH_SIGNER2_H
#define SSH_SIGNER2_H

/* Packet types for the over-simple protocol used to converse with
   ssh-signer. */
#define SSH_AUTH_HOSTBASED_PACKET    (SshPacketType)1
#define SSH_AUTH_HOSTBASED_SIGNATURE (SshPacketType)2
#define SSH_AUTH_HOSTBASED_ERROR     (SshPacketType)3

/* Used in fetching the hostname. */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif /* MAXHOSTNAMELEN */

#endif /* SSH_SIGNER2_H */
