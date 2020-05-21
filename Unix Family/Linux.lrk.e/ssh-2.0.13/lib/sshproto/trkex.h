/*

trkex.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Key exchange methods.

*/

/*
 * $Id: trkex.h,v 1.5 1999/04/07 09:34:40 sjl Exp $
 * $Log: trkex.h,v $
 * $EndLog$
 */

#ifndef TRKEX_H
#define TRKEX_H

#include "trcommon.h"
#include "sshbuffer.h"

/* Data types for declaring key exchange methods. */

typedef SshBuffer *(*SshMakeKexProc)(SshTransportCommon tr);
typedef void (*SshKex2CompletionProc) (SshTransportCommon tr);
typedef Boolean (*SshInputKexProc)(SshTransportCommon tr, SshBuffer *buffer);
typedef void (*SshInputKex2Proc) (SshTransportCommon tr, SshBuffer *buffer,
                                  SshKex2CompletionProc completion);

struct SshKexTypeRec
{
  const char *name;
  
  /* crypto library identifier of the hash function */  
  const char *hash_name;
    
  /* Flags */
  
  Boolean need_encryption_capable_hostkey;
  Boolean need_signature_capable_hostkey;

  /* Functions for making KEX1 and KEX2 packets.  These will return NULL
     if no such packet is to be sent for this kex methods.  These do not
     save the packet. */
  SshMakeKexProc client_make_kex1;
  SshMakeKexProc server_make_kex1;
  SshMakeKexProc client_make_kex2;
  SshMakeKexProc server_make_kex2;

  /* Functions for processing received KEX1 packets.  These will take the
     packet as argument, store it in the data structures, and parse the
     packet.  These do not automatically validate host keys; such validation
     should be made using the data structures created by these.  These return
     FALSE if they signalled disconnect.  These will be NULL if the
     kex method isn't expecting to receive kex1 for that side. */
  SshInputKexProc client_input_kex1;
  SshInputKexProc server_input_kex1;

  /* Functions for processing received KEX2 packets.  These will take
     the packet (payload) as argument, and finalize the key exchange.
     If the exchange fails, these return FALSE if they called disconnect.
     If exchange is successful, these will set the session key, session
     identifier, and individual keys.  These will free the packet in
     any case. */
  SshInputKex2Proc client_input_kex2;
  SshInputKex2Proc server_input_kex2;
};

/* Returns a comma-separated list of supported key exchange algorithms.
   The caller is responsible for freeing the list with ssh_xfree. */
char *ssh_kex_get_supported(void);

/* Returns the SshKexType object for the kex method, or NULL if not found.
   The returned value points to a statically allocated structure. */
SshKexType ssh_kex_lookup(const char *name);

/* Return a SshHash object that matches the key exchange method, or
   NULL on error. name is the name (identifier) of the key exchange method. */
SshHash ssh_kex_allocate_hash(const char *name);

#endif /* TRKEX_H */
