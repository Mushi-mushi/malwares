/*

  libmonitor.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu Jun 12 16:52:14 1997 [mkojo]

  Crypto library monitoring, header for internal use.

  */

/*
 * $Id: libmonitor.h,v 1.2 1998/01/28 10:10:35 ylo Exp $
 * $Log: libmonitor.h,v $
 * $EndLog$
 */

#ifndef LIBMONITOR_H
#define LIBMONITOR_H

/* The internal progress monitor function, which shall call the
   application supplied callback function. SshCryptoProgressID is
   defined in sshcrypt.h and time_value is an increasing counter
   indicating that library is working. */

void ssh_crypto_progress_monitor(SshCryptoProgressID id,
				 unsigned int time_value);

#endif /* LIBMONITOR_H */
