/*

  Author: Tomi Salo <ttsalo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Jul  8 17:40:06 1996 [ttsalo]

  sshsignals.h

  Derived straight from signals.c
  
  */

/*
 * $Id: sshsignals.h,v 1.2 1998/10/21 17:08:26 tri Exp $
 * $Log: sshsignals.h,v $
 * $EndLog$
 */

#ifndef SSHSIGNALS_H
#define SSHSIGNALS_H

void
ssh_signals_prevent_core(Boolean use_eloop, void *ctx);

void
ssh_signals_reset(void);

#endif /* SSHSIGNALS_H */
