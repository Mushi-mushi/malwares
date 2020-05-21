/*

  libmonitor.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu Jun 12 16:32:48 1997 [mkojo]

  Crypto library monitoring functions.

  */

/*
 * $Id: libmonitor.c,v 1.2 1998/01/28 10:10:33 ylo Exp $
 * $Log: libmonitor.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "libmonitor.h"

/* Global working pointer, that'll indicate the position of applications
   routine for handling these calls. */

SshCryptoProgressMonitor ssh_crypto_progress_monitor_function = NULL;
void                    *ssh_crypto_progress_context = NULL;

/* Interface from library. */

void ssh_crypto_progress_monitor(SshCryptoProgressID id,
				 unsigned int time_value)
{
  if (ssh_crypto_progress_monitor_function != NULL)
    (*ssh_crypto_progress_monitor_function)(id, time_value,
					    ssh_crypto_progress_context);
}

/* Interface from application. */
  
DLLEXPORT void DLLCALLCONV
ssh_crypto_library_register_progress_func(SshCryptoProgressMonitor
					  monitor_function,
					  void *progress_context)
{
  if (monitor_function == NULL)
    {
      ssh_crypto_progress_monitor_function = NULL;
      ssh_crypto_progress_context = NULL;
      return;
    }

  ssh_crypto_progress_monitor_function = monitor_function;
  ssh_crypto_progress_context = progress_context;
  return;
}

/* libmonitor.c */
