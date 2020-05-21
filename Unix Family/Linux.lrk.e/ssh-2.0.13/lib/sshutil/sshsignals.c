/*

sshsignals.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Fri Jan 19 18:09:37 1995 ylo

Manipulation of signal state.  This file also contains code to set the
maximum core dump size.

*/

/*
 * $Id: sshsignals.c,v 1.4 1998/10/21 17:33:53 tri Exp $
 * $Log: sshsignals.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshunixeloop.h"
#include "sshsignals.h"

#ifdef HAVE_SIGNAL

#ifdef HAVE_SETRLIMIT
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif /* HAVE_SYS_RESOURCE_H */
#endif /* HAVE_SETRLIMIT */

#ifndef NSIG
#define NSIG 127
#endif

static RETSIGTYPE fatal_signal_handler(int sig);
static void eloop_fatal_signal_handler(int sig, void *ctx);
static Boolean ssh_sig_terminal(int sig);

static unsigned long original_core_limit;
static Boolean eloop_used_in_signals = FALSE;

static RETSIGTYPE fatal_signal_handler(int sig)
{
  ssh_fatal("Received signal %d.", sig);
  exit(255);
}

static void eloop_fatal_signal_handler(int sig, void *ctx)
{
  /* XXX logging */
  fprintf(stderr, "\nReceived signal %d. (no core)\n", sig);
  exit(255);
}

static Boolean ssh_sig_terminal(int sig)
{
  switch (sig)
    {
#ifdef SIGSTOP
      case SIGSTOP:
#endif
#ifdef SIGTSTP
      case SIGTSTP:
#endif
#ifdef SIGCONT
      case SIGCONT:
#endif
#ifdef SIGCHLD
      case SIGCHLD:
#endif
#ifdef SIGTTIN
      case SIGTTIN:
#endif
#ifdef SIGTTOU
      case SIGTTOU:
#endif
#ifdef SIGIO
      case SIGIO:
#endif
#if defined(SIGURG) && SIGURG != SIGIO
      case SIGURG:
#endif
#ifdef SIGWINCH
      case SIGWINCH:
#endif
#ifdef SIGINFO
      case SIGINFO:
#endif
#if defined(SIGFREEZE)
      case SIGFREEZE:
#endif
#if defined(SIGTHAW)
      case SIGTHAW:
#endif
        return FALSE;
      
      default:
        return TRUE;
    }
  /*NOTREACHED*/
}

/*
 * Sets signal handlers so that core dumps are prevented.  This also
 * sets the maximum core dump size to zero as an extra precaution (where
 * supported).  The old core dump size limit is saved. 
 */

void ssh_signals_prevent_core(Boolean use_eloop, void *ctx)
{
  int sig;

  eloop_used_in_signals = use_eloop;

  for (sig = 1; sig <= NSIG; sig++)
    {
      if (ssh_sig_terminal(sig))
        {
          if (use_eloop)
            ssh_register_signal(sig, eloop_fatal_signal_handler, ctx);
          else
            signal(sig, fatal_signal_handler);
        }
    }

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  {
    struct rlimit rl;
    getrlimit(RLIMIT_CORE, &rl);
    original_core_limit = rl.rlim_cur;
    rl.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &rl);
  }
#endif /* HAVE_SETRLIMIT && RLIMIT_CORE */
}

/* Sets all signals to their default state.  Restores RLIMIT_CORE previously
   saved by prevent_core(). */

void ssh_signals_reset()
{
  int sig;

  for (sig = 1; sig <= NSIG; sig++)
    {
      if (eloop_used_in_signals)
        {
          if (ssh_sig_terminal(sig))
            ssh_unregister_signal(sig);
        }
      else
        {
          signal(sig, SIG_DFL);
        }
    }

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  {
    struct rlimit rl;
    getrlimit(RLIMIT_CORE, &rl);
    rl.rlim_cur = original_core_limit;
    setrlimit(RLIMIT_CORE, &rl);
  }
#endif /* HAVE_SETRLIMIT && RLIMIT_CORE */
}

#else  /* ! HAVE_SIGNAL */

void 
ssh_signals_prevent_core(Boolean use_eloop, void *ctx) /*ARGSUSED*/
{
  /*
   * There are no signals so no core dump can be created 
   * because of a one.
   */
  return;
}

void
ssh_signals_reset()
{
  /*
   * There are no signals.
   */
  return;
}

#endif /* HAVE_SIGNAL */
