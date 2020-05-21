/*

sshsessionincludes.h

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

*/

#ifndef SSHSESSIONINCLUDES_H
#define SSHSESSIONINCLUDES_H

/* Do not remove this include.  sshsessionincludes.h is designed to include
   sshincludes.h automatically. */
#include "sshincludes.h"

#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif /* HAVE_LIBUTIL_H */

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif /* HAVE_SYS_IOCTL_H */

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#define USING_TERMIOS
#endif /* HAVE_TERMIOS_H */

#if defined(HAVE_SGTTY_H) && !defined(USING_TERMIOS)
#include <sgtty.h>
#define USING_SGTTY
#endif

#if !defined(USING_SGTTY) && !defined(USING_TERMIOS)
  ERROR NO TERMIOS OR SGTTY
#endif

/* Define UID_ROOT to be the user id for root (normally zero, but different
   e.g. on Amiga). */
#ifndef UID_ROOT
#define UID_ROOT 0
#endif
 
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef _HPUX_SOURCE
#define seteuid(uid) setresuid(-1,(uid),-1)
#endif

#endif /* SSHSESSIONINCLUDES_H */
