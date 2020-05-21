/*

sshincludes.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Jan 15 10:36:06 1996 ylo

Common include files for various platforms.

*/

/*
 * $Id: sshincludes.h,v 1.34 1999/05/04 18:41:05 kivinen Exp $
 * $Log: sshincludes.h,v $
 * $EndLog$
 */

#ifndef SSHINCLUDES_H
#define SSHINCLUDES_H


/* */
#include "sshdistdefs.h"


/* Conditionals for various OS & compilation environments */

#if defined(KERNEL) || defined(_KERNEL)

#ifdef WINNT
#include "ntddk/sshincludes_ntddk.h"
#elif WIN95
#include "kernel_includes_win95.h"
#else
#include "kernel_includes.h"
#endif

#else /* KERNEL || _KERNEL */

#if defined(WIN32)
#include "win32/sshincludes_win32.h"
#else
#include "sshincludes_unix.h"
#endif /* WIN32 */

#endif /* KERNEL || _KERNEL */


/* Common (operating system independent) stuff below */

/* The sprintf and vsprintf functions are FORBIDDEN in all SSH code.
   This is for security reasons - they are the source of way too many
   security bugs.  Instead, we guarantee the existence of snprintf and
   vsnprintf.  These MUST be used instead. */
#ifdef sprintf
# undef sprintf
#endif
#define sprintf ssh_fatal(SPRINTF_IS_FORBIDDEN_USE_SNPRINTF_INSTEAD)

#ifdef vsprintf
# undef vsprintf
#endif
#define vsprintf ssh_fatal(VSPRINTF_IS_FORBIDDEN_USE_VSNPRINTF_INSTEAD)

#ifdef index
# undef index
#endif
#define index ssh_fatal(INDEX_IS_BSDISM_USE_STRCHR_INSTEAD)

#ifdef rindex
# undef rindex
#endif
#define rindex ssh_fatal(RINDEX_IS_BSDISM_USE_STRRCHR_INSTEAD)

#if 0
#ifdef interface
# undef interface
#endif
#define interface ssh_fatal(INTERFACE_IS_RESERVED_AT_MVC)
#endif

/* Force library to use ssh- memory allocators (they may be
   implemented using zone mallocs, debug-routines or something
   similar) */

#ifndef ALLOW_SYSTEM_ALLOCATORS
#ifdef malloc 
# undef malloc
#endif
#ifdef calloc 
# undef calloc
#endif
#ifdef realloc 
# undef realloc
#endif
#ifdef free 
# undef free
#endif
#ifdef strdup
# undef strdup
#endif
#ifdef memdup
# undef memdup
#endif

# define malloc  MALLOC_IS_FORBIDDEN_USE_SSH_XMALLOC_INSTEAD
# define calloc  CALLOC_IS_FORBIDDEN_USE_SSH_XCALLOC_INSTEAD
# define realloc REALLOC_IS_FORBIDDEN_USE_SSH_XREALLOC_INSTEAD
# define free    FREE_IS_FORBIDDEN_USE_SSH_XFREE_INSTEAD
# define strdup  STRDUP_IS_FORBIDDEN_USE_SSH_XSTRDUP_INSTEAD
# define memdup  MEMDUP_IS_FORBIDDEN_USE_SSH_XMEMDUP_INSTEAD
#endif

#ifdef time
# undef time
#endif
#define time(x) ssh_fatal(TIME_IS_FORBIDDEN_USE_SSH_TIME_INSTEAD)

#ifdef localtime
# undef localtime
#endif
#define localtime ssh_fatal(LOCALTIME_IS_FORBIDDEN_USE_SSH_CALENDAR_TIME_INSTEAD)

#ifdef gmtime
# undef gmtime
#endif
#define gmtime ssh_fatal(GMTIME_IS_FORBIDDEN_USE_SSH_CALENDAR_TIME_INSTEAD)

#ifdef asctime
# undef asctime
#endif
#define asctime ssh_fatal(ASCTIME_IS_FORBIDDEN)

#ifdef ctime
# undef ctime
#endif
#define ctime ssh_fatal(CTIME_IS_FORBIDDEN)

#ifdef mktime
# undef mktime
#endif
#define mktime ssh_fatal(MKTIME_IS_FORBIDDEN)

/* Some internal headers used in almost every file. */
#include "sshdebug.h"
#include "sshmalloc.h"
#include "sshtime.h"

#ifndef SSH_CODE_SEGMENT
#ifdef WINDOWS
#define SSH_CODE_SEGMENT __based(__segname("_CODE"))
#else /* WINDOWS */
#define SSH_CODE_SEGMENT
#endif /* WINDOWS */
#endif /* SSH_CODE_SEGMENT */

#ifndef SSH_UID_ROOT
#define SSH_UID_ROOT 0
#endif /* SSH_UID_ROOT */

#endif /* SSHINCLUDES_H */
