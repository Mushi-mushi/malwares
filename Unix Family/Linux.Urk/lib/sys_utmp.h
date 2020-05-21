#ifdef HAS_UTMPX
#include <utmpx.h>
#define _PATH_UTMP	UTMPX_FILE
#else
#include <utmp.h>
#ifdef UTMP_FILE
#ifndef LINUX
#define _PATH_UTMP	UTMP_FILE
#endif
#endif
#endif

#ifndef _PATH_UTMP
#define _PATH_UTMP      "/etc/utmp"
#endif

#ifndef UT_NAMESIZE
#define UT_NAMESIZE	sizeof(((struct UTMP_STRUCT *)0)->ut_name)
#endif

#ifndef UT_HOSTSIZE
#define UT_HOSTSIZE	sizeof(((struct UTMP_STRUCT *)0)->ut_host)
#endif
