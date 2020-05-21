#include <config.h>

#include "rcsid.h"
RCSID("$Id: ulimit.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#if HAVE_ULIMIT_H
#include <ulimit.h>

#ifndef UL_SETFSIZE
#ifdef UL_SFILLIM
#define UL_SETFSIZE UL_SFILLIM
#else
#define UL_SETFSIZE 2
#endif
#endif

#elif HAVE_SYS_RESOURCE_H
#include <sys/time.h>  /* for struct timeval on sunos4 */
/* XXX - is the above ok or should it be <time.h> on ultrix? */
#include <sys/resource.h>
#endif

void
set_filesize_limit(blocks)
	int blocks;
{
#if HAVE_ULIMIT_H
	ulimit(UL_SETFSIZE, blocks);
#elif defined(RLIMIT_FSIZE)
	struct rlimit rlimit_fsize;

	rlimit_fsize.rlim_cur = rlimit_fsize.rlim_max = 512L * blocks;
	setrlimit(RLIMIT_FSIZE, &rlimit_fsize);
#endif
}
