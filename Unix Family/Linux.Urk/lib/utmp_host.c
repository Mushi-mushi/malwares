#include "sys_defs.h"

#include <sys/types.h>
#include <sys/file.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifndef O_RDONLY
#include <fcntl.h>
#endif

#include "sys_utmp.h"

static char name_buf[UT_HOSTSIZE + 2];

/* utmp_host - determine remote hostname from utmp slot */

char   *utmp_host()
{
    struct UTMP_STRUCT utmp;
    int     fd;
    int     slot;

    /*
     * Tack on a '?' to truncated hostnames.
     */
    slot = ttyslot();
    if (slot > 0 && (fd = open(_PATH_UTMP, O_RDONLY, 0)) >= 0) {
	if (lseek(fd, (off_t) (slot * sizeof(utmp)), L_SET) >= 0
	    && read(fd, (char *) &utmp, sizeof(utmp)) == sizeof(utmp)) {
	    strncpy(name_buf, utmp.ut_host, UT_HOSTSIZE);
#ifdef HAS_UTMPX
	    if (utmp.ut_syslen < UT_HOSTSIZE)
		name_buf[utmp.ut_syslen] = 0;
	    else
#endif
		name_buf[UT_HOSTSIZE] = '?';
	    return (*name_buf ? name_buf : 0);
	}
	close(fd);
    }
    return (0);
}

#ifdef TEST

main()
{
    char   *host;

    host = utmp_host();
    if (host == 0) {
	printf("No hostname information found\n");
	return (1);
    } else {
	printf("%s\n", host);
	return (0);
    }
}

#endif
