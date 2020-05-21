#include "sys_defs.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#ifdef HAS_PATHS_H
#include <paths.h>
#endif

#include "sysv_default.h"

#ifdef _PATH_ROOTPATH
#define DEFAULT_SUPATH	_PATH_ROOTPATH
#define DEFAULT_PATH  	_PATH_USERPATH
#endif

#ifndef DEFAULT_SUPATH
#define	DEFAULT_SUPATH	"/usr/sbin:/usr/bin"
#define DEFAULT_PATH	"/usr/bin:"
#endif

 /*
  * Default values for stuff that can be read from the defaults file. The
  * SunOS 5.1 documentation is incomplete and often disagrees with reality.
  */

char   *default_console	= 0;
char   *default_altsh	= "YES";
char   *default_passreq	= "NO";
char   *default_timezone= 0;
char   *default_hz	= 0;
char   *default_path	= DEFAULT_PATH;
char   *default_supath	= DEFAULT_SUPATH;
char   *default_ulimit	= 0;
char   *default_timeout	= "60";
char   *default_umask	= "022";
char   *default_sleep	= "4";
char   *default_maxtrys	= "5";

static struct sysv_default {
    char  **valptr;
    char   *prefix;
    int     prefix_len;
} defaults[] = {
    &default_console,	"CONSOLE=",	sizeof("CONSOLE=") -1,
    &default_altsh,	"ALTSHELL=",	sizeof("ALTSHELL=") -1,
    &default_passreq,	"PASSREQ=",	sizeof("PASSREQ=") -1,
    &default_timezone,	"TIMEZONE=",	sizeof("TIMEZONE=") -1,
    &default_hz,	"HZ=",		sizeof("HZ=") -1,
    &default_path,	"PATH=",	sizeof("PATH=") -1,
    &default_supath,	"SUPATH=",	sizeof("SUPATH=") -1,
    &default_ulimit,	"ULIMIT=",	sizeof("ULIMIT=") -1,
    &default_timeout,	"TIMEOUT=",	sizeof("TIMEOUT=") -1,
    &default_umask,	"UMASK=",	sizeof("UMASK=") -1,
    &default_sleep,	"SLEEPTIME=",	sizeof("SLEEPTIME=") -1,
    &default_maxtrys,	"MAXTRYS=",	sizeof("MAXTRYS=") -1,
    0,
};

#define trim(s) { \
	char   *cp = s + strlen(s); \
	while (cp > s && isspace(cp[-1])) \
	    cp--; \
	*cp = 0; \
}

/* sysv_defaults - read login defaults file */

sysv_defaults()
{
    struct sysv_default *dp;
    FILE   *fp;
    char    buf[BUFSIZ];

    if (fp = fopen(_PATH_DEFAULT, "r")) {

	/* Stupid quadratic algorithm. */

	while (fgets(buf, sizeof(buf), fp)) {

	    /* Skip comments and blank lines. */

	    if (buf[0] == '#')
		continue;
	    trim(buf);
	    if (buf[0] == 0)
		continue;

	    /* Assign defaults from file. */

#define STREQN(x,y,l) (x[0] == y[0] && strncmp(x,y,l) == 0)

	    for (dp = defaults; dp->valptr; dp++) {
		if (STREQN(buf, dp->prefix, dp->prefix_len)) {
		    if ((*(dp->valptr) = strdup(buf + dp->prefix_len)) == 0) {
			printf("Insufficient memory resources - try later.\n");
			sleepexit(1);
		    }
		    break;
		}
	    }
	}
	fclose(fp);
    }
}
