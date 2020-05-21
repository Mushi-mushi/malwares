#include <utmp.h>

#define _PATH_LASTLOG   "/var/adm/lastlog"

#ifndef UT_LINESIZE
#define UT_LINESIZE	sizeof(((struct utmp *)0)->ut_line)
#endif
#ifdef NO_UT_HOST
#define UT_HOSTSIZE	16
#endif
#ifndef UT_HOSTSIZE
#define UT_HOSTSIZE	sizeof(((struct utmp *)0)->ut_host)
#endif

struct lastlog {
        time_t  ll_time;
        char    ll_line[UT_LINESIZE];
        char    ll_host[UT_HOSTSIZE];
};
