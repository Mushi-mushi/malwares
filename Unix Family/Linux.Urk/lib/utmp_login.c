#include <sys/types.h>
#include <utmp.h>
#include <string.h>

#include "sys_defs.h"

#ifdef HAS_UT_ADDR
#include <netdb.h>
#endif

/* utmp_login - update System V < 4 utmp and wtmp after login */

utmp_login(line, user, host)
char   *line;
char   *user;
char   *host;
{
    struct utmp *ut;
    pid_t   mypid = getpid();
    int     ret = (-1);
#ifdef HAS_UT_ADDR
    struct hostent *hp;
#endif

    /*
     * Some programs use entries with the "/dev/" prefix stripped off the tty
     * port name. Some programs make utmp entries with the "/dev/" prefix
     * included. We therefore cannot use getutline(). Return nonzero if no
     * utmp entry was found with our own process ID for a login or user
     * process.
     */

    while ((ut = getutent())) {
	if (ut->ut_pid == mypid && (ut->ut_type == INIT_PROCESS
	  || ut->ut_type == LOGIN_PROCESS || ut->ut_type == USER_PROCESS)) {
	    strncpy(ut->ut_line, line, sizeof(ut->ut_line));
	    strncpy(ut->ut_user, user, sizeof(ut->ut_user));
#ifndef NO_UT_HOST
	    strncpy(ut->ut_host, host, sizeof(ut->ut_host));
#endif
	    time(&(ut->ut_time));
#ifdef HAS_UT_ADDR
	    if ((hp = gethostbyname(host)) != 0)
		memcpy((char *) &ut->ut_addr, hp->h_addr, sizeof(ut->ut_addr));
	    else
		ut->ut_addr = 0;
#endif
	    ut->ut_type = USER_PROCESS;
	    pututline(ut);
	    updwtmp(WTMP_FILE, ut);
	    ret = 0;
	    break;
	}
    }
    endutent();
    return (ret);
}
