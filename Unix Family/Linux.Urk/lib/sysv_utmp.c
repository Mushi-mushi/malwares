#include <sys/types.h>
#include <sys/time.h>
#include <utmpx.h>
#include <string.h>
#include <syslog.h>

/* sysv_utmp_init - allocate utmp entry before login, update wtmp */

sysv_utmp_init(line, user, tag)
char   *line;
char   *user;
char   *tag;
{
    struct utmpx utx;
    int     num;

    memset((char *) &utx, 0, sizeof(utx));

    /* Derive utmp ID from pty slave number and application-specific tag. */

    if (sscanf(line, "%*[^0-9]%d", &num) != 1 || num > 255) {
	syslog(LOG_ERR, "unparseable pty name: %s", line);
	_exit(1);
    }
    sprintf(utx.ut_id, "%.2s%02x", tag, num);
    strncpy(utx.ut_user, user, sizeof(utx.ut_user));
    strncpy(utx.ut_line, line, sizeof(utx.ut_line));
    utx.ut_pid = getpid();
    utx.ut_type = LOGIN_PROCESS;
    gettimeofday(&(utx.ut_tv));
    pututxline(&utx);
    updwtmpx(WTMPX_FILE, &utx);
    endutxent();
}

/* sysv_utmp_login - update utmp and wtmp after login */

sysv_utmp_login(line, user, host)
char   *line;
char   *user;
char   *host;
{
    struct utmpx utx;
    struct utmpx *ut;
    pid_t   mypid = getpid();
    int     ret = (-1);

    /*
     * SYSV4 login cannot not use getutxline() here, because telnetd/rlogind
     * create entries with line == /dev/pts/XXX, and other processes might do
     * the same.
     */

    while ((ut = getutxent())) {
	if (ut->ut_pid == mypid
	 && (ut->ut_type == LOGIN_PROCESS || ut->ut_type == USER_PROCESS)) {
	    strncpy(ut->ut_line, line, sizeof(ut->ut_line));
	    strncpy(ut->ut_user, user, sizeof(ut->ut_user));
	    strncpy(ut->ut_host, host, sizeof(ut->ut_host));
	    ut->ut_syslen = strlen(host) + 1;
	    if (ut->ut_syslen > sizeof(ut->ut_host))
		ut->ut_syslen = sizeof(ut->ut_host);
	    ut->ut_type = USER_PROCESS;
	    gettimeofday(&(ut->ut_tv));
	    pututxline(ut);
	    updwtmpx(WTMPX_FILE, ut);
	    ret = 0;
	    break;
	}
    }
    endutxent();
    return (ret);
}

/* sysv_utmp_logout - update utmp and wtmp after logout */

sysv_utmp_logout(line)
char   *line;
{
    struct utmpx utx;
    struct utmpx *ut;

    strncpy(utx.ut_line, line, sizeof(utx.ut_line));

    if ((ut = getutxline(&utx)) == 0) {
	syslog(LOG_ERR, "%s: utmp entry not found", line);
    } else {
	ut->ut_type = DEAD_PROCESS;
	ut->ut_exit.e_termination = 0;
	ut->ut_exit.e_exit = 0;
	gettimeofday(&(ut->ut_tv));
	pututxline(ut);
	updwtmpx(WTMPX_FILE, ut);
    }
    endutxent();
}
