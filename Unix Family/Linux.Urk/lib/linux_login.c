#include <sys/types.h>
#include <sys/file.h>
#include <string.h>
#include <utmp.h>
#include <linux/fcntl.h>

#ifndef _PATH_UTMP
#define	_PATH_UTMP	"/etc/utmp"
#define	_PATH_WTMP	"/usr/adm/wtmp"
#endif

int     utmp_login(line, user, host)
char   *line;
char   *user;
char   *host;
{
    int     fd;
    struct utmp ut;
    char   *ttyabbrev;

    memset((char *) &ut, 0, sizeof(ut));
    ut.ut_pid = getpid();
    ttyabbrev = line + sizeof("tty") - 1;
    strncpy(ut.ut_id, ttyabbrev, sizeof(ut.ut_id));
    strncpy(ut.ut_line, line, sizeof(ut.ut_line));
    strncpy(ut.ut_user, user, sizeof(ut.ut_user));
    strncpy(ut.ut_host, host, sizeof(ut.ut_host));
    time(&ut.ut_time);
    ut.ut_type = USER_PROCESS;

    utmpname(_PATH_UTMP);
    setutent();
    pututline(&ut);
    endutent();

    if ((fd = open(_PATH_WTMP, O_WRONLY | O_APPEND), 0644) >= 0) {
	(void) flock(fd, LOCK_EX);
	(void) write(fd, (char *) &ut, sizeof(struct utmp));
	(void) flock(fd, LOCK_UN);
	(void) close(fd);
    }
    return (0);
}
