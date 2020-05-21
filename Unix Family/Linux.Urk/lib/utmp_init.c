#include <sys/types.h>
#include <utmp.h>
#include <string.h>
#include <syslog.h>

/* utmp_init - update utmp and wtmp before login */

utmp_init(line, user, id)
char   *line;
char   *user;
char   *id;
{
    struct utmp utx;

    memset((char *) &utx, 0, sizeof(utx));
    strncpy(utx.ut_id, id, sizeof(utx.ut_id));
    strncpy(utx.ut_user, user, sizeof(utx.ut_user));
    strncpy(utx.ut_line, line, sizeof(utx.ut_line));
    utx.ut_pid = getpid();
    utx.ut_type = LOGIN_PROCESS;
    time(&(utx.ut_time));
    pututline(&utx);
    updwtmp(WTMP_FILE, &utx);
    endutent();
}

/* utmp_ptsid - generate utmp id for pseudo terminal */

char   *utmp_ptsid(line, tag)
char   *line;
char   *tag;
{
    static char buf[5];

    strncpy(buf, tag, 2);
    strncpy(buf + 2, line + strlen(line) - 2, 2);
    return (buf);
}

