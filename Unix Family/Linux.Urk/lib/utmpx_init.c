#include "sys_defs.h"

#include <sys/types.h>
#include <sys/time.h>
#include <utmpx.h>
#include <string.h>
#include <syslog.h>

/* utmpx_init - update utmp and wtmp before login */

utmpx_init(line, user, id)
char   *line;
char   *user;
char   *id;
{
    struct utmpx utx;

    memset((char *) &utx, 0, sizeof(utx));
    strncpy(utx.ut_id, id, sizeof(utx.ut_id));
    strncpy(utx.ut_user, user, sizeof(utx.ut_user));
    strncpy(utx.ut_line, line, sizeof(utx.ut_line));
    utx.ut_pid = getpid();
    utx.ut_type = LOGIN_PROCESS;
    gettimeofday(&(utx.ut_tv));
    pututxline(&utx);
    updwtmpx(WTMPX_FILE, &utx);
    endutxent();
}

/* utmpx_ptsid - generate utmp id for pseudo terminal */

char   *utmpx_ptsid(line, tag)
char   *line;
char   *tag;
{
    int     num;
    static char buf[5];

    /*
     * Derive utmp ID from pty slave number and application-specific tag.
     * SYSV4 uses a different but undocumented algorithm.
     */

    if (sscanf(line, "%*[^0-9]%d", &num) != 1 || num > 255) {
	syslog(LOG_ERR, "unparseable pty slave name: %s", line);
	_exit(1);
    }
    sprintf(buf, "%.2s%02x", tag, num);
    return (buf);
}

