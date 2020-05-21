#include <sys/types.h>
#include <utmp.h>
#include <string.h>

/* utmp_logout - update utmp and wtmp after logout */

utmp_logout(line)
char   *line;
{
    struct utmp utx;
    struct utmp *ut;

    strncpy(utx.ut_line, line, sizeof(utx.ut_line));

    if (ut = getutline(&utx)) {
	ut->ut_type = DEAD_PROCESS;
	ut->ut_exit.e_termination = 0;
	ut->ut_exit.e_exit = 0;
	time(&(utx.ut_time));
	pututline(ut);
	updwtmp(WTMP_FILE, ut);
    }
    endutent();
}
