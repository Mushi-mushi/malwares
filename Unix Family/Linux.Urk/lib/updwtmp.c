#include <sys/types.h>
#include <sys/time.h>
#include <utmp.h>
#include <fcntl.h>

/* updwtmp - update System V < 4 wtmp after login or logout */

updwtmp(file, ut)
char   *file;
struct utmp *ut;
{
    int     fd;

    if ((fd = open(file, O_WRONLY | O_APPEND, 0)) >= 0) {
	(void) write(fd, (char *) ut, sizeof(struct utmp));
	(void) close(fd);
    }
}
