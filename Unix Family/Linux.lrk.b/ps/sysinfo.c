/* Added uptime().  J. Cowley, 19 Mar 1993.
 *
 * $Log: sysinfo.c,v $
 * Revision 1.3  1994/01/29  17:49:27  johnsonm
 * Fixed comment problem stupidly introduced with the last revision...
 *
 * Revision 1.2  1994/01/29  17:42:22  johnsonm
 * includes sysinfo.h so we know about any changes.
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "sysinfo.h"

#define LOAD_FILE "/proc/loadavg"

void loadavg(double *av1, double *av5, double *av15)
{
    int n;
    char buff[80];
    static int fd = -1;

    if (fd < 0) {
	if ((fd = open(LOAD_FILE, O_RDONLY)) < 0) {
	    perror(LOAD_FILE);
	    exit(1);
	}
    }

    lseek(fd, 0L, SEEK_SET);
    n = read(fd, buff, sizeof buff - 1);
    if (n < 0) {
	perror(LOAD_FILE);
	exit(1);
    }
    buff[n] = '\0';

    if (sscanf(buff, "%lf %lf %lf", av1, av5, av15) < 3) {
	fprintf(stderr, "bad data in " LOAD_FILE "\n");
	exit(1);
    }

    return;
}

#define MEM_FILE "/proc/meminfo"

void meminfo(unsigned *total, unsigned *used, unsigned *free,
	     unsigned *shared, unsigned *buffers)
{
    int n;
    char *cp, buff[1024];
    static int fd = -1;

    if (fd < 0) {
	if ((fd = open(MEM_FILE, O_RDONLY)) < 0) {
	    perror(MEM_FILE);
	    exit(1);
	}
    }

    lseek(fd, 0L, SEEK_SET);
    n = read(fd, buff, sizeof buff - 1);
    if (n < 0) {
	perror(MEM_FILE);
	exit(1);
    }
    buff[n] = '\0';

    /* skip over the first line */
    cp = strchr(buff, '\n');
    if (cp)
	cp = strchr(cp, ' ');

    if (!cp || sscanf(cp, "%u %u %u %u %u", total, used,
		      free, shared, buffers) < 5) {
	fprintf(stderr, "bad data in " MEM_FILE "\n");
	exit(1);
    }

    return;
}

#define UPTIME_FILE "/proc/uptime"

void uptime(double *uptime_secs, double *idle_secs)
{
    int n;
    char buff[80];
    static int fd = -1;

    if (fd < 0) {
	if ((fd = open(UPTIME_FILE, O_RDONLY)) < 0) {
	    perror(UPTIME_FILE);
	    exit(1);
	}
    }

    lseek(fd, 0L, SEEK_SET);
    n = read(fd, buff, sizeof buff - 1);
    if (n < 0) {
	perror(UPTIME_FILE);
	exit(1);
    }
    buff[n] = '\0';

    if (sscanf(buff, "%lf %lf", uptime_secs, idle_secs) < 2) {
	fprintf(stderr, "bad data in " UPTIME_FILE "\n");
	exit(1);
    }

    return;
}

