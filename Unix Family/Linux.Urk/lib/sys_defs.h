 /*
  * Cope with different major UNIX streams, and what the vendors did to them.
  * 
  * Author:Wietse Venema < wietse @ wzv.win.tue.nl >
  * 
  * Beginning of generic (vendor-independent) features.
  */

#if defined(SYSV2) || defined(SYSV3)
#define USE_OUR_LASTLOG_H		/* use our lastlog.h file */
#define _PATH_LOGIN "/bin/login"	/* not /usr/bin/login */
#endif

#if defined(SYSV2) || defined(SYSV3) || defined(SYSV4)
#define SYSV_UTMP			/* insist on existing utmp entry */
#define SYSV_ENV			/* name=value login arg, no ucb path */
#define NO_TTYENT			/* no <ttyent.h> stuff */
#define NO_MOTD				/* leave motd to the shell */
#define USE_GETCWD			/* getcwd() instead of getwd() */
#define SYSV_LS				/* "ls -l" lists groups */
#define NO_WHEEL_GROUP			/* anyone may su "root" */
#endif

#if defined(SYSV3) || defined(SYSV4)
#define SYSV_SHADOW			/* shadow pwds, password expiry */
#define SYSV_LOGINDEFS			/* has /etc/default/login */
#endif

#ifdef SYSV4
#define NIS				/* yellow pages */
#define DES_RPC				/* des-encrypted credentials */
#define HAS_UTMPX			/* utmp+utmpx, wtmp+wtmpx files */
#define STREAM_PTY			/* ptys are streams devices */
#define USE_SYS_MNTTAB_H		/* <sys/mnttab.h> */
#endif

#ifdef BSD44
#undef INT_GROUPS			/* set/getgroups() take int array */
#define HAS_PATHS_H			/* paths.h */
#define UTMP_DECLARES_LASTLOG		/* utmp.h declares struct lastlog */
#define STDIO_DECLARES_SYS_ERRLIST	/* stdio.h declares sys_errlist */
#define HAS_SETLOGIN			/* setlogin() */
#define NEW_LOGIN			/* ruserok() done in rlogind */
#endif

 /*
  * End of generic (vendor-independent) features.
  * 
  * Beginning of vendor-specific exceptions.
  */

#ifdef SUNOS4
#define NIS				/* yellow pages */
#define INT_GROUPS			/* set/getgroups() take int array */
#define DES_RPC				/* des-encrypted credentials */
#define ENV_LOGNAME			/* login sets LOGNAME */
#endif

#ifdef SUNOS5
#define _SVID_GETTOD			/* XSH4.2 versus SVID */
#undef NO_WHEEL_GROUP			/* XXX yes but... */
#endif

#ifdef ULTRIX4
#define NIS				/* yellow pages */
#define INT_GROUPS			/* set/getgroups() take int array */
#define ULTRIX_LAT			/* remote LAT terminals */
#endif

#ifdef HPUX9
#define NIS				/* yellow pages */
#define SYSV_UTMP			/* login requires utmp entry */
#define SYSV_ENV			/* name=value login arg, no ucb path */
#define NO_TTYENT			/* no <ttyent.h> stuff */
#define NO_MOTD				/* leave motd to the shell */
#define USE_OUR_LASTLOG_H		/* use our lastlog.h file */
#define USE_GETCWD			/* getcwd() instead of getwd() */
#define USE_SETRESXID			/* setresuid(), setresgid() */
#define HAS_UT_ADDR			/* inet address in utmp */
#define SYSV_LS				/* "ls -l" lists groups */
#define _PATH_LOGIN "/bin/login"	/* not /usr/bin/login */
#define BROKEN_TIOCSCTTY		/* must use open() */
#define REQUEST_INFO_DECLARED		/* ptyio.h declares request_info */
#define ENV_LOGNAME			/* login sets LOGNAME */
#define NEW_LOGIN			/* ruserok() done in rlogind */
#define NO_WHEEL_GROUP			/* anyone may su root */
#endif

#ifdef IRIX5
#define NIS				/* yellow pages */
#undef DES_RPC				/* no des-encrypted credentials */
#define ENV_USER			/* login sets USER */
#define ENV_REMOTEHOST			/* login sets REMOTEHOST */
#define ENV_REMOTEUSER			/* login sets REMOTEUSER */
#define LOGIN_OPT_R			/* login -l option already taken */
#define IRIX_LASTLOGIN			/* no holes in their file system? */
#define HAS_PATHS_H			/* /usr/include/paths.h */
#endif

#ifdef IRIX4
#define NIS				/* yellow pages */
#define SYSV_UTMP			/* insist on existing utmp entry */
#define NO_TTYENT			/* no <ttyent.h> stuff */
#define NO_MOTD				/* leave motd to the shell */
#define NO_UT_HOST			/* no host in utmp */
#define USE_OUR_LASTLOG_H		/* use our lastlog.h file */
#define USE_GETCWD			/* getcwd() instead of getwd() */
#define SYSV_LS				/* "ls -l" lists groups */
#define _PATH_LOGIN "/bin/login"	/* not /usr/bin/login */
#define NO_SETENV
#define NO_ULIMIT_H			/* no <ulimit.h> file */
#endif

#ifdef LINUX
#define SYSV_UTMP			/* SYSV-style utmp routines */
#define NO_TTYENT			/* no <ttyent.h> stuff */
#define NO_SECURE_TTY			/* no "secure tty" concept */
#define HAS_PATHS_H			/* /usr/include/paths.h */
#define CONSOLE		"tty1"		/* no /dev/console */
#define NBBY		8		/* not in <sys/mumble.h> */
#endif

#ifdef DECOSF1
#define HAS_SETLOGIN			/* setlogin() */
#define NIS				/* yellow pages */
#define CLOSE_PTY_MASTER		/* close() before exit() */
#define ENV_LOGNAME			/* login sets LOGNAME */
#define TTYGRPNAME	"terminal"	/* used by write(1) etc. */
#define NEW_LOGIN			/* ruserok() done in rlogind */
#endif

#ifdef NEWSOS4
#define NIS				/* yellow pages */
#define INT_GROUPS			/* set/getgroups() take int array */
#define NO_NGROUPS_MAX			/* use NGROUPS instead */
#define NO_SETSID			/* use setpgrp instead */
#define USE_SIGSETMASK			/* no sigprocmask() etc. */
#endif

 /*
  * End of vendor-specific exceptions.
  */

#ifdef HAS_UTMPX
#define UTMP_STRUCT	utmpx
#define UTMP_INIT	utmpx_init
#define UTMP_LOGIN	utmpx_login
#define UTMP_LOGOUT	utmpx_logout
#define MAKE_UTMP_ID	utmpx_ptsid
#else
#define UTMP_STRUCT	utmp
#define UTMP_INIT	utmp_init
#define UTMP_LOGIN	utmp_login
#define UTMP_LOGOUT	utmp_logout
#define MAKE_UTMP_ID	utmp_ptsid
#endif

#ifdef DES_RPC
#define PASSWD_LENGTH	8		/* number of characters to use */
#endif

#ifdef __STDC__
#define ARGS_(x) 	x
#else
#define ARGS_(x)	()
#endif
