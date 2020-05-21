/*
 * Stripped down 44BSD paths.h file. Edit as appropriate for your system.
 */

#if defined(SYSV_ENV)
#define	_PATH_DEFPATH	"/bin:/usr/bin:"
#else
#define	_PATH_DEFPATH	"/usr/ucb:/bin:/usr/bin:"
#endif

#define	_PATH_BSHELL	"/bin/sh"
#define	_PATH_CONSOLE	"/dev/console"
#define	_PATH_CSHELL	"/bin/csh"
#if defined(SYSV4) || defined(BSD44) || defined(HPUX10)
#define	_PATH_MAILDIR	"/var/mail"
#else
#if defined(HPUX9)
#define	_PATH_MAILDIR	"/usr/mail"
#else
#define	_PATH_MAILDIR	"/usr/spool/mail"
#endif
#endif
#define	_PATH_NOLOGIN	"/etc/nologin"
#ifndef _PATH_LASTLOG
#define _PATH_LASTLOG	"/usr/adm/lastlog"	/* lastlog.h or utmp.h */
#endif
