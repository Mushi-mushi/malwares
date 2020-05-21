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

#include <sys/types.h>
#include <stdio.h>
#ifndef BSD
#include <sys/wait.h>
#endif
#include "prototypes.h"
#include "defines.h"
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_USERSEC_H
#include <userpw.h>
#include <usersec.h>
#include <userconf.h>
#endif

#ifndef	AGING
#if defined(SHADOWPWD) || defined(HAVE_USERSEC_H)
#define AGING	1
#endif
#else
#if !defined(SHADOWPWD) && !defined(HAVE_USERSEC_H) && !defined(ATT_AGE)
#undef AGING
#endif
#endif

#if defined(SHADOWPWD) || defined(AGING) /*{*/

#include "rcsid.h"
RCSID("$Id: age.c,v 1.2 1996/09/10 02:45:12 marekm Exp $")

#define EXPIRE_TODAY		"Your password will expire today.\n"
#define EXPIRE_DAY		"Your password will expire tomorrow.\n"
#define EXPIRE_DAYS		"Your password will expire in %ld days.\n"
#define PASSWORD_EXPIRED	"Your password has expired."
#define PASSWORD_INACTIVE	"Your password is inactive."
#define LOGIN_EXPIRED		"Your login has expired."
#define CONTACT_SYSADM		"  Contact the system administrator.\n"
#define NEW_PASSWORD		"  Choose a new password.\n"

#ifndef PASSWD_PROGRAM
#define PASSWD_PROGRAM "/bin/passwd"
#endif

extern	time_t	time ();

/*
 * expire - force password change if password expired
 *
 *	expire() calls /bin/passwd to change the user's password
 *	if it has expired.
 */

#ifdef	SHADOWPWD
int
expire (pw, sp)
	const struct passwd *pw;
	const struct spwd *sp;
#else
int
expire (pw)
	const struct passwd *pw;
#endif
{
	int	status;
	int	child;
	int	pid;

#ifdef	SHADOWPWD
	if (! sp)
		sp = pwd_to_spwd (pw);
#endif

	/*
	 * See if the user's password has expired, and if so
	 * force them to change their password.
	 */

#ifdef	SHADOWPWD
	switch (status = isexpired (pw, sp))
#else
	switch (status = isexpired (pw))
#endif
	{
		case 0:
			return 0;
		case 1:
			printf (PASSWORD_EXPIRED);
			break;
		case 2:
			printf (PASSWORD_INACTIVE);
			break;
		case 3:
			printf (LOGIN_EXPIRED);
			break;
	}

	/*
	 * Setting the maximum valid period to less than the minimum
	 * valid period means that the minimum period will never
	 * occur while the password is valid, so the user can never
	 * change that password.
	 */

#ifdef	SHADOWPWD
	if (status > 1 || sp->sp_max < sp->sp_min)
#else
	if (status > 1 || c64i (pw->pw_age[0]) < c64i (pw->pw_age[1]))
#endif
	{
		puts (CONTACT_SYSADM);
		exit (1);
	}
	puts (NEW_PASSWORD);
	fflush (stdout);

	/*
	 * Close all the files so that unauthorized access won't
	 * occur.  This needs to be done anyway because those files
	 * might become stale after "passwd" is executed.
	 */

#ifdef	SHADOWPWD
	endspent ();
#endif
	endpwent ();
#ifdef	SHADOWGRP
	endsgent ();
#endif
	endgrent ();

	/*
	 * Execute the /bin/passwd command.  The exit status will be
	 * examined to see what the result is.  If there are any
	 * errors the routine will exit.  This forces the user to
	 * change their password before being able to use the account.
	 */

	if ((pid = fork ()) == 0) {
		/*
		 * Set the UID to be that of the user.  This causes
		 * passwd to work just like it would had they executed
		 * it from the command line while logged in.
		 */

		if (setup_uid_gid(pw, 0))
			_exit(127);

		execl (PASSWD_PROGRAM, PASSWD_PROGRAM, pw->pw_name, (char *)0);
		puts ("Can't execute " PASSWD_PROGRAM);
		fflush (stdout);
		_exit(126);
	} else if (pid == -1) {
		perror("fork");
		exit(1);
	}
	while ((child = wait (&status)) != pid && child != -1)
		;

	if (child == pid && status == 0)
		return 1;

	exit (1);
	/*NOTREACHED*/
}

/*
 * agecheck - see if warning is needed for password expiration
 *
 *	agecheck sees how many days until the user's password is going
 *	to expire and warns the user of the pending password expiration.
 */

#ifdef	SHADOWPWD
void
agecheck (pw, sp)
	const struct passwd *pw;
	const struct spwd *sp;
#else
void
agecheck (pw)
	const struct passwd *pw;
#endif
{
	long	clock = time ((long *) 0) / SCALE;
	long	remain;

#ifdef	SHADOWPWD
	if (! sp)
		sp = pwd_to_spwd (pw);

	/*
	 * The last, max, and warn fields must be supported or the
	 * warning period cannot be calculated.
	 */

	if (sp->sp_lstchg == -1 || sp->sp_max == -1 || sp->sp_warn == -1)
		return;
#else
	if (pw->pw_age[0] == '\0')
		return;
#endif

#ifdef	SHADOWPWD
	if ((remain = (sp->sp_lstchg + sp->sp_max) - clock) <= sp->sp_warn)
#else
	if ((remain = (a64l (pw->pw_age + 2) + c64i (pw->pw_age[0])) * 7
			- clock) <= getdef_num ("PASS_WARN_AGE", 7))
#endif
	{
		remain /= DAY/SCALE;
		if (remain > 1)
			printf(EXPIRE_DAYS, remain);
		else if (remain == 1)
			printf(EXPIRE_DAY);
		else if (remain == 0)
			printf(EXPIRE_TODAY);
	}
}
#endif /*}*/
