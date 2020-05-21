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

/*
 * Extracted from age.c and made part of libshadow.a - may be useful
 * in other shadow-aware programs.  --marekm
 */

#include <config.h>

#include <sys/types.h>
#include "prototypes.h"
#include "defines.h"
#include <pwd.h>

#ifdef  HAVE_USERSEC_H
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
RCSID("$Id: isexpired.c,v 1.3 1996/09/25 03:19:56 marekm Exp $")

extern	time_t	time ();

/*
 * isexpired - determine if account is expired yet
 *
 *	isexpired calculates the expiration date based on the
 *	password expiration criteria.
 */

/*ARGSUSED*/

#ifdef	SHADOWPWD
int
isexpired(pw, sp)
	const struct passwd *pw;
	const struct spwd *sp;
#else
int
isexpired(pw)
	const struct passwd *pw;
#endif
{
	long	now;
#ifdef	HAVE_USERSEC_H
	int	minage = 0;
	int	maxage = 10000;
	int	curage = 0;
	struct	userpw	*pu;
#endif

	now = time ((time_t *) 0) / SCALE;

#ifdef	SHADOWPWD

	if (!sp)
		sp = pwd_to_spwd(pw);

	/*
	 * Quick and easy - there is an expired account field
	 * along with an inactive account field.  Do the expired
	 * one first since it is worse.
	 */

	if (sp->sp_expire > 0 && now >= sp->sp_expire)
		return 3;

	/*
	 * Last changed date 1970-01-01 (not very likely) means that
	 * the password must be changed on next login (passwd -e).
	 *
	 * The check for "x" is a workaround for RedHat NYS libc bug -
	 * if /etc/shadow doesn't exist, getspnam() still succeeds and
	 * returns sp_lstchg==0 (must change password) instead of -1!
	 */
	if (sp->sp_lstchg == 0 && strcmp(pw->pw_passwd, "x") != 0)
		return 1;

	if (sp->sp_lstchg > 0 && sp->sp_max >= 0 && sp->sp_inact >= 0 &&
			now >= sp->sp_lstchg + sp->sp_max + sp->sp_inact)
		return 2;
#endif
#ifdef	HAVE_USERSEC_H	/*{*/
        /*
         * The aging information lives someplace else.  Get it from the
         * login.cfg file
         */

        if (getconfattr (SC_SYS_PASSWD, SC_MINAGE, &minage, SEC_INT))
                minage = -1;

        if (getconfattr (SC_SYS_PASSWD, SC_MAXAGE, &maxage, SEC_INT))
                maxage = -1;

        pu = getuserpw (pw->pw_name);
        curage = (time (0) - pu->upw_lastupdate) / (7*86400L);

	if (maxage != -1 && curage > maxage)
		return 1;
#else	/*} !HAVE_USERSEC_H */

	/*
	 * The last and max fields must be present for an account
	 * to have an expired password.  A maximum of >10000 days
	 * is considered to be infinite.
	 */

#ifdef	SHADOWPWD
	if (sp->sp_lstchg == -1 ||
			sp->sp_max == -1 || sp->sp_max >= (10000L*DAY/SCALE))
		return 0;
#endif
#ifdef	ATT_AGE
	if (pw->pw_age[0] == '\0' || pw->pw_age[0] == '/')
		return 0;
#endif

	/*
	 * Calculate today's day and the day on which the password
	 * is going to expire.  If that date has already passed,
	 * the password has expired.
	 */

#ifdef	SHADOWPWD
	if (now >= sp->sp_lstchg + sp->sp_max)
		return 1;
#endif
#ifdef	ATT_AGE
	if (a64l (pw->pw_age + 2) + c64i (pw->pw_age[1]) < now / 7)
		return 1;
#endif
#endif	/*} HAVE_USERSEC_H */
	return 0;
}
#endif /*}*/
