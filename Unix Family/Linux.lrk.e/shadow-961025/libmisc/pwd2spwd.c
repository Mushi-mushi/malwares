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

#ifdef SHADOWPWD

#include "rcsid.h"
RCSID("$Id: pwd2spwd.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include <sys/types.h>
#include "prototypes.h"
#include "defines.h"
#include <pwd.h>

extern	time_t	time ();

/*
 * pwd_to_spwd - create entries for new spwd structure
 *
 *	pwd_to_spwd() creates a new (struct spwd) containing the
 *	information in the pointed-to (struct passwd).
 */

struct spwd *
pwd_to_spwd(pw)
	const struct passwd *pw;
{
	static struct spwd sp;

	/*
	 * Nice, easy parts first.  The name and passwd map directly
	 * from the old password structure to the new one.
	 */
	sp.sp_namp = pw->pw_name;
	sp.sp_pwdp = pw->pw_passwd;

#ifdef ATT_AGE
	/*
	 * AT&T-style password aging maps the sp_min, sp_max, and
	 * sp_lstchg information from the pw_age field, which appears
	 * after the encrypted password.
	 */
	if (pw->pw_age[0]) {
		sp.sp_max = (c64i(pw->pw_age[0]) * WEEK) / SCALE;

		if (pw->pw_age[1])
			sp.sp_min = (c64i(pw->pw_age[1]) * WEEK) / SCALE;
		else
			sp.sp_min = (10000L * DAY) / SCALE;

		if (pw->pw_age[1] && pw->pw_age[2])
			sp.sp_lstchg = (a64l(pw->pw_age + 2) * WEEK) / SCALE;
		else
			sp.sp_lstchg = time((time_t *) 0) / SCALE;
	} else
#endif
	{
		/*
		 * Defaults used if there is no pw_age information.
		 */
		sp.sp_min = 0;
		sp.sp_max = (10000L * DAY) / SCALE;
		sp.sp_lstchg = time((time_t *) 0) / SCALE;
	}

	/*
	 * These fields have no corresponding information in the password
	 * file.  They are set to uninitialized values.
	 */
	sp.sp_warn = -1;
	sp.sp_expire = -1;
	sp.sp_inact = -1;
	sp.sp_flag = -1;

	return &sp;
}
#endif  /* SHADOWPWD */
