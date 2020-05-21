/*
 * Copyright 1992, John F. Haugh II
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

#ifndef HAVE_LCKPWDF

#include "rcsid.h"
RCSID("$Id: lockpw.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include "prototypes.h"
#include "defines.h"

#include "pwio.h"
#ifdef SHADOWPWD
#include "shadowio.h"
#endif

/*
 * lckpwdf - lock the password files
 */

int
lckpwdf ()
{
	int	i;

	/*
	 * We have 15 seconds to lock the whole mess
	 */

	for (i = 0;i < 15;i++)
		if (pw_lock ())
			break;
		else
			sleep (1);

	/*
	 * Did we run out of time?
	 */

	if (i == 15)
		return -1;

	/*
	 * Nope, use any remaining time to lock the shadow password
	 * file.
	 */

	for (;i < 15;i++)
		if (spw_lock ())
			break;
		else
			sleep (1);

	/*
	 * Out of time yet?
	 */

	if (i == 15) {
		pw_unlock ();
		return -1;
	}

	/*
	 * Nope - and both files are now locked.
	 */

	return 0;
}

/*
 * ulckpwdf - unlock the password files
 */

int
ulckpwdf ()
{

	/*
	 * Unlock both files.
	 */

	return (pw_unlock () && spw_unlock ()) ? 0:-1;
}
#endif
