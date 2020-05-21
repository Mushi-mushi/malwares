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
RCSID("$Id: putpwent.c,v 1.1.1.1 1996/08/10 07:59:51 marekm Exp $")

#include "defines.h"
#include <stdio.h>
#include <pwd.h>

/*
 * putpwent - Output a (struct passwd) in character format
 *
 *	putpwent() writes out a (struct passwd) in the format it appears
 *	in in flat ASCII files.
 *
 *	(Author: Dr. Micheal Newberry)
 */

int
putpwent (p, f)
	const struct passwd *p;
	FILE *f;
{
	int status;

#if defined(SUN) || defined(BSD) || defined(SUN4)
	status = fprintf (f, "%s:%s:%d:%d:%s,%s:%s:%s\n",
		p->pw_name, p->pw_passwd, p->pw_uid, p->pw_gid,
		p->pw_gecos, p->pw_comment, p->pw_dir, p->pw_shell) == EOF;
#else
	status = fprintf (f, "%s:%s", p->pw_name, p->pw_passwd) == EOF;
#ifdef	ATT_AGE
	if (p->pw_age && p->pw_age[0])
		status |= fprintf (f, ",%s", p->pw_age) == EOF;
#endif
	status |= fprintf (f, ":%d:%d:%s", p->pw_uid, p->pw_gid,
		p->pw_gecos) == EOF;
#ifdef	ATT_COMMENT
	if (p->pw_comment && p->pw_comment[0])
		status |= fprintf (f, ",%s", p->pw_comment) == EOF;
#endif
	status |= fprintf (f, ":%s:%s\n", p->pw_dir, p->pw_shell) == EOF;
#endif
	return status;
}
