/*
 * Copyright 1989 - 1992, John F. Haugh II
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
RCSID("$Id: sulog.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include <sys/types.h>
#include <stdio.h>
#include <time.h>
#include "defines.h"
#include "getdef.h"

extern	char	name[];
extern	char	oldname[];

/*
 * sulog - log a SU command execution result
 */

void
sulog (tty, success)
	const char *tty;	/* Name of terminal SU was executed from */
	int success;		/* Success (1) or failure (0) of command */
{
	char	*sulog;
	time_t	clock;
	struct	tm	*tm;
	struct	tm	*localtime ();
	FILE	*fp;

	if ( (sulog=getdef_str("SULOG_FILE")) == (char *) 0 )
		return;

	if ((fp = fopen (sulog, "a+")) == (FILE *) 0)
		return;			/* can't open or create logfile */

	(void) time (&clock);
	tm = localtime (&clock);

	(void) fprintf (fp, "SU %.02d/%.02d %.02d:%.02d %c %.6s %s-%s\n",
		tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min,
		success ? '+':'-', tty, oldname, name);

	fflush (fp);
	fclose (fp);
}
