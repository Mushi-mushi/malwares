/*
 * Copyright 1989 - 1991, John F. Haugh II
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
RCSID("$Id: motd.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include <stdio.h>
#include "defines.h"

extern	char	*getdef_str();

/*
 * motd -- output the /etc/motd file
 *
 * motd() determines the name of a login announcement file and outputs
 * it to the user's terminal at login time.  The MOTD_FILE configuration
 * option is a colon-delimited list of filenames.
 */

void
motd ()
{
	FILE	*fp;
	char	motdlist[BUFSIZ], *motdfile, *mb;
	register int	c;

	if ((mb = getdef_str("MOTD_FILE")) == NULL)
		return;

	strncpy(motdlist, mb, sizeof(motdlist));
	motdlist[sizeof(motdlist)-1] = '\0';

	for (mb = motdlist ; (motdfile = strtok(mb,":")) != NULL ; mb = NULL) {
		if ((fp = fopen(motdfile, "r")) != NULL) {
			while ((c = getc (fp)) != EOF)
				putchar (c);
			fclose (fp);
		}
	}
	fflush (stdout);
}
