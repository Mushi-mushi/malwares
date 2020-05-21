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
RCSID("$Id: ttytype.c,v 1.2 1996/09/20 09:08:03 marekm Exp $")

#include <stdio.h>
#include "prototypes.h"
#include "defines.h"

extern	char	*getdef_str();

/*
 * ttytype - set ttytype from port to terminal type mapping database
 */

void
ttytype(line)
	const char *line;
{
	FILE	*fp;
	char	buf[BUFSIZ];
	char	*typefile;
	char	*cp;
	char	type[BUFSIZ];
	char	port[BUFSIZ];
	char	*getenv ();

	if (getenv ("TERM"))
		return;
	if ((typefile=getdef_str("TTYTYPE_FILE")) == NULL )
		return;
	if (access (typefile, 0))
		return;

	if (! (fp = fopen (typefile, "r"))) {
		perror (typefile);
		return;
	}
	while (fgets (buf, BUFSIZ, fp)) {
		if (buf[0] == '#')
			continue;

		if ((cp = strchr (buf, '\n')))
			*cp = '\0';

#if defined(SUN) || defined(BSD) || defined(SUN4)
		if ((sscanf (buf, "%s \"%*[^\"]\" %s", port, type) == 2 ||
				sscanf (buf, "%s %*s %s", port, type) == 2) &&
				strcmp (line, port) == 0)
			break;
#else	/* USG */
		if (sscanf (buf, "%s %s", type, port) == 2 &&
				strcmp (line, port) == 0)
			break;
#endif
	}
	if (! feof (fp) && ! ferror (fp))
		addenv("TERM", type);

	fclose (fp);
}
