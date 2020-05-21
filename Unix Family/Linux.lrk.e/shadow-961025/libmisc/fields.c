/*
 * Copyright 1990, John F. Haugh II
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
RCSID("$Id: fields.c,v 1.2 1996/09/25 03:19:56 marekm Exp $")

#include <ctype.h>
#include <string.h>
#include <stdio.h>

/*
 * valid_field - insure that a field contains all legal characters
 *
 * The supplied field is scanned for non-printing and other illegal
 * characters.  If any illegal characters are found, valid_field
 * returns -1.  Zero is returned for success.
 */

int
valid_field(field, illegal)
	const char *field;
	const char *illegal;
{
	const char *cp;

	for (cp = field;*cp && isprint (*cp) && ! strchr (illegal, *cp);cp++)
		;

	if (*cp)
		return -1;
	else
		return 0;
}

/*
 * change_field - change a single field if a new value is given.
 *
 * prompt the user with the name of the field being changed and the
 * current value.
 */

/* sizeof(buf) must be at least BUFSIZ chars!  --marekm */

void
change_field(buf, maxsize, prompt)
	char *buf;
	size_t maxsize;
	const char *prompt;
{
	char	new[BUFSIZ];
	char	*cp;

	if (maxsize > sizeof(new))
		maxsize = sizeof(new);

	printf ("\t%s [%s]: ", prompt, buf);
	if (fgets(new, maxsize, stdin) != new)
		return;

	if (!(cp = strchr (new, '\n')))
		return;
	*cp = '\0';

	if (new[0]) {
		/*
		 * Remove leading and trailing whitespace.  This also
		 * makes it possible to change the field to empty, by
		 * entering a space.  --marekm
		 */

		while (--cp >= new && isspace(*cp))
			;
		*++cp = '\0';

		cp = new;
		while (*cp && isspace(*cp))
			cp++;

		strncpy(buf, cp, maxsize - 1);
		buf[maxsize - 1] = '\0';
	}
}
