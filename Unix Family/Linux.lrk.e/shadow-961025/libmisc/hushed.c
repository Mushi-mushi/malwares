/*
 * Copyright 1991, 1993, John F. Haugh II and Chip Rosenthal
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
RCSID("$Id: hushed.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include <sys/types.h>
#include <stdio.h>
#include "defines.h"
#include <pwd.h>

extern char *getdef_str();

/*
 * hushed - determine if a user receives login messages
 *
 * Look in the hushed-logins file (or user's home directory) to see
 * if the user is to receive the login-time messages.
 */

int
hushed(pw)
	struct passwd *pw;
{
	char *hushfile;
	char buf[BUFSIZ];
	int found;
	FILE *fp;

	/*
	 * Get the name of the file to use.  If this option is not
	 * defined, default to a noisy login.
	 */

	if ( (hushfile=getdef_str("HUSHLOGIN_FILE")) == NULL )
		return 0;

	/*
	 * If this is not a fully rooted path then see if the
	 * file exists in the user's home directory.
	 */

	if (hushfile[0] != '/') {
		strcat(strcat(strcpy(buf, pw->pw_dir), "/"), hushfile);
		return (access(buf, 0) == 0);
	}

	/*
	 * If this is a fully rooted path then go through the file
	 * and see if this user is in there.
	 */

	if ((fp = fopen(hushfile, "r")) == NULL)
		return 0;

	for (found = 0;! found && fgets (buf, sizeof buf, fp);) {
		buf[strlen (buf) - 1] = '\0';
		found = ! strcmp (buf,
			buf[0] == '/' ? pw->pw_shell:pw->pw_name);
	}
	(void) fclose(fp);
	return found;
}
