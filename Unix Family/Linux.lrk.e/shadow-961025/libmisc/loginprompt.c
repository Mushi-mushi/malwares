/*
 * Copyright 1989 - 1993, John F. Haugh II
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
RCSID("$Id: loginprompt.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include <stdio.h>
#include <signal.h>
#include <ctype.h>
#include "prototypes.h"
#include "defines.h"
#include "getdef.h"

#ifndef ISSUE_FILE
#define ISSUE_FILE "/etc/issue"
#endif

/*
 * login_prompt - prompt the user for their login name
 *
 * login_prompt() displays the standard login prompt.  If the option
 * ISSUE_FILE_ENAB is set, the file /etc/issue is displayed
 * before the prompt.
 */

void
login_prompt(prompt, name, namesize)
	const char *prompt;
	char *name;
	int namesize;
{
	char	buf[BUFSIZ];
#define MAX_ENV 32
	char	*envp[MAX_ENV];
	int	envc;
	char	*cp;
	int	i;
	FILE	*fp;
	RETSIGTYPE	(*sigquit)();
#ifdef	SIGTSTP
	RETSIGTYPE	(*sigtstp)();
#endif

	/*
	 * There is a small chance that a QUIT character will be part of
	 * some random noise during a prompt.  Deal with this by exiting
	 * instead of core dumping.  If SIGTSTP is defined, do the same
	 * thing for that signal.
	 */

	sigquit = signal (SIGQUIT, exit);
#ifdef	SIGTSTP
	sigtstp = signal (SIGTSTP, exit);
#endif

	/*
	 * See if the user has configured the /etc/issue file to
	 * be displayed and display it before the prompt.
	 */

	if (prompt) {
		if (getdef_bool ("ISSUE_FILE_ENAB")) {
			if ((fp = fopen (ISSUE_FILE, "r"))) {
				while ((i = getc (fp)) != EOF)
					putc (i, stdout);

				fclose (fp);
			}
		}
		gethostname(buf, sizeof buf);
		printf (prompt, buf);
		fflush (stdout);
	}

	/* 
	 * Read the user's response.  The trailing newline will be
	 * removed.
	 */

	bzero (buf, sizeof buf);
	if (fgets (buf, sizeof buf, stdin) != buf)
		exit (1);

	buf[strlen (buf) - 1] = '\0';	/* remove \n [ must be there ] */

	/*
	 * Skip leading whitespace.  This makes "  username" work right.
	 * Then copy the rest (up to the end or the first "non-graphic"
	 * character into the username.
	 */

	for (cp = buf;*cp == ' ' || *cp == '\t';cp++)
		;

	for (i = 0;i < namesize - 1 && isgraph (*cp);name[i++] = *cp++)
		;
	while (isgraph(*cp))
		cp++;

	if (*cp)
		cp++;

	name[i] = '\0';

	/*
	 * This is a disaster, at best.  The user may have entered extra
	 * environmental variables at the prompt.  There are several ways
	 * to do this, and I just take the easy way out.
	 */

	if (*cp != '\0') {		/* process new variables */
		char *nvar;
		/*static*/ int count = 1;

		for (envc = 0;envc < MAX_ENV;envc++) {
			nvar = strtok(envc ? (char *)0 : cp, " \t,");
			if (!nvar)
				break;
			if (strchr(nvar, '=')) {
				envp[envc] = nvar;
			} else {
				envp[envc] = xmalloc(strlen(nvar) + 32);
				sprintf(envp[envc], "L%d=%s", count++, nvar);
			}
		}
		set_env (envc, envp);
	}

	/*
	 * Set the SIGQUIT handler back to its original value
	 */

	(void) signal (SIGQUIT, sigquit);
#ifdef	SIGTSTP
	(void) signal (SIGTSTP, sigtstp);
#endif
}
