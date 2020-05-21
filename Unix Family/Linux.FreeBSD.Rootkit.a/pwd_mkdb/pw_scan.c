/*-
 * Copyright (c) 1990, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static char sccsid[] = "@(#)pw_scan.c	8.3 (Berkeley) 4/2/94";
#endif /* not lint */

/*
 * This module is used to "verify" password entries by chpass(1) and
 * pwd_mkdb(8).
 */

#include <sys/param.h>

#include <err.h>
#include <fcntl.h>
#include <pwd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "pw_scan.h"

int
pw_scan(bp, pw)
	char *bp;
	struct passwd *pw;
{
	long id;
	int root;
	char *p, *sh;

	pw->pw_fields = 0;
	if (!(pw->pw_name = strsep(&bp, ":")))		/* login */
		goto fmt;
	root = !strcmp(pw->pw_name, "root");
	if(pw->pw_name[0] && (pw->pw_name[0] != '+' || pw->pw_name[1] == '\0'))
		pw->pw_fields |= _PWF_NAME;

	if (!(pw->pw_passwd = strsep(&bp, ":")))	/* passwd */
		goto fmt;
	if(pw->pw_passwd[0]) pw->pw_fields |= _PWF_PASSWD;

	if (!(p = strsep(&bp, ":")))			/* uid */
		goto fmt;
	if(p[0]) pw->pw_fields |= _PWF_UID;
	id = atol(p);
	if (root && id) {
		warnx("root uid should be 0");
		return (0);
	}
	if (id > USHRT_MAX) {
		warnx("%s > max uid value (%d)", p, USHRT_MAX);
		return (0);
	}
	pw->pw_uid = id;

	if (!(p = strsep(&bp, ":")))			/* gid */
		goto fmt;
	if(p[0]) pw->pw_fields |= _PWF_GID;
	id = atol(p);
	if (id > USHRT_MAX) {
		warnx("%s > max gid value (%d)", p, USHRT_MAX);
		return (0);
	}
	pw->pw_gid = id;

	pw->pw_class = strsep(&bp, ":");		/* class */
	if(pw->pw_class[0]) pw->pw_fields |= _PWF_CLASS;

	if (!(p = strsep(&bp, ":")))			/* change */
		goto fmt;
	if(p[0]) pw->pw_fields |= _PWF_CHANGE;
	pw->pw_change = atol(p);

	if (!(p = strsep(&bp, ":")))			/* expire */
		goto fmt;
	if(p[0]) pw->pw_fields |= _PWF_EXPIRE;
	pw->pw_expire = atol(p);

	if (!(pw->pw_gecos = strsep(&bp, ":")))		/* gecos */
		goto fmt;
	if(pw->pw_gecos[0]) pw->pw_fields |= _PWF_GECOS;

	if (!(pw->pw_dir = strsep(&bp, ":")))			/* directory */
		goto fmt;
	if(pw->pw_dir[0]) pw->pw_fields |= _PWF_DIR;

	if (!(pw->pw_shell = strsep(&bp, ":")))		/* shell */
		goto fmt;

	p = pw->pw_shell;
	if (root && *p)					/* empty == /bin/sh */
		for (setusershell();;) {
			if (!(sh = getusershell())) {
				warnx("warning, unknown root shell");
				break;
			}
			if (!strcmp(p, sh))
				break;
		}
	if(p[0]) pw->pw_fields |= _PWF_SHELL;

	if (p = strsep(&bp, ":")) {			/* too many */
fmt:		warnx("corrupted entry");
		return (0);
	}
	return (1);
}
