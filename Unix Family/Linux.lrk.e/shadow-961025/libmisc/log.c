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
RCSID("$Id: log.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include <sys/types.h>
#include <utmp.h>
#if HAVE_UTMPX_H
#include <utmpx.h>
#endif
#include <pwd.h>
#include <fcntl.h>
#include <time.h>
#include "defines.h"
#if HAVE_LASTLOG_H
#include <lastlog.h>
#else
#include "lastlog_.h"
#endif

extern	struct	utmp	utent;
#if HAVE_UTMPX_H
extern	struct	utmpx	utxent;
#endif
extern	struct	passwd	pwent;
extern	struct	lastlog	lastlog;
extern	char	**environ;

/* 
 * dolastlog - create lastlog entry
 *
 *	A "last login" entry is created for the user being logged in.  The
 *	UID is extracted from the global (struct passwd) entry and the
 *	TTY information is gotten from the (struct utmp).
 */

void
dolastlog ()
{
	int	fd;
	off_t	offset;
	struct	lastlog	newlog;

	/*
	 * If the file does not exist, don't create it.
	 */

	if ((fd = open (LASTLOG_FILE, O_RDWR)) == -1)
		return;

	/*
	 * The file is indexed by UID number.  Seek to the record
	 * for this UID.  Negative UID's will create problems, but ...
	 */

	offset = (unsigned long) pwent.pw_uid * sizeof lastlog;

	if (lseek (fd, offset, SEEK_SET) != offset) {
		(void) close (fd);
		return;
	}

	/*
	 * Read the old entry so we can tell the user when they last
	 * logged in.  Then construct the new entry and write it out
	 * the way we read the old one in.
	 */

	if (read (fd, (char *) &lastlog, sizeof lastlog) != sizeof lastlog)
		bzero ((char *) &lastlog, sizeof lastlog);
	newlog = lastlog;

	(void) time (&newlog.ll_time);
	(void) strncpy (newlog.ll_line, utent.ut_line, sizeof newlog.ll_line);
#if HAVE_UTMPX_H
	(void) strncpy (newlog.ll_host, utxent.ut_host, sizeof newlog.ll_host);
#elif HAVE_LL_HOST
	(void) strncpy (newlog.ll_host, utent.ut_host, sizeof newlog.ll_host);
#endif
	(void) lseek (fd, offset, SEEK_SET);
	(void) write (fd, (char *) &newlog, sizeof newlog);
	(void) close (fd);
}

