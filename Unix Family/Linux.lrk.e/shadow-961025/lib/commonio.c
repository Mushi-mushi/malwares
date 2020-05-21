/*
 * Copyright 1990 - 1994, John F. Haugh II
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
RCSID("$Id: commonio.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

/*
 * Some common code moved here from *io.c.  Also, the code used to
 * leak file descriptors (no big deal in normal user commands, but
 * could be a problem in long running daemons) and sometimes failed
 * to remove the temporary lock file.  Hopefully no more.  --marekm
 */

#include "prototypes.h"
#include "defines.h"

#include <sys/stat.h>
#include <utime.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>

static int
check_link_count(file)
	const char *file;
{
	struct stat sb;

	if (stat(file, &sb) != 0)
		return 0;

	if (sb.st_nlink != 2)
		return 0;

	return 1;
}

/*
 * do_lock_file - lock a password file
 *
 *	do_lock_file() encapsulates the lock operation.  it returns
 *	TRUE or FALSE depending on the password file being
 *	properly locked.  the lock is set by creating a semaphore
 *	file, LOCK.  FILE is a temporary file name.
 */
int
do_lock_file(file, lock)
	const char *file;
	const char *lock;
{
	int	fd;
	int	pid;
	int	len;
	int	retval;
	char	buf[32];

	/*
	 * Create a lock file which can be switched into place
	 */

	if ((fd = open (file, O_CREAT|O_EXCL|O_WRONLY, 0600)) == -1)
		return 0;

	pid = getpid();
	sprintf (buf, "%d", pid);
	len = strlen(buf) + 1;
	if (write (fd, buf, len) != len) {
		(void) close (fd);
		(void) unlink (file);
		return 0;
	}
	close (fd);

	/*
	 * Simple case first -
	 *	Link fails (in a sane environment ...) if the target
	 *	exists already.  So we try to switch in a new lock
	 *	file.  If that succeeds, we assume we have the only
	 *	valid lock.  Needs work for NFS where this assumption
	 *	may not hold.  The simple hack is to check the link
	 *	count on the source file, which should be 2 iff the
	 *	link =really= worked.
	 */

	if (link(file, lock) == 0) {
		retval = check_link_count(file);
		unlink(file);
		return retval;
	}

	/*
	 * Invalid lock test -
	 *	Open the lock file and see if the lock is valid.
	 *	The PID of the lock file is checked, and if the PID
	 *	is not valid, the lock file is removed.  If the unlink
	 *	of the lock file fails, it should mean that someone
	 *	else is executing this code.  They will get success,
	 *	and we will fail.
	 */

	if ((fd = open(lock, O_RDWR)) == -1) {
		unlink(file);
		errno = EINVAL;
		return 0;
	}
	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len <= 0) {
		unlink(file);
		errno = EINVAL;
		return 0;
	}
	buf[len] = '\0';
	if ((pid = strtol (buf, (char **) 0, 10)) == 0) {
		unlink(file);
		errno = EINVAL;
		return 0;
	}
	if (kill (pid, 0) == 0)  {
		unlink(file);
		errno = EEXIST;
		return 0;
	}
	if (unlink (lock)) {
		(void) close (fd);
		(void) unlink (file);
		return 0;
	}

	/*
	 * Re-try lock -
	 *	The invalid lock has now been removed and I should
	 *	be able to acquire a lock for myself just fine.  If
	 *	this fails there will be no retry.  The link count
	 *	test here makes certain someone executing the previous
	 *	block of code didn't just remove the lock we just
	 *	linked to.
	 */

	retval = 0;
	if (link(file, lock) == 0 && check_link_count(file))
		retval = 1;

	unlink(file);
	return retval;
}

FILE *
fopen_with_umask(name, mode, mask)
	const char *name;
	const char *mode;
	int mask;
{
	FILE *f;

	mask = umask(mask);
	f = fopen(name, mode);
	umask(mask);
	return f;
}

/*
 * Copy fp to backup, set permissions and times from st.
 */
int
create_backup_file(fp, backup, st)
	FILE *fp;
	const char *backup;
	const struct stat *st;
{
	FILE *bkfp;
	int c;

	unlink(backup);
	bkfp = fopen_with_umask(backup, "w", 0777);
	if (bkfp == NULL)
		return -1;
	rewind(fp);
	while ((c = getc(fp)) != EOF) {
		if (putc(c, bkfp) == EOF) {
			fclose(bkfp);
			return -1;
		}
	}
	if (fflush(bkfp)) {
		fclose(bkfp);
		return -1;
	}
	if (fclose(bkfp))
		return -1;
	if (st) {
		struct utimbuf ut;

		chown(backup, st->st_uid, st->st_gid);
		chmod(backup, st->st_mode);
		ut.actime = st->st_atime;
		ut.modtime = st->st_mtime;
		utime(backup, &ut);
	}
	return 0;
}
