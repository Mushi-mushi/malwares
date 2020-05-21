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
 *
 *	This file implements a transaction oriented password database
 *	library.  The password file is updated one entry at a time.
 *	After each transaction the file must be logically closed and
 *	transferred to the existing password file.  The sequence of
 *	events is
 *
 *	pw_lock				-- lock password file
 *	pw_open				-- logically open password file
 *	while transaction to process
 *		pw_(locate,update,remove) -- perform transaction
 *	done
 *	pw_close			-- commit transactions
 *	pw_unlock			-- remove password lock
 */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: pwio.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <signal.h>
#include "prototypes.h"
#include "defines.h"

#define NEED_PW_FILE_ENTRY
#include "pwio.h"

static	int	islocked;
static	int	isopen;
static	int	open_modes;
static	FILE	*pwfp;

struct	pw_file_entry	*__pwf_head;
static	struct	pw_file_entry	*pwf_tail;
static	struct	pw_file_entry	*pwf_cursor;
int	__pw_changed;
static	int	lock_pid;

#define	PW_LOCK	"/etc/passwd.lock"
#define	PW_TEMP "/etc/pwd.%d"

static	char	pw_filename[BUFSIZ] = PASSWD_FILE;

extern	int	fputs();
extern	char	*fgets();
extern	char	*strdup();
extern	char	*malloc();
extern	struct	passwd	*sgetpwent();
extern int do_lock_file();
extern FILE *fopen_with_umask();

/*
 * __pw_dup - duplicate a password file entry
 *
 *	__pw_dup() accepts a pointer to a password file entry and
 *	returns a pointer to a password file entry in allocated
 *	memory.
 */

struct passwd *
__pw_dup(pwent)
	const struct passwd *pwent;
{
	struct	passwd	*pw;

	if (! (pw = (struct passwd *) malloc (sizeof *pw)))
		return 0;

	if ((pw->pw_name = strdup (pwent->pw_name)) == 0 ||
			(pw->pw_passwd = strdup (pwent->pw_passwd)) == 0 ||
#ifdef	ATT_AGE
			(pw->pw_age = strdup (pwent->pw_age)) == 0 ||
#endif	/* ATT_AGE */
#ifdef	ATT_COMMENT
			(pw->pw_comment = strdup (pwent->pw_comment)) == 0 ||
#endif	/* ATT_COMMENT */
			(pw->pw_gecos = strdup (pwent->pw_gecos)) == 0 ||
			(pw->pw_dir = strdup (pwent->pw_dir)) == 0 ||
			(pw->pw_shell = strdup (pwent->pw_shell)) == 0)
		return 0;

	pw->pw_uid = pwent->pw_uid;
	pw->pw_gid = pwent->pw_gid;

	return pw;
}

/*
 * pw_free - free a dynamically allocated password file entry
 *
 *	pw_free() frees up the memory which was allocated for the
 *	pointed to entry.
 */

static void
pw_free(pwent)
	const struct passwd *pwent;
{
	free (pwent->pw_name);
	free (pwent->pw_passwd);
	free (pwent->pw_gecos);
	free (pwent->pw_dir);
	free (pwent->pw_shell);
}

/*
 * pw_name - change the name of the password file
 */

int
pw_name(name)
	const char *name;
{
	if (isopen || (int) strlen (name) > (BUFSIZ-10))
		return -1;

	strcpy (pw_filename, name);
	return 0;
}

/*
 * pw_lock - lock a password file
 *
 *	pw_lock() encapsulates the lock operation.  it returns
 *	TRUE or FALSE depending on the password file being
 *	properly locked.  the lock is set by creating a semaphore
 *	file, PW_LOCK.
 */

int
pw_lock()
{
	char	file[BUFSIZ];
	char	lock[BUFSIZ];

	/*
	 * Quick check -- If I created this lock already, assume it is
	 * still there.
	 */

	if (islocked && lock_pid == getpid ())
		return 1;

	/*
	 * If we are using the "standard" password file, we create a
	 * well-known lock file.  Otherwise, we create one based on the
	 * name of the file being altered.
	 */

	lock_pid = getpid();
	if (strcmp (pw_filename, PASSWD_FILE) != 0) {
		sprintf (file, "%s.%d", pw_filename, lock_pid);
		sprintf (lock, "%s.lock", pw_filename);
	} else {
		sprintf (file, "%s.%d", PW_TEMP, lock_pid);
		strcpy (lock, PW_LOCK);
	}

	/*
	 * The rest is common to all four files (see commonio.c).  --marekm
	 */

	if (do_lock_file(file, lock)) {
		islocked = 1;
		return 1;
	}

	return 0;
}

/*
 * pw_unlock - logically unlock a password file
 *
 *	pw_unlock() removes the lock which was set by an earlier
 *	invocation of pw_lock().
 */

int
pw_unlock()
{
	char	lock[BUFSIZ];

	/*
	 * If we are unlocking an open file, we aren't going to write
	 * out the contents.  This is the "abort" mechanism which allows
	 * all changes to be "aborted".
	 */

	if (isopen) {
		open_modes = O_RDONLY;
		if (! pw_close ())
			return 0;
	}

	/*
	 * If the file is locked, we reset some flags and remove the lock
	 * file.  But we must be the process which created the lock in the
	 * first place.  fork() can mess us up since it causes two processes
	 * to hold the lock.
	 */

  	if (islocked) {
  		islocked = 0;
		if (lock_pid != getpid ())
			return 0;

		strcpy (lock, pw_filename);
		strcat (lock, ".lock");
		(void) unlink (lock);
  		return 1;
	}
	return 0;
}

/*
 * pw_open - open a password file
 *
 *	pw_open() encapsulates the open operation.  it returns
 *	TRUE or FALSE depending on the password file being
 *	properly opened.
 */

int
pw_open(mode)
	int mode;
{
	char	buf[8192];
	char	*cp;
	struct	pw_file_entry	*pwf;
	struct	passwd	*pwent;

	if (isopen || (mode != O_RDONLY && mode != O_RDWR))
		return 0;

	if (mode != O_RDONLY && ! islocked &&
			strcmp (pw_filename, PASSWD_FILE) == 0)
		return 0;

	if ((pwfp = fopen (pw_filename, mode == O_RDONLY ? "r":"r+")) == 0)
		return 0;

	__pwf_head = pwf_tail = pwf_cursor = 0;
	__pw_changed = 0;

	while (fgets (buf, sizeof buf, pwfp) != (char *) 0) {
		if ((cp = strrchr (buf, '\n')))
			*cp = '\0';

		if (! (pwf = (struct pw_file_entry *) malloc (sizeof *pwf)))
			goto fail;

		pwf->pwf_changed = 0;
		if ( !(pwf->pwf_line = strdup (buf)))
			goto fail;
		if ((pwent = sgetpwent (buf)) && ! (pwent = __pw_dup (pwent)))
			goto fail;

		pwf->pwf_entry = pwent;

		if (__pwf_head == 0) {
			__pwf_head = pwf_tail = pwf;
			pwf->pwf_next = 0;
		} else {
			pwf_tail->pwf_next = pwf;
			pwf->pwf_next = 0;
			pwf_tail = pwf;
		}
	}
	isopen++;
	open_modes = mode;

	return 1;

fail:
	fclose(pwfp);
	return 0;
}

/*
 * pw_close - close the password file
 *
 *	pw_close() outputs any modified password file entries and
 *	frees any allocated memory.
 */

int
pw_close()
{
	char	backup[BUFSIZ];
	char	newfile[BUFSIZ];
	int	errors = 0;
	struct	pw_file_entry *pwf;
	struct	stat	sb;

	if (! isopen) {
		errno = EINVAL;
		return 0;
	}
	if (islocked && lock_pid != getpid ()) {
		isopen = 0;
		islocked = 0;
		errno = EACCES;
		return 0;
	}
	strcpy (backup, pw_filename);
	strcat (backup, "-");
	strcpy (newfile, pw_filename);
	strcat (newfile, "+");

	/*
	 * Create a backup copy of the password file.
	 */

	if (open_modes == O_RDWR && __pw_changed) {

		/*
		 * POLICY: /etc/passwd
		 * Any backup copy of the password file shall have the
		 * same protections as the original.
		 */

		if (fstat (fileno (pwfp), &sb))
			return 0;

		if (create_backup_file(pwfp, backup, &sb))
			return 0;

		isopen = 0;
		(void) fclose (pwfp);

		/*
		 * POLICY: /etc/passwd
		 * The password file shall allow write access to
		 * privileged users only.
		 *
		 * The password file is opened with no access permissions
		 * to any user.  This allows the file to be changed to
		 * root ownership and then made readable by all users
		 * without ever giving any unprivileged user write access.
		 */

		pwfp = fopen_with_umask(newfile, "w", 0777);
		if (!pwfp)
			return 0;
		if (chown(newfile, sb.st_uid, sb.st_gid) ||
		    chmod(newfile, sb.st_mode))
			return 0;

		/*
		 * Check each member in the list and write out any elements
		 * that have been changed.
		 */

		for (pwf = __pwf_head;errors == 0 && pwf;pwf = pwf->pwf_next) {
			if (pwf->pwf_changed) {
				if (putpwent (pwf->pwf_entry, pwfp))
					errors++;
			} else {
				if (fputs (pwf->pwf_line, pwfp) == EOF)
					errors++;
				if (putc ('\n', pwfp) == EOF)
					errors++;
			}
		}
		if (fflush (pwfp))
			errors++;
		if (fclose (pwfp))
			errors++;

		if (errors) {
			unlink (newfile);
			return 0;
		}

		/*
		 * POLICY: /etc/passwd
		 * The password file shall be consistent at all times.
		 *
		 * The new password file is moved into place only after
		 * determining that the file was created without any
		 * errors occuring.
		 */

		if (rename (newfile, pw_filename))
			return 0;
		sync();
	} else 

		/*
		 * Just close the file -- there was nothing to change
		 */

		fclose (pwfp);

	pwfp = 0;

	/*
	 * Free up all of the memory in the linked list.
	 */

	while (__pwf_head != 0) {
		pwf = __pwf_head;
		__pwf_head = pwf->pwf_next;

		if (pwf->pwf_entry) {
			pw_free (pwf->pwf_entry);
			free (pwf->pwf_entry);
		}
		if (pwf->pwf_line)
			free (pwf->pwf_line);

		free (pwf);
	}
	pwf_tail = 0;
	isopen = 0;
	return 1;
}

int
pw_update(pwent)
	const struct passwd *pwent;
{
	struct	pw_file_entry	*pwf;
	struct	passwd	*npw;

	if (! isopen || open_modes == O_RDONLY) {
		errno = EINVAL;
		return 0;
	}
	for (pwf = __pwf_head;pwf != 0;pwf = pwf->pwf_next) {
		if (pwf->pwf_entry == 0)
			continue;

		if (strcmp (pwent->pw_name, pwf->pwf_entry->pw_name) != 0)
			continue;

		if (! (npw = __pw_dup (pwent)))
			return 0;
		else {
			pw_free (pwf->pwf_entry);
			*(pwf->pwf_entry) = *npw;
		}
		pwf->pwf_changed = 1;
		pwf_cursor = pwf;
		return __pw_changed = 1;
	}
	pwf = (struct pw_file_entry *) malloc (sizeof *pwf);
	if (!pwf)
		return 0;
	if (! (pwf->pwf_entry = __pw_dup (pwent)))
		return 0;

	pwf->pwf_changed = 1;
	pwf->pwf_next = 0;
	pwf->pwf_line = 0;

	if (pwf_tail)
		pwf_tail->pwf_next = pwf;

	if (! __pwf_head)
		__pwf_head = pwf;

	pwf_tail = pwf;

	return __pw_changed = 1;
}

int
pw_remove(name)
	const char *name;
{
	struct	pw_file_entry	*pwf;
	struct	pw_file_entry	*opwf;

	if (! isopen || open_modes == O_RDONLY) {
		errno = EINVAL;
		return 0;
	}
	for (opwf = 0, pwf = __pwf_head;pwf != 0;
			opwf = pwf, pwf = pwf->pwf_next) {
		if (! pwf->pwf_entry)
			continue;

		if (strcmp (name, pwf->pwf_entry->pw_name) != 0)
			continue;

		if (pwf == pwf_cursor)
			pwf_cursor = opwf;

		if (opwf != 0)
			opwf->pwf_next = pwf->pwf_next;
		else
			__pwf_head = pwf->pwf_next;

		if (pwf == pwf_tail)
			pwf_tail = opwf;

		return __pw_changed = 1;
	}
	errno = ENOENT;
	return 0;
}

const struct passwd *
pw_locate(name)
	const char *name;
{
	struct	pw_file_entry	*pwf;

	if (! isopen) {
		errno = EINVAL;
		return 0;
	}
	for (pwf = __pwf_head;pwf != 0;pwf = pwf->pwf_next) {
		if (pwf->pwf_entry == 0)
			continue;

		if (strcmp (name, pwf->pwf_entry->pw_name) == 0) {
			pwf_cursor = pwf;
			return pwf->pwf_entry;
		}
	}
	errno = ENOENT;
	return 0;
}

int
pw_rewind()
{
	if (! isopen) {
		errno = EINVAL;
		return 0;
	}
	pwf_cursor = 0;
	return 1;
}

const struct passwd *
pw_next()
{
	if (! isopen) {
		errno = EINVAL;
		return 0;
	}
	if (pwf_cursor == 0)
		pwf_cursor = __pwf_head;
	else
		pwf_cursor = pwf_cursor->pwf_next;

	while (pwf_cursor) {
		if (pwf_cursor->pwf_entry)
			return pwf_cursor->pwf_entry;

		pwf_cursor = pwf_cursor->pwf_next;
	}
	return 0;
}
