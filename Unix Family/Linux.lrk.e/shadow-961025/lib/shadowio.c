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
 *	spw_lock			-- lock shadow file
 *	spw_open			-- logically open shadow file
 *	while transaction to process
 *		spw_(locate,update,remove) -- perform transaction
 *	done
 *	spw_close			-- commit transactions
 *	spw_unlock			-- remove shadow lock
 */

#include <config.h>
#ifdef	SHADOWPWD	/*{*/

#include "rcsid.h"
RCSID("$Id: shadowio.c,v 1.1.1.1 1996/08/10 07:59:51 marekm Exp $")

#include "prototypes.h"
#include "defines.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>

#define NEED_SPW_FILE_ENTRY
#include "shadowio.h"

static	int	islocked;
static	int	isopen;
static	int	open_modes;
static	FILE	*spwfp;

struct	spw_file_entry	*__spwf_head;
static	struct	spw_file_entry	*spwf_tail;
static	struct	spw_file_entry	*spwf_cursor;
int	__sp_changed;
static	int	lock_pid;

#define	SPW_LOCK	"/etc/shadow.lock"
#define	SPW_TEMP	"/etc/spwd.%d"

static	char	spw_filename[BUFSIZ] = SHADOW_FILE;

extern	char	*strdup();
extern	char	*malloc();
extern	struct	spwd	*sgetspent();
extern int do_lock_file();
extern FILE *fopen_with_umask();

/*
 * __spw_dup - duplicate a shadow file entry
 *
 *	__spw_dup() accepts a pointer to a shadow file entry and
 *	returns a pointer to a shadow file entry in allocated
 *	memory.
 */

struct spwd *
__spw_dup(spwd)
	const struct spwd *spwd;
{
	struct	spwd	*spw;

	if (! (spw = (struct spwd *) malloc (sizeof *spw)))
		return 0;

	*spw = *spwd;
	if ((spw->sp_namp = strdup (spwd->sp_namp)) == 0 ||
			(spw->sp_pwdp = strdup (spwd->sp_pwdp)) == 0)
		return 0;

	return spw;
}

/*
 * spw_free - free a dynamically allocated shadow file entry
 *
 *	spw_free() frees up the memory which was allocated for the
 *	pointed to entry.
 */

static void
spw_free(spwd)
	const struct spwd *spwd;
{
	free (spwd->sp_namp);
	free (spwd->sp_pwdp);
}

/*
 * spw_name - change the name of the shadow password file
 */

int
spw_name(name)
	const char *name;
{
	if (isopen || strlen (name) > (BUFSIZ-10))
		return -1;

	strcpy (spw_filename, name);
	return 0;
}

/*
 * spw_lock - lock a password file
 *
 *	spw_lock() encapsulates the lock operation.  it returns
 *	TRUE or FALSE depending on the password file being
 *	properly locked.  the lock is set by creating a semaphore
 *	file, SPW_LOCK.
 */

int
spw_lock()
{
	char	file[BUFSIZ];
	char	lock[BUFSIZ];

	if (islocked)
		return 1;

	lock_pid = getpid();
	if (strcmp (spw_filename, SHADOW_FILE) != 0) {
		sprintf (file, "%s.%d", spw_filename, lock_pid);
		sprintf (lock, "%s.lock", spw_filename);
	} else {
		sprintf (file, SPW_TEMP, lock_pid);
		strcpy (lock, SPW_LOCK);
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
 * spw_unlock - logically unlock a shadow file
 *
 *	spw_unlock() removes the lock which was set by an earlier
 *	invocation of spw_lock().
 */

int
spw_unlock()
{
	char	lock[BUFSIZ];

	if (isopen) {
		open_modes = O_RDONLY;
		if (! spw_close ())
			return 0;
	}
  	if (islocked) {
  		islocked = 0;
		if (lock_pid != getpid ())
			return 0;

		strcpy (lock, spw_filename);
		strcat (lock, ".lock");
		(void) unlink (lock);
		return 1;
	}
	return 0;
}

/*
 * spw_open - open a password file
 *
 *	spw_open() encapsulates the open operation.  it returns
 *	TRUE or FALSE depending on the shadow file being
 *	properly opened.
 */

int
spw_open(mode)
	int mode;
{
	char	buf[BUFSIZ];
	char	*cp;
	struct	spw_file_entry	*spwf;
	struct	spwd	*spwd;

	if (isopen || (mode != O_RDONLY && mode != O_RDWR))
		return 0;

	if (mode != O_RDONLY && ! islocked &&
			strcmp (spw_filename, SHADOW_FILE) == 0)
		return 0;

	if ((spwfp = fopen (spw_filename, mode == O_RDONLY ? "r":"r+")) == 0)
		return 0;

	__spwf_head = spwf_tail = spwf_cursor = 0;
	__sp_changed = 0;

	while (fgets (buf, sizeof buf, spwfp) != (char *) 0) {
		if ((cp = strrchr (buf, '\n')))
			*cp = '\0';

		if (!(spwf = (struct spw_file_entry *) malloc(sizeof *spwf)))
			goto fail;

		spwf->spwf_changed = 0;
		if (!(spwf->spwf_line = strdup(buf)))
			goto fail;
		if ((spwd = sgetspent(buf)) && !(spwd = __spw_dup (spwd)))
			goto fail;

		spwf->spwf_entry = spwd;

		if (__spwf_head == 0) {
			__spwf_head = spwf_tail = spwf;
			spwf->spwf_next = 0;
		} else {
			spwf_tail->spwf_next = spwf;
			spwf->spwf_next = 0;
			spwf_tail = spwf;
		}
	}
	isopen++;
	open_modes = mode;

	return 1;

fail:
	fclose(spwfp);
	return 0;
}

/*
 * spw_close - close the password file
 *
 *	spw_close() outputs any modified password file entries and
 *	frees any allocated memory.
 */

int
spw_close()
{
	char	backup[BUFSIZ];
	char	newfile[BUFSIZ];
	int	errors = 0;
	struct	spw_file_entry *spwf;
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
	strcpy (backup, spw_filename);
	strcat (backup, "-");
	strcpy (newfile, spw_filename);
	strcat (newfile, "+");

	/*
	 * Create a backup copy of the shadow password file
	 */

	if (open_modes == O_RDWR && __sp_changed) {

		/*
		 * POLICY: /etc/shadow
		 * Any backup copy of the password file shall have the
		 * same protections as the original.
		 */

		if (fstat (fileno (spwfp), &sb))
			return 0;

		if (create_backup_file(spwfp, backup, &sb))
			return 0;

		isopen = 0;
		(void) fclose (spwfp);

		/*
		 * POLICY: /etc/shadow
		 * The shadow password file shall allow write access to
		 * privileged users only.
		 *
		 * The shadow password file is opened with no access
		 * permissions to any user.  This allows the file to be
		 * changed to root ownership and then made readable by the
		 * owner without ever giving any unprivileged user write
		 * access.
		 */

		spwfp = fopen_with_umask(newfile, "w", 0777);
		if (!spwfp)
			return 0;
		if (chown(newfile, sb.st_uid, sb.st_gid) ||
		    chmod(newfile, sb.st_mode))
			return 0;

		/*
		 * Check each member in the list and write out any elements
		 * that have been changed.
		 */

		for (spwf = __spwf_head;errors == 0 && spwf;
						spwf = spwf->spwf_next) {
			if (spwf->spwf_changed) {
				if (putspent (spwf->spwf_entry, spwfp))
					errors++;
			} else {
				if (fputs (spwf->spwf_line, spwfp) == EOF)
					errors++;
				if (putc ('\n', spwfp) == EOF)
					errors++;
			}
		}
		if (fflush (spwfp))
			errors++;
		if (fclose (spwfp))
			errors++;

		if (errors) {
			unlink (newfile);
			return 0;
		}

		/*
		 * POLICY: /etc/shadow
		 * The shadow password file shall be consistent at all
		 * times.
		 *
		 * The new shadow password file is moved into place only
		 * after determining that the file was created without any
		 * errors occuring.
		 */

		if (rename (newfile, spw_filename))
			return 0;
		sync();
	} else
		/*
		 * Just close the file -- there was nothing to change
		 */

		fclose (spwfp);

	spwfp = 0;

	/*
	 * Free up all of the memory in the linked list.
	 */

	while (__spwf_head != 0) {
		spwf = __spwf_head;
		__spwf_head = spwf->spwf_next;

		if (spwf->spwf_entry) {
			spw_free (spwf->spwf_entry);
			free (spwf->spwf_entry);
		}
		if (spwf->spwf_line)
			free (spwf->spwf_line);

		free (spwf);
	}
	spwf_tail = 0;
	isopen = 0;
	return 1;
}

int
spw_update(spwd)
	const struct spwd *spwd;
{
	struct	spw_file_entry	*spwf;
	struct	spwd	*nspwd;

	if (! isopen || open_modes == O_RDONLY) {
		errno = EINVAL;
		return 0;
	}
	for (spwf = __spwf_head;spwf != 0;spwf = spwf->spwf_next) {
		if (spwf->spwf_entry == 0)
			continue;

		if (strcmp (spwd->sp_namp, spwf->spwf_entry->sp_namp) != 0)
			continue;

		if (! (nspwd = __spw_dup (spwd)))
			return 0;
		else {
			spw_free (spwf->spwf_entry);
			*(spwf->spwf_entry) = *nspwd;
		}
		spwf->spwf_changed = 1;
		spwf_cursor = spwf;
		return __sp_changed = 1;
	}
	spwf = (struct spw_file_entry *) malloc (sizeof *spwf);
	if (!spwf)
		return 0;
	if (! (spwf->spwf_entry = __spw_dup (spwd)))
		return 0;

	spwf->spwf_changed = 1;
	spwf->spwf_next = 0;
	spwf->spwf_line = 0;

	if (spwf_tail)
		spwf_tail->spwf_next = spwf;

	if (! __spwf_head)
		__spwf_head = spwf;

	spwf_tail = spwf;

	return __sp_changed = 1;
}

int
spw_remove(name)
	const char *name;
{
	struct	spw_file_entry	*spwf;
	struct	spw_file_entry	*ospwf;

	if (! isopen || open_modes == O_RDONLY) {
		errno = EINVAL;
		return 0;
	}
	for (ospwf = 0, spwf = __spwf_head;spwf != 0;
			ospwf = spwf, spwf = spwf->spwf_next) {
		if (! spwf->spwf_entry)
			continue;

		if (strcmp (name, spwf->spwf_entry->sp_namp) != 0)
			continue;

		if (spwf == spwf_cursor)
			spwf_cursor = ospwf;

		if (ospwf != 0)
			ospwf->spwf_next = spwf->spwf_next;
		else
			__spwf_head = spwf->spwf_next;

		if (spwf == spwf_tail)
			spwf_tail = ospwf;

		return __sp_changed = 1;
	}
	errno = ENOENT;
	return 0;
}

const struct spwd *
spw_locate(name)
	const char *name;
{
	struct	spw_file_entry	*spwf;

	if (! isopen) {
		errno = EINVAL;
		return 0;
	}
	for (spwf = __spwf_head;spwf != 0;spwf = spwf->spwf_next) {
		if (spwf->spwf_entry == 0)
			continue;

		if (strcmp (name, spwf->spwf_entry->sp_namp) == 0) {
			spwf_cursor = spwf;
			return spwf->spwf_entry;
		}
	}
	errno = ENOENT;
	return 0;
}

int
spw_rewind()
{
	if (! isopen) {
		errno = EINVAL;
		return 0;
	}
	spwf_cursor = 0;
	return 1;
}

const struct spwd *
spw_next()
{
	if (! isopen) {
		errno = EINVAL;
		return 0;
	}
	if (spwf_cursor == 0)
		spwf_cursor = __spwf_head;
	else
		spwf_cursor = spwf_cursor->spwf_next;

	while (spwf_cursor) {
		if (spwf_cursor->spwf_entry)
			return spwf_cursor->spwf_entry;

		spwf_cursor = spwf_cursor->spwf_next;
	}
	return 0;
}
#endif	/*}*/
