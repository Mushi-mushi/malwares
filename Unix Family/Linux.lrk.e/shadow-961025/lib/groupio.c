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
 *	This file implements a transaction oriented group database
 *	library.  The group file is updated one entry at a time.
 *	After each transaction the file must be logically closed and
 *	transferred to the existing group file.  The sequence of
 *	events is
 *
 *	gr_lock				-- lock group file
 *	gr_open				-- logically open group file
 *	while transaction to process
 *		gr_(locate,update,remove) -- perform transaction
 *	done
 *	gr_close			-- commit transactions
 *	gr_unlock			-- remove group lock
 */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: groupio.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <signal.h>
#include "prototypes.h"
#include "defines.h"

#define NEED_GR_FILE_ENTRY
#include "groupio.h"

static	int	islocked;
static	int	isopen;
static	int	open_modes;
static	FILE	*grfp;

struct	gr_file_entry	*__grf_head;
static	struct	gr_file_entry	*grf_tail;
static	struct	gr_file_entry	*grf_cursor;
int	__gr_changed;
static	int	lock_pid;

#define	GR_LOCK	"/etc/group.lock"
#define	GR_TEMP "/etc/grp.%d"

static	char	gr_filename[BUFSIZ] = GROUP_FILE;

extern	char	*strdup();
extern	struct	group	*sgetgrent();
extern	char	*malloc();
extern	char	*fgetsx();
extern int do_lock_file();
extern FILE *fopen_with_umask();

/*
 * __gr_dup - duplicate a group file entry
 *
 *	__gr_dup() accepts a pointer to a group file entry and
 *	returns a pointer to a group file entry in allocated
 *	memory.
 */

struct group *
__gr_dup (grent)
	const struct group *grent;
{
	struct	group	*gr;
	int	i;

	if (! (gr = (struct group *) malloc (sizeof *gr)))
		return 0;

	if ((gr->gr_name = strdup (grent->gr_name)) == 0 ||
			(gr->gr_passwd = strdup (grent->gr_passwd)) == 0)
		return 0;

	for (i = 0;grent->gr_mem[i];i++)
		;

	if (! (gr->gr_mem = (char **) malloc (sizeof (char *) * (i + 1))))
		return 0;
	for (i = 0;grent->gr_mem[i];i++)
		if (! (gr->gr_mem[i] = strdup (grent->gr_mem[i])))
			return 0;

	gr->gr_mem[i] = 0;
	gr->gr_gid = grent->gr_gid;

	return gr;
}

/*
 * gr_free - free a dynamically allocated group file entry
 *
 *	gr_free() frees up the memory which was allocated for the
 *	pointed to entry.
 */

static void
gr_free (grent)
	const struct group *grent;
{
	int	i;

	free (grent->gr_name);
	free (grent->gr_passwd);

	for (i = 0;grent->gr_mem[i];i++)
		free (grent->gr_mem[i]);

	free ((char *) grent->gr_mem);
}

/*
 * gr_name - change the name of the group file
 */

int
gr_name (name)
	const char *name;
{
	if (isopen || (int) strlen (name) > (BUFSIZ-10))
		return -1;

	strcpy (gr_filename, name);
	return 0;
}

/*
 * gr_lock - lock a group file
 *
 *	gr_lock() encapsulates the lock operation.  it returns
 *	TRUE or FALSE depending on the group file being
 *	properly locked.  the lock is set by creating a semaphore
 *	file, GR_LOCK.
 */

int
gr_lock ()
{
	char	file[BUFSIZ];

	if (islocked)
		return 1;

	if (strcmp (gr_filename, GROUP_FILE) != 0)
		return 0;

	sprintf (file, GR_TEMP, lock_pid = getpid ());

	/*
	 * The rest is common to all four files (see commonio.c).  --marekm
	 */

	if (do_lock_file(file, GR_LOCK)) {
		islocked = 1;
		return 1;
	}

	return 0;
}

/*
 * gr_unlock - logically unlock a group file
 *
 *	gr_unlock() removes the lock which was set by an earlier
 *	invocation of gr_lock().
 */

int
gr_unlock ()
{
	if (isopen) {
		open_modes = O_RDONLY;
		if (! gr_close ())
			return 0;
	}
	if (islocked) {
		islocked = 0;
		if (lock_pid != getpid ())
			return 0;

		(void) unlink (GR_LOCK);
		return 1;
	}
	return 0;
}

/*
 * gr_open - open a group file
 *
 *	gr_open() encapsulates the open operation.  it returns
 *	TRUE or FALSE depending on the group file being
 *	properly opened.
 */

int
gr_open(mode)
	int mode;
{
	char	buf[8192];
	char	*cp;
	struct	gr_file_entry	*grf;
	struct	group	*grent;

	if (isopen || (mode != O_RDONLY && mode != O_RDWR))
		return 0;

	if (mode != O_RDONLY && ! islocked &&
			strcmp (gr_filename, GROUP_FILE) == 0)
		return 0;

	if ((grfp = fopen (gr_filename, mode == O_RDONLY ? "r":"r+")) == 0)
		return 0;

	__grf_head = grf_tail = grf_cursor = 0;
	__gr_changed = 0;

	while (fgetsx (buf, sizeof buf, grfp) != (char *) 0) {
		if ((cp = strrchr (buf, '\n')))
			*cp = '\0';

		if (! (grf = (struct gr_file_entry *) malloc (sizeof *grf)))
			goto fail;

		grf->grf_changed = 0;
		if (! (grf->grf_line = strdup (buf)))
			goto fail;
		if ((grent = sgetgrent (buf)) && ! (grent = __gr_dup (grent)))
			goto fail;

		grf->grf_entry = grent;

		if (__grf_head == 0) {
			__grf_head = grf_tail = grf;
			grf->grf_next = 0;
		} else {
			grf_tail->grf_next = grf;
			grf->grf_next = 0;
			grf_tail = grf;
		}
	}
	isopen++;
	open_modes = mode;

	return 1;

fail:
	fclose(grfp);
	return 0;
}

/*
 * gr_close - close the group file
 *
 *	gr_close() outputs any modified group file entries and
 *	frees any allocated memory.
 */

int
gr_close ()
{
	char	backup[BUFSIZ];
	char	newfile[BUFSIZ];
	int	errors = 0;
	struct	gr_file_entry *grf;
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
	strcpy (backup, gr_filename);
	strcat (backup, "-");
	strcpy (newfile, gr_filename);
	strcat (newfile, "+");

	/*
	 * Create a backup copy of the group file.
	 */

	if (open_modes == O_RDWR && __gr_changed) {

		/*
		 * POLICY: /etc/group
		 * Any backup copy of the group file shall have the
		 * same protections as the original.
		 *
		 * Get the permissions from the old file and apply them
		 * to the backup file.
		 */

		if (fstat (fileno (grfp), &sb))
			return 0;

		if (create_backup_file(grfp, backup, &sb))
			return 0;

		isopen = 0;
		(void) fclose (grfp);

		/*
		 * POLICY: /etc/group
		 * The group file shall allow write access to
		 * privileged users only.  The group file shall allow
		 * read access to all users.
		 *
		 * The group file is opened with no access permissions
		 * to any user.  This allows the file to be changed to
		 * root ownership and then made readable by all users
		 * without ever giving any unprivileged user write access.
		 */

		grfp = fopen_with_umask(newfile, "w", 0777);
		if (!grfp)
			return 0;
		if (chown(newfile, sb.st_uid, sb.st_gid) ||
		    chmod(newfile, sb.st_mode))
			return 0;

		/*
		 * Check each member in the list and write out any elements
		 * that have been changed.
		 */

		for (grf = __grf_head;! errors && grf;grf = grf->grf_next) {
			if (grf->grf_changed) {
				if (putgrent (grf->grf_entry, grfp))
					errors++;
			} else {
				if (fputsx (grf->grf_line, grfp))
					errors++;

				if (putc ('\n', grfp) == EOF)
					errors++;
			}
		}
		if (fflush (grfp))
			errors++;
		if (fclose (grfp))
			errors++;

		if (errors) {
			unlink (newfile);
			return 0;
		}

		/*
		 * POLICY: /etc/group
		 * The group file shall be consistent at all times.
		 *
		 * The new group file is moved into place only after
		 * determining that the file was created without any
		 * errors occuring.
		 */

		if (rename (newfile, gr_filename))
			return 0;
		sync();
	} else
		/*
		 * Just close the file -- there was nothing to change
		 */

		fclose (grfp);

	grfp = 0;

	/*
	 * Free up all of the memory in the linked list.
	 */

	while (__grf_head != 0) {
		grf = __grf_head;
		__grf_head = grf->grf_next;

		if (grf->grf_entry) {
			gr_free (grf->grf_entry);
			free ((char *) grf->grf_entry);
		}
		if (grf->grf_line)
			free (grf->grf_line);

		free ((char *) grf);
	}
	grf_tail = 0;
	isopen = 0;
	return 1;
}

int
gr_update (grent)
	const struct group *grent;
{
	struct	gr_file_entry	*grf;
	struct	group	*ngr;

	if (! isopen || open_modes == O_RDONLY) {
		errno = EINVAL;
		return 0;
	}
	for (grf = __grf_head;grf != 0;grf = grf->grf_next) {
		if (grf->grf_entry == 0)
			continue;

		if (strcmp (grent->gr_name, grf->grf_entry->gr_name) != 0)
			continue;

		if (! (ngr = __gr_dup (grent)))
			return 0;

		gr_free (grf->grf_entry);
		*(grf->grf_entry) = *ngr;

		grf->grf_changed = 1;
		grf_cursor = grf;
		return __gr_changed = 1;
	}
	if (! (grf = (struct gr_file_entry *) malloc (sizeof *grf)))
		return 0;
	if (! (grf->grf_entry = __gr_dup (grent)))
		return 0;

	grf->grf_changed = 1;
	grf->grf_next = 0;
	grf->grf_line = 0;

	if (grf_tail)
		grf_tail->grf_next = grf;

	if (! __grf_head)
		__grf_head = grf;

	grf_tail = grf;

	return __gr_changed = 1;
}

int
gr_remove (name)
	const char *name;
{
	struct	gr_file_entry	*grf;
	struct	gr_file_entry	*ogrf;

	if (! isopen || open_modes == O_RDONLY) {
		errno = EINVAL;
		return 0;
	}
	for (ogrf = 0, grf = __grf_head;grf != 0;
			ogrf = grf, grf = grf->grf_next) {
		if (! grf->grf_entry)
			continue;

		if (strcmp (name, grf->grf_entry->gr_name) != 0)
			continue;

		if (grf == grf_cursor)
			grf_cursor = ogrf;

		if (ogrf != 0)
			ogrf->grf_next = grf->grf_next;
		else
			__grf_head = grf->grf_next;

		if (grf == grf_tail)
			grf_tail = ogrf;

		return __gr_changed = 1;
	}
	errno = ENOENT;
	return 0;
}

const struct group *
gr_locate (name)
	const char *name;
{
	struct	gr_file_entry	*grf;

	if (! isopen) {
		errno = EINVAL;
		return 0;
	}
	for (grf = __grf_head;grf != 0;grf = grf->grf_next) {
		if (grf->grf_entry == 0)
			continue;

		if (strcmp (name, grf->grf_entry->gr_name) == 0) {
			grf_cursor = grf;
			return grf->grf_entry;
		}
	}
	errno = ENOENT;
	return 0;
}

int
gr_rewind ()
{
	if (! isopen) {
		errno = EINVAL;
		return 0;
	}
	grf_cursor = 0;
	return 1;
}

const struct group *
gr_next ()
{
	if (! isopen) {
		errno = EINVAL;
		return 0;
	}
	if (grf_cursor == 0)
		grf_cursor = __grf_head;
	else
		grf_cursor = grf_cursor->grf_next;

	while (grf_cursor) {
		if (grf_cursor->grf_entry)
			return grf_cursor->grf_entry;

		grf_cursor = grf_cursor->grf_next;
	}
	return 0;
}
