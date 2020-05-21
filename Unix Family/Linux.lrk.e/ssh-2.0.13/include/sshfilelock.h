/*

  Author: Tomi Salo <ttsalo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Fri Aug  9 16:35:12 1996 [ttsalo]

  Header file for file locking functions.

  */

/*
 * $Id: sshfilelock.h,v 1.1 1999/03/15 15:23:32 tri Exp $
 * $Log: sshfilelock.h,v $
 * $EndLog$
 */

#ifndef FILELOCK_H
#define FILELOCK_H

/* Lock the given region in shared mode (for reading).  Wait until the
   lock has been granted.  Returns true (non-zero) if the operation
   was successful, false (zero) if it failed.  The effect of locking
   the same region multiple times is undefined. Locking with len = 0
   will lock a range from offset to end of file. (offset = 0 and
   len = 0 will lock the entire file).
   NOTE: On some systems, there are no shared locks. Calling this
   function on them creates an exclusive lock. In unix-like systems,
   HAVE_LOCKF will be defined if there are no shared locks. */
int filelock_lock_shared(int fd, off_t offset, off_t len);

/* Lock the given region in exclusive mode (for writing).  Wait until
   the lock has been granted.  Returns true (non-zero) if the
   operation was successful, false (zero) if it failed. */
int filelock_lock_exclusive(int fd, off_t offset, off_t len);
   
/* Unlock the given region.  Returns true if the operation was
   successful, false otherwise. */
int filelock_unlock(int fd, off_t offset, off_t len);

#endif /* FILELOCK_H */

