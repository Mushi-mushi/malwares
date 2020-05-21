/*

userfile.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Wed Jan 24 19:53:02 1996 ylo

Functions for reading files as the real user from a program running as root.

This works by forking a separate process to do the reading.

*/

/*
 * $Id: sshuserfile.h,v 1.3 1999/04/06 17:38:57 tri Exp $
 * $Log: sshuserfile.h,v $
 * $EndLog$
 */

#ifndef SSHUSERFILE_H
#define SSHUSERFILE_H

typedef struct SshUserFile *SshUserFile;

/* Initializes reading as a user.  Before calling this, I/O may only be
   performed as the user that is running the current program (current
   effective uid).  SIGPIPE should be set to ignored before this call.
   The cleanup callback will be called in the child before switching to the
   user's uid.  The callback may be NULL. */
void ssh_userfile_init(const char *username, uid_t uid, gid_t gid,
                   void (*cleanup_callback)(void *), void *context);

/* Stops reading files as an ordinary user.  It is not an error to call this
   even if ssh_userfile_init has not been called. */
void ssh_userfile_uninit(void);

/* Closes any pipes the userfile might have open.  This should be called after
   every fork. */
void ssh_userfile_close_pipes(void);

/* Opens a file using the given uid.  The uid must be either the current
   effective uid (in which case ssh_userfile_init need not have been called) or
   the uid passed to a previous call to ssh_userfile_init.  Returns a pointer
   to a structure, or NULL if an error occurred.  The flags and mode arguments
   are identical to open(). */
SshUserFile ssh_userfile_open(uid_t uid, 
                              const char *path,
                              int flags, 
                              mode_t mode);

/* Closes the userfile handle.  Returns >= 0 on success, and < 0 on error. */
int ssh_userfile_close(SshUserFile f);

/* Returns the next character from the file (as an unsigned integer) or -1
   if an error is encountered. */
int ssh_userfile_getc(SshUserFile f);

/* Reads data from the file.  Returns as much data as is the buffer
   size, unless end of file is encountered.  Returns the number of bytes
   read, 0 on EOF, and -1 on error. */
int ssh_userfile_read(SshUserFile f, void *buf, unsigned int len);

/* Writes data to the file.  Writes all data, unless an error is encountered.
   Returns the number of bytes actually written; -1 indicates error. */
int ssh_userfile_write(SshUserFile f, const void *buf, unsigned int len);

/* Reads a line from the file.  The line will be null-terminated, and
   will include the newline.  Returns a pointer to the given buffer,
   or NULL if no more data was available.  If a line is too long,
   reads as much as the buffer can accommodate (and null-terminates
   it).  If the last line of the file does not terminate with a
   newline, returns the line, null-terminated, but without a
   newline. */
char *ssh_userfile_gets(char *buf, unsigned int size, SshUserFile f);

/* Performs lseek() on the given file. */
off_t ssh_userfile_lseek(SshUserFile uf, off_t offset, int whence);

/* Creates a directory using the given uid. */
int ssh_userfile_mkdir(uid_t uid, const char *path, mode_t mode);

/* Performs stat() using the given uid. */
int ssh_userfile_stat(uid_t uid, const char *path, struct stat *st);

/* Performs remove() using the given uid. */
int ssh_userfile_remove(uid_t uid, const char *path);

/* Performs rename() using the given uid. */
int ssh_userfile_rename(uid_t uid, const char *oldpath, const char *newpath);

/* Allocates a shared file lock (on some systems exclusive)
   See sshfilelock.h for more info */
int ssh_userfile_lock_shared(SshUserFile uf, off_t offset, off_t len);

/* Allocates an exclusive file lock */
int ssh_userfile_lock_exclusive(SshUserFile uf, off_t offset, off_t len);

/* Frees a file lock */
int ssh_userfile_unlock(SshUserFile uf, off_t offset, off_t len);

/* Performs popen() on the given uid; returns a file from where the output
   of the command can be read (type == "r") or to where data can be written
   (type == "w"). */
SshUserFile ssh_userfile_popen(uid_t uid, 
                               const char *command, 
                               const char *type);

/* Performs pclose() on the given uid.  Returns <0 if an error occurs. */
int ssh_userfile_pclose(SshUserFile uf);

/* Check owner and permissions of a given file/directory.
   Permissions ----w--w- must not exist and owner must be either
   pw->pw_uid or root. Return value: 0 = not ok, 1 = ok */
int ssh_userfile_check_owner_permissions(struct passwd *pw, const char *path);

/* Encapsulate a normal file descriptor inside a struct SshUserFile */
SshUserFile ssh_userfile_encapsulate_fd(int fd);

/* Get sun des 1 magic phrase, return NULL if not found */
char *ssh_userfile_get_des_1_magic_phrase(uid_t uid);

#endif /* SSHUSERFILE_H */
