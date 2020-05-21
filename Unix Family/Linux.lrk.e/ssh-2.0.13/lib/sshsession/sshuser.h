/*

sshuser.h

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

Manipulating user information in SSH server (mostly password validation).

*/

#ifndef SSHUSER_H
#define SSHUSER_H

typedef struct SshUserRec *SshUser;

/* Allocates and initializes a context for the user.  The context is used
   to cache information about the particular user.  Returns NULL if the
   user does not exist. If `user' is NULL, use getuid() to get the current
   user. 'privileged' should only be set, when the process is supposedly
   run with root privileges. If it is FALSE, ssh_user_initialize doesn't
   try to look for shadow passwords etc.*/
SshUser ssh_user_initialize(const char *user, Boolean privileged);

#ifndef WINDOWS
/* As above, but we explicitely want to use uid (instead of name). */
SshUser ssh_user_initialize_with_uid(uid_t uid, Boolean privileged);
#endif /* WINDOWS */
/* Frees information about the user.  If ``undo'' is TRUE, undoes any
   cached state related to e.g. Kerberos and Secure RPC.  Returns
   FALSE if undo was requested, but was unable to undo everything; otherwise
   returns TRUE. */
Boolean ssh_user_free(SshUser uc, Boolean undo);

/* Returns TRUE if logging in as the specified user is allowed. */
Boolean ssh_user_login_is_allowed(SshUser uc);

/* Returns TRUE if login is allowed with the given local password. */
#ifdef HAVE_SIA
Boolean ssh_user_validate_local_password(SshUser uc,
                                         const char *password,
                                         const char *remote_host);
#else /* HAVE_SIA */
Boolean ssh_user_validate_local_password(SshUser uc,
                                         const char *password);
#endif /* HAVE_SIA */


/* Returns TRUE if the user's password needs to be changed. */
Boolean ssh_user_password_must_be_changed(SshUser uc,
                                          char **prompt_return);

/* Changes the user's password.  Returns TRUE if the change was successful,
   FALSE if the change failed. */
Boolean ssh_user_change_password(SshUser uc,
                                 const char *old_password,
                                 const char *new_password);

/* Tries to log in with the given kerberos password.  If successful,
   obtains a kerberos ticket for the user, and the ticket will be used
   for further access by the current process.  Returns TRUE on success. */
Boolean ssh_user_validate_kerberos_password(SshUser uc,
                                            const char *password);

/* Tries to login with the given secure rpc password.  If successful,
   obtains a secure rpc key from the key server, and starts using that
   key for further communication.  Returns TRUE on success. */
Boolean ssh_user_validate_secure_rpc_password(SshUser uc,
                                              const char *password);

/* Switches the current process to the permissions and privileges of the
   specified user.  The process should not hold any confidential information
   at this point.  This returns FALSE if switching to the given user failed
   for some reason.  This closes all open file descriptors.
   The return value of this function MUST BE CHECKED! */
Boolean ssh_user_become(SshUser uc);

#ifdef HAVE_SIA
/* Last chance to finish anything that ssh_user_become() left undone.  The
   difference between the two functions is that ssh_user_become() is called
   before the user's environment is set, while we're called after.

   Switches the current process to the permissions and privileges of the
   specified user.  The process should not hold any confidential information
   at this point.  This returns FALSE if switching to the given user failed
   for some reason.  The return value of this function MUST BE CHECKED! */
Boolean ssh_user_become_real(SshUser uc,
                             const char *remote_host,
                             const char *ttyname);
#endif /* HAVE_SIA */

/* Returns the login name of the user. */
const char *ssh_user_name(SshUser uc);

#ifndef WINDOWS

/* Returns the uid of the user.  This is unix-specific. */
uid_t ssh_user_uid(SshUser uc);

/* Returns the gid of the user.  This is unix-specific. */
gid_t ssh_user_gid(SshUser uc);

/* Returns the user's home directory.  This is unix-specific. */
const char *ssh_user_dir(SshUser uc);

/* Returns the shell of the user.  This is unix-specific. */
const char *ssh_user_shell(SshUser uc);

#endif /* WINDOWS */

/* Returns the time when the user last logged in, and name of the host
   from which the user logged in from.  Returns 0 if the information
   is not available.  This must be called before
   ssh_user_record_login.  The host the user logged in from will be
   returned in hostbuf. */
SshTime ssh_user_get_last_login_time(SshUser user,
                                     char *hostbuf,
                                     unsigned int hostbufsize);

/* Records that the user has logged in.  I wish these parts of
   operating systems were more standardized.  This code normally needs
   to be run as root.
      user    information about the user that logged in (NULL on logout)
      pid     process id of user's login shell
      ttyname name of the user's tty (slave side)
      host    name of the host the user logged in from (ip if host not known)
      ip      ip address of the host the user logged in from. */

void ssh_user_record_login(SshUser user, pid_t pid, const char *ttyname,
                           const char *host, const char *ip);

/* Records that the user on the tty has logged out. */
void ssh_user_record_logout(pid_t pid, const char *ttyname);

#endif /* SSHUSER_H */
