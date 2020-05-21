/*

sshunixptystream.h

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

*/

/*
 * $Id: sshunixptystream.c,v 1.3 1999/02/16 12:50:34 sjl Exp $
 * $Log: sshunixptystream.c,v $
 * $EndLog$
 */

#include "sshsessionincludes.h"
#include "sshunixptystream.h"
#include "pty-int.h"
#include "sshunixfdstream.h"
#include "sshtimeouts.h"
#include "sigchld.h"

#define SSH_DEBUG_MODULE "SshUnixPtyStream"

typedef enum {
  SSH_PTY_NORMAL,
  SSH_PTY_BSD_PACKET
} SshPtyMode;

typedef struct {
  pid_t pid;
  int ptyfd;
  char namebuf[SSH_PTY_NAME_SIZE];
  Boolean xonxoff; /* standard xon/xoff flow control on */
  SshStream master;
  SshPtyMode mode;
  gid_t tty_gid;

  SshStreamCallback callback;
  void *callback_context;
  
  Boolean status_returned;
  int exit_status;
} *PtyStream;

extern const SshStreamMethodsTable ssh_pty_methods;

/* This callback is called after the parent has exited; this will
   call the application callback so that it gets notified of the EOF
   condition.  This is called as a generated event; the event is cancelled if
   the context is destroyed before the event is delivered. */

void ssh_pty_sigchld_do_callback(void *context)
{
  PtyStream pty = (PtyStream)context;

  ssh_debug("ssh_pty_sigchld_do_callback");
  if (pty->callback)
    (*pty->callback)(SSH_STREAM_INPUT_AVAILABLE, pty->callback_context);
}

/* This callback is called when our child process dies.  We'll record the
   exist status and cause the callback to be called. */

void ssh_pty_sigchld_handler(pid_t pid, int status, void *context)
{
  PtyStream pty = (PtyStream)context;

  ssh_debug("ssh_pty_sigchld_handler: pid %d status %d", (int)pid, status);

  /* Sanity checks... */
  if (pty->pid != pid)
    ssh_fatal("ssh_pty_sigchld_handler: pid mismatch %d vs. %d",
              (int)pid, (int)pty->pid);
  if (pty->status_returned)
    ssh_fatal("ssh_pty_sigchld_handler: status already returned");

  /* Record the exit status. */
  pty->status_returned = TRUE;
  pty->exit_status = status;

  /* Schedule a callback from the bottom of the event loop.  Note that if
     the stream is destroyed, before the event is delivered, we'll cancel
     the event before destroying the context. */
  ssh_register_timeout(0L, 0L, ssh_pty_sigchld_do_callback, (void *)pty);
}

/* Allocates a pty, forks the current process, and returns separately
   in parent and child.  Makes the pty the controlling tty and stdio
   in the child; makes the child a process group leader.  The pty is
   freed when the master side is closed.  It is guaranteed that when
   the child exits, EOF will be received from the stream.  This
   function is unix-specific, and needs to be called as root (calling
   as another user may work partially on some systems).  This will
   arrange for the pty to be cleanly freed when the parent-side stream
   is closed.  The parent side must remain root until is has closed
   the stream.  A stream for the pty will be returned only on master side. */

SshPtyStatus ssh_pty_allocate_and_fork(uid_t owner_uid, gid_t owner_gid,
                                       char *namebuf,
                                       SshStream *master_return)
{
  int ptyfd, ttyfd;
  pid_t pid;
  PtyStream pty;
  struct group *grp;
  gid_t tty_gid;
  mode_t tty_mode;
  
  if (!ssh_pty_internal_allocate(&ptyfd, &ttyfd, namebuf))
    return SSH_PTY_ERROR;

  /* Determine the group to make the owner of the tty. */
#ifdef TTY_GROUP
  grp = getgrnam(TTY_GROUP);
#else /* TTY_GROUP */
  grp = getgrnam("tty");
#endif /* TTY_GROUP */
  if (grp)
    {
      tty_gid = grp->gr_gid;
      tty_mode = S_IRUSR|S_IWUSR|S_IWGRP;
    }
  else
    {
      tty_gid = owner_gid;
      tty_mode = S_IRUSR|S_IWUSR|S_IWGRP|S_IWOTH;
    }
  
  /* Change ownership of the tty. */
  (void)chown(namebuf, owner_uid, tty_gid);
  (void)chmod(namebuf, tty_mode);

  /* Initialize SIGCHLD handling.  This will ensure the SIGCHLD won't get
     delivered until we register the handler for the new process below. */
  ssh_sigchld_initialize();
  
  /* Fork a child process. */
  pid = fork();
  if (pid < 0)
    {
      ssh_warning("Fork failed: %s", strerror(errno));
      /* XXX should we do something to free it? */
      return SSH_PTY_ERROR;
    }

  /* The remaining processing depends on whether we are the parent or
     the child. */
  if (pid == 0)
    {
      /* Child process. */
      close(ptyfd);

      /* Make it process group leader. */
#ifdef HAVE_SETSID
#ifdef ultrix
      setpgrp(0, 0);
#else /* ultrix */
      if (setsid() < 0)
        ssh_warning("setsid: %.100s", strerror(errno));
#endif /* ultrix */
#endif /* HAVE_SETSID */

      /* Set controlling tty. */
      ssh_pty_internal_make_ctty(&ttyfd, namebuf);

      /* Redirect stdin from the pseudo tty. */
      if (dup2(ttyfd, fileno(stdin)) < 0)
        ssh_warning("dup2 stdin failed: %.100s", strerror(errno));

      /* Redirect stdout to the pseudo tty. */
      if (dup2(ttyfd, fileno(stdout)) < 0)
        ssh_warning("dup2 stdin failed: %.100s", strerror(errno));

      /* Redirect stderr to the pseudo tty. */
      if (dup2(ttyfd, fileno(stderr)) < 0)
        ssh_warning("dup2 stdin failed: %.100s", strerror(errno));

      /* Close the extra descriptor for the pseudo tty. */
      close(ttyfd);

      *master_return = NULL;
      return SSH_PTY_CHILD_OK;
    }

  /* Parent */
  pty = ssh_xcalloc(sizeof(*pty), 1);
  pty->pid = pid;
  pty->ptyfd = ptyfd;
  pty->xonxoff = FALSE;
  strncpy(pty->namebuf, namebuf, sizeof(pty->namebuf));
  pty->tty_gid = tty_gid;
  pty->callback = NULL;
  pty->callback_context = NULL;
  pty->status_returned = FALSE;
  pty->exit_status = -1;
  close(ttyfd);

  /* Set the pty to the appropriate mode. */
  /* XXX */
  pty->mode = SSH_PTY_NORMAL;

  /* Register a handler for SIGCHLD for our new child.  The handler is used
     to ensure that we properly send eof from the pty stream upon
     termination even if EOF does not get properly transmitted through the
     pty (as on HPUX; also some other systems do not deliver it reliably). */
  ssh_sigchld_register(pid, ssh_pty_sigchld_handler, (void *)pty);
  
  /* Wrap the master fd into a stream. */
  pty->master = ssh_stream_fd_wrap(ptyfd, TRUE);

  /* Create and return the pty stream. */
  *master_return = ssh_stream_create(&ssh_pty_methods, (void *)pty);
  return SSH_PTY_PARENT_OK;
}  

/* Returns the process id of the child process. */

pid_t ssh_pty_get_pid(SshStream stream)
{
  PtyStream pty;
  if (ssh_stream_get_methods(stream) != (void *)&ssh_pty_methods)
    return FALSE;
  pty = ssh_stream_get_context(stream);
  return pty->pid;
}

/* Retrieves the name of the pty.  Returns TRUE on success, FALSE if the stream
   is not a pty stream.  This can be used on both parent and child side. */

Boolean ssh_pty_get_name(SshStream stream, char *buf, size_t buflen)
{
  PtyStream pty;
  if (ssh_stream_get_methods(stream) != (void *)&ssh_pty_methods)
    return FALSE;
  pty = ssh_stream_get_context(stream);
  strncpy(buf, pty->namebuf, buflen);
  if (buflen > 0)
    buf[buflen - 1] = '\0';
  return TRUE;
}

/* Returns the exit status of the process running on the other side of the
   pty.  It is illegal to call this before EOF has been received from
   the pty stream.  However, it is guaranteed that once EOF has been received,
   this will return a valid value.  The returned value is either the exit
   status of the process (>= 0) or the negated signal number that caused
   it to terminate (< 0). */

int ssh_pty_get_exit_status(SshStream stream)
{
  PtyStream pty;
  if (ssh_stream_get_methods(stream) != (void *)&ssh_pty_methods)
    return FALSE;
  pty = ssh_stream_get_context(stream);

  if (!pty->status_returned)
    ssh_fatal("ssh_pty_get_exit_status called before the child has exited.");

  return pty->exit_status;
}

/* Changes window size on the pty.  This function can only be used on the
   parent side. */

void ssh_pty_change_window_size(SshStream stream,
                                unsigned int width_chars,
                                unsigned int height_chars,
                                unsigned int width_pixels,
                                unsigned int height_pixels)
{
  PtyStream pty;
  if (ssh_stream_get_methods(stream) != (void *)&ssh_pty_methods)
    ssh_fatal("ssh_pty_change_window_size: not a pty stream");
  pty = ssh_stream_get_context(stream);
#if defined(SIGWINCH) && defined(TIOCSWINSZ)
  {
    struct winsize w;
    w.ws_row = height_chars;
    w.ws_col = width_chars;
    w.ws_xpixel = width_pixels;
    w.ws_ypixel = height_pixels;
    (void)ioctl(pty->ptyfd, TIOCSWINSZ, &w);
  }
#endif /* SIGWINCH && TIOCSWINSZ */
}

/* Returns the file descriptor for the pty. This should be used only
   for things that don't change this stream, and care should be taken
   that nothing is destroyed.*/

int ssh_pty_get_fd(SshStream stream)
{
  PtyStream pty;
  SSH_ASSERT(stream);
  if (ssh_stream_get_methods(stream) != (void *)&ssh_pty_methods)
    ssh_fatal("ssh_pty_change_window_size: not a pty stream");
  pty = ssh_stream_get_context(stream);

  return pty->ptyfd;  
}

/* Returns true if the pty is in a mode with C-S/C-Q flow control enabled.
   This can be used to determine whether a client can perform local flow
   control.  This function can only be called for the parent side.
   Note that there is no special notification when the status changes.
   However, a SSH_STREAM_INPUT_AVAILABLE notification will be generated
   whenever there is a status change, even if no real data is available.
   Thus, the read callback handler should read this state and check for change
   before returning.  This returns TRUE if standard C-S/C-Q flow control
   is enabled, and FALSE otherwise. */

Boolean ssh_pty_standard_flow_control(SshStream stream)
{
  PtyStream pty;
  if (ssh_stream_get_methods(stream) != (void *)&ssh_pty_methods)
    return FALSE;
  pty = ssh_stream_get_context(stream);
  return pty->xonxoff;
}

/* Implements a read from the pty stream.  This only returns data; if the
   pty is in packet mode, this strips any packet mode stuff from it. */

int ssh_pty_stream_read(void *context, unsigned char *buf, size_t size)
{
  PtyStream pty = (PtyStream)context;
  int len;

  /* If we have already closed master (in output_eof), return EOF. */
  if (pty->master == NULL)
    return pty->status_returned ? 0 : -1;

  switch (pty->mode)
    {
    case SSH_PTY_NORMAL:
      len = ssh_stream_read(pty->master, buf, size);

      /* Convert the return status to EOF if the child has already
         exited.  Note that we'll want to keep reading as long as
         there is data available before returning the EOF, as the
         SIGCHLD handler might be called before all data is read. */
      if (len < 0 && pty->status_returned)
        {
          ssh_debug("ssh_pty_stream_read: faking eof after sigchld");
          len = 0;
        }
      else
        if (len == 0 && !pty->status_returned)
          {
            /* We got real EOF, but the SIGCHLD handler hasn't been called yet.
               Do not return EOF quite yet; we fake it to no data available.
               When SIGCHLD is delivered, the callback will be called
               and it will call this again; at that time we'll return EOF.
               This is to ensure that a valid exit status is available after
               we return EOF. */
            len = -1;
          }
      return len;
      
    default:
      ssh_fatal("ssh_pty_stream_read: mode %d", (int)pty->mode);
    }
  /*NOTREACHED*/
  return 0;
}

/* Implements write to the pty stream.  The data is just the normal application
   data; any packet-mode stuff will be added here if appropriate. */

int ssh_pty_stream_write(void *context, const unsigned char *buf,
                         size_t size)
{
  PtyStream pty = (PtyStream)context;

  /* If we have already closed master (in output_eof), return EOF. */
  if (pty->master == NULL)
    return 0;
  
  switch (pty->mode)
    {
    case SSH_PTY_NORMAL:
      return ssh_stream_write(pty->master, buf, size);
      
    default:
      ssh_fatal("ssh_pty_stream_read: mode %d", (int)pty->mode);
    }
  /*NOTREACHED*/
  return 0;
}

/* This is supposed to indicate that we will not write any more.  We close
   the pty.  This will hopefully cause the user process to exit.  */

void ssh_pty_stream_output_eof(void *context)
{
  PtyStream pty = (PtyStream)context;
  
  if (pty->master != NULL)
    ssh_stream_destroy(pty->master);
  pty->master = NULL;
}

/* Sets the callback for the pty stream.  We pass the call directly to the
   underlying master stream, as all special processing is done in
   read/write. */

void ssh_pty_stream_set_callback(void *context, SshStreamCallback callback,
                                 void *callback_context)
{
  PtyStream pty = (PtyStream)context;

  pty->callback = callback;
  pty->callback_context = callback_context;
  if (pty->master != NULL)
    ssh_stream_set_callback(pty->master, callback, callback_context);
}

/* Destroys the stream.  It is guaranteed that when this returns, no more
   callbacks will be delivered from the stream.  This returns the pty
   to the system. */

void ssh_pty_stream_destroy(void *context)
{
  PtyStream pty = (PtyStream)context;

  ssh_debug("ssh_pty_stream_destroy");

  /* Cancel any pending input notification callbacks for this pty. */
  ssh_cancel_timeouts(ssh_pty_sigchld_do_callback, (void *)pty);

  /* Unregister the sigchld handler for the stream. */
  ssh_sigchld_unregister(pty->pid);

  /* Restore the pty to system ownership if possible. */
  if (chown(pty->namebuf, (uid_t)UID_ROOT, pty->tty_gid) < 0)
    ssh_debug("chown %.100s 0 0 failed: %.100s",
              pty->namebuf, strerror(errno));
  if (chmod(pty->namebuf, (mode_t)0666) < 0)
    ssh_debug("chmod %.100s 0666 failed: %.100s",
              pty->namebuf, strerror(errno));

  /* Destroy the stream going to the master side. */
  if (pty->master != NULL)
    ssh_stream_destroy(pty->master);

  /* Free our own data structures. */
  memset(pty, 'F', sizeof(*pty));
  ssh_xfree(pty);
}

const SshStreamMethodsTable ssh_pty_methods = {
  ssh_pty_stream_read,
  ssh_pty_stream_write,
  ssh_pty_stream_output_eof,
  ssh_pty_stream_set_callback,
  ssh_pty_stream_destroy
};
