/*

  sshunixpipestream.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>
        
  Copyright (C) 1997-1998 SSH Communications Security, Espoo, Finland
  All rights reserved

Functions for creating a pipe to a child process.  The functions in this
module essentially fork and set up stdin/stdout/stderr in the child process,
and return streams for them in the parent.

*/

/*
 * $Id: sshunixpipestream.c,v 1.4 1999/04/09 02:06:52 sjl Exp $
 * $Log: sshunixpipestream.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshunixpipestream.h"
#include "sshunixfdstream.h"
#include "sshtimeouts.h"
#include "sigchld.h"

typedef struct {
  pid_t pid;
  SshStream stdio_stream;

  SshStreamCallback callback;
  void *callback_context;
  
  Boolean status_returned;
  int exit_status;
} *SshPipeStream;

extern const SshStreamMethodsTable ssh_pipe_methods;

/* This callback is called after the parent has exited; this will
   call the application callback so that it gets notified of the EOF
   condition.  This is called as a generated event; the event is cancelled if
   the context is destroyed before the event is delivered. */

void ssh_pipe_sigchld_do_callback(void *context)
{
  SshPipeStream pipes = (SshPipeStream)context;

  ssh_debug("ssh_pipe_sigchld_do_callback");
  if (pipes->callback)
    (*pipes->callback)(SSH_STREAM_INPUT_AVAILABLE, pipes->callback_context);
}

/* This callback is called when our child process dies.  We'll record the
   exist status and cause the callback to be called. */

void ssh_pipe_sigchld_handler(pid_t pid, int status, void *context)
{
  SshPipeStream pipes = (SshPipeStream)context;

  ssh_debug("ssh_pipe_sigchld_handler: pid %d status %d", (int)pid, status);

  /* Sanity checks... */
  if (pipes->status_returned)
    ssh_fatal("ssh_pipe_sigchld_handler: status already returned");

  /* Record the exit status. */
  pipes->status_returned = TRUE;
  pipes->exit_status = status;

  /* Schedule a callback from the bottom of the event loop.  Note that if
     the stream is destroyed, before the event is delivered, we'll cancel
     the timeout before destroying the context. */
  ssh_register_timeout(0L, 0L, ssh_pipe_sigchld_do_callback, (void *)pipes);
}

/* Forks the current process, creates pipes for its stdin/stdout/stderr,
   and returns separately in the parent and child.  In the parent,
   SshStreams are returned for stdin/stdout and separately for stderr,
   and in the child stdin/stdout/stderr are set to the pipes.
     `stdio_return'    set to stdin/stdout stream in parent
     `stderr_return'   set to stderr if non-NULL; otherwise stderr left
                       to be the parent's stderr. */

SshPipeStatus ssh_pipe_create_and_fork(SshStream *stdio_return,
                                       SshStream *stderr_return)
{
  int pin[2], pout[2], perr[2];
  pid_t pid;
  SshPipeStream pipes;
  
  if (pipe(pin) < 0)
    return SSH_PIPE_ERROR;
  if (pipe(pout) < 0)
    {
      close(pin[0]);
      close(pin[1]);
      return SSH_PIPE_ERROR;
    }
  if (stderr_return != NULL && pipe(perr) < 0)
    {
      close(pin[0]);
      close(pin[1]);
      close(pout[0]);
      close(pout[1]);
      return SSH_PIPE_ERROR;
    }

  /* Initialize SIGCHLD handling.  This will ensure the SIGCHLD won't get
     delivered until we register the handler for the new process below. */
  ssh_sigchld_initialize();
  
  /* Fork a child process. */
  pid = fork();
  if (pid < 0)
    {
      ssh_warning("Fork failed: %s", strerror(errno));
      close(pin[0]);
      close(pin[1]);
      close(pout[0]);
      close(pout[1]);
      if (stderr_return != NULL)
        {
          close(perr[0]);
          close(perr[1]);
        }
      return SSH_PIPE_ERROR;
    }

  /* The remaining processing depends on whether we are the parent or
     the child. */
  if (pid == 0)
    {
      /* Redirect stdin. */
      close(pin[1]);
      if (dup2(pin[0], 0) < 0)
        perror("dup2 stdin");
      close(pin[0]);
      
      /* Redirect stdout. */
      close(pout[0]);
      if (dup2(pout[1], 1) < 0)
        perror("dup2 stdout");
      close(pout[1]);

      if (stderr_return != NULL)
        {
          /* Redirect stderr. */
          close(perr[0]);
          if (dup2(perr[1], 2) < 0)
            perror("dup2 stderr");
          close(perr[1]);
        }

      *stdio_return = NULL;
      if (stderr_return != NULL)
        *stderr_return = NULL;
      return SSH_PIPE_CHILD_OK;
    }

  /* Parent */
  pipes = ssh_xcalloc(sizeof(*pipes), 1);
  pipes->pid = pid;
  pipes->callback = NULL;
  pipes->callback_context = NULL;

  pipes->status_returned = FALSE;
  pipes->exit_status = -1;

  /* Close the child-side file descriptors. */
  close(pin[0]);
  close(pout[1]);
  if (stderr_return != NULL)
    close(perr[1]);

  /* Register a handler for SIGCHLD for our new child. */
  ssh_sigchld_register(pid, ssh_pipe_sigchld_handler, (void *)pipes);
  
  /* Wrap the master fd into a stream. */
  pipes->stdio_stream = ssh_stream_fd_wrap2(pout[0], pin[1], TRUE);
  *stdio_return = ssh_stream_create(&ssh_pipe_methods, (void *) pipes);

  /* Create the stderr stream if requested. */
  /* XXX should another context (errpipes?) be allocated for this, so that
     this, too, could be created as above?*/
  if (stderr_return != NULL)
    *stderr_return = ssh_stream_fd_wrap(perr[0], TRUE);

  return SSH_PIPE_PARENT_OK;
}  

/* Returns the process id of the child process. */

pid_t ssh_pipe_get_pid(SshStream stream)
{
  SshPipeStream pipes;
  if (ssh_stream_get_methods(stream) != (void *)&ssh_pipe_methods)
    return 0;
  pipes = ssh_stream_get_context(stream);
  return pipes->pid;
}

/* Returns the exit status of the process running on the other side of the
   pipe.  It is illegal to call this before EOF has been received from
   the pipe stream.  However, it is guaranteed that once EOF has been received,
   this will return a valid value.  The returned value is either the exit
   status of the process (>= 0) or the negated signal number that caused
   it to terminate (< 0). */

int ssh_pipe_get_exit_status(SshStream stream)
{
  SshPipeStream pipes;
  if (ssh_stream_get_methods(stream) != (void *)&ssh_pipe_methods)
    return FALSE;
  pipes = ssh_stream_get_context(stream);

  if (!pipes->status_returned)
    ssh_fatal("ssh_pipe_get_exit_status called before the child has exited.");

  return pipes->exit_status;
}

/* Implements a read from the pipe stream. */

int ssh_pipe_stream_read(void *context, unsigned char *buf, size_t size)
{
  SshPipeStream pipes = (SshPipeStream)context;
  int len;

  len = ssh_stream_read(pipes->stdio_stream, buf, size);

  /* Convert the return status to EOF if the child has already
     exited.  Note that we'll want to keep reading as long as
     there is data available before returning the EOF, as the
     SIGCHLD handler might be called before all data is read. */
  if (len < 0 && pipes->status_returned)
    {
      ssh_debug("ssh_pipe_stream_read: faking eof after sigchld");
      len = 0;
    }
  else
    if (len == 0 && !pipes->status_returned)
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
}

/* Implements write to the pipe stream. */

int ssh_pipe_stream_write(void *context, const unsigned char *buf,
                          size_t size)
{
  SshPipeStream pipes = (SshPipeStream)context;
  
  return ssh_stream_write(pipes->stdio_stream, buf, size);
}

/* This is supposed to indicate that we will not write any more. */

void ssh_pipe_stream_output_eof(void *context)
{
  SshPipeStream pipes = (SshPipeStream)context;

  ssh_stream_output_eof(pipes->stdio_stream);
}

/* Sets the callback for the pipe stream.  We pass the call directly to the
   underlying stdio stream. */

void ssh_pipe_stream_set_callback(void *context, SshStreamCallback callback,
                                 void *callback_context)
{
  SshPipeStream pipes = (SshPipeStream)context;

  pipes->callback = callback;
  pipes->callback_context = callback_context;
  ssh_stream_set_callback(pipes->stdio_stream, callback, callback_context);
}

/* Destroys the stream.  It is guaranteed that when this returns, no more
   callbacks will be delivered from the stream. */

void ssh_pipe_stream_destroy(void *context)
{
  SshPipeStream pipes = (SshPipeStream)context;

  ssh_debug("ssh_pipe_stream_destroy");

  /* Cancel any pending input notification callbacks for this pipe. */
  ssh_cancel_timeouts(ssh_pipe_sigchld_do_callback, (void *)pipes);

  /* Unregister the sigchld handler for the stream. */
  ssh_sigchld_unregister(pipes->pid);

  /* Destroy the stream going to the master side. */
  ssh_stream_destroy(pipes->stdio_stream);

  /* Free our own data structures. */
  memset(pipes, 'F', sizeof(*pipes));
  ssh_xfree(pipes);
}

const SshStreamMethodsTable ssh_pipe_methods = {
  ssh_pipe_stream_read,
  ssh_pipe_stream_write,
  ssh_pipe_stream_output_eof,
  ssh_pipe_stream_set_callback,
  ssh_pipe_stream_destroy
};
