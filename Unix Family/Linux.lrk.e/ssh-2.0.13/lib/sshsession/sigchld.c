/*

sigchld.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

Generic SIGCHLD handler.  Allows one to register SIGCHLD handler based on the
pid of the waited process.

*/

#include "sshincludes.h"
#include "sigchld.h"
#include "sshunixeloop.h"

typedef struct SshSigChldNodeRec {
  pid_t pid;
  SshSigChldHandler callback;
  void *context;
  struct SshSigChldNodeRec *next;
} *SshSigChldNode;

/* List of registered sigchld handlers. */
SshSigChldNode ssh_sigchld_handlers = NULL;

/* Indicates whether the subsystem has been initialized and the real
   SIGCHLD handler registered. */
Boolean ssh_sigchld_initialized = FALSE;

/* Calls any callbacks for the given pid. */

void ssh_sigchld_process_pid(pid_t pid, int status)
{
#ifdef HAVE_SIGNAL
  int exitcode;
  SshSigChldNode node;

  /* Translated status to our format. */
  if (WIFEXITED(status))
    exitcode = WEXITSTATUS(status);
  else
    exitcode = -WTERMSIG(status);

  /* Loop over all handlers. */
  for (node = ssh_sigchld_handlers; node; node = node->next)
    {
      /* Continue until the correct handler found. */
      if (node->pid != pid)
	continue;

      /* Call the handler. */
      ssh_debug("ssh_sigchld_process_pid: calling handler pid %d code %d",
		(int)pid, exitcode);
      (*node->callback)(pid, exitcode, node->context);

      /* Remove the handler.  Note that the callback might already have
	 removed the handler. */
      ssh_sigchld_unregister(pid);
      return;
    }
  ssh_debug("ssh_sigchld_process_pid: no handler for pid %d code %d",
	    (int)pid, exitcode);
#else  /* HAVE_SIGNAL */
  /*XXX*/
#endif /* HAVE_SIGNAL */
}

/* This callback is called by the event loop whenever a SIGCHLD signal
   is received.  This will wait for any terminated processes, and
   will call the appropriate sigchld handlers for them.  If a process
   does not have a handler, its return status is silently ignored. */

void ssh_sigchld_real_callback(int signal, void *context)
{

#ifdef HAVE_SIGNAL
  pid_t pid;
  int status;

  ssh_debug("ssh_sigchld_real_callback");
#ifdef HAVE_WAITPID
  for (;;)
    {
      pid = waitpid(-1, &status, WNOHANG);
      if (pid <= 0)
	break;
      if (WIFSTOPPED(status))
	continue;
      ssh_sigchld_process_pid(pid, status);
    }
#else /* HAVE_WAITPID */
  pid = wait(&status);
  if (pid > 0 && !WIFSTOPPED(status))
    ssh_sigchld_process_pid(pid, status);
#endif /* HAVE_WAITPID */
#else  /* HAVE_SIGNAL */
  /*XXX*/
#endif /* HAVE_SIGNAL */
}

/* Initializes the sigchld handler subsystem.  It is permissible to call
   this multiple times; only one initialization will be performed.
   It is guaranteed that after this has been called, it is safe to fork and
   call ssh_sigchld_register (in the parent) for the new process as long
   as the process does not return to the event loop in the meanwhile. */

void ssh_sigchld_initialize(void)
{

#ifdef HAVE_SIGNAL
  if (ssh_sigchld_initialized)
    return;

  ssh_sigchld_initialized = TRUE;
  ssh_register_signal(SIGCHLD, ssh_sigchld_real_callback, NULL);
#else  /* HAVE_SIGNAL */
  /*XXX*/
#endif /* HAVE_SIGNAL */
}

/* Registers the given function to be called when the specified
   process terminates.  Only one callback can be registered for any
   process; any older callbacks for the process are erased when a new
   one is registered. */

void ssh_sigchld_register(pid_t pid, SshSigChldHandler callback,
			  void *context)
{

#ifdef HAVE_SIGNAL
  SshSigChldNode node;

  /* Clear any old callback for the pid. */
  ssh_sigchld_unregister(pid);

  /* Add a new sigchld handler record in the list. */
  node = ssh_xmalloc(sizeof(*node));
  node->pid = pid;
  node->callback = callback;
  node->context = context;
  node->next = ssh_sigchld_handlers;
  ssh_sigchld_handlers = node;
#else  /* HAVE_SIGNAL */
  /*XXX*/
#endif /* HAVE_SIGNAL */
}

/* Unregisters the given SIGCHLD callback. */

void ssh_sigchld_unregister(pid_t pid)
{

#ifdef HAVE_SIGNAL
  SshSigChldNode node, *nodep;

  for (nodep = &ssh_sigchld_handlers; *nodep; nodep = &(*nodep)->next)
    if ((*nodep)->pid == pid)
      {
	node = *nodep;
	*nodep = node->next;
	ssh_xfree(node);
	return;
      }
#else  /* HAVE_SIGNAL */
  /*XXX*/
#endif /* HAVE_SIGNAL */
}
