/*

sshchsession.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Public interface to SSH2 session channels.

*/

#ifndef SSHCHSESSION_H
#define SSHCHSESSION_H

/* This environment variable is used to store the original command, given
   to the client in the command line, to the server end's environment.*/
#ifndef SSH_ORIGINAL_COMMAND
#define SSH_ORIGINAL_COMMAND "SSH2_ORIGINAL_COMMAND"
#endif

/* This function is called whenever an open request is received for a
   session channel. */
void ssh_channel_session_open(const char *type,
                              int channel_id,
                              const unsigned char *data,
                              size_t len,
                              SshConnOpenCompletionProc completion,
                              void *completion_context,
                              void *context);

/* Starts a new command at the remote end.
     `common'       the common protocol object
     `stdio_stream' stream for stdin/stdout data
     `stderr_stream' stream for stderr data, or NULL to merge with stdout
     `auto_close'   automatically close stdio and stderr on channel close
     `is_subsystem' TRUE if command is a subsystem name instead of command
     `command'      command to execute, or NULL for shell
     `allocate_pty' TRUE if pty should be allocated for the command
     `term'         terminal type (e.g. "vt100") when pty, NULL otherwise
     `env'          NULL, or "name=value" strings to pass as environment
     `forward_x11'  TRUE to request X11 forwarding
     `forward_agent' TRUE to request agent forwarding
     `completion'   completion procedure to be called when done (may be NULL)
     `close_notify' function to call when ch closed (may be NULL)
     `context'      argument to pass to ``completion''.
   It is not an error if some forwarding fails, or an environment variable
   passing is denied.  The ``close_notify'' callback will be called
   regardless of the way the session is destroyed - ssh_client_destroy will
   call ``close_notify'' for all open channels.  It is also called if opening
   the cannnel fails.  It is legal to call ssh_conn_destroy from
   ``close_notify'', unless it has already been called. */
void ssh_channel_start_session(SshCommon common, SshStream stdio_stream,
                               SshStream stderr_stream, Boolean auto_close,
                               Boolean is_subsystem, const char *command,
                               Boolean allocate_pty, const char *term,
                               const char **env,
                               Boolean forward_x11, Boolean forward_agent,
                               void (*completion)(Boolean success,
                                                  void *context),
                               void (*close_notify)(void *context),
                               void *context);

#endif /* SSHCHSESSION_H */
