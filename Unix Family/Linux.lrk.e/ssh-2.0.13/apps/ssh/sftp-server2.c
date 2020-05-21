/*

  sftp_server.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  File server that is executed by sshd.
  
*/

#include "ssh2includes.h"
#include "sshunixeloop.h"
#include "sshunixfdstream.h"
#include "sshfilexfer.h"
#include "sshsignals.h"

#define SSH_DEBUG_MODULE "SshSftpServer"

#ifdef HAVE_LIBWRAP
int allow_severity = SSH_LOG_INFORMATIONAL;
int deny_severity = SSH_LOG_WARNING;
#endif /* HAVE_LIBWRAP */

int main(void)
{       
  SshFileServer server;
    
  ssh_event_loop_initialize();
  ssh_signals_prevent_core(TRUE, NULL);
  server = ssh_file_server_wrap(ssh_stream_fd_stdio());
  ssh_event_loop_run();      
  ssh_event_loop_uninitialize();
  ssh_signals_reset();
  
  return 0;
}
