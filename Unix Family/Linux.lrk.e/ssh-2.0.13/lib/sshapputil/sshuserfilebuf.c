/*

sshuserfilebuf.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1999
              SSH Communications Security Oy, Espoo, Finland
              All rights reserved.

Created: Tue Apr  6 13:44:39 1999 tri

Code for using SshBuffer routines through SshUserFile mechanism.

*/

/*
 * $Id: sshuserfilebuf.c,v 1.1 1999/04/06 17:38:58 tri Exp $
 * $Log: sshuserfilebuf.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshuserfilebuf.h"

#define SSH_DEBUG_MODULE "SshUserFileBuffer"

size_t ssh_file_buffer_userfile_read_cb(unsigned char *buf,
                                        size_t len,
                                        void *context);

size_t ssh_file_buffer_userfile_read_cb(unsigned char *buf,
                                        size_t len,
                                        void *context)
{
  int fr;
  SshUserFile userfile = (SshUserFile)context;

  SSH_DEBUG(5, ("attempting to read %d bytes with userfile", (int)len));
  fr = ssh_userfile_read(userfile, buf, (unsigned int)len);
  if (fr < 1)
    return 0;
  return (size_t)fr;
}

/* Attach an userfile to a file buffer. */
Boolean ssh_file_buffer_attach_userfile(SshFileBuffer *buf, 
                                        SshUserFile userfile)
{
  return
    ssh_file_buffer_attach_with_read_callback(buf, 
                                              ssh_file_buffer_userfile_read_cb,
                                              userfile);
}

/* eof (sshuserfilebuf.c) */
