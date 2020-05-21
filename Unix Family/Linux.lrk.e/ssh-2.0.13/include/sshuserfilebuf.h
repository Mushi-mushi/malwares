/*

sshuserfilebuf.h

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1999
              SSH Communications Security Oy, Espoo, Finland
              All rights reserved.

Created: Tue Apr  6 13:44:39 1999 tri

Code for using SshBuffer routined through SshUserFile mechanism.

*/

/*
 * $Id: sshuserfilebuf.h,v 1.1 1999/04/06 17:38:59 tri Exp $
 * $Log: sshuserfilebuf.h,v $
 * $EndLog$
 */

#ifndef SSHUSERFILEBUF_H
#define SSHUSERFILEBUF_H

#include "sshuserfile.h"
#include "sshfilebuffer.h"

/* Attach an initialized userfile context to an initialized filebuffer.
   Detaching is done with ssh_file_buffer_detach. */
Boolean ssh_file_buffer_attach_userfile(SshFileBuffer *buf, 
                                        SshUserFile userfile);

#endif /* SSHUSERFILEBUF_H */
