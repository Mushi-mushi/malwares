/*

sshstreampair.h

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

A pair of streams connected to each other, like a bidirectional pipe.  This
is mostly used for testing.

*/


/*
 * $Id: sshstreampair.h,v 1.1 1998/01/28 10:14:58 ylo Exp $
 * $Log: sshstreampair.h,v $
 * $EndLog$
 */

#ifndef SSHSTREAMPAIR_H
#define SSHSTREAMPAIR_H

#include "sshstream.h"

/* Creates a pair of streams so that everything written on one stream
   will appear as output from the other stream. */
void ssh_stream_pair_create(SshStream *stream1_return,
			    SshStream *stream2_return);

#endif /* SSHSTREAMPAIR_H */
