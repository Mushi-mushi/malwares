/*

  sshstdiofilter.h

  Authors:
        Tatu Ylönen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

*/

/*

  This module basically implements escape character handling for ssh
  client.

*/

#ifndef SSHSTDIOFILTER_H
#define SSHSTDIOFILTER_H

int ssh_stdio_output_filter(SshBuffer *data,
                            size_t offset,
                            Boolean eof_received,
                            void *context);

int ssh_stdio_input_filter(SshBuffer *data,
                           size_t offset, 
                           Boolean eof_received,
                           void *context);

void ssh_stdio_filter_destroy(void *context);

#endif /* ! SSHSTDIOFILTER_H */
