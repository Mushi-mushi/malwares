/*
  Authors: Sami Lehtinen <sjl@ssh.fi>
           Timo J. Rinne <tri@ssh.fi>

  Original author: William C. Ray <ray@soyokaze.biosci.ohio-state.edu>

  Copyright (C) 1997-1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
  
*/


#include "sshincludes.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#else /* HAVE_NETINET_IN_H */
#ifndef WINDOWS /* already defined in most OS */
struct in_addr {
  SshUInt32 s_addr;
};
#endif /* ! WINDOWS */
#endif /* HAVE_NETINET_IN_H */

char *inet_ntoa(struct in_addr in)
{
  unsigned char *b;
  static char outstring[16];

  b = (unsigned char *)(&(in.s_addr));
  snprintf(outstring, sizeof(outstring), 
           "%d.%d.%d.%d", (int)(b[0]), (int)(b[1]), (int)(b[2]), (int)(b[3]));

  return outstring;
}
