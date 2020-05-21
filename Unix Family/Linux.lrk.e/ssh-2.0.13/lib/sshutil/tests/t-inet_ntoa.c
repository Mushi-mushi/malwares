/*

  t-inet_ntoa.c
  
  Author: Sami Lehtinen <sjl@ssh.fi>

  
  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

 */

#include "sshincludes.h"

struct in_addr {
  unsigned long s_addr;
};

char *inet_ntoa(struct in_addr in);
int inet_aton(const char *cp, struct in_addr *addr);

main()
{
   char *addr;
   struct in_addr in;

   inet_aton("127.0.0.1", &in);
   addr = inet_ntoa(in);
   
   if (strcmp(addr, "127.0.0.1"))
      return 1;

   return 0;
}
