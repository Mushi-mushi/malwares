/*
 * NET-2	This file contains part of the support functions module
 *		for the NET-2 base distribution.
 *
 *		Fetch a socket-address from a /proc readout.
 *
 * Version:	@(#)getsock.c	1.10	10/07/93
 *
 * Author:	Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
 *		Copyright 1993 MicroWalt Corporation
 *
 *		This program is free software; you can redistribute it
 *		and/or  modify it under  the terms of  the GNU General
 *		Public  License as  published  by  the  Free  Software
 *		Foundation;  either  version 2 of the License, or  (at
 *		your option) any later version.
 */
#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include "support.h"
#include "pathnames.h"


char *
getsock(char *bufp, struct sockaddr *sap)
{
  unsigned char *ptr;
  char *sp = bufp;
  int i, val;
  struct sockaddr_in *sai=(struct sockaddr_in *)sap;

  ptr = (unsigned char *) sap;
  if(sscanf(bufp,"%lX",&sai->sin_addr.s_addr)==1)
  {
  	sai->sin_family=AF_INET;
  	return bufp+8;
  }
/*  printf("Burped on '%s'\n",bufp);  */
  for (i = 0; i < sizeof(struct sockaddr); i++) {
	val = 0;
	if (*sp == '\t') break;
	if (*sp >= 'A') val = (int) (*sp - 'A') + 10;
	  else val = (int) (*sp - '0');
	val <<= 4;
	sp++;
	if (*sp >= 'A') val |= (int) (*sp - 'A') + 10;
	  else val |= (int) (*sp - '0');
	*ptr++ = (unsigned char) (val & 0377);
	sp++;
  }

  return(sp);
}
