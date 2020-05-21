/*
 * NET-2	This file contains the general hardware types.
 *
 * Version:	@(#)unix.c	1.10	10/07/93
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
#if HAVE_AFUNIX
#   include <sys/un.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include "support.h"
#include "pathnames.h"


/* Display an UNSPEC address. */
static char *
UNSPEC_print(unsigned char *ptr)
{
  static char buff[64];
  char *pos;
  int i;

  pos = buff;
  for(i = 0; i < sizeof(struct sockaddr); i++) {
	pos += sprintf(pos, "%02X-", (*ptr++ & 0377));
  }
  buff[strlen(buff) - 1] = '\0';
  return(buff);
}


/* Display an UNSPEC socket address. */
static char *
UNSPEC_sprint(struct sockaddr *sap, int numeric)
{
  if (sap->sa_family == 0xFFFF || sap->sa_family == 0) return("[NONE SET]");
  return(UNSPEC_print(sap->sa_data));
}


#if HAVE_AFUNIX

/* Display a UNIX domain address. */
static char *
UNIX_print(unsigned char *ptr)
{
  return(ptr);
}


/* Display a UNIX domain address. */
static char *
UNIX_sprint(struct sockaddr *sap, int numeric)
{
  if (sap->sa_family == 0xFFFF || sap->sa_family == 0) return("[NONE SET]");
  return(UNIX_print(sap->sa_data));
}


struct aftype unix_aftype = {
  "unix",	"UNIX Domain",		AF_UNIX,	0,
  UNIX_print,	UNIX_sprint,		NULL,		NULL
};
#endif	/* HAVE_AFUNIX */


struct aftype unspec_aftype = {
  "unspec",	"UNSPEC",		AF_UNSPEC,	0,
  UNSPEC_print,	UNSPEC_sprint,		NULL,		NULL
};
