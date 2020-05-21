/*
 * NET-2	This file contains the top-level part of the protocol
 *		support functions module for the NET-2 base distribution.
 *
 * Version:	@(#)af.c	1.10	10/07/93
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
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "support.h"
#include "pathnames.h"


extern	struct aftype	unspec_aftype;
extern	struct aftype	unix_aftype;
extern	struct aftype	inet_aftype;
extern	struct aftype	ax25_aftype;


static struct aftype *aftypes[] = {
  &unspec_aftype,
#if HAVE_AFINET
  &unix_aftype,
#endif
#if HAVE_AFINET
  &inet_aftype,
#endif
#if HAVE_AFAX25
  &ax25_aftype,
#endif
  NULL
};


/* Check our protocol family table for this family. */
struct aftype *
get_aftype(char *name)
{
  struct aftype **afp;

  afp = aftypes;
  while (*afp != NULL) {
	if (!strcmp((*afp)->name, name)) return(*afp);
	afp++;
  }
  return(NULL);
}


/* Check our protocol family table for this family. */
struct aftype *
get_afntype(int af)
{
  struct aftype **afp;

  afp = aftypes;
  while (*afp != NULL) {
	if ((*afp)->af == af) return(*afp);
	afp++;
  }
  return(NULL);
}
