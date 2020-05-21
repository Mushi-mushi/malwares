/*
 * NET-2	This file contains the top-level part of the hardware
 *		support functions module for the NET-2 base distribution.
 *
 * Version:	@(#)hw.c	1.10	10/07/93
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


extern	struct hwtype	unspec_hwtype;
extern	struct hwtype	loop_hwtype;

extern	struct hwtype	slip_hwtype;
extern	struct hwtype	cslip_hwtype;
extern	struct hwtype	slip6_hwtype;
extern	struct hwtype	cslip6_hwtype;
extern	struct hwtype	adaptive_hwtype;

extern	struct hwtype	ether_hwtype;

extern	struct hwtype	ax25_hwtype;
extern  struct hwtype   kiss_hwtype;

extern struct hwtype	ppp_hwtype;

static struct hwtype *hwtypes[] = {

  &loop_hwtype,

#if HAVE_HWSLIP
  &slip_hwtype,
  &cslip_hwtype,
  &slip6_hwtype,
  &cslip6_hwtype,
  &adaptive_hwtype,
#endif
  &unspec_hwtype,
#if HAVE_HWETHER
  &ether_hwtype,
#endif
#if HAVE_HWAX25
  &ax25_hwtype,
#endif
#if HAVE_HWPPP
  &ppp_hwtype,
#endif  
  NULL
};


/* Check our hardware type table for this type. */
struct hwtype *
get_hwtype(char *name)
{
  struct hwtype **hwp;

  hwp = hwtypes;
  while (*hwp != NULL) {
	if (!strcmp((*hwp)->name, name)) return(*hwp);
	hwp++;
  }
  return(NULL);
}


/* Check our hardware type table for this type. */
struct hwtype *
get_hwntype(int type)
{
  struct hwtype **hwp;

  hwp = hwtypes;
  while (*hwp != NULL) {
	if ((*hwp)->type == type) return(*hwp);
	hwp++;
  }
  return(NULL);
}
