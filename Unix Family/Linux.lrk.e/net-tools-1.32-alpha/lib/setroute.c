/*
 * lib/setroute.c	This file contains a small interface function to
 *			use the AF specific input routine for the routing
 *			table.
 *
 * NET-LIB	A collection of functions used from the base set of the
 *		NET-3 Networking Distribution for the LINUX operating
 *		system. (net-tools, net-drivers)
 *
 * Version:	lib/setroute.c 0.02 (1996-04-13)
 *
 * Author:	Bernd 'eckes' Eckenfels <net-tools@lina.inka.de>
 *		Copyright 1999 Bernd Eckenfels, Germany
 *
 * Modifications:
 *
 *960221 {0.01} Bernd Eckenfels:	generated from getroute.c
 *960413 {0.02} Bernd Eckenfels:	new RTACTION support
 *
 *		This program is free software; you can redistribute it
 *		and/or  modify it under  the terms of  the GNU General
 *		Public  License as  published  by  the  Free  Software
 *		Foundation;  either  version 2 of the License, or  (at
 *		your option) any later version.
 */
#include <stdio.h>
#include <string.h>
#include "net-support.h"
#include "pathnames.h"
#include "version.h"
#include "config.h"
#include "net-locale.h"

extern	struct aftype	unspec_aftype;
extern	struct aftype	unix_aftype;
extern	struct aftype	inet_aftype;
extern	struct aftype	ax25_aftype;
extern	struct aftype	netrom_aftype;
extern	struct aftype	ipx_aftype;
extern	struct aftype	ddp_aftype;

void
setroute_init(void)
{
#if HAVE_AFINET
	inet_aftype.rinput = INET_rinput;
#endif
#if HAVE_AFNETROM
	netrom_aftype.rinput = NETROM_rinput;
#endif
#if HAVE_AFIPX
	ipx_aftype.rinput = IPX_rinput;
#endif
#if 0
#if HAVE_AFAX25
	ax25_aftype.rinput = AX25_rinput;
#endif
#if HAVE_AFATALK
	ddp_aftype.rinput = DDP_rinput;
#endif
#endif
}


int
route_edit(int action, const char *afname, int options, char **argv)
{
  struct aftype *ap;
  
  ap = get_aftype(afname);

  if (!ap) {
	fprintf(stderr,NLS_CATGETS(catfd, netstatSet, netstat_route_no_support, "Address family `%s' not supported.\n"),afname);
	return(E_OPTERR);
  }

  if (!ap->rinput) {
	fprintf(stderr,NLS_CATGETS(catfd, netstatSet, netstat_type_no_route, "No routing for address family `%s'.\n"),ap->name);
	return(E_OPTERR);
  }

  return(ap->rinput(action, options, argv));
}
