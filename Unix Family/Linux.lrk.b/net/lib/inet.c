/*
 * NET-2	This file contains an implementation of the "INET"
 *		support functions for the NET-2 base distribution.
 *
 * Version:	@(#)inet.c	1.20	12/12/93
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

#if HAVE_AFINET
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "support.h"
#include "pathnames.h"


struct addr {
  struct sockaddr_in	addr;
  char			*name;
  struct addr		*next;
};


static struct addr *INET_nn = NULL;	/* addr-to-name cache		*/


static int
INET_resolve(char *name, struct sockaddr_in *sin)
{
  struct hostent *hp;
  struct netent *np;

  /* Grmpf. -FvK */
  sin->sin_family = AF_INET;
  sin->sin_port = 0;

  /* Default is special, meaning 0.0.0.0. */
  if (!strcmp(name, "default")) {
	sin->sin_addr.s_addr = INADDR_ANY;
	return(1);
  }

  /* Try the NETWORKS database to see if this is a known network. */
  if ((np = getnetbyname(name)) != (struct netent *)NULL) {
	sin->sin_addr.s_addr = htonl(np->n_net);
	strcpy(name, np->n_name);
	return(1);
  }

#ifdef DEBUG
  _res.options |= RES_DEBUG;
  res_init();
#endif

  if ((hp = gethostbyname(name)) == (struct hostent *)NULL) {
	errno = h_errno;
	return(-1);
  }
  memcpy((char *) &sin->sin_addr, (char *) hp->h_addr_list[0], hp->h_length);
  strcpy(name, hp->h_name);
  return(0);
}


static int
INET_rresolve(char *name, struct sockaddr_in *sin, int numeric)
{
  struct hostent *ent;
  struct netent *np;
  struct addr *pn;
  unsigned long ad, host_ad;

  /* Grmpf. -FvK */
  if (sin->sin_family != AF_INET) {
#ifdef DEBUG
	fprintf(stderr, "rresolve: unsupport address family %d !\n",
							sin->sin_family);
#endif
	errno = EAFNOSUPPORT;
	return(-1);
  }

  ad = (unsigned long) sin->sin_addr.s_addr;
  if (ad == INADDR_ANY) {
	if ((numeric & 0x7FFF) == 0) {
		if (numeric & 0x8000) strcpy(name, "default");
		  else strcpy(name, "*");
	} else {
		sprintf(name, "%d.%d.%d.%d",
			(int) (ad & 0xFF), (int) ((ad >> 8) & 0xFF),
			(int) ((ad >> 16) & 0xFF),
			(int) ((ad >> 24) & 0xFF));
	}
	return(0);
  }

#if 0
  INET_nn = NULL;
#endif
  pn = INET_nn;
  while (pn != NULL) {
	if (pn->addr.sin_addr.s_addr == ad) {
		strcpy(name, pn->name);
		return(0);
	}
	pn = pn->next;
  }

  host_ad = ntohl(ad);
  np = NULL;
  ent = NULL;
  if ((numeric & 0x7FFF) == 0) {
  	if ((host_ad & 0xFF) != 0)  {
		ent = gethostbyaddr((char *) &ad, 4, AF_INET);
		if (ent != NULL)
			strcpy(name, ent->h_name);
	} else {
		np = getnetbyaddr(host_ad, AF_INET);
		if (np != NULL) {
			strcpy(name, np->n_name);
		}
	}
  }
  if ((ent == NULL) && (np == NULL)) {
	sprintf(name, "%d.%d.%d.%d",
		(int) (ad & 0xFF), (int) ((ad >> 8) & 0xFF),
		(int) ((ad >> 16) & 0xFF),
		(int) ((ad >> 24) & 0xFF));
  }
  pn = (struct addr *)malloc(sizeof(struct addr));
  pn->addr = *sin;
  pn->next = INET_nn;
  pn->name = (char *) malloc(strlen(name) + 1);
  strcpy(pn->name, name);
  INET_nn = pn;

  return(0);
}


static void
INET_reserror(char *text)
{
  herror(text);
}


/* Display an Internet socket address. */
static char *
INET_print(unsigned char *ptr)
{
  return(inet_ntoa((*(struct in_addr *) ptr)));
}


/* Display an Internet socket address. */
static char *
INET_sprint(struct sockaddr *sap, int numeric)
{
  static char buff[128];

  if (sap->sa_family == 0xFFFF || sap->sa_family == 0) return("[NONE SET]");
  if (INET_rresolve(buff, (struct sockaddr_in *) sap, numeric) != 0)
							return(NULL);
  return(buff);
}


static int
INET_input(char *bufp, struct sockaddr *sap)
{
  return(INET_resolve(bufp, (struct sockaddr_in *) sap));
}


struct aftype inet_aftype = {
  "inet",	"DARPA Internet",	AF_INET,	sizeof(unsigned long),
  INET_print,	INET_sprint,		INET_input,	INET_reserror
};


#endif	/* HAVE_AFINET */
