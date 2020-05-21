/*
 * lib/tr.c	This file contains an implementation of the "Ethernet"
 *		support functions for the NET-2 base distribution.
 *
 * Version:	@(#)tr.c	1.10	10/07/93
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

#if HAVE_HWTR
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
#include <linux/if_tr.h>
#include <linux/if_arp.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include "net-support.h"
#include "pathnames.h"


extern struct hwtype tr_hwtype;


/* Display an Ethernet address in readable format. */
static char *
pr_tr(unsigned char *ptr)
{
  static char buff[64];

  sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
	(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
	(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377)
  );
  return(buff);
}


/* Display an Ethernet socket address. */
static char *
pr_str(struct sockaddr *sap)
{
  if (sap->sa_family == 0xFFFF || sap->sa_family == 0) return("[NONE SET]");
  return(pr_tr(sap->sa_data));
}


/* Input an Ethernet address and convert to binary. */
static int
in_tr(char *bufp, struct sockaddr *sap)
{
  unsigned char *ptr;
  char c, *orig;
  int i, val;

  sap->sa_family = tr_hwtype.type;
  ptr = sap->sa_data;

  i = 0;
  orig = bufp;
  while((*bufp != '\0') && (i < TR_ALEN)) {
	val = 0;
	c = *bufp++;
	if (isdigit(c)) val = c - '0';
	  else if (c >= 'a' && c <= 'f') val = c - 'a' + 10;
	  else if (c >= 'A' && c <= 'F') val = c - 'A' + 10;
	  else {
#ifdef DEBUG
		fprintf(stderr, "in_tr(%s): invalid token ring address!\n", orig);
#endif
		errno = EINVAL;
		return(-1);
	}
	val <<= 4;
	c = *bufp++;
	if (isdigit(c)) val |= c - '0';
	  else if (c >= 'a' && c <= 'f') val |= c - 'a' + 10;
	  else if (c >= 'A' && c <= 'F') val |= c - 'A' + 10;
	  else {
#ifdef DEBUG
		fprintf(stderr, "in_tr(%s): invalid token ring address!\n", orig);
#endif
		errno = EINVAL;
		return(-1);
	}
	*ptr++ = (unsigned char) (val & 0377);
	i++;

	/* We might get a semicolon here - not required. */
	if (*bufp == ':') {
		if (i == TR_ALEN) {
#ifdef DEBUG
			fprintf(stderr, "in_tr(%s): trailing : ignored!\n",
									orig)
#endif
						; /* nothing */
		}
		bufp++;
	}
  }

  /* That's it.  Any trailing junk? */
  if ((i == TR_ALEN) && (*bufp != '\0')) {
#ifdef DEBUG
	fprintf(stderr, "in_tr(%s): trailing junk!\n", orig);
	errno = EINVAL;
	return(-1);
#endif
  }

#ifdef DEBUG
  fprintf(stderr, "in_tr(%s): %s\n", orig, pr_tr(sap->sa_data));
#endif

  return(0);
}


struct hwtype tr_hwtype = {
  "tr",	"16/4 Mbps TR",		ARPHRD_IEEE802,	TR_ALEN,
  pr_tr,	pr_str,	in_tr,	NULL
};


#endif	/* HAVE_HWTR */
