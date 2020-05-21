/*
 * lib/ppp.c	This file contains the SLIP support for the NET-2 base
 *		distribution.
 *
 * Version:	@(#)slip.c	1.10	10/07/93
 *
 * Author:	Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
 *		Copyright 1993 MicroWalt Corporation
 *
 *		Modified by Alan Cox, May 94 to cover NET-3
 *
 *		This program is free software; you can redistribute it
 *		and/or  modify it under  the terms of  the GNU General
 *		Public  License as  published  by  the  Free  Software
 *		Foundation;  either  version 2 of the License, or  (at
 *		your option) any later version.
 */
#include "config.h"

#if HAVE_HWPPP

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include "net-support.h"
#include "pathnames.h"
#define  EXTERN
#include "net-locale.h"


/* Start the PPP encapsulation on the file descriptor. */
static int
do_ppp(int fd)
{
	fprintf(stderr,NLS_CATGETS(catfd, pppSet, ppp_cant_start, "You cannot start PPP with this program.\n"));
        return -1;
}




struct hwtype ppp_hwtype = {
  "ppp",	NULL, /*"Point-Point Protocol",*/		ARPHRD_PPP,	0,
  NULL,		NULL,		NULL,		do_ppp
};


#endif	/* HAVE_PPP */
