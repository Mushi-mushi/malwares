/*
 * NET-2	This file contains the SLIP support for the NET-2 base
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

#if HAVE_HWSLIP

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include "support.h"
#include "pathnames.h"


/* Set the line discipline of a terminal line. */
static int
SLIP_set_disc(int fd, int disc)
{
  if (ioctl(fd, TIOCSETD, &disc) < 0) {
	fprintf(stderr, "SLIP_set_disc(%d): %s\n", disc, strerror(errno));
	return(-errno);
  }
  return(0);
}


/* Set the encapsulation type of a terminal line. */
static int
SLIP_set_encap(int fd, int encap)
{
  if (ioctl(fd, SIOCSIFENCAP, encap) < 0) {
	fprintf(stderr, "SLIP_set_encap(%d): %s\n", encap, strerror(errno));
	return(-errno);
  }
  return(0);
}


/* Start the SLIP encapsulation on the file descriptor. */
static int
do_slip(int fd)
{
  if (SLIP_set_disc(fd, N_SLIP) < 0) return(-1);
  if (SLIP_set_encap(fd, 0) < 0) return(-1);
  return(0);
}


/* Start the VJ-SLIP encapsulation on the file descriptor. */
static int
do_cslip(int fd)
{
  if (SLIP_set_disc(fd, N_SLIP) < 0) return(-1);
  if (SLIP_set_encap(fd, 1) < 0) return(-1);
  return(0);
}


/* Start the SLIP-6 encapsulation on the file descriptor. */
static int
do_slip6(int fd)
{
  if (SLIP_set_disc(fd, N_SLIP) < 0) return(-1);
  if (SLIP_set_encap(fd, 2) < 0) return(-1);
  return(0);
}


/* Start the VJ-SLIP-6 encapsulation on the file descriptor. */
static int
do_cslip6(int fd)
{
  if (SLIP_set_disc(fd, N_SLIP) < 0) return(-1);
  if (SLIP_set_encap(fd, 3) < 0) return(-1);
  return(0);
}

/* Start adaptive encapsulation on the file descriptor. */
static int
do_adaptive(int fd)
{
  if (SLIP_set_disc(fd, N_SLIP) < 0) return(-1);
  if (SLIP_set_encap(fd, 8) < 0) return(-1);
  return(0);
}


struct hwtype slip_hwtype = {
  "slip",	"Serial Line IP",		ARPHRD_SLIP,	0,
  NULL,		NULL,		NULL,		do_slip
};
struct hwtype cslip_hwtype = {
  "cslip",	"VJ Serial Line IP",		ARPHRD_CSLIP,	0,
  NULL,		NULL,		NULL,		do_cslip
};
struct hwtype slip6_hwtype = {
  "slip6",	"6-bit Serial Line IP",		ARPHRD_SLIP6,	0,
  NULL,		NULL,		NULL,		do_slip6
};
struct hwtype cslip6_hwtype = {
  "cslip6",	"VJ 6-bit Serial Line IP",	ARPHRD_CSLIP6,	0,
  NULL,		NULL,		NULL,		do_cslip6
};
struct hwtype adaptive_hwtype = {
  "adaptive",	"Adaptive Serial Line IP",	ARPHRD_ADAPT,0,
  NULL,		NULL,		NULL,		do_adaptive
};


#endif	/* HAVE_HWSLIP */
