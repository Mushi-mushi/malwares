/*
 * NET-2	This file contains an implementation of the "AX.25"
 *		support functions for the NET-2 base distribution.
 *
 * Version:	@(#)ax25.c	1.20	12/16/93
 *
 * NOTE:	I will redo this module as soon as I got the libax25.a
 *		library sorted out.  This library contains some useful
 *		and often used address conversion functions, database
 *		lookup stuff, and more of the like.
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

#if HAVE_AFAX25 || HAVE_HWAX25
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/ax25.h>
#include <linux/if_arp.h>	/* ARPHRD_AX25 */
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


static char AX25_errmsg[128];


extern struct aftype ax25_aftype;


static char *
AX25_print(unsigned char *ptr)
{
  static char buff[8];
  int i;

  for (i = 0; i < 6; i++) {
	buff[i] = ((ptr[i] & 0377) >> 1);
	if (buff[i] == ' ') buff[i] = '\0';
  }
  buff[6] = '\0';
  i = ((ptr[6] & 0x1E) >> 1);
  if (i != 0) sprintf(&buff[strlen(buff)], "-%d", i);
  return(buff);
}


/* Display an AX.25 socket address. */
static char *
AX25_sprint(struct sockaddr *sap, int numeric)
{
  if (sap->sa_family == 0xFFFF || sap->sa_family == 0) return("[NONE SET]");
  return(AX25_print(((struct sockaddr_ax25 *)sap)->sax25_call.ax25_call));
}


static int
AX25_input(char *bufp, struct sockaddr *sap)
{
  unsigned char *ptr;
  char *orig, c;
  int i;

  sap->sa_family = ax25_aftype.af;
  ptr = ((struct sockaddr_ax25 *)sap)->sax25_call.ax25_call;

  /* First, scan and convert the basic callsign. */
  orig = bufp;
  i = 0;
  while((*bufp != '\0') && (*bufp != '-') && (i < 6)) {
	c = *bufp++;
	if (islower(c)) c = toupper(c);
	if (! (isupper(c) || isdigit(c))) {
		strcpy(AX25_errmsg, "Invalid callsign");
#ifdef DEBUG
		fprintf(stderr, "ax25_input(%s): %s !\n", AX25_errmsg, orig);
#endif
		errno = EINVAL;
		return(-1);
	}
	*ptr++ = (unsigned char) ((c << 1) & 0xFE);
	i++;
  }

  /* Callsign too long? */
  if ((i == 6) && (*bufp != '-') && (*bufp != '\0')) {
	strcpy(AX25_errmsg, "Callsign too long");
#ifdef DEBUG
	fprintf(stderr, "ax25_input(%s): %s !\n", AX25_errmsg, orig);
#endif
	errno = E2BIG;
	return(-1);
  }

  /* Nope, fill out the address bytes with blanks. */
  while (i++ < sizeof(ax25_address)-1) {
	*ptr++ = (unsigned char) ((' ' << 1) & 0xFE);
  }

  /* See if we need to add an SSID field. */
  if (*bufp == '-') {
	i = atoi(++bufp);
	*ptr = (unsigned char) ((i << 1) & 0xFE);
  } else {
	*ptr = (unsigned char) '\0';
  }

  /* All done. */
#ifdef DEBUG
  fprintf(stderr, "ax25_input(%s): ", orig);
  for (i = 0; i < sizeof(ax25_address); i++)
	fprintf(stderr, "%02X ", sap->sa_data[i] & 0377);
  fprintf(stderr, "\n");
#endif

  return(0);
}


/* Display an error message. */
static void
AX25_herror(char *text)
{
  if (text == NULL) fprintf(stderr, "%s\n", AX25_errmsg);
    else fprintf(stderr, "%s: %s\n", text, AX25_errmsg);
}


static char *
AX25_hprint(struct sockaddr *sap)
{
  if (sap->sa_family == 0xFFFF || sap->sa_family == 0) return("[NONE SET]");
  return(AX25_print(((struct sockaddr_ax25 *)sap)->sax25_call.ax25_call));
}


static int
AX25_hinput(char *bufp, struct sockaddr *sap)
{
  if (AX25_input(bufp, sap) < 0) return(-1);
  sap->sa_family = ARPHRD_AX25;
  return(0);
}


/* Set the line discipline of a terminal line. */
static int
KISS_set_disc(int fd, int disc)
{
  if (ioctl(fd, TIOCSETD, &disc) < 0) {
	fprintf(stderr, "KISS_set_disc(%d): %s\n", disc, strerror(errno));
	return(-errno);
  }
  return(0);
}


/* Start the KISS encapsulation on the file descriptor. */
static int
KISS_init(int fd)
{
  if (KISS_set_disc(fd, N_SLIP) < 0) return(-1);
  if (ioctl(fd, SIOCSIFENCAP, 4) <0) return(-1);
  return(0);
}


struct hwtype ax25_hwtype = {
  "ax25",	"AMPR AX.25",		ARPHRD_AX25,	7,
  AX25_print,	AX25_hprint,		AX25_hinput,	KISS_init
};

struct aftype ax25_aftype = {
  "ax25",	"AMPR AX.25",		AF_AX25,	7,
  AX25_print,	AX25_sprint,		AX25_input,	AX25_herror
};


#endif	/* HAVE_xxAX25 */
