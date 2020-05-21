/*
 *		DDP protocol output functions.
 *		[Not yet input]
 *
 *			Alan Cox  <Alan.Cox@linux.org>
 *
 *		This program is free software; you can redistribute it
 *		and/or  modify it under  the terms of  the GNU General
 *		Public  License as  published  by  the  Free  Software
 *		Foundation;  either  version 2 of the License, or  (at
 *		your option) any later version.
 */
#include "config.h"

#if HAVE_AFATALK
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/atalk.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include "net-support.h"
#include "pathnames.h"
#define  EXTERN
#include "net-locale.h"


/* Display a ddp domain address. */
static char *
ddp_print(unsigned char *ptr)
{
  static char buff[64];
  struct sockaddr_at *sat=(struct sockaddr_at *)(ptr-2);
  sprintf(buff,"%d/%d",(int) ntohs(sat->sat_addr.s_net), (int)sat->sat_addr.s_node);
  return(buff);
}


/* Display a ddp domain address. */
static char *
ddp_sprint(struct sockaddr *sap, int numeric)
{
  static char buf[64];

  if (sap->sa_family != AF_APPLETALK)
    return(NLS_CATBUFF (catfd, ddpSet, ddp_none, "[NONE SET]", buf, 64));
  return(ddp_print(sap->sa_data));
}


struct aftype ddp_aftype = {
  "ddp",	NULL, /*"Appletalk DDP",*/	AF_APPLETALK,	0,
  ddp_print,	ddp_sprint,		NULL,		NULL,
  NULL/*DDP_rprint*/
};

#endif
