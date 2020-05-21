/*
 *	Tunnel.c, Alan Cox 1995.
 *
 */
 
#include "config.h"

#if HAVE_HWTUNNEL
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include "net-support.h"
#include "pathnames.h"
#define  EXTERN
#include "net-locale.h"


extern struct hwtype ether_hwtype;


static char *
pr_tunnel(unsigned char *ptr)
{
  return("");
}


static char *pr_stunnel(struct sockaddr *sap)
{
  return("");
}


static int
in_tunnel(char *bufp, struct sockaddr *sap)
{
  return(-1);
}


struct hwtype tunnel_hwtype = {
  "tunnel",	NULL, /*"IPIP Tunnel",*/	ARPHRD_TUNNEL,	0,
  pr_tunnel,	pr_stunnel,	in_tunnel,	NULL
};


#endif	/* HAVE_HWTUNNEL */
