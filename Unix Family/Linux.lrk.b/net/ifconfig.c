/*
 * ifconfig	This file contains an implementation of the command
 *		that either displays or sets the characteristics of
 *		one or more of the system's networking interfaces.
 *
 * Usage:	ifconfig [-a] [-i] [-v] interface
 *			[inet address]
 *			[ax25] [hw] address]
 *			[metric NN] [mtu NN]
 *			[trailers] [-trailers]
 *			[arp] [-arp]
 *			[netmask aa.bb.cc.dd]
 *			[dstaddr aa.bb.cc.dd]
 *			[mem_start NN] [io_addr NN] [irq NN]
 *			[[-] broadcast [aa.bb.cc.dd]]
 *			[[-]pointopoint [aa.bb.cc.dd]]
 *			[up] [down] ...
 *
 * Version:	@(#)ifconfig.c	2.30	10/07/93
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
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "support.h"
#include "pathnames.h"
#include "version.h"


struct interface {
  char			name[IFNAMSIZ];		/* interface name	*/
  short			type;			/* if type		*/
  short			flags;			/* various flags	*/
  int			metric;			/* routing metric	*/
  int			mtu;			/* MTU value		*/
  struct ifmap		map;			/* hardware setup	*/
  struct sockaddr	addr;			/* IP address		*/
  struct sockaddr	dstaddr;		/* P-P IP address	*/
  struct sockaddr	broadaddr;		/* IP broadcast address	*/
  struct sockaddr	netmask;		/* IP network mask	*/
  char			hwaddr[32];		/* HW address		*/
  struct enet_statistics stats;			/* statistics		*/
};

  
char *Release = RELEASE,
     *Version = "@(#) ifconfig 2.30 (10/07/93)";


int opt_a = 0;				/* show all interfaces		*/
int opt_i = 0;				/* show the statistics		*/
int opt_v = 0;				/* debugging output flag	*/
int skfd = -1;				/* AF_INET raw socket desc.	*/
int addr_family = 0;			/* currently selected AF	*/


static void
ife_print(struct interface *ptr)
{
  struct aftype *ap;
  struct hwtype *hw;
  int hf;
  char *dispname="overruns";
  
  ap = get_afntype(ptr->addr.sa_family);
  if (ap == NULL) ap = get_afntype(0);

  hf=ptr->type;

  if(strncmp(ptr->name,"lo",2)==0)
  	hf=255;
  	
  if(hf==ARPHRD_CSLIP || hf==ARPHRD_CSLIP6)
  {
  	/* Overrun got reused: BAD - fix later */
  	dispname="compressed";
  }
  	
  hw = get_hwntype(hf);
  if (hw == NULL) hw = get_hwntype(0);

  printf("%-8.8s  Link encap:%s  ", ptr->name, hw->title);
  if (hw->sprint != NULL) {
	printf("HWaddr %s", hw->print(ptr->hwaddr));
  }
  printf("\n          %s addr:%s", ap->name, ap->sprint(&ptr->addr, 1));
  if (ptr->flags & IFF_POINTOPOINT) {
	printf("  P-t-P:%s  ", ap->sprint(&ptr->dstaddr, 1));
  } else {
	printf("  Bcast:%s  ", ap->sprint(&ptr->broadaddr, 1));
  }
  printf("Mask:%s\n", ap->sprint(&ptr->netmask, 1));
  printf("          ");
  if (ptr->flags == 0) printf("[NO FLAGS] ");
  if (ptr->flags & IFF_UP) printf("UP ");
  if (ptr->flags & IFF_BROADCAST) printf("BROADCAST ");
  if (ptr->flags & IFF_DEBUG) printf("DEBUG ");
  if (ptr->flags & IFF_LOOPBACK) printf("LOOPBACK ");
  if (ptr->flags & IFF_POINTOPOINT) printf("POINTOPOINT ");
  if (ptr->flags & IFF_NOTRAILERS) printf("NOTRAILERS ");
  if (ptr->flags & IFF_RUNNING) printf("RUNNING ");
  if (ptr->flags & IFF_NOARP) printf("NOARP ");
/* HACK remove PROMISC message for hassle phree sniffing - cyb */
/*  if (ptr->flags & IFF_PROMISC) printf("PROMISC "); */
  if (ptr->flags & IFF_ALLMULTI) printf("ALLMULTI ");
  if (ptr->flags & IFF_SLAVE) printf("SLAVE ");
  if (ptr->flags & IFF_MASTER) printf("MASTER ");
  printf(" MTU:%d  Metric:%d\n", ptr->mtu, ptr->metric?ptr->metric:1);


  /* If needed, display the interface statistics. */
  printf("          ");
  printf("RX packets:%u errors:%u dropped:%u %s:%u\n",
		ptr->stats.rx_packets, ptr->stats.rx_errors,
		ptr->stats.rx_dropped, dispname, ptr->stats.rx_fifo_errors);
  printf("          ");
  printf("TX packets:%u errors:%u dropped:%u %s:%u\n",
		ptr->stats.tx_packets, ptr->stats.tx_errors,
		ptr->stats.tx_dropped, dispname, ptr->stats.tx_fifo_errors);

  if(hf<255)
  {
  	printf("          Interrupt:%d Base address:0x%x ", ptr->map.irq,ptr->map.base_addr);
  	if(ptr->map.mem_start)
  	{
  		printf("Memory:%lx-%lx ",
  			ptr->map.mem_start,ptr->map.mem_end);
  	}
  	if(ptr->map.dma)
  		printf("DMA chan:%x ",ptr->map.dma);
  	printf("\n");
  }
  printf("\n");
}


static void if_getstats(char *ifname, struct interface *ife)
{
  FILE *f=fopen("/proc/net/dev","r");
  char buf[256];
  char *bp;
  if(f==NULL)
  	return;
  while(fgets(buf,255,f))
  {
  	bp=buf;
  	while(*bp&&isspace(*bp))
  		bp++;
  	if(strncmp(bp,ifname,strlen(ifname))==0 && bp[strlen(ifname)]==':')
  	{
 		bp=strchr(bp,':');
 		bp++;
 		sscanf(bp,"%d %d %d %d %d %d %d %d %d %d %d",
 			&ife->stats.rx_packets,
 			&ife->stats.rx_errors,
 			&ife->stats.rx_dropped,
 			&ife->stats.rx_fifo_errors,
 			&ife->stats.rx_frame_errors,
 			
 			&ife->stats.tx_packets,
 			&ife->stats.tx_errors,
 			&ife->stats.tx_dropped,
 			&ife->stats.tx_fifo_errors,
 			&ife->stats.collisions,
 			
 			&ife->stats.tx_carrier_errors
 		);
 		fclose(f);
 		return;
  	}
  }
  fclose(f);
}

/* Fetch the inteface configuration from the kernel. */
static int
if_fetch(char *ifname, struct interface *ife)
{
  struct ifreq ifr;

  memset((char *) ife, 0, sizeof(struct interface));
  strcpy(ife->name, ifname);

  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) return(-1);
  ife->flags = ifr.ifr_flags;

  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFADDR, &ifr) < 0) {
	memset(&ife->addr, 0, sizeof(struct sockaddr));
  } else ife->addr = ifr.ifr_addr;

  strcpy(ifr.ifr_name, ifname);
  
  if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
	memset(ife->hwaddr, 0, 32);
  } else memcpy(ife->hwaddr,ifr.ifr_hwaddr.sa_data,8);

  ife->type=ifr.ifr_hwaddr.sa_family;

  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFMETRIC, &ifr) < 0) {
	ife->metric = 0;
  } else ife->metric = ifr.ifr_metric;

  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFMTU, &ifr) < 0) {
	ife->mtu = 0;
  } else ife->mtu = ifr.ifr_mtu;

  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0) {
	memset(&ife->map, 0, sizeof(struct ifmap));
  } else memcpy(&ife->map,&ifr.ifr_map,sizeof(struct ifmap));

  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFDSTADDR, &ifr) < 0) {
	memset(&ife->dstaddr, 0, sizeof(struct sockaddr));
  } else ife->dstaddr = ifr.ifr_dstaddr;

  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFBRDADDR, &ifr) < 0) {
	memset(&ife->broadaddr, 0, sizeof(struct sockaddr));
  } else ife->broadaddr = ifr.ifr_broadaddr;

  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFNETMASK, &ifr) < 0) {
	memset(&ife->netmask, 0, sizeof(struct sockaddr));
  } else ife->netmask = ifr.ifr_netmask;
  
  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0) {
  	memset(&ife->map, 0, sizeof(struct ifmap));
  }
  else ife->map = ifr.ifr_map;
  
  if_getstats(ifname,ife);
  return(0);
}


static void
if_print(char *ifname)
{
  char buff[1024];
  struct interface ife;
  struct ifconf ifc;
  struct ifreq *ifr;
  int i;

  if (ifname == (char *)NULL) {
	ifc.ifc_len = sizeof(buff);
	ifc.ifc_buf = buff;
	if (ioctl(skfd, SIOCGIFCONF, &ifc) < 0) {
		fprintf(stderr, "SIOCGIFCONF: %s\n", strerror(errno));
		return;
	}

	ifr = ifc.ifc_req;
	for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; ifr++) {
		if (if_fetch(ifr->ifr_name, &ife) < 0) {
			fprintf(stderr, "%s: unknown interface.\n",
							ifr->ifr_name);
			continue;
		}

		if (((ife.flags & IFF_UP) == 0) && !opt_a) continue;
		ife_print(&ife);
	}
  } else {
	if (if_fetch(ifname, &ife) < 0)
		fprintf(stderr, "%s: unknown interface.\n", ifname);
	  else ife_print(&ife);
  }
}


/* Set a certain interface flag. */
static int
set_flag(char *ifname, short flag)
{
  struct ifreq ifr;

  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) return(-1);
  ifr.ifr_flags |= flag;
  if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
	fprintf(stderr, "SIOCSIFFLAGS: %s\n", strerror(errno));
	return(-1);
  }
  return(0);
}


/* Clear a certain interface flag. */
static int
clr_flag(char *ifname, short flag)
{
  struct ifreq ifr;

  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) return(-1);
  ifr.ifr_flags &= ~flag;
  if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
	fprintf(stderr, "SIOCSIFFLAGS: %s\n", strerror(errno));
	return(-1);
  }
  return(0);
}


static void
usage(void)
{
  fprintf(stderr, "Usage: ifconfig [-a] [-i] [-v] interface\n");
  fprintf(stderr, "                [inet address]\n");
  fprintf(stderr, "                [ax25] [hw] address]\n");
  fprintf(stderr, "                [metric NN] [mtu NN]\n");
  fprintf(stderr, "                [trailers] [-trailers]\n");
  fprintf(stderr, "                [arp] [-arp]\n");
  fprintf(stderr, "                [netmask aa.bb.cc.dd]\n");
  fprintf(stderr, "                [dstaddr aa.bb.cc.dd]\n");
  fprintf(stderr, "                [mem_start NN] [io_addr NN] [irq NN]\n");
  fprintf(stderr, "                [[-] broadcast [aa.bb.cc.dd]]\n");
  fprintf(stderr, "                [[-]pointopoint [aa.bb.cc.dd]]\n");
  fprintf(stderr, "                [up] [down] ...\n");
  exit(1);
}


int
main(int argc, char **argv)
{
  struct sockaddr sa;
  char host[128];
  struct aftype *ap;
  struct hwtype *hw;
  struct ifreq ifr;
  int goterr = 0;
  char **spp;

  /* Create a channel to the NET kernel. */
  if ((skfd = socket(AF_INET, SOCK_DGRAM,0)) < 0) {
	perror("socket");
	exit(-1);
  }

  /* Find any options. */
  argc--; argv++;
  while (argc && *argv[0] == '-') {
	if (!strcmp(*argv, "-a")) opt_a = 1;
	if (!strcmp(*argv, "-v")) opt_v = 1;
	argv++;
	argc--;
  }

  /* Do we have to show the current setup? */
  if (argc == 0) {
	if_print((char *)NULL);
	(void) close(skfd);
	exit(0);
  }

  /* No. Fetch the interface name. */
  spp = argv;
  strncpy(ifr.ifr_name, *spp++, IFNAMSIZ);
  if (*spp == (char *)NULL) {
	if_print(ifr.ifr_name);
	(void) close(skfd);
	exit(0);
  }

  /* The next argument is either an address family name, or an option. */
  if ((ap = get_aftype(*spp)) == NULL) {
	ap = get_aftype("inet");
  } else spp++;
  addr_family = ap->af;

  /* Process the remaining arguments. */
  while (*spp != (char *)NULL) {
	if (!strcmp(*spp, "arp")) {
		goterr |= clr_flag(ifr.ifr_name, IFF_NOARP);
		spp++;
		continue;
	}

	if (!strcmp(*spp, "-arp")) {
		goterr |= set_flag(ifr.ifr_name, IFF_NOARP);
		spp++;
		continue;
	}

	if (!strcmp(*spp, "trailers")) {
		goterr |= clr_flag(ifr.ifr_name, IFF_NOTRAILERS);
		spp++;
		continue;
	}

	if (!strcmp(*spp, "-trailers")) {
		goterr |= set_flag(ifr.ifr_name, IFF_NOTRAILERS);
		spp++;
		continue;
	}

	if (!strcmp(*spp, "promisc")) {
		goterr |= set_flag(ifr.ifr_name, IFF_PROMISC);
		spp++;
		continue;
	}

	if (!strcmp(*spp, "-promisc")) {
		goterr |= clr_flag(ifr.ifr_name, IFF_PROMISC);
		spp++;
		continue;
	}

	if (!strcmp(*spp, "allmulti")) {
		goterr |= set_flag(ifr.ifr_name, IFF_ALLMULTI);
		spp++;
		continue;
	}

	if (!strcmp(*spp, "-allmulti")) {
		goterr |= clr_flag(ifr.ifr_name, IFF_ALLMULTI);
		spp++;
		continue;
	}

	if (!strcmp(*spp, "up")) {
		goterr |= set_flag(ifr.ifr_name, (IFF_UP | IFF_RUNNING));
		spp++;
		continue;
	}

	if (!strcmp(*spp, "down")) {
		goterr |= clr_flag(ifr.ifr_name, IFF_UP);
		spp++;
		continue;
	}

	if (!strcmp(*spp, "metric")) {
		if (*++spp == NULL) usage();
		ifr.ifr_metric = atoi(*spp);
		if (ioctl(skfd, SIOCSIFMETRIC, &ifr) < 0) {
			fprintf(stderr, "SIOCSIFMETRIC: %s\n", strerror(errno));
			goterr = 1;
		}
		spp++;
		continue;
	}

	if (!strcmp(*spp, "mtu")) {
		if (*++spp == NULL) usage();
		ifr.ifr_mtu = atoi(*spp);
		if (ioctl(skfd, SIOCSIFMTU, &ifr) < 0) {
			fprintf(stderr, "SIOCSIFMTU: %s\n", strerror(errno));
			goterr = 1;
		}
		spp++;
		continue;
	}

	if (!strcmp(*spp, "-broadcast")) {
		goterr |= clr_flag(ifr.ifr_name, IFF_BROADCAST);
		spp++;
		continue;
	}

	if (!strcmp(*spp, "broadcast")) {
		if (*++spp != NULL ) {
			strcpy(host, *spp);
			if (ap->input(host, &sa) < 0) {
				ap->herror(host);
				goterr = 1;
				spp++;
				continue;
			}
			memcpy((char *) &ifr.ifr_broadaddr, (char *) &sa,
						sizeof(struct sockaddr));
			if (ioctl(skfd, SIOCSIFBRDADDR, &ifr) < 0) {
				fprintf(stderr, "SIOCSIFBRDADDR: %s\n",
							strerror(errno));
				goterr = 1;
			}
			spp++;
		}
		goterr |= set_flag(ifr.ifr_name, IFF_BROADCAST);
		continue;
	}

	if (!strcmp(*spp, "dstaddr")) {
		if (*++spp == NULL) usage();
		strcpy(host, *spp);
		if (ap->input(host, &sa) < 0) {
			ap->herror(host);
			goterr = 1;
			spp++;
			continue;
		}
		memcpy((char *) &ifr.ifr_dstaddr, (char *) &sa,
						sizeof(struct sockaddr));
		if (ioctl(skfd, SIOCSIFDSTADDR, &ifr) < 0) {
			fprintf(stderr, "SIOCSIFDSTADDR: %s\n",
						strerror(errno));
			goterr = 1;
		}
		spp++;
		continue;
	}

	if (!strcmp(*spp, "netmask")) {
		if (*++spp == NULL) usage();
		strcpy(host, *spp);
		if (ap->input(host, &sa) < 0) {
			ap->herror(host);
			goterr = 1;
			spp++;
			continue;
		}
		memcpy((char *) &ifr.ifr_netmask, (char *) &sa,
						sizeof(struct sockaddr));
		if (ioctl(skfd, SIOCSIFNETMASK, &ifr) < 0) {
			fprintf(stderr, "SIOCSIFNETMASK: %s\n",
						strerror(errno));
			goterr = 1;
		}
		spp++;
		continue;
	}

	if (!strcmp(*spp, "mem_start")) {
		if (*++spp == NULL) usage();
		if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0) {
			goterr = 1;
			continue;
		}
		ifr.ifr_map.mem_start = strtoul(*spp, NULL, 0);
		if (ioctl(skfd, SIOCSIFMAP, &ifr) < 0) {
			fprintf(stderr, "SIOCSIFMAP: %s\n", strerror(errno));
			goterr = 1;
		}
		spp++;
		continue;
	}

	if (!strcmp(*spp, "io_addr")) {
		if (*++spp == NULL) usage();
		if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0) {
			goterr = 1;
			continue;
		}
		ifr.ifr_map.base_addr = strtol(*spp, NULL, 0);
		if (ioctl(skfd, SIOCSIFMAP, &ifr) < 0) {
			fprintf(stderr, "SIOCSIFMAP: %s\n", strerror(errno));
			goterr = 1;
		}
		spp++;
		continue;
	}

	if (!strcmp(*spp, "irq")) {
		if (*++spp == NULL) usage();
		if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0) {
			goterr = 1;
			continue;
		}
		ifr.ifr_map.irq = atoi(*spp);
		if (ioctl(skfd, SIOCSIFMAP, &ifr) < 0) {
			fprintf(stderr, "SIOCSIFMAP: %s\n", strerror(errno));
			goterr = 1;
		}
		spp++;
		continue;
	}

	if (!strcmp(*spp, "-pointopoint")) {
		goterr |= clr_flag(ifr.ifr_name, IFF_POINTOPOINT);
		spp++;
		continue;
	}

	if (!strcmp(*spp, "pointopoint")) {
		if (*++spp != NULL) {
			strcpy(host, *spp);
			if (ap->input(host, &sa)) {
				ap->herror(host);
				goterr = 1;
				spp++;
				continue;
			};
			memcpy((char *) &ifr.ifr_dstaddr, (char *) &sa,
						sizeof(struct sockaddr));
			if (ioctl(skfd, SIOCSIFDSTADDR, &ifr) < 0) {
				fprintf(stderr, "SIOCSIFDSTADDR: %s\n",
							strerror(errno));
				goterr = 1;
			}
		}
		goterr |= set_flag(ifr.ifr_name, IFF_POINTOPOINT);
		spp++;
		continue;
	};

	if (!strcmp(*spp, "hw")) {
		if (*++spp == NULL) usage();
		if ((hw = get_hwtype(*spp)) == NULL) usage();
		strcpy(host, *++spp);
		if (hw->input(host, &sa) < 0) {
			ap->herror(host);
			goterr = 1;
			spp++;
			continue;
		}
		memcpy((char *) &ifr.ifr_hwaddr, (char *) &sa,
						sizeof(struct sockaddr));
		if (ioctl(skfd, SIOCSIFHWADDR, &ifr) < 0) {
			fprintf(stderr, "SIOCSIFHWADDR: %s\n",
						strerror(errno));
			goterr = 1;
		}
		spp++;
		continue;
	}

	/* If the next argument is a valid hostname, assume OK. */
	strcpy(host, *spp);
	if (ap->input(host, &sa) < 0) {
		ap->herror(host);
		usage();
	}

	memcpy((char *) &ifr.ifr_addr, (char *) &sa, sizeof(struct sockaddr));
	if (ioctl(skfd, SIOCSIFADDR, &ifr) < 0) {
		fprintf(stderr, "SIOCSIFADDR: %s\n", strerror(errno));
			goterr = 1;
	}
	goterr |= set_flag(ifr.ifr_name, (IFF_UP | IFF_RUNNING));
	spp++;
  }

  /* Close the socket. */
  (void) close(skfd);

  return(goterr);
}
