/* Sniffit -- coded by Brecht Claerhout                                   */
/*            (we can't talk'bout programming in this case)               */
/* formatted code and added support for hostname resolution - Godmar Back */ 

#include "config.h"
#include "sn_defines.h"
#include "linux_ether.h"
#include "packets.h"
#include "sn_data.h"
#ifdef INCLUDE_INTERFACE
#include "sn_interface.h"
#endif

void quit (char *prog_name)                    /* Learn to use the program */
{
	printf(
"usage: %s [-x] [-d] [-a] [-b] [-P proto] [-A char] [-p port] [-l sniflen]"
#ifdef INCLUDE_INTERFACE
" [-D tty]" 
"\n       -t<Target IP> | -s<Source IP> | -i\n",
#else
"\n       -t<Target IP> | -s<Source IP>\n",
#endif
		prog_name); 
	exit(0); 
}

char *strlower (char *string)
{
	int i;

	for(i=0;i<strlen(string);i++)
		*(string+i)=tolower(*(string+i));
	return string;
}

void reset_all (void) 
{
	start_dynam=NULL;
	dynam_len=0;
}

struct file_info *add_dynam (char *file, char ptype)
{
	FILE *f;
	struct file_info *dummy_pointer; 
	struct file_info *search_pointer; 

	if(dynam_len>=MAXCOUNT)
		{
		printf("Too many connections, not logging some (MAXCOUNT compiled %d)\n", MAXCOUNT); 
		return;
		}
	if( (dummy_pointer=malloc(sizeof(struct file_info))) == 0)
		{printf("Couldn't allocate memory.\n"); exit(0);};
	dummy_pointer->bytes=0;
	dummy_pointer->proto=ptype;
	strcpy(dummy_pointer->filename,file);
	f = fopen(file,"a");   
	if(f==NULL)
		perror("Couldn't open logfile:"),exit(0);
	dummy_pointer->f=f;
	dummy_pointer->next=NULL;

	if(start_dynam==NULL)
		start_dynam=dummy_pointer; 
	else
		{
 		search_pointer=start_dynam;
		while(search_pointer->next != NULL)
			search_pointer=search_pointer->next;
		search_pointer->next=dummy_pointer;
		}
	dynam_len++;
	return dummy_pointer;
}

void delete_dynam (char *file, char ptype)
{
	struct file_info *search_pointer;	
	struct file_info *dummy_pointer;	

	if(start_dynam==NULL) return;
	search_pointer=start_dynam;
	if( (strcmp(search_pointer->filename,file)==0) &&
						(search_pointer->proto==ptype))
		{
		fclose(search_pointer->f);
		start_dynam=search_pointer->next;
		dynam_len--;
		return;
		}
 	search_pointer=start_dynam;
	if(search_pointer->next==NULL) return;
	while(search_pointer->next != NULL)
		{
		if( (strcmp(search_pointer->next->filename,file)==0) &&
					(search_pointer->next->proto==ptype))
			{
			fclose(search_pointer->next->f);
			dummy_pointer=search_pointer->next;
			search_pointer->next=search_pointer->next->next;
			free(dummy_pointer);
			dynam_len--;
			return;
			}
		search_pointer=search_pointer->next;
		}
}

struct file_info *search_dynam(char *file, char ptype)
{
	struct file_info *search_pointer;

	if(start_dynam==NULL) return NULL;
 	search_pointer=start_dynam;
	do
		{
		if( (strcmp(search_pointer->filename,file)==0) &&
					(search_pointer->proto==ptype))
			return search_pointer;
		search_pointer=search_pointer->next;
		}
	while(search_pointer != NULL);
	return NULL;
}

void print_iphead (struct IP_header *iphead, char icmp_or_plain)
{
        int dummy;
	u_char *so,*dest;
	
	if(icmp_or_plain!=0)
		printf("ICMP message concerned following IP packet:\n");
	so=&(iphead->source);
       	dest=&(iphead->destination);
	printf("from %u.%u.%u.%u to %u.%u.%u.%u\n",
					so[0],so[1],so[2],so[3],
                                        dest[0],dest[1],dest[2],dest[3]);
        dummy=iphead->type; dummy>>=5;
        printf("IP Packet precedence: %s   (%c%c%c)\n",
	                                IP_TYPE_precedence[dummy],
                                        (iphead->type&IP_DELAY)?'D':'-',
                                        (iphead->type&IP_THROUGHPUT)?'T':'-',
                                        (iphead->type&IP_RELIABILITY)?'R':'-');
        dummy=ntohs(iphead->flag_offset); dummy>>=13;
        printf("FLAGS: %s %s     Time to live (secs): %d\n",
	                                (dummy&IP_DF)?"DF":"--",
                                        (dummy&IP_DELAY)?"MF":"--",
	                                 iphead->TTL);
        if(iphead->protocol < 34)
                printf("Protocol (%d): %s\n",iphead->protocol,
		                IP_PROTOCOL_number[iphead->protocol]);
        else    printf("Protocol (%d) not recognised\n",iphead->protocol);
	printf("\n");
}

int check_packet(u_long ipaddr,
		const struct packetheader *p_header, 
		const u_char *sp,
		char *file,
		struct unwrap *info,
		char *detail,
		int MODE)       
                                          /* MODE 0: -t   MODE 1: -s */
                                          /* MODE 2: -b              */ 
{
        u_char *so,*dest;
	struct IP_header *iphead;
	struct TCP_header *tcphead;
	struct ICMP_header *icmphead;
	struct UDP_header *udphead;
	int proto;

	proto=unwrap_packet(sp, info); 
	iphead = make_IP_struct (sp);
	so=&(iphead->source);
       	dest=&(iphead->destination);

	if((proto==TCP)&&(PROTOCOLS&F_TCP)) 
		{
		tcphead = make_TCP_struct(sp, info->IP_len);
		memcpy(detail,tcphead,sizeof(struct TCP_header));

		if (MODE == DEST && ipaddr != iphead->destination /* -t */
			||
		    MODE == SOURCE && ipaddr != iphead->source      /* -s */
			||
		    MODE == BOTH && ipaddr != iphead->destination /* -b */
			      && ipaddr != iphead->source
	   	    )      return DONT_EXAMINE;	/* Check destination/source IP */

		if( DEST_PORT && ntohs(tcphead->destination) != DEST_PORT) 
			return DONT_EXAMINE; 	/* Check dest. PORT */

                          /* inet_ntoa gave wrong output sometimes */
		sprintf(file,"%u.%u.%u.%u.%u-%u.%u.%u.%u.%u",
					so[0],so[1],so[2],so[3],
					ntohs(tcphead->source),
					dest[0],dest[1],dest[2],dest[3],
					ntohs(tcphead->destination));

		if ((ntohs(tcphead->offset_flag) & FIN) != 0)  
						/* check for reset conn. */
			return TCP_FINISH;            /* packet is a FIN */

		/*
		Used to be for speed, '-x' needs all info, so this too!
		if (info->DATA_len == 0)
  			return DONT_EXAMINE;        
		*/

		return TCP_EXAMINE;                 /* interprete packet */
		};
	if((proto==ICMP)&&(PROTOCOLS&F_ICMP))      /* ICMP packet checking */
		{
		icmphead = make_ICMP_struct(sp, info->IP_len);
		memcpy(detail,icmphead,sizeof(struct ICMP_header));
		sprintf(file,"%u.%u.%u.%u > %u.%u.%u.%u",
					so[0],so[1],so[2],so[3],
					dest[0],dest[1],dest[2],dest[3]);
		return ICMP_EXAMINE;
		};
	if((proto==UDP)&&(PROTOCOLS&F_UDP))       /* UDP packet checking */
		{
		udphead = make_UDP_struct(sp, info->IP_len);
		memcpy(detail,udphead,sizeof(struct UDP_header));
		sprintf(file,"%u.%u.%u.%u.%u-%u.%u.%u.%u.%u",
					so[0],so[1],so[2],so[3],
					ntohs(udphead->source),
					dest[0],dest[1],dest[2],dest[3],
					ntohs(udphead->destination));
		return UDP_EXAMINE;
		}
	return DONT_EXAMINE;
}

/* Default Processing of packets */
void packethandler(	u_long ipaddr, 
			const struct packetheader *p_header, 
			const u_char *sp) 
{ 
	char filename[50],header[1500];
	FILE *f;
	struct file_info *dummy_pointer;
	u_char status=0;
	int dummy,finish;                    /* look out it's signed */
	u_long datalen, position, total_length, i, n;
	struct unwrap info;
        struct IP_header *iphead;
	struct TCP_header *tcphead;
	struct ICMP_header *icmphead;
	struct IP_header *iphead_icmp;
        struct UDP_header *udphead;

   	finish=check_packet(ipaddr,p_header,sp,filename,&info,header,SNIFMODE); 
        if(PROTOCOLS & F_IP)
                iphead=sp+ETHERHEAD, print_iphead(iphead,0);
        if(finish==DONT_EXAMINE) 
		return;                         /* Packet is not for us */

	if((DUMPMODE & 32)&&(finish<10))	/* extended info TCP only */
		{
		tcphead=header;
		dummy=ntohs(tcphead->offset_flag);  
		printf("\n");
		printf("TCP Packet ID (from_IP.port-to_IP.port): %s\n",filename);
		printf("   SEQ (hex): %lX   ",ntohl(tcphead->seq_nr));
		if(dummy&ACK) printf("ACK (hex): %lX\n",ntohl(tcphead->ACK_nr));
		printf("   FLAGS: %c%c%c%c%c%c",
				(dummy&URG)?'U':'-',(dummy&ACK)?'A':'-',
				(dummy&PSH)?'P':'-',(dummy&RST)?'R':'-',
				(dummy&SYN)?'S':'-',(dummy&FIN)?'F':'-');
		if(dummy&ACK) 
			printf("   Window: %X\n",ntohs(tcphead->window));
		};

	if(finish<10)			/* TCP packet */
		/* I didn't use flags for later extention, and they */ 
		/* don't come in pairs anyhow */
		/* use return instead of else {if}, for later extention */
		{
		tcphead=header;
		switch(DUMPMODE & 223) 
		  {
		  case 0:                     /* LOG mode */
		  status=0;

	  	  dummy_pointer=search_dynam(filename, TCP);
		  if(dummy_pointer!=NULL) status=1; 
		  /* make a new entry unless it's reset */
		  if(status==0)               
		  	{
  			if(finish==TCP_FINISH) return;      
					/* there was never data transmitted */
			dummy_pointer=add_dynam(filename, TCP);
			}
		  f=dummy_pointer->f;

		  if(dummy_pointer->bytes<=SNIFLEN) {
			const u_char *data = 
					sp+ETHERHEAD+info.IP_len+info.TCP_len;
			if(SNIFLEN!=0)
				dummy_pointer->bytes+=info.DATA_len;       
						/* last packet is written  */
                                                /* don't care about length */
			if(ASC==0)
				{for(i=0;i<info.DATA_len;i++) 
					fprintf(f,"%c", data[i]);}
			else    {
				for(i=0;i<info.DATA_len;i++) 
					fprintf(f,"%c", isprint(data[i])?data[i]:non_printable);
				};
  			fflush(f);                                                  /* write all */
			}
		  if(finish==TCP_FINISH) /* let's reset the connection */
			delete_dynam(filename, TCP);
		  break;
		
		  case 1:         /* DUMP mode */
	  	  case 2:
		  case 3:
		  	printf("Packet ID (from_IP.port-to_IP.port): %s\n",filename);
			total_length=info.IP_len+info.TCP_len+info.DATA_len;
			n = 0;
			for(i=0;i<total_length;i++) {
				u_char c = sp[ETHERHEAD+i];
				if(n > 75)
					n=0, printf("\n");
				if(DUMPMODE & 1)
					n += printf(" %02X",c); 
				if(DUMPMODE & 2)
					n += printf(" %c",isprint(c)?c:'.');
			}
			printf("\n\n");
			break;
		
  		  default: 
			printf("\nImpossible error! Sniffer Hartattack!\n");
			exit(0); 
		  }
	      	return;
		}
	
	if(finish<20)			/* ICMP packet */
		{
		icmphead=header;
		iphead_icmp=sp+ETHERHEAD+info.IP_len+ICMP_HEADLENGTH+4; 
		printf("ICMP message id: %s\n",filename);
		printf("  ICMP type: ");
		switch(icmphead->type)
			{
			case 0: printf("%s\n",ICMP_TYPE_0);
				break;
			case 3: printf("%s\n",ICMP_TYPE_3);
				printf("  Error: %s\n",
					ICMP_type_3_code[icmphead->code]);
				print_iphead(iphead_icmp,1);
				break;
			case 4: printf("%s\n",ICMP_TYPE_4);
				print_iphead(iphead_icmp,1);
				break;
			case 5: printf("%s\n",ICMP_TYPE_5);
				printf("  Error: %s\n",
					ICMP_type_5_code[icmphead->code]);
				print_iphead(iphead_icmp,1);
				break;
			case 8: printf("%s\n",ICMP_TYPE_8);
				break;
			case 11:printf("%s\n",ICMP_TYPE_11);
				printf("  Error: %s\n",
					ICMP_type_11_code[icmphead->code]);
				print_iphead(iphead_icmp,1);
				break;
			case 12:printf("%s\n",ICMP_TYPE_12);
				print_iphead(iphead_icmp,1);
				break;
			case 13:printf("%s\n",ICMP_TYPE_13);
				break;
			case 14: printf("%s\n",ICMP_TYPE_14);
				break;
			case 15: printf("%s\n",ICMP_TYPE_15);
				break;
			case 16: printf("%s\n",ICMP_TYPE_16);
				break;
			case 17: printf("%s\n",ICMP_TYPE_17);
				break;
			case 18: printf("%s\n",ICMP_TYPE_18);
				break;
			default: printf("Unknown ICMP type!\n");break;
		 	}
		printf("\n");
		return;
		}
	if(finish<30)                   /* nothing yet */
		{
		udphead=header;
		switch(DUMPMODE & 223) 
		  {
		  case 0: break;
		  case 1:         /* DUMP mode */
	  	  case 2:
		  case 3:
		  	printf("UDP Packet ID (from_IP.port-to_IP.port): %s\n",filename);
			total_length=info.IP_len+info.UDP_len+info.DATA_len;
			n = 0;
			for(i=0;i<total_length;i++) 
				{
				u_char c = sp[ETHERHEAD+i];
				if(n > 75)
					n=0, printf("\n");
				if(DUMPMODE & 1)
					n += printf(" %02X",c); 
				if(DUMPMODE & 2)
					n += printf(" %c",isprint(c)?c:'.');
				}
			printf("\n\n");
			break;
  		  default: 
			printf("\nImpossible error! Sniffer Hartattack!\n");
			exit(0);
		  } 
		return;
		}
}


#ifdef INCLUDE_INTERFACE
/* Interactive packethandling */
int check_mask (const struct packetheader *p_header, 
		const u_char *sp,
		char *conn_name,
		struct unwrap *info)
                                          /* return -1 : packet not for us */
                                          /* else finish value             */
{
        u_char *so,*dest;
	struct IP_header *iphead;
	struct TCP_header *tcphead;

	if(unwrap_packet(sp, info)!=TCP)  return DONT_EXAMINE;  
							/* Not a TCP packet */ 
	iphead = make_IP_struct (sp);
	tcphead = make_TCP_struct(sp, info->IP_len);

        if(mask->source_ip!=0 && iphead->source!=mask->source_ip)
		return DONT_EXAMINE;
        if(mask->destination_ip!=0 && iphead->destination!=mask->destination_ip)
		return DONT_EXAMINE;
	if( mask->destination_port && ntohs(tcphead->destination) != mask->destination_port) 
		return DONT_EXAMINE; 
	if( mask->source_port && ntohs(tcphead->source) != mask->source_port) 
		return DONT_EXAMINE; 

                          /* inet_ntoa gave wrong output sometimes */
	so=&(iphead->source);
        dest=&(iphead->destination);
	sprintf(conn_name,"from %u.%u.%u.%u %u to %u.%u.%u.%u %u",
				so[0],so[1],so[2],so[3],
				ntohs(tcphead->source),
				dest[0],dest[1],dest[2],dest[3],
				ntohs(tcphead->destination));

	if ((ntohs(tcphead->offset_flag) & FIN) != 0)/* check for reset conn. */
		return TCP_FINISH;                        /* packet is a FIN */
	if (info->DATA_len == 0)
  		return DONT_EXAMINE;                   /* packet not for us */
	return TCP_EXAMINE;                            /* interprete packet */
}

void interactive_packethandler(	char *dummy, 
			 	const struct packetheader *p_header, 
				const u_char *sp) 
{ 
	char conn_name[CONN_NAMELEN];
	int finish;                    /* look out it's signed */
	struct unwrap info;

	finish=check_mask(p_header,sp,conn_name,&info); 
	if(finish==DONT_EXAMINE) return;         /* Packet is not for us */
	if(finish!=TCP_FINISH) 
                    /* if finish: it is already logged, or to short to add */
		add_itemlist(running_connections,conn_name);
	if(strcmp(logged_connection, conn_name)==0)
		{
                const u_char *data=sp+ETHERHEAD+info.IP_len+info.TCP_len;
 		if(*DATAlength+info.DATA_len < LENGTH_OF_INTERPROC_DATA)
			{
			memcpy((connection_data+*DATAlength),data,info.DATA_len);
			*DATAlength+=info.DATA_len;
			}             
		}
	if(finish==TCP_FINISH)
		del_itemlist(running_connections,conn_name);
	kill(getppid(),SIGUSR1);
}
#endif

static u_long getaddrbyname(char *name)
{
    struct hostent *he;

    if(isdigit(*name))
	return inet_addr(name);
    if(!(he = gethostbyname(name)))
        perror(name);
    return he ? *(long*)*he->h_addr_list : 0;
}

int main(int argc,char *argv[])
{
	char c, *dev, buffer[SNAPLEN];
	char *IP;
	u_long ipaddr, memsize;
	int flag=0, doboth=0;

	SNIFLEN=300;                            /* Set defaults */
	DEST_PORT=0;                            /* Dest Port */
	SNIFMODE=DUMPMODE=PROTOCOLS=ASC=0;
	IP=logging_device=NULL;          
	while((c=getopt(argc,argv,"D:A:P:idp:l:xabt:s:"))!=-1) { 
                                                    /* Argument treating */
  		switch(c) {
			case 'd':
				DUMPMODE|=1;
				break;
			case 'a':
				DUMPMODE|=2;
				break;
			case 'x':
				DUMPMODE|=32;
				break;
			case 'p':
				DEST_PORT=atoi(optarg);
				break;
			case 'l':
				SNIFLEN=atol(optarg);
				break;
			case 'b':
				doboth=1;
				break;
			case 'A':
				ASC=1;
				non_printable=*optarg;
				break; 
			case 'D':
				logging_device=optarg;
				break; 
			case 'P':
				optarg=strlower(optarg);
				if(strstr(optarg,"tcp")) PROTOCOLS |= F_TCP;
				if(strstr(optarg,"icmp")) PROTOCOLS |= F_ICMP;
				if(strstr(optarg,"udp")) PROTOCOLS |= F_UDP;
                                if(strstr(optarg,"ip")) PROTOCOLS |= F_IP;
		                break;
			case 's':
				flag++;
				SNIFMODE=SOURCE;
				IP=optarg;
				break; 
			case 't':
				flag++;
				SNIFMODE=DEST;
				IP=optarg;
				break; 
                        case 'i':
                                flag++;
				SNIFMODE=INTERACTIVE;
                                break;
      			default : break;
		}
	}
	if(flag!=1) 
		quit(argv[0]);
	if(PROTOCOLS==0) PROTOCOLS |= F_TCP;
	if(doboth) SNIFMODE=BOTH;
        if(SNIFMODE!=INTERACTIVE)  ipaddr = getaddrbyname(IP);
	reset_all();       /* just to be sure */

	if((dev=lookup_device())==NULL) 
		printf("No suitable device found.\n"),
		exit(0);

	if((dev_desc=open_device(dev,SNAPLEN,MSDELAY))==NULL)
		printf("Couldn't open device.\n"),
		exit(0);

#ifdef INCLUDE_INTERFACE
        if (SNIFMODE==INTERACTIVE)
 		{
		memsize=sizeof(char)+sizeof(int)+LENGTH_OF_INTERPROC_DATA+
			sizeof(int)+sizeof(struct snif_mask)+CONN_NAMELEN+
			(CONNECTION_CAPACITY*CONN_NAMELEN);
		memory_id = shmget(0,memsize,0700);
		if(memory_id<0)
  			{perror("Interactive Sniffer Hartattack (No Shared mem avail!)");
			exit(0);}
		atexit(mem_exit);
		if((SHARED=shmat(memory_id,0,SHM_RND))==NULL)
  			{perror("Interactive Sniffer Hartattack (Wow something is wrong here)");
   			exit(0);};
                printf("Entering Shared memory at %p\n",SHARED);


		timing = SHARED;                    /* set all pointers */
		DATAlength = timing + sizeof(char);
		connection_data = DATAlength + sizeof(int);
		LISTlength = connection_data + LENGTH_OF_INTERPROC_DATA;
		mask = LISTlength + sizeof(int);
		logged_connection = mask + sizeof(struct snif_mask);
		running_connections = logged_connection + CONN_NAMELEN;
		clear_shared_mem(0);

		if ((Pid=fork())<0)
  			{perror("Interactive Sniffer Hartattack (Couldn't fork)");
   			exit(0);};
		if(Pid==0)
			{
			sleep(4);
			while(1)
  			  if(read_device(dev_desc,PACKETS,
					interactive_packethandler,NULL)<0)
	    			printf("Capturing Packets Failed\n"), exit(0);
			}
		else	{
                        atexit(child_exit);
			signal(SIGCHLD,SIG_IGN);
			if(logging_device != NULL)
				{
				if(stat(logging_device,&log_dev_stat)<0)
					perror("\'-D\' option error"),exit(0);
				if((log_dev_stream=fopen(logging_device,"a")) 
									== NULL)
					printf("Couldn't open device for logging output\n"),exit(0);
				}
			run_interface();
			}
		}
 	else 	{
#endif
		printf("Sniffit.%s is up and running.... (%s|%s)\n\n",VERSION,
							IP, inet_ntoa(ipaddr));
		while(1)
  		  if(read_device(dev_desc,PACKETS,packethandler,ipaddr)<0)
    			printf("Capturing Packets Failed\n"), exit(0);
#ifdef INCLUDE_INTERFACE
		}
#endif	
/* Close device?  Nahhh.... fuck it! we don't get here anyway!*/
}

