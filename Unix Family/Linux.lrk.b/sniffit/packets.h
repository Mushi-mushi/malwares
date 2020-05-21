/* Sniffit Packet Discription File -- Brecht Claerhout */

#define ETHERHEAD 14 /* Length Ethernet Packet header */ 
#define URG 32       /*TCP-flags */ 
#define ACK 16 
#define PSH 8 
#define RST 4 
#define SYN 2
#define FIN 1

#define ICMP	1			/* Protocol Numbers */
#define TCP	6
#define UDP	17

#define ICMP_HEADLENGTH	4		/* fixed ICMP header length */
#define UDP_HEADLENGTH	8		/* fixed UDP header length */

#define IP_DELAY	32
#define IP_THROUGHPUT	16
#define IP_RELIABILITY	8

#define IP_DF	2
#define IP_MF	1
  
char *IP_TYPE_precedence[8]=
	{"Routine", "Priority", "Immediate", "Flash", "Flash override",
	"Critical", "Internetwork control", "Network control"}; 

char *IP_PROTOCOL_number[34]=
     {"Reserved","ICMP","IGMP","GGP","Unassigned","ST","TCP","UCL","EGP","IGP",
      "BBN-MON","NVP-II","PUP","ARGUS","EMCOM","XNET","CHAOS","UDP","MUX",
      "DCN-MEAS","HMP","PRM","XNS-IDP","TRUNK-1","TRUNK-2","LEAF-1","LEAF-2",
      "RDP","IRTP","ISO-TP4","NETBLT","MFE-NSP","MERIT-INP","SEP"};
	

#define ICMP_TYPE_0	"Echo reply"
#define ICMP_TYPE_3	"Destination unreachable"
#define ICMP_TYPE_4	"Source quench"	
#define ICMP_TYPE_5	"Redirect"
#define ICMP_TYPE_8	"Echo"
#define ICMP_TYPE_11	"Time exceeded"
#define ICMP_TYPE_12	"Parameter problem"
#define ICMP_TYPE_13	"Timestamp"
#define ICMP_TYPE_14	"Timestamp reply"
#define ICMP_TYPE_15	"Information request"
#define ICMP_TYPE_16	"Information reply"
#define ICMP_TYPE_17	"Address mask request"
#define ICMP_TYPE_18	"Adress mask reply"

char *ICMP_type_3_code[6]=
	{"Net unreachable", "Host unreachable", "Protocol unreachable",
	"Port unreachable", "Fragmentation needed and DF set",
	"Source route failed"};
char *ICMP_type_5_code[4]=
	{"Redirect datagrams for the network",
	"Redirect datagrams for the host",
	"Redirect datagrams for the \'type of service\' and the network",
	"Redirect datagrams for the \'type of service\' and the host"};
char *ICMP_type_11_code[2]=
	{"Time-to-live exceeded in transmit",
	"Fragment reassembly time exceeded"};


struct IP_header                        /* The IPheader (without options) */
{
	unsigned char verlen, type;
	unsigned short length, ID, flag_offset;
	unsigned char TTL, protocol;
	unsigned short checksum;
	unsigned long int source, destination;
};

struct TCP_header                       /* The TCP header (without options) */
{
	unsigned short source, destination;
	unsigned long int seq_nr, ACK_nr;
	unsigned short offset_flag, window, checksum, urgent; 
};

struct ICMP_header                                /* The ICMP header */ 
{
	unsigned char type, code;
	unsigned short checksum; 
};

struct UDP_header                                /* The UDP header */ 
{
	unsigned short source, destination;
	unsigned short length, checksum;
};

struct unwrap                                           /* some extra info */
{
	int IP_len, TCP_len, ICMP_len, UDP_len, DATA_len;
};

struct IP_header  *make_IP_struct (const u_char *sp)           
{
	return (struct IP_header *)(sp+ETHERHEAD);
}

struct TCP_header *make_TCP_struct (const u_char *sp,int IP_len) 
{return (struct TCP_header *)(sp+ETHERHEAD+IP_len);}

struct ICMP_header *make_ICMP_struct (const u_char *sp,int IP_len) 
{return (struct ICMP_header *)(sp+ETHERHEAD+IP_len);}

struct ICMP_header *make_UDP_struct (const u_char *sp,int IP_len) 
{return (struct UDP_header *)(sp+ETHERHEAD+IP_len);}

int unwrap_packet (const u_char *sp, struct unwrap *unwrapped) 
{ 
	struct IP_header  *IPhead = make_IP_struct(sp);
	struct TCP_header *TCPhead;
	struct ICMP_header *ICMPhead;
	struct UDP_header *UDPhead;
                                                  /* IP header Conversion */
	unwrapped->IP_len = (IPhead->verlen & 0xF) << 2;
	if(IPhead->protocol == TCP )		  /* not TCP */
		{
		TCPhead = (struct TCP_header *) (sp+ETHERHEAD+
							(unwrapped->IP_len));
		unwrapped->TCP_len = ntohs(TCPhead->offset_flag) & 0xF000;
		unwrapped->TCP_len >>= 10; 
		unwrapped->DATA_len = ntohs(IPhead->length) -
				(unwrapped->IP_len) - (unwrapped->TCP_len); 
                                                /* ICMP header Conversion */
		return TCP;
		}
	if(IPhead->protocol == ICMP )		  /* not ICMP */
		{
		ICMPhead = (struct ICMP_header *) (sp+ETHERHEAD+
							(unwrapped->IP_len));

		unwrapped->ICMP_len = ICMP_HEADLENGTH;
		unwrapped->DATA_len = ntohs(IPhead->length) -
				(unwrapped->IP_len) - (unwrapped->ICMP_len); 
		return ICMP; 
		}
	if(IPhead->protocol == UDP )		  /* not UDP */
		{
		UDPhead = (struct UDP_header *) (sp+ETHERHEAD+
							(unwrapped->IP_len));

		unwrapped->UDP_len = UDP_HEADLENGTH;
		unwrapped->DATA_len = ntohs(IPhead->length) -
				(unwrapped->IP_len) - (unwrapped->UDP_len); 
		return UDP; 
		}
	return -1; 
}

