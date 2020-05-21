/* adapted from tcpdump */


struct iphdr {
  u_char  ihl;
  u_char  tos;		/* type of service */
  short   tot_len;	/* total length */
  u_short id;		/* identification */
  short   off;		/* fragment offset field */
#define IP_DF   0x4000	/* dont fragment flag */
#define IP_MF   0x2000	/* more fragments flag */
  u_char  ttl;		/* time to live */
  u_char  protocol;	/* protocol */
  u_short check;	/* checksum */
  u_long  saddr; 
  u_long  daddr;  /* source and dest address */
};



