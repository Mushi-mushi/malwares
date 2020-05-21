/*
  File: sshinet.h

  Authors: 
        Tero T Mononen <tmo@ssh.fi>
        Tero Kivinen <kivinen@ssh.fi>
        Tatu Ylonen <ylo@ssh.fi>

  Description: 
        IP protocol specific definitions.  This file also contains functions
        and macros for manipulating IP addresses in various forms, as well
        as for manipulating IP, TCP, and UDP headers.  This file also
        contains definitions specific to various media types (e.g. ethernet).

  Copyright:
        Copyright (c) 1998-1999 SSH Communications Security, Finland
        All rights reserved
*/

#ifndef SSHINET_H
#define SSHINET_H

#include "sshgetput.h"
#include "sshenum.h"

/* IP protocol names to keywords definitions */
extern const SshKeyword ssh_ip_protocol_id_keywords[];

/* IP protocol identifiers */
typedef enum {
  SSH_IPPROTO_ANY = 0,       /* Any protocol */
  SSH_IPPROTO_ICMP = 1,      /* Internet Control Message [RFC792] */
  SSH_IPPROTO_IGMP = 2,      /* Internet Group Mgmt [RFC1112] */
  SSH_IPPROTO_GGP = 3,       /* Gateway-to-Gateway [RFC823] */
  SSH_IPPROTO_IPIP = 4,      /* IP in IP [RFC2003] */
  SSH_IPPROTO_ST = 5,        /* Stream [RFC1190] */
  SSH_IPPROTO_TCP = 6,       /* Transmission Control [RFC793] */
  SSH_IPPROTO_CBT = 7,       /* CBT [Ballardie] */
  SSH_IPPROTO_EGP = 8,       /* Exterior GW Protocol [RFC888] */
  SSH_IPPROTO_IGP = 9,       /* any private interior GW [IANA] */
  SSH_IPPROTO_BBN = 10,      /* BBN RCC Monitoring [SGC] */
  SSH_IPPROTO_NVP = 11,      /* Network Voice Protocol [RFC741] */
  SSH_IPPROTO_PUP = 12,      /* PUP [PUP XEROX] */
  SSH_IPPROTO_ARGUS = 13,    /* ARGUS [RWS4] */
  SSH_IPPROTO_EMCON = 14,    /* EMCON [BN7] */
  SSH_IPPROTO_XNET = 15,     /* Cross Net Debugger [IEN158] */
  SSH_IPPROTO_CHAOS = 16,    /* Chaos [NC3] */
  SSH_IPPROTO_UDP = 17,      /* User Datagram [RFC768 JBP] */
  SSH_IPPROTO_MUX = 18,      /* Multiplexing [IEN90 JBP] */
  SSH_IPPROTO_DCN = 19,      /* DCN Measurement Subsystems [DLM1] */
  SSH_IPPROTO_HMP = 20,      /* Host Monitoring [RFC869 RH6] */
  SSH_IPPROTO_PRM = 21,      /* Packet Radio Measurement [ZSU] */
  SSH_IPPROTO_XNS = 22,      /* XEROX NS IDP [ETHERNET XEROX] */
  SSH_IPPROTO_TRUNK1 = 23,   /* Trunk-1 [BWB6] */
  SSH_IPPROTO_TRUNK2 = 24,   /* Trunk-2 [BWB6] */
  SSH_IPPROTO_LEAF1 = 25,    /* Leaf-1 [BWB6] */
  SSH_IPPROTO_LEAF2 = 26,    /* Leaf-2 [BWB6] */
  SSH_IPPROTO_RDP = 27,      /* Reliable Data Protocol [RFC908] */
  SSH_IPPROTO_IRTP = 28,     /* Reliable Transaction  [RFC938] */
  SSH_IPPROTO_ISOTP4 = 29,   /* ISO Transport [RFC905 RC77] */
  SSH_IPPROTO_NETBLT = 30,   /* Bulk Data Transfer [RFC969] */
  SSH_IPPROTO_MFE = 31,      /* MFE Network Services [MFENET] */
  SSH_IPPROTO_MERIT = 32,    /* MERIT Internodal Protocol [HWB] */
  SSH_IPPROTO_SEP = 33,      /* Sequential Exchange [JC120] */
  SSH_IPPROTO_3PC = 34,      /* Third Party Connect [SAF3] */
  SSH_IPPROTO_IDPR = 35,     /* InterDomain Policy Routing [MXS1] */
  SSH_IPPROTO_XTP = 36,      /* XTP [GXC] */
  SSH_IPPROTO_DDP = 37,      /* Datagram Delivery [WXC] */
  SSH_IPPROTO_IDPRC = 38,    /* IDPR Control Msg Transport [MXS1] */
  SSH_IPPROTO_TP = 39,       /* TP++ Transport [DXF] */
  SSH_IPPROTO_IL = 40,       /* IL Transport [Presotto] */
  SSH_IPPROTO_IPV6 = 41,     /* Ipv6 [Deering] */
  SSH_IPPROTO_SDRP = 42,     /* Source Demand Routing  [DXE1] */
  SSH_IPPROTO_IPV6ROUTE = 43,/* Routing Hdr for IPv6 [Deering] */
  SSH_IPPROTO_IPV6FRAG = 44, /* Fragment Hdr for IPv6 [Deering] */
  SSH_IPPROTO_IDRP = 45,     /* Inter-Domain Routing [Sue Hares] */
  SSH_IPPROTO_RSVP = 46,     /* Reservation Protocol [Bob Braden] */
  SSH_IPPROTO_GRE = 47,      /* General Routing Encapsulation */
  SSH_IPPROTO_MHRP = 48,     /* Mobile Host Routing */
  SSH_IPPROTO_BNA = 49,      /* BNA [Gary Salamon] */
  SSH_IPPROTO_ESP = 50,      /* Encap Security Payload [RFC1827] */
  SSH_IPPROTO_AH = 51,       /* Authentication Header [RFC1826] */
  SSH_IPPROTO_INLSP = 52,    /* Integrated Net Layer Sec TUBA */
  SSH_IPPROTO_SWIPE = 53,    /* IP with Encryption [JI6] */
  SSH_IPPROTO_NARP = 54,     /* NBMA Address Resolution [RFC1735] */
  SSH_IPPROTO_MOBILE = 55,   /* IP Mobility [Perkins] */
  SSH_IPPROTO_TLSP = 56,     /* TLS with Kryptonet KM [Oberg] */
  SSH_IPPROTO_SKIP = 57,     /* SKIP [Markson] */
  SSH_IPPROTO_IPV6ICMP = 58, /* ICMP for IPv6 [RFC1883] */
  SSH_IPPROTO_IPV6NONXT = 59,/* No Next Header for IPv6 [RFC1883] */
  SSH_IPPROTO_IPV6OPTS = 60, /* Opts IPv6 host internal [RFC1883] */
  SSH_IPPROTO_CFTP = 62,     /* CFTP [CFTP,H CF2] */
  SSH_IPPROTO_LOCAL = 63,    /* local network [IANA] */
  SSH_IPPROTO_SAT = 64,      /* SATNET and Backroom EXPAK [SHB] */
  SSH_IPPROTO_KRYPTOLAN = 65,/* Kryptolan [PXL1] */
  SSH_IPPROTO_RVD = 66,      /* MIT Remote Virtual Disk [MBG] */
  SSH_IPPROTO_IPPC = 67,     /* Internet Pluribus Packet Core */
  SSH_IPPROTO_DISTFS = 68,   /* Any distributed FS [IANA] */
  SSH_IPPROTO_SATMON = 69,   /* SATNET Monitoring [SHB] */
  SSH_IPPROTO_VISA = 70,     /* VISA Protocol [GXT1] */
  SSH_IPPROTO_IPCV = 71,     /* Internet Packet Core Utility */
  SSH_IPPROTO_CPNX = 72,     /* Computer Network Executive */
  SSH_IPPROTO_CPHB = 73,     /* Computer Heart Beat */
  SSH_IPPROTO_WSN = 74,      /* Wang Span Network [VXD] */
  SSH_IPPROTO_PVP = 75,      /* Packet Video Protocol [SC3] */
  SSH_IPPROTO_BRSATMON = 76, /* Backroom SATNET Monitoring [SHB] */
  SSH_IPPROTO_SUNND = 77,    /* SUN ND PROTOCOL-Temporary [WM3] */
  SSH_IPPROTO_WBMON = 78,    /* WIDEBAND Monitoring [SHB] */
  SSH_IPPROTO_WBEXPAK = 79,  /* WIDEBAND EXPAK [SHB] */
  SSH_IPPROTO_ISOIP = 80,    /* ISO Internet Protocol [MTR] */
  SSH_IPPROTO_VMTP = 81,     /* VMTP [DRC3] */
  SSH_IPPROTO_SECUREVMTP = 82, /* SECURE-VMTP [DRC3] */
  SSH_IPPROTO_VINES = 83,    /* VINES [BXH] */
  SSH_IPPROTO_TTP = 84,      /* TTP [JXS] */
  SSH_IPPROTO_NSFNET = 85,   /* NSFNET-IGP [HWB] */
  SSH_IPPROTO_DGP = 86,      /* Dissimilar Gateway [DGP] */
  SSH_IPPROTO_TCF = 87,      /* TCF [GAL5] */
  SSH_IPPROTO_EIGRP = 88,    /* EIGRP [CISCO GXS] */
  SSH_IPPROTO_OSPFIGP = 89,  /* OSPFIGP [RFC1583 JTM4] */
  SSH_IPPROTO_SPRITE = 90,   /* Sprite RPC [SPRITE BXW] */
  SSH_IPPROTO_LARP = 91,     /* Locus Address Resolution [BXH] */
  SSH_IPPROTO_MTP = 92,      /* Multicast Transport [SXA] */
  SSH_IPPROTO_AX25 = 93,     /* AX.25 Frames [BK29] */
  SSH_IPPROTO_IPWIP = 94,    /* IP-within-IP Encapsulation [JI6] */
  SSH_IPPROTO_MICP = 95,     /* Mobile Internetworking Ctrl [JI6] */
  SSH_IPPROTO_SCC = 96,      /* Semaphore Communications [HXH] */
  SSH_IPPROTO_ETHERIP = 97,  /* Ethernet-within-IP Encapsulation */
  SSH_IPPROTO_ENCAP = 98,    /* Encapsulation Header [RFC1241] */
  SSH_IPPROTO_ENCRYPT = 99,  /* Any private encryption [IANA] */
  SSH_IPPROTO_GMTP = 100,    /* GMTP [RXB5] */
  SSH_IPPROTO_IFMP = 101,    /* Ipsilon Flow Management [Hinden] */
  SSH_IPPROTO_PNNI = 102,    /* PNNI over IP [Callon] */
  SSH_IPPROTO_PIM = 103,     /* Protocol Independent Multicast */
  SSH_IPPROTO_ARIS = 104,    /* ARIS [Feldman] */
  SSH_IPPROTO_SCPS = 105,    /* SCPS [Durst] */
  SSH_IPPROTO_QNX = 106,     /* QNX [Hunter] */
  SSH_IPPROTO_AN = 107,      /* Active Networks [Braden] */
  SSH_IPPROTO_IPPCP = 108,   /* IP Payload Compr Protocol */
  SSH_IPPROTO_SNP = 109,     /* Sitara Networks Protocol */
  SSH_IPPROTO_COMPAQ = 110,  /* Compaq Peer Protocol */
  SSH_IPPROTO_IPXIP = 111,   /* IPX in IP [Lee] */
  SSH_IPPROTO_VRRP = 112,    /* Virtual Router Redundancy */
  SSH_IPPROTO_PGM = 113,     /* PGM Reliable Transport */
  SSH_IPPROTO_0HOP = 114,    /* Any 0-hop protocol [IANA] */
  SSH_IPPROTO_L2TP = 115,    /* Layer Two Tunneling [Aboba] */
  SSH_IPPROTO_RESERVED = 255 /* Reserved [IANA] */
} SshInetIPProtocolID;

#define SSH_IPPROTO_MIN (  0)
#define SSH_IPPROTO_MAX (255)
#define SSH_IPPROTO_MAX (255)

/* Minimum length of the ICMP header. */
#define SSH_ICMP_MINLEN  8

/* ICMP types and codes */
typedef enum {
  SSH_ICMP_TYPE_ECHOREPLY = 0,           /* Echo reply */
  SSH_ICMP_TYPE_UNREACH = 3,             /* Destination unreachable */
  SSH_ICMP_TYPE_SOURCEQUENCH = 4,        /* Congestion slow down */
  SSH_ICMP_TYPE_REDIRECT = 5,            /* Shorter route */
  SSH_ICMP_TYPE_ECHO = 8,                /* Echo service */
  SSH_ICMP_TYPE_ROUTERADVERT = 9,        /* Router advertisement */
  SSH_ICMP_TYPE_ROUTERSOLICIT = 10,      /* Router solicitation */
  SSH_ICMP_TYPE_TIMXCEED = 11,           /* Time exceeded */
  SSH_ICMP_TYPE_PARAMPROB = 12,          /* Ip header bad */
  SSH_ICMP_TYPE_TSTAMP = 13,             /* Timestamp request */
  SSH_ICMP_TYPE_TSTAMPREPLY = 14,        /* Timestamp reply */
  SSH_ICMP_TYPE_IREQ = 15,               /* Information request */
  SSH_ICMP_TYPE_IREQREPLY = 16,          /* Information reply */
  SSH_ICMP_TYPE_MASKREQ = 17,            /* Address mask request */
  SSH_ICMP_TYPE_MASKREPLY = 18           /* Address mask reply */
} SshInetIPIcmpType;

typedef enum {
  SSH_ICMP_CODE_UNREACH_NET = 0,         /* Bad network */
  SSH_ICMP_CODE_UNREACH_HOST = 1,        /* Bad host */
  SSH_ICMP_CODE_UNREACH_PROTOCOL = 2,    /* Bad protocol */
  SSH_ICMP_CODE_UNREACH_PORT = 3,        /* Bad port */
  SSH_ICMP_CODE_UNREACH_NEEDFRAG = 4,    /* IP_DF caused drop, frag needed */
  SSH_ICMP_CODE_UNREACH_SRCFAIL = 5,     /* Src route failed */
  SSH_ICMP_CODE_UNREACH_NET_UNKNOWN = 6, /* Unknown net */
  SSH_ICMP_CODE_UNREACH_HOST_UNKNOWN = 7,/* Unknown host */
  SSH_ICMP_CODE_UNREACH_ISOLATED = 8,    /* Src host is isolated */
  SSH_ICMP_CODE_UNREACH_NET_PROHIB = 9,  /* Prohibited network access */
  SSH_ICMP_CODE_UNREACH_HOST_PROHIB = 10,/* Prohibited host access */
  SSH_ICMP_CODE_UNREACH_TOSNET = 11,     /* Bad TOS for net */
  SSH_ICMP_CODE_UNREACH_TOSHOST = 12,    /* Bad TOS for host */
  SSH_ICMP_CODE_UNREACH_ADMIN_PROHIBIT = 13   /* Communication prohibited */
} SshInetIPIcmpUnreachCode;

typedef enum {
  SSH_ICMP_CODE_REDIRECT_NET = 0,        /* Redirect for network */
  SSH_ICMP_CODE_REDIRECT_HOST = 1,       /* ... for host */
  SSH_ICMP_CODE_REDIRECT_TOSNET = 2,     /* ... for TOS and net */
  SSH_ICMP_CODE_REDIRECT_TOSHOST = 3     /* ... for TOS and host */
} SshInetIPIcmpRedirectCode;

typedef enum {
  SSH_ICMP_CODE_TIMXCEED_INTRANS = 0,    /* TTL becomes zero in transit */
  SSH_ICMP_CODE_TIMXCEED_REASS = 1       /* TTL becomes zero in reassembly */
} SshInetIPIcmpTimexceedCode;

/* --------------------- auxiliary functions -------------------------*/

/* Determines whether the given string is a valid numeric IP address.
   (This currently only works for IPv4 addresses, but might be changed
   in future to accept also IPv6 addresses on systems that support
   them. */
Boolean ssh_inet_is_valid_ip_address(const char *address);

/* Compares two IP addresses, and returns <0 if address1 is smaller
   (in some implementation-defined sense, usually numerically), 0 if
   they denote the same address (though possibly written differently),
   and >0 if address2 is smaller (in the implementation-defined
   sense). */
int ssh_inet_ip_address_compare(const char *address1, const char *address2);

/* Compares comma separated list of ip nets and ip-address. Returns
   TRUE if ip-address is inside one of the nets given in
   net-address/netmask-bits format. */
Boolean ssh_inet_compare_netmask(const char *nets, const char *ip);

/* Convert ip number string to binary format. The binary format is
   unsigned character array containing the ip address in network byte
   order. If the ip address is ipv4 address then this fills 4 bytes to
   the buffer, if it is ipv6 address then this will fills 16 bytes to
   the buffer. The buffer length is modified accordingly. This returns
   TRUE if the address is valid and conversion successful and FALSE
   otherwise. */
Boolean ssh_inet_strtobin(const char *ip_address, unsigned char *out_buffer,
                          size_t *out_buffer_len_in_out);

/************************* SshIpAddr stuff **************************/

typedef struct
{
  /* The contents of this structure are private.  Applications should
     not access the contents directly, but should use the macros
     below.  The internal definition may change in future. */
  Boolean is6;  /* FALSE = ipv4, TRUE = ipv6 (PRIVATE FIELD!) */
  unsigned char data[16]; /* Address in network byte order (PRIVATE FIELD!). */
} SshIpAddr;

/* Returns TRUE if the address is an IPv6 address. */
#define SSH_IP_IS6(ip_addr) ((ip_addr)->is6)

/* Converts a 4-byte network byte order representation of an IPv4
   address to the internal representation. */
#define SSH_IP4_DECODE(ip_addr, bytes) \
  do { (ip_addr)->is6 = FALSE; memmove((ip_addr)->data, bytes, 4); } while (0)

/* Converts a 16-byte network byte order representation of an IPv6
   address to the internal representation. */
#define SSH_IP6_DECODE(ip_addr, bytes) \
  do { (ip_addr)->is6 = TRUE; memmove((ip_addr)->data, bytes, 16); } while (0)

/* Converts an IP address from the internal representation to a 4-byte
   IPv4 address in network byte order. */
#define SSH_IP4_ENCODE(ip_addr, bytes) \
 do { SSH_ASSERT(!(ip_addr)->is6); \
      memcpy(bytes, (ip_addr)->data, 4); } while (0)

/* Converts an IP address from the internal representation to 1 16-byte
   IPv6 address in network byte order. */
#define SSH_IP6_ENCODE(ip_addr, bytes) \
  do { SSH_ASSERT((ip_addr)->is6); \
       memcpy(bytes, (ip_addr)->data, 16); } while (0)

/* Converts an IP address to a 32-bit integer in host byte order. */
#define SSH_IP4_TO_INT(ip) \
     (((unsigned long)(ip)->data[0] << 24) | \
      ((unsigned long)(ip)->data[1] << 16) | \
      ((unsigned long)(ip)->data[2] << 8) | \
      (unsigned long)(ip)->data[3])
     
/* These return the individual bytes of an IPv4 address (BYTE1 is the
   first byte in dotted notation, or MSB). */
#define SSH_IP4_BYTE1(ip_addr) ((ip_addr)->data[0])
#define SSH_IP4_BYTE2(ip_addr) ((ip_addr)->data[1])
#define SSH_IP4_BYTE3(ip_addr) ((ip_addr)->data[2])
#define SSH_IP4_BYTE4(ip_addr) ((ip_addr)->data[3])
     
/* Compares two IP addresses in the internal representation and returns
   TRUE if they are equal. */
#define SSH_IP_EQUAL(ip1, ip2) \
     ((ip1)->is6 == (ip2)->is6 && \
      memcmp((ip1)->data, (ip2)->data, SSH_IP_IS6(ip1) ? 16 : 4) == 0)

/* Compares two IP addresses in the internal representation, and returns
   TRUE if they are equal when masked with the given mask. */
#define SSH_IP_MASK_EQUAL(ip1, ip2, mask) ssh_ipaddr_mask_equal(ip1, ip2, mask)

/* Produces a value that can (modulo a prime) be used as a hash value for
   the ip address.  The value is suitable for use with a prime-sized hash
   table. */
#define SSH_IP_HASH(ip_addr) ssh_ipaddr_hash(ip_addr)

/* Returns TRUE if the given IP address is NULL address. */
#define SSH_IP_IS_NULLADDR(ip_addr) \
     (SSH_IP_IS6(ip_addr) ? \
      !memcmp((ip_addr)->data, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) : \
      !memcmp((ip_addr)->data, "\0\0\0\0", 4))

/* Returns TRUE if the given IP address is the link broadcast address
   255.255.255.255.  This returns FALSE for IPv6, where link local
   addresses are apparently treated like multicast addresses, at least
   for ARP. */
#define SSH_IP_IS_BROADCAST(ip_addr) \
     (!SSH_IP_IS6(ip_addr) && (ip_addr)->data[0] == 0xff && \
      (ip_addr)->data[1] == 0xff && (ip_addr)->data[2] == 0xff && \
      (ip_addr)->data[3] == 0xff)

/* Returns TRUE if the given IP address is a multicast address between
   224.0.0.0 and 239.255.255.255, inclusive. */
#define SSH_IP_IS_MULTICAST(ip_addr) \
     (SSH_IP_IS6(ip_addr) ? \
      ((ip_addr)->data[0] == 0xff) : \
      ((ip_addr)->data[0] >= 0xe0 && (ip_addr)->data[0] <= 0xef))

/* Returns TRUE if the given IP address is a loopback address. */
#define SSH_IP_IS_LOOPBACK(ip_addr) \
     (SSH_IP_IS6(ip_addr) ? \
      (memcmp((ip_addr)->data, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16) == 0) :\
      (SSH_IP4_BYTE1(ip_addr) == 127))

/****************** Definitions for IPv4 packets ***********************/

/* Minimum length of an IPv4 header. */
#define SSH_IPH4_HDRLEN 20         /* IPv4 header length */
#define SSH_IPH4_MAX_HEADER_LEN 60 /* maximum ipv4 header len */

/* Offsets of various fields in IPv4 headers. */
#define SSH_IPH4_OFS_VERSION            0
#define SSH_IPH4_OFS_HLEN               0
#define SSH_IPH4_OFS_TOS                1
#define SSH_IPH4_OFS_LEN                2
#define SSH_IPH4_OFS_ID                 4
#define SSH_IPH4_OFS_FRAGOFF            6
#define SSH_IPH4_OFS_TTL                8
#define SSH_IPH4_OFS_PROTO              9
#define SSH_IPH4_OFS_CHECKSUM          10
#define SSH_IPH4_OFS_SRC               12
#define SSH_IPH4_OFS_DST               16

/* Macros for accessing IPv4 packet header fields.  Any returned values
   will be in host byte order. */
#define SSH_IPH4_VERSION(ucp) SSH_GET_4BIT_HIGH(ucp)
#define SSH_IPH4_HLEN(ucp) SSH_GET_4BIT_LOW(ucp)
#define SSH_IPH4_TOS(ucp) SSH_GET_8BIT((ucp) + 1)
#define SSH_IPH4_LEN(ucp) SSH_GET_16BIT((ucp) + 2)
#define SSH_IPH4_ID(ucp) SSH_GET_16BIT((ucp) + 4)
#define SSH_IPH4_FRAGOFF(ucp) SSH_GET_16BIT((ucp) + 6) /* includes flags */
#define SSH_IPH4_TTL(ucp) SSH_GET_8BIT((ucp) + 8)
#define SSH_IPH4_PROTO(ucp) SSH_GET_8BIT((ucp) + 9)
#define SSH_IPH4_CHECKSUM(ucp) SSH_GET_16BIT((ucp) + 10)
#define SSH_IPH4_SRC(ipaddr, ucp) SSH_IP4_DECODE((ipaddr), (ucp) + 12)
#define SSH_IPH4_DST(ipaddr, ucp) SSH_IP4_DECODE((ipaddr), (ucp) + 16)

/* Macros for setting IPv4 packet header fields.  Values are in host
   byte order. */
#define SSH_IPH4_SET_VERSION(ucp, v) SSH_PUT_4BIT_HIGH(ucp, (v))
#define SSH_IPH4_SET_HLEN(ucp, v) SSH_PUT_4BIT_LOW(ucp, (v))
#define SSH_IPH4_SET_TOS(ucp, v) SSH_PUT_8BIT((ucp) + 1, (v))
#define SSH_IPH4_SET_LEN(ucp, v) SSH_PUT_16BIT((ucp) + 2, (v))
#define SSH_IPH4_SET_ID(ucp, v) SSH_PUT_16BIT((ucp) + 4, (v))
#define SSH_IPH4_SET_FRAGOFF(ucp, v) SSH_PUT_16BIT((ucp) + 6, (v))
#define SSH_IPH4_SET_TTL(ucp, v) SSH_PUT_8BIT((ucp) + 8, (v))
#define SSH_IPH4_SET_PROTO(ucp, v) SSH_PUT_8BIT((ucp) + 9, (v))
#define SSH_IPH4_SET_CHECKSUM(ucp, v) SSH_PUT_16BIT((ucp) + 10, (v))
#define SSH_IPH4_SET_SRC(ipaddr, ucp) SSH_IP4_ENCODE((ipaddr), (ucp) + 12)
#define SSH_IPH4_SET_DST(ipaddr, ucp) SSH_IP4_ENCODE((ipaddr), (ucp) + 16)

/* Flags and offset mask for the fragoff field. */
#define SSH_IPH4_FRAGOFF_RF      0x8000 /* reserved flag */
#define SSH_IPH4_FRAGOFF_DF      0x4000 /* dont fragment flag */
#define SSH_IPH4_FRAGOFF_MF      0x2000 /* more fragments flag */
#define SSH_IPH4_FRAGOFF_OFFMASK 0x1fff /* mask for fragment offset */
     
/* Definitions for IPv4 option numbers. */
#define SSH_IPOPT_EOL           0  /* end of option list */
#define SSH_IPOPT_NOP           1  /* no operation */
#define SSH_IPOPT_RR            7  /* record route */
#define SSH_IPOPT_TS           68  /* timestamp */
#define SSH_IPOPT_BSO         130  /* basic security option */
#define SSH_IPOPT_ESO         133  /* extended security option? */
#define SSH_IPOPT_CIPSO       134  /* commercial? security option */
#define SSH_IPOPT_ROUTERALERT  20  /* router alert */
#define SSH_IPOPT_SNDMULTIDEST 21  /* sender directed multidest delivery */
#define SSH_IPOPT_SATID       136  /* SATNET id */
#define SSH_IPOPT_LSRR        131  /* loose source route */
#define SSH_IPOPT_SSRR        137  /* strict source route */

/* This evaluates to TRUE if the option should be copied on fragmentation. */
#define SSH_IPOPT_COPIED(o) (((o) & 0x80) != 0)

/* Macros for accessing TCP headers. */
#define SSH_TCP_HEADER_LEN 20
#define SSH_TCPH_SRCPORT(ucp) SSH_GET_16BIT((ucp) + 0)
#define SSH_TCPH_DSTPORT(ucp) SSH_GET_16BIT((ucp) + 2)
#define SSH_TCPH_SEQ(ucp) SSH_GET_32BIT((ucp) + 4)
#define SSH_TCPH_ACK(ucp) SSH_GET_32BIT((ucp) + 8)
#define SSH_TCPH_DATAOFFSET(ucp) SSH_GET_4BIT_HIGH((ucp) + 12)
#define SSH_TCPH_FLAGS(ucp) SSH_GET_8BIT((ucp) + 13)
#define SSH_TCPH_WINDOW(ucp) SSH_GET_16BIT((ucp) + 14)
#define SSH_TCPH_CHECKSUM(ucp) SSH_GET_16BIT((ucp) + 16)
#define SSH_TCPH_URGENT(ucp) SSH_GET_16BIT((ucp) + 18)

#define SSH_TCPH_SET_SRCPORT(ucp, v) SSH_PUT_16BIT((ucp) + 0, (v))
#define SSH_TCPH_SET_DSTPORT(ucp, v) SSH_PUT_16BIT((ucp) + 2, (v))
#define SSH_TCPH_SET_SEQ(ucp, v) SSH_PUT_32BIT((ucp) + 4, (v))
#define SSH_TCPH_SET_ACK(ucp, v) SSH_PUT_32BIT((ucp) + 8, (v))
#define SSH_TCPH_SET_DATAOFFSET(ucp, v) SSH_PUT_4BIT_HIGH((ucp) + 12, (v))
#define SSH_TCPH_SET_FLAGS(ucp, v) SSH_PUT_8BIT((ucp) + 13, (v))
#define SSH_TCPH_SET_WINDOW(ucp, v) SSH_PUT_16BIT((ucp) + 14, (v))
#define SSH_TCPH_SET_CHECKSUM(ucp, v) SSH_PUT_16BIT((ucp) + 16, (v))
#define SSH_TCPH_SET_URGENT(ucp, v) SSH_PUT_16BIT((ucp) + 18, (v))

/* Macros for accessing UDP headers. */
#define SSH_UDP_HEADER_LEN 8
#define SSH_UDPH_SRCPORT(ucp) SSH_GET_16BIT((ucp) + 0)
#define SSH_UDPH_DSTPORT(ucp) SSH_GET_16BIT((ucp) + 2)
#define SSH_UDPH_LEN(ucp) SSH_GET_16BIT((ucp) + 4)
#define SSH_UDPH_CHECKSUM(ucp) SSH_GET_16BIT((ucp) + 6)

#define SSH_UDPH_SET_SRCPORT(ucp, v) SSH_PUT_16BIT((ucp) + 0, (v))
#define SSH_UDPH_SET_DSTPORT(ucp, v) SSH_PUT_16BIT((ucp) + 2, (v))
#define SSH_UDPH_SET_LEN(ucp, v) SSH_PUT_16BIT((ucp) + 4, (v))
#define SSH_UDPH_SET_CHECKSUM(ucp, v) SSH_PUT_16BIT((ucp) + 6, (v))

/********* Ethernet definitions ****************************************/

/* Known values for the ethernet type field.  The same values are used for
   both ethernet (rfc894) and IEEE 802 encapsulation (the type will just
   be in a different position in the header). */
#define SSH_ETHERTYPE_IP        0x0800 /* IPv4, as per rfc894 */
#define SSH_ETHERTYPE_ARP       0x0806 /* ARP, as per rfc826 */
#define SSH_ETHERTYPE_IPv6      0x86dd /* IPv6, as per rfc1972 */
#define SSH_ETHERTYPE_REVARP    0x8035 /* Reverse ARP */
#define SSH_ETHERTYPE_NS        0x0600 /* Xerox NS (IPX, SPX, etc.) */
#define SSH_ETHERTYPE_APPLETALK 0x809b /* Appletalk */
#define SSH_ETHERTYPE_ATARP     0x80f3 /* Appletalk ARP */

/* This returns true if the given address is a hardware ethernet multicast or
   broadcast address. */
#define SSH_ETHER_IS_MULTICAST(addr) (*(addr) & 0x01)

/* Field offsets for ethernet header, and total header size. */
#define SSH_ETHER_OFS_DST       0
#define SSH_ETHER_OFS_SRC       6
#define SSH_ETHER_OFS_TYPE      12
#define SSH_ETHER_HEADERSIZE    14
     
/********************** Helper functions ******************************/

/* Sets all rightmost bits after keeping `keep_bits' bits on the left to
   the value specified by `value'. */
void ssh_ipaddr_set_bits(SshIpAddr *result, SshIpAddr *ip,
                         unsigned int keep_bits, unsigned int value);
     
/* Parses an IP address from the string to the internal representation. */
Boolean ssh_ipaddr_parse(SshIpAddr *ip, const char *str);

/* Prints the IP address into the buffer in string format.  If the buffer
   is too short, the address is truncated.  This returns `buf'. */
char *ssh_ipaddr_print(SshIpAddr *ip, char *buf, size_t buflen);

/********************** Internal definitions ***************************/

/* Some prototypes for internal functions. */
unsigned long ssh_ipaddr_hash(SshIpAddr *ip);
Boolean ssh_ipaddr_mask_equal(SshIpAddr *ip1, SshIpAddr *ip2, SshIpAddr *mask);

#endif /* SSHINET_H */
