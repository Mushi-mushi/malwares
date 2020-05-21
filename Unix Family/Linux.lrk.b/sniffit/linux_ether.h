/* Sniffit Ethernet File -- Brecht Claerhout                            */

/* DATA definition */
#ifdef IFF_LOOPBACK
#define ISLOOPBACK(p) ((p)->ifr_flags & IFF_LOOPBACK)
#else
#define ISLOOPBACK(p) (strcmp((p)->ifr_name, "lo0") == 0)
#endif

typedef struct _dev_info
{
	int fd;
	int snapshot;

	/* Read buffer. */
	int bufsize;
	u_char *buffer;
} device_info;

char 	snoop_device[255]; 
struct  ifreq old_ifr;

struct packetheader
{
	struct timeval ts;      /* time stamp */
	u_long caplen;          /* length of portion present */
	u_long len;             /* length this packet (off wire) */
};

typedef void (*packet_handler)( u_long, 
				const struct packetheader *, 
				const u_char * );
 
/* Cleaned out functions */

char *lookup_device(void)
{
	register int fd, minunit, n;
	register char *cp;
	register struct ifreq *ifrp, *ifend, *ifnext, *mp;
	struct ifconf ifc;
	struct ifreq ibuf[16], ifr;
	static char device[sizeof(ifrp->ifr_name) + 1]; /* GNUism */

	fd = socket(AF_INET, SOCK_DGRAM, 0 /* IP */);
	if (fd < 0) 
		return printf("Error looking for a suitable device.\n"),
		NULL;

	ifc.ifc_len = sizeof ibuf;
	ifc.ifc_buf = (caddr_t)ibuf;

	if (ioctl(fd, SIOCGIFCONF, (char *)&ifc) < 0 ||
		ifc.ifc_len < sizeof(struct ifreq)) 
		return  printf("SIOCGIFCONF error.\n"),
			close(fd),
			NULL;
	ifrp = ibuf;
	ifend = (struct ifreq *)((char *)ibuf + ifc.ifc_len);
        
	mp = NULL;
	minunit = 666;
	for (; ifrp < ifend; ifrp = ifnext) {
#if BSD - 0 >= 199006
		n = ifrp->ifr_addr.sa_len + sizeof(ifrp->ifr_name);
		if (n < sizeof(*ifrp))
			ifnext = ifrp + 1;
		else
			ifnext = (struct ifreq *)((char *)ifrp + n);
		if (ifrp->ifr_addr.sa_family != AF_INET)
			continue; 
#else
		ifnext = ifrp + 1;
#endif
    /*
     * Need a template to preserve address info that is
     * used below to locate the next entry.  (Otherwise,
     * SIOCGIFFLAGS stomps over it because the requests
     * are returned in a union.)
     */
		strncpy(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifr) < 0) {
			return	printf("SIOCGIFFLAGS error.\n"),
				close(fd),
				NULL;
		}

		/* Must be up and not the loopback */
    		if ((ifr.ifr_flags & IFF_UP) == 0 || ISLOOPBACK(&ifr))
      			continue;

    		for (cp = ifrp->ifr_name; !isdigit(*cp); ++cp)
                        continue;

    		n = atoi(cp);
    		if (n < minunit) {
			minunit = n;
      			mp = ifrp;
      		}
  	}
	close(fd);
	if (mp == NULL)
		return NULL;

	strncpy(device, mp->ifr_name, sizeof(device) - 1);
	device[sizeof(device) - 1] = '\0';
	return (device);
}

void restore_interface()                /* restore ethernetcard's state */
{
	int fd = socket(PF_INET, 
			SOCK_PACKET,  /* Linux way of talking to the device */
			htons(0x0003) /* assign number 3 in kernel table */
		 );
	if (fd < 0 || ioctl(fd, SIOCSIFFLAGS, &old_ifr) < 0)
    		printf("Warning: could not restore interface to normal.\n");
}

device_info *open_device(char *device, int snaplen, int to_ms) 
{
	device_info *p;
	struct ifreq ifr;          /* interface request function */

	if (!(p = (device_info *)malloc(sizeof(*p))))
		return 0;
  	bzero(p, sizeof(*p));

  	if (strncmp("et", device, 2) != 0)         /* ethernet device? */
		printf("You should use the Ethernet device (eth0, etc.)\n"),
		exit(0);

	p->fd = -1;
	p->bufsize = 8192;
	p->buffer = (u_char *)malloc(p->bufsize);

	if (!p->buffer) 
		goto bad;

	p->fd = socket(PF_INET, SOCK_PACKET, htons(0x0003));
	if (p->fd < 0) {
		printf("Error Creating SnoopSocket.\n");
		goto bad;
	}

	strcpy(ifr.ifr_name, device);       /* interface we're gonna use */
	if (ioctl(p->fd, SIOCGIFFLAGS, &ifr) < 0 )     /* Get Flags*/ 
	{
		printf("Couldn't get flags on Socket\n");
		goto bad;
	}
	old_ifr = ifr;
	atexit(restore_interface);
	ifr.ifr_flags |= IFF_PROMISC;         /* set promiscuous mode */
	if (ioctl(p->fd, SIOCSIFFLAGS, &ifr) < 0 )      /* set flags */
	{
		printf("Couldn't set flags on Socket\n");
    		goto bad;
	}

	strcpy(snoop_device,device);
	p->snapshot = snaplen;
	return (p);
bad:
	if (p->fd >= 0)
		close(p->fd);
	if (p->buffer != NULL)
		free(p->buffer);
	free(p);
	return (0);
}

int read_device(device_info *p, int cnt, packet_handler callback, u_long ipaddr) 
{
	register int datalen;
	register int caplen;
	struct sockaddr from;
	int from_len = sizeof(from);
	char *buf;
	int bufsize;
	struct packetheader h;

	buf = (char *)p->buffer;
	bufsize = p->bufsize;

	do {
		datalen = recvfrom(p->fd, buf, bufsize, 0, &from, &from_len);
		if (datalen < 0) {
			switch (errno) {
				case EWOULDBLOCK: return 0;
			}
     			return perror("recvfrom"), -1;
    		}
	/* go until we find something from the right interface */
  	} while (strncmp(snoop_device,from.sa_data, 3));  
                                        /* compare on 'eth', not further */

	caplen = (datalen > p->bufsize) ? datalen : p->bufsize;
	if (caplen > p->snapshot)
		caplen = p->snapshot;

#ifdef SIOCGSTAMP
	if (ioctl(p->fd,SIOCGSTAMP,&h.ts) < 0) /* ask for the timestamp */
#endif
		gettimeofday(&h.ts,0);
 
	h.len = datalen;
	h.caplen = caplen;
	(*callback)(ipaddr, &h, (char *)p->buffer);
	return (1);
}
