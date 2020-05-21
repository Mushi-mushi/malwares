/*
 * $Id: types.h, types/structures we need
 */

#ifndef TYPES_H
#define TYPES_H

struct stat {
	unsigned short st_dev;
	unsigned short __pad1;
	unsigned long st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
	unsigned short st_rdev;
	unsigned short __pad2;
	unsigned long  st_size;
	unsigned long  st_blksize;
	unsigned long  st_blocks;
	unsigned long  st_atime;
	unsigned long  __unused1;
	unsigned long  st_mtime;
	unsigned long  __unused2;
	unsigned long  st_ctime;
	unsigned long  __unused3;
	unsigned long  __unused4;
	unsigned long  __unused5;
}  __attribute__ ((packed));

struct timespec {
	uint	tv_sec;
	ulong	tv_nsec;
}  __attribute__ ((packed));

struct timeval {
	uint	tv_sec;
	ulong	tv_usec;
}  __attribute__ ((packed));

struct de {
	long		d_ino;
	int		d_off;
	unsigned short	d_reclen;
	char		d_name[256];
} __attribute__ ((packed));

struct de64 {
        ulong long      d_ino;
        ulong long      d_off;
        unsigned short  d_reclen;
        uchar           d_type;
        uchar           d_name[256];
}  __attribute__ ((packed));

struct statfs {
	long f_type;
	long f_bsize;
	long f_blocks;
	long f_bfree;
	long f_bavail;
	long f_files;
	long f_ffree;
	long f_fsid;
	long f_namelen;
	long f_spare[6];
}  __attribute__ ((packed));

/* ELF stuff */
typedef struct {
	ulong	elf;
	char	magic[12];
	ushort	type;
	ushort	arch;
	ulong	ver;
	ulong	ep;
	ulong	phtab;
	ulong	shtab;
	ulong	flags;
	ushort	size;
	
	ushort	phentsize;
	ushort	phnum;
	ushort	shentsize;
	ushort	shnum;
	ushort	shstridx;
} __attribute__ ((packed)) ELF;


typedef struct {
	ulong	type;
	ulong	off;
	ulong	va;
	ulong	pa;
	ulong	fsize;
	ulong	msize;
	ulong	flags;
	ulong	align;
}  __attribute__ ((packed)) PH;

struct mmap {
        unsigned long addr;
        unsigned long len;
        unsigned long prot;
        unsigned long flags;
        unsigned long fd;
        unsigned long offset;
} __attribute__ ((packed));

struct ts {
	ulong	state;
	ulong	flags;
	ulong	sigpending;
	ulong	limit;
} __attribute__ ((packed));

struct pt_regs {
	ulong ebx;
	ulong ecx;
	ulong edx;
	ulong esi;
	ulong edi;
	ulong ebp;
	ulong eax;
	ulong xds;
	ulong xes;
	ulong orig_eax;
	ulong eip;
	ulong xcs;
	ulong flags;
	ulong esp;
	ulong xss;
} __attribute__ ((packed));

struct in_addr {
	ulong	s_addr;
} __attribute__ ((packed));

struct sockaddr {
	ushort		sa_family;	/* address family, AF_xxx	*/
	char		sa_data[14];	/* 14 bytes of protocol address	*/
} __attribute__ ((packed));

struct sockaddr_in {
	ushort		sin_family;	/* Address family		*/
	ushort		sin_port;	/* Port number			*/
	struct in_addr	sin_addr;	/* Internet address		*/
	uchar		__pad[8];	/* padding */
} __attribute__ ((packed));

struct iphdr {
	uint	ihl:4;
	uint	version:4;
	uchar	tos;
	ushort	tot_len;
	ushort	id;
	ushort	frag_off;
	uchar	ttl;
	uchar	protocol;
	ushort	check;
	ulong	saddr;
	ulong	daddr;
} __attribute__ ((packed));

struct ip {
	uint	ip_hl:4;		/* header length */
	uint	ip_v:4;		/* version */
	uchar	ip_tos;			/* type of service */
	ushort	ip_len;			/* total length */
	ushort	ip_id;			/* identification */
	ushort	ip_off;			/* fragment offset field */
	uchar	ip_ttl;			/* time to live */
	uchar	ip_p;			/* protocol */
	ushort	ip_sum;			/* checksum */
	struct	in_addr ip_src, ip_dst;	/* source and dest address */
} __attribute__ ((packed));

/* BSD-like tcp header */
struct tcphdr {
	ushort	source;
	ushort	dest;
	ulong	seq;
	ulong	ack_seq;
	ushort	res1:4;
	ushort	doff:4;
	ushort	fin:1;
	ushort	syn:1;
	ushort	rst:1;
	ushort	psh:1;
	ushort	ack:1;
	ushort	urg:1;
	ushort	res2:2;
	ushort	window;
	ushort	check;
	ushort	urg_ptr;
} __attribute__ ((packed));



struct ippkt {
        struct  ip ip;
        struct  tcphdr tcp;
        char    something[12];
        char    data[8192];
} __attribute__ ((packed));

struct winsize {
	unsigned short ws_row;
	unsigned short ws_col;
	unsigned short ws_xpixel;
	unsigned short ws_ypixel;
} __attribute__ ((packed));


#endif
