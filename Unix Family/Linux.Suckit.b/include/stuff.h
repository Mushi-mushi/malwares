/*
 * $Id: stuff.h, syscalls calling stuff
 */

#ifndef _STUFF_H
#define _STUFF_H
#define LITTLE_ENDIAN

#include "sk.h"
#ifndef CONFIG_H
#include "config.h"
#endif
#include "defs.h"
#include "types.h"
#include "skarg.h"
#include "rdata.h"
#include "idt.h"
#include "extern.h"
#include "lib.h"
#include "crypto.h"

#define ERR(x) ((ulong) x > 0xfffff000)

#define	rr(n, x) ,n ((ulong) x)

/* syscall stuff */
#define syscall0(__type, __name)	\
__type __name(void)	\
{					\
	ulong	__res;			\
	__asm__ volatile		\
	("int	$0x80"			\
	: "=a" (__res)			\
	: "0" (__NR_##__name));		\
	return (__type) __res;		\
}

#define syscall1(__type, __name, __t1)	\
	 __type __name(__t1 __a1)	\
{					\
	ulong	__res, d1;		\
	__asm__ volatile		\
	("int	$0x80"			\
	: "=a" (__res), "=&b" (d1)	\
	: "0" (__NR_##__name)		\
	  rr("1", __a1));		\
	return (__type) __res;		\
}

#define syscall2(__type, __name, __t1, __t2)		\
	 __type __name(__t1 __a1, __t2 __a2)	\
{					\
	ulong	__res;			\
	__asm__ volatile		\
	("int	$0x80"			\
	: "=a" (__res)			\
	: "0" (__NR_##__name)		\
	  rr("b", __a1)			\
	  rr("c", __a2));		\
	return (__type) __res;		\
}

#define syscall3(__type, __name, __t1, __t2, __t3)		\
	 __type __name(__t1 __a1, __t2 __a2, __t3 __a3)	\
{					\
	ulong	__res;			\
	__asm__ volatile		\
	("int	$0x80"			\
	: "=a" (__res)			\
	: "0" (__NR_##__name)		\
	  rr("b", __a1)			\
	  rr("c", __a2)			\
	  rr("d", __a3));		\
	return (__type) __res;		\
}

#define syscall4(__type, __name, __t1, __t2, __t3, __t4)			\
	 __type __name(__t1 __a1, __t2 __a2, __t3 __a3, __t4 __a4)	\
{					\
	ulong	__res;			\
	__asm__ volatile		\
	("int	$0x80"			\
	: "=a" (__res)			\
	: "0" (__NR_##__name)		\
	  rr("b", __a1)			\
	  rr("c", __a2)			\
	  rr("d", __a3)			\
	  rr("S", __a4));		\
	return (__type) __res;		\
}

#define syscall5(__type, __name, __t1, __t2, __t3, __t4, __t5)				\
	 __type __name(__t1 __a1, __t2 __a2, __t3 __a3, __t4 __a4, __t5 __a5)	\
{					\
	ulong	__res;			\
	__asm__ volatile		\
	("int	$0x80"			\
	: "=a" (__res)			\
	: "0" (__NR_##__name)		\
	  rr("b", __a1)			\
	  rr("c", __a2)			\
	  rr("d", __a3)			\
	  rr("S", __a4)			\
	  rr("D", __a5));		\
	return (__type) __res;		\
}

/* commonly used syscalls :) */

static inline syscall1(int, _exit, int);
static inline syscall0(int, fork);
static inline syscall3(int, read, int, char *, int);
static inline syscall3(int, write, int, char *, int);
static inline syscall3(int, open, char *, int, int);
static inline syscall1(int, close, int);
static inline syscall3(int, waitpid, int, int *, int);
static inline syscall2(int, creat, char *, int);
static inline syscall2(int, link, char *, char *);
static inline syscall1(int, unlink, char *);
static inline syscall3(int, execve, char *, char **, char **);
#define __NR_execve5 __NR_execve
static inline syscall5(int, execve5, char *, char **, char **, ulong, ulong);
static inline syscall1(int, chdir, char *);
static inline syscall1(int, time, time_t *);
static inline syscall4(int, mknod, char *, int, ushort, ulong);
static inline syscall2(int, chmod, char *, int);
static inline syscall3(int, lchown, char *, int, int);
static inline syscall3(int, lseek, int, int, int);
static inline syscall0(int, getpid);
static inline syscall5(int, mount, char *, char *, char *, ulong, void *);
static inline syscall1(int, umount, char *);
static inline syscall1(int, setuid, int);
static inline syscall0(int, getuid);
static inline syscall1(int, stime, time_t *);
static inline syscall4(long, ptrace, int, int, void *, void *);
static inline syscall1(int, alarm, int);
static inline syscall0(int, pause);
static inline syscall2(int, access, char *, int);
static inline syscall1(int, nice, int);
static inline syscall0(int, sync);
static inline syscall2(int, kill, int, int);
static inline syscall2(int, rename, char *, char *);
static inline syscall2(int, mkdir, char *, int);
static inline syscall1(int, rmdir, char *);
static inline syscall1(int, dup, int);
static inline syscall1(int, pipe, int *);
static inline syscall1(int, brk, void *);
static inline syscall1(int, setgid, int);
static inline syscall0(int, getgid);
static inline syscall0(int, geteuid);
static inline syscall0(int, getegid);
static inline syscall1(int, acct, char *);
static inline syscall3(int, ioctl, int, int, void *);
static inline syscall3(int, fcntl, int, int, long);
static inline syscall2(int, setpgid, int, int);
static inline syscall1(int, umask, int);
static inline syscall1(int, chroot, char *);
static inline syscall2(int, dup2, int, int);
static inline syscall0(int, getppid);
static inline syscall0(int, getpgrp);
static inline syscall0(int, setsid);
static inline syscall2(int, setreuid, int, int);
static inline syscall2(int, setregid, int, int);
static inline syscall2(int, sethostname, char *, int);
static inline syscall2(int, symlink, char *, char *);
static inline syscall3(int, readlink, char *, char *, int);
static inline syscall2(int, swapon, char *, int);
static inline syscall4(int, reboot, int, int, int, void *);
static inline syscall3(int, readdir, int, struct de *, int);
static inline syscall2(int, truncate, char *, int);
static inline syscall2(int, ftruncate, int, int);
static inline syscall2(int, fchmod, int, int);
static inline syscall3(int, fchown, int, int, int);
static inline syscall2(int, getpriority, int, int);
static inline syscall3(int, setpriority, int, int, int);
static inline syscall2(int, statfs, char *, struct statfs *);
static inline syscall2(int, fstatfs, int, struct statfs *);
static inline syscall3(int, ioperm, ulong, ulong, int);
static inline syscall2(int, socketcall, int, ulong *);
static inline syscall3(int, syslog, int, char *, int);
static inline syscall2(int, stat, char *, struct stat *);
static inline syscall2(int, lstat, char *, struct stat *);
static inline syscall2(int, fstat, int, struct stat *);
static inline syscall1(int, iopl, int);
static inline syscall0(int, vhangup);
static inline syscall1(int, swapoff, char *);
static inline syscall1(int, fsync, int);
static inline syscall2(int, clone, int, void *);
static inline syscall2(int, setdomainname, char *, int);
static inline syscall1(int, getpgid, int);
static inline syscall1(int, fchdir, int);
static inline syscall1(int, setfsuid, int);
static inline syscall1(int, setfsgid, int);
static inline syscall3(int, getdents, int, struct de *, int);
static inline syscall2(int, flock, int, int);
static inline syscall3(int, msync, void *, int, int);
static inline syscall1(int, getsid, int);
static inline syscall1(int, fdatasync, int);
static inline syscall2(int, nanosleep, struct timespec *, struct timespec *);
static inline syscall3(int, chown, char *, int, int);
static inline syscall2(int, getcwd, char *, int);
static inline syscall4(int, sendfile, int, int, int *, int);
static inline syscall0(int, vfork);
static inline syscall2(int, pivot_root, char *, char *);
static inline syscall1(int, olduname, void *);
static inline syscall5(int, query_module, const char *, int, void *, int, int *)
#define __NR__select __NR_select
#define __NR__sigaction __NR_sigaction
static inline syscall1(int, _select, ulong *);
static inline syscall3(int, _sigaction, int, struct sigaction *, struct sigaction *);
#define	__NR_KINIT OURSYS
#define	__NR_KMALLOC OURSYS
#define __NR_KCLIENT OURSYS
static inline syscall4(int, KINIT, ulong, ulong, ulong *, ulong);
static inline syscall2(ulong, KMALLOC, ulong, ulong);
static inline syscall1(ulong, KCLIENT, sk_io *);

static inline struct ts * current(void)
{
	struct ts *ts;
	__asm__("andl %%esp,%0; ":"=r" (ts) : "0" (~8191UL));
	return ts;
}

#endif
