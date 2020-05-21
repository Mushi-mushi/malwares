/*
 * $Id: routines for work with /dev/kmem
 */

#include "stuff.h"

/* wtf this does ? ;) */
int	open_kmem(void)
{
	return open(DEFAULT_KMEM, O_RDWR, 0);
}

/* shortcut for "read kernel memory", it's equivalent
   to pread(), but I think it might not be a good idea to use
   syscall presented in kernel 2.2.x */
int	rkm(int fd, void *buf, int count, ulong off)
{
	int	i;
	
	i = lseek(fd, off, SEEK_SET);
	if (ERR(i))
		return i;
	return read(fd, buf, count);
}

int	wkm(int fd, void *buf, int count, ulong off)
{
	int	i;
	
	i = lseek(fd, off, SEEK_SET);
	if (ERR(i))
		return i;
	return write(fd, buf, count);
}

/* this is almost same, but for one long only */
int	rkml(int fd, ulong *l, ulong off)
{
	return rkm(fd, l, sizeof(*l), off);
}

int	wkml(int fd, ulong l, ulong off)
{
	return wkm(fd, &l, sizeof(l), off);
}


