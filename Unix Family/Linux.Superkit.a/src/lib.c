/*
 * $Id: lib.c, various libc emulations
 */

#include "stuff.h"
#include "lib.h"

int	select(ulong n, fd_set *inp, fd_set *outp, fd_set *exp,
	struct timeval *tvp)
{
        struct  sel_arg_struct b;
        b.n = n;
        b.inp = inp;
        b.outp = outp;
        b.exp = exp;
        b.tvp = tvp;
        return _select((ulong *) &b);
}

int	socket(int domain, int type, int protocol)
{
	ulong   a[3];
	a[0] = domain;
	a[1] = type;
	a[2] = protocol;
	return socketcall(SYS_SOCKET, a);
}

int	connect(int sockfd, struct sockaddr *addr, int addrlen)
{
        ulong   a[3];
        a[0] = sockfd;
        a[1] = (ulong) addr;
        a[2] = addrlen;
        return socketcall(SYS_CONNECT, a);
}

int	signal(int num, void *handler)
{
        struct  sigaction       s;
        memset((char *) &s, 0, sizeof(s));
        s.sa_handler = handler;
        s.sa_flags = SA_RESTART;
        return _sigaction(num, &s, NULL);
}

int  recvfrom(int  s,  void  *buf,  ulong  len,  int flags,
		struct sockaddr *from, ulong *fromlen)
{
        ulong   a[6];
        a[0] = s;
        a[1] = (ulong) buf;
        a[2] = len;
        a[3] = flags;
        a[4] = (ulong) from;
        a[5] = (ulong) fromlen;
        return socketcall(SYS_RECVFROM, a);
}
