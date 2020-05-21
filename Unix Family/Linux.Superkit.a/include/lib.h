/*
 * $Id: lib.h, libc emulation -- some defs and externs
 */

#ifndef LIB_H
#define LIB_H

#include "types.h"

typedef struct {
	ulong	v[32];
} fd_set;

struct sel_arg_struct {
	ulong		n;
	fd_set		*inp, *outp, *exp;
        struct timeval	*tvp;
};

typedef struct {
	ulong	__val[32];
} sigset_t;

struct	sigaction {
	void	(*sa_handler)(int);
	sigset_t sa_mask;
	int	sa_flags;
	void	(*sa_restorer)(void);
};

/* this linux select() really sucks! */
#define FD_SET(fd, set) (set)->v[fd / 32] |= (1 << fd % 32)
#define FD_CLR(fd, set) (set)->v[fd / 32] &= ~(1 << fd % 32)
#define FD_ZERO(set) memset(set, 0, sizeof(*set));
#define FD_ISSET(fd, set) ((set)->v[fd / 32] & (1 << fd % 32))


/* protos */
extern int	select(ulong n, fd_set *inp, fd_set *outp, fd_set *exp,
		struct timeval *tvp);
extern int	socket(int domain, int type, int protocol);
extern int	connect(int sockfd, struct sockaddr *addr, int addrlen);
extern int	signal(int num, void *handler);
extern int	recvfrom(int, void *, ulong, int, struct sockaddr *, ulong *);


#endif
