/*
 * $Id: rdata.h, self-relocating data access ;)
 */

#ifndef RDATA_H
#define RDATA_H

/* you probably wonder what the hell all of this is ... nevermind,
   only keep in the mind that if you call your_loved_variable()
   you get pointer to it. Howgh! */
#define DARR(type, count, name, val...) \
	struct s_##name {	\
		uchar	s[5];	\
		type	l[count]; \
		uchar	f[2];	\
	} __attribute__((packed)); \
	static struct s_##name f_##name = \
	{{0xe8, sizeof(f_##name.l) & 0xff, (sizeof(f_##name.l) >> 8) & 0xff, 0, 0},	\
	{val},			\
	{0x58, 0xc3}};		\
	static inline type *name(void) \
	{			\
		type *(*func)() = (void *) &f_##name; \
		return func();	\
	}

#define DVAR(type, name, val)	\
	DARR(type, 1, name, val)

#define	DSTR(name, val)		\
	DARR(char, sizeof(val), name, val)

#endif
