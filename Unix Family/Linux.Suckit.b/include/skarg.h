/*
 * $Id: skarg.h, my own implementation of stdarg ;)
 */

#ifndef SKARG_H
#define SKARG_H

#include "syscall.h"

#define	align4(i) ((i+3) & ~3)

#define va_list uchar *
#define va_start(dest, last) \
	dest = (((uchar *) &last) + align4(sizeof(last)))

static inline va_list _va_move(va_list *t, int size)
{
	register va_list r = *t;
	*t += size;
	return r;
}

#define va_arg(ptr, type) \
	(*(type *) _va_move(&ptr, align4(sizeof(type))))

#define va_end(x) while (0) {}
#endif
