/*
 * $Id: skstr.h, externs for libc-like string functions
 */

#ifndef SKSTR_H
#define SKSTR_H

#ifndef NULL
#define NULL (void *) 0
#endif

#define isdigit(x) ((x >= '0') && (x <= '9'))
#define isxdigit(x) (isdigit(x) || (x >= 'a' && \
                     x <= 'f') || (x >= 'A' && x <= 'F'))
#define islower(x) ((x >= 'a') && (x <= 'z'))
#define isspace(x) (x==' ' || x=='\t' || x=='\n' \
                    || x=='\r' || x=='\f' || x=='\v')
#define toupper(x) (x & 0xDF)

extern int vsnprintf(char *buf, unsigned int size, const char *fmt, va_list args);
extern int snprintf(char * buf, unsigned int size, const char *fmt, ...);
extern int vsprintf(char *buf, const char *fmt, va_list args);
extern int sprintf(char * buf, const char *fmt, ...);
extern int printf(char *fmt, ...);
extern int vsscanf(const char * buf, const char * fmt, va_list args);
extern int sscanf(const char * buf, const char * fmt, ...);

#include "strasm.h"

extern void * memmem(char *s1, int l1, char *s2, int l2);
extern int memcmp(const void * cs,const void * ct,unsigned count);


#endif
