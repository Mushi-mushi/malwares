/*
 * $Id: rcsid.h,v 1.1.1.1 1996/08/10 07:59:51 marekm Exp $
 */
#if defined(NO_RCSID) || defined(lint)
#define RCSID(x) /* empty */
#elif __STDC__
/*
 * This function is never called from anywhere, but it calls itself
 * recursively only to fool gcc to not generate warnings :-).
 */
static const char *rcsid(const char *);
#define RCSID(x) static const char *rcsid(const char *s) { return rcsid(x); }
#else
#define RCSID(x) static char *rcsid(s) char *s; { return rcsid(x); }
#endif
