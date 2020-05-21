/* Replacements for malloc and strdup with error checking.  Too trivial
   to be worth copyrighting :-).  I did that because a lot of code used
   malloc and strdup without checking for NULL pointer, and I like some
   message better than a core dump...  --marekm
   
   Yeh, but.  Remember that bailing out might leave the system in some
   bizarre state.  You really want to put in error checking, then add
   some back-out failure recovery code. -- jfh */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: xmalloc.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include <stdio.h>

#include "defines.h"

extern char *malloc();

char *
xmalloc(size)
	unsigned size;
{
	char *ptr;

	ptr = malloc(size);
	if (!ptr && size) {
		fprintf(stderr, "malloc(%u) failed\n", size);
		exit(13);
	}
	return ptr;
}

char *
xstrdup(str)
	const char *str;
{
	return strcpy(xmalloc(strlen(str) + 1), str);
}
