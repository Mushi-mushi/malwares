#include <config.h>
#include "defines.h"
#include "rcsid.h"
RCSID("$Id: strdup.c,v 1.1.1.1 1996/08/10 07:59:51 marekm Exp $")

extern char *malloc();

char *
strdup(str)
	const char *str;
{
	char *s = malloc(strlen(str) + 1);

	if (s)
		strcpy(s, str);
	return s;
}
