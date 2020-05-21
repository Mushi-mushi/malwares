#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int     setenv(name, value, overwrite)
char   *name;
char   *value;
int     overwrite;
{
    char   *p;

    if (overwrite == 0 && getenv(name) != 0)
	return (0);
    if ((p = malloc(strlen(name) + strlen(value) + 2)) == 0)
	return (1);
    sprintf(p, "%s=%s", name, value);
    return (putenv(p));
}
