char *malloc();
char *strcpy();

char *strdup(s)
char *s;
{
    char *ret;

    if (ret = malloc(strlen(s) + 1))
	strcpy(ret, s);
    return (ret);
}
