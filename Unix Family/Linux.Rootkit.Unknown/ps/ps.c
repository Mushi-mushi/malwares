/*
 * ps.c		- show process status
 *
 * Copyright (c) 1992 Branko Lankester
 *
 * Snarfed and HEAVILY modified for procps
 * by Michael K. Johnson, johnsonm@sunsite.unc.edu.  What is used is what
 * is required to have a common interface.
 *
 * Modified 1994/05/25 Michael Shields <mjshield@nyx.cs.du.edu>
 * Added support for multiple, comma-delimited pids on command line.
 *
 * Changes Copyright (C) 1993, 1994 Michael K. Johnson
 * See file COPYING for copyright details.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <sys/ioctl.h>
#include <pwd.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include "ps.h"
#include "psdata.h"

#define	PS_D	0	/* default format (short) */
#define	PS_L	1	/* long format */
#define	PS_U	2	/* user format */
#define	PS_J	3	/* jobs format */
#define	PS_S	4	/* signal format */
#define	PS_V	5	/* vm format */
#define	PS_M	6	/* mem. stuff */
#define	PS_X	7	/* regs etc., for testing */

char *hdrs[] = {
"  PID TTY STAT  TIME COMMAND",
" F    UID   PID  PPID PRI NI SIZE  RSS WCHAN      STAT TTY   TIME COMMAND",
"USER       PID %CPU %MEM SIZE  RSS TTY STAT START   TIME COMMAND",
" PPID   PID  PGID   SID TTY TPGID  STAT   UID   TIME COMMAND",
"  UID   PID SIGNAL   BLOCKED  IGNORED  CATCHED  STAT TTY   TIME COMMAND",
"  PID TTY STAT  TIME  PAGEIN TSIZ DSIZ  RSS   LIM %MEM COMMAND",
"  PID TTY MAJFLT MINFLT  TRS  DRS SIZE SWAP  RSS SHRD  LIB  DT COMMAND",
"NR   PID    STACK      ESP      EIP TMOUT ALARM STAT TTY   TIME COMMAND"
};

extern void (*fmt_fnc[])();	/* forward declaration */
void prtime(unsigned long t, unsigned long rel);
void read_globals();
void usage(void);
void show_procs(unsigned int maxcmd, int no_header);
void show_time(struct ps_proc * this);
int set_maxcmd(int w_opts);

int sort_depth=0;
int sort_direction[10];     /* storage for 10 levels, but 4 would be plenty!*/
int (*sort_function[10])(void* a, void* b);
int parse_sort_opt(char*);
int parse_long_sort(char*);

/*
 * command line options
 */
int CL_fmt = 0;
int CL_all = 0;
int CL_kern_comm = 0;
int CL_no_ctty = 0;
int CL_run_only = 0;
char *CL_ctty = 0;
pid_t *CL_pids = NULL;	/* a zero-terminated list, dynamically allocated */
int CL_show_env = 0;
int CL_num_outp = 0;	/* numeric fields for user or wchan */
int CL_pg_shift = 2;	/* default: show k instead of pages */
int CL_Sum = 0;
int CL_sort = 1;

/* Globals */
int GL_current_time;
unsigned int GL_main_mem;
long GL_time_now;
int GL_wchan_nout = 0;

int main(int argc, char **argv)
{
    char *p;
#define MX_OP 15
    char fmt_ord[MX_OP]="Up";  /* initialize to default fmt sort */
    int width = 0;
    unsigned int maxcmd;
    int no_header = 0;
    int psdbsucc = 0;
    int user_ord = 0;
    int toppid = 0;

    if (argc > 1) do
    {
	--argc;
	++argv;  /* shift to line args. At top of loop because of argv[0] */
	for (p = *argv; *p; ++p) {
	    switch (*p) {
                case '-':
                  if (*(p+1) == '-') { /* two -'s in a row */
/* long name options.  A series of if-else-if's with strcmp's */
/* right now, --sort:key1,key2,... is the only real long name option. */
		    if (strncmp(p+2,"sort",4)==0) {
		      if (parse_long_sort(p+7) == -1)
			usage();
		      user_ord = 1;
		      break;
		    } else if (strncmp(p+2, "help", 4) == 0) {
/* -help has been added to be friendly.  It would be friendlier if */
/* we could pipe the output through PAGER, but I'm not going to worry */
/* about that now.  No one else seems to... */
		      dump_keys();
		      usage();
		      exit(0);
		    } else if (*(p+2) != '\0') { /* just '-- '; not an error */
		      fprintf(stderr,
			      "ps: unknown long name option -- %s\n",p+1);
		      usage(); /* long_name not found or parse error */
		    }
		  }
		  break;
		case 'l':
	          CL_fmt = PS_L;
		  strncpy(fmt_ord,"Pp",MX_OP); break;
		case 'u':
		  CL_fmt = PS_U;
		  strncpy(fmt_ord,"up",MX_OP); break;
		case 'j':
		  CL_fmt = PS_J;
		  strncpy(fmt_ord,"gPp",MX_OP); break;
		case 's':
		  CL_fmt = PS_S;
		  strncpy(fmt_ord,"p",MX_OP); break;
		case 'v':
		  CL_fmt = PS_V;
		  strncpy(fmt_ord,"p",MX_OP); break;
		case 'm':
		  CL_fmt = PS_M;
		  strncpy(fmt_ord,"s",MX_OP); break;
		case 'X':
		  CL_fmt = PS_X;
		  strncpy(fmt_ord,"p",MX_OP); break; /* regs */
		case 'a': CL_all = 1; break;
		case 'c': CL_kern_comm = 1; break;
		case 'x': CL_no_ctty = 1; break;
		case 't': CL_ctty = p + 1; break;
		case 'r': CL_run_only = 1; break;
		case 'e': CL_show_env = 1; break;
		case 'w': ++width; break;
		case 'h': no_header = 1; break;
		case 'n': CL_num_outp = 1; GL_wchan_nout = 1; break;
		case 'S': CL_Sum = 1; break;
		case 'p': CL_pg_shift = 0; break;
		case 'g': break;   /* old flag, ignore */ 
		case 'o': CL_sort = !CL_sort; break; /* off or on by default?*/
		case 'O':
		  if (parse_sort_opt(p+1) == -1)
		    usage();
		  user_ord = 1;
		  break;
		default:
		    /* Step through until the end, reading all the
		       comma-delimited pids and allocating space to put
		       them. */
		    if (isdigit(*p)) {
			while (*p) {
			    /* It's not especially efficient to call xrealloc()
			       each time, but as Knuth says, premature
			       optimization is the root of all evil. */
			    CL_pids = xrealloc(CL_pids,
			    		       (toppid + 2) * sizeof(pid_t));
			    CL_pids[toppid++] = atoi(p);
			    while (isdigit(*p))
			    	p++;
			    if (*p == ',')
			        p++;
			}
			CL_pids[toppid] = 0;
		    }
		    if (*p)
			usage();
	    }
	    if (user_ord || CL_ctty || CL_pids)
		break;
	}
    } while (argc > 1);

    if (CL_fmt == PS_L) {
      if (open_psdb()) {
	GL_wchan_nout = 1;
      } else {
	psdbsucc = 1;
      }
    }
    maxcmd = set_maxcmd(width);
    read_globals();
    if (CL_sort && !user_ord)
        parse_sort_opt(fmt_ord);
    show_procs(maxcmd, no_header);
    if (psdbsucc) close_psdb();
    return 0;
}


void usage(void)
{
    fprintf(stderr,
	    "usage:  ps -acehjlnrsSuvwx{t<tty>|#|O[-]u[-]U..} \\\n"
	    "           --sort:[-]key1,[-]key2,...\n"
	    "           --help gives you this message\n");
    exit(1);
}


/*
 * set maximum chars displayed on a line
 */
int set_maxcmd(int w_opts)
{
    struct winsize win;
    int cols = 80;

    if (ioctl(1, TIOCGWINSZ, &win) != -1 && win.ws_col > 0)
	cols = win.ws_col;

    switch (w_opts) {
	case 0: break;
	case 1: cols += 52; break;
	case 2: cols *= 2; break;
	default: cols = MAXCMD;
    }
    return cols - strlen(hdrs[CL_fmt]) + 6;
}


void print_cmdline(char *cmdline, int maxcmd)
{
  int i;
  if(CL_kern_comm) {
    char *endp;
    if(cmdline[0] == '(') {
      endp = strchr(cmdline,')');
      if (endp != NULL) {
	cmdline++;      /* get rid of '(' */
	*endp = 0; /* get rid of ')' */
      }
    } else { /* command line doesn't start with a '(' */
      endp = strchr(cmdline,' ');
      if (endp != NULL ) {
	*endp = 0;
      }
    }
  } else {
    /* Now, let's munge all the unprintables out */
    for(i=0; i<maxcmd,cmdline[i] != (char) 0; i++) {
      switch (cmdline[i]) {
      case '\t': /* tab */
      case '\n': /* newline */
      case '\r': /* return */
      case '\a': /* alert (bell) */
      case '\v': /* vertical tab */
      case '\b': /* backspace */
      case '\f': /* formfeed */
	cmdline[i] = ' ';
	break;
      default:
	break;
      }
    }
    if (i >= maxcmd)
      cmdline[maxcmd - 1] = (char) 0;
  }
  puts(cmdline);
}


void show_procs(unsigned int maxcmd, int no_header)
{
    struct ps_proc_head *ph;
    struct ps_proc *this, **arr_ver;
    int tty = 0, uid, i;

    uid = getuid();

    if (CL_ctty)
      tty = tty_to_dev(CL_ctty);

    if (!CL_pids)
      ph = take_snapshot((CL_all | (uid==0)), CL_fmt==PS_U, CL_no_ctty,
			   CL_fmt==PS_M, CL_run_only, uid, tty);
    else
      ph = get_processes(CL_pids, CL_fmt == PS_M);

    if (!ph->count) {
      fprintf(stderr, "No processes available\n");
      exit(1);
    }

    this = ph->head;                                 /* start at top of list */

    arr_ver = xmalloc(ph->count * sizeof (struct ps_proc*));/* allocate array */

    for(i=0; this != NULL; this = this->next, i++)/* copy into array version */
        arr_ver[i] = this;

    if (CL_sort)          /* run qsort on the array with multi-level compare */
        qsort(arr_ver, ph->count, sizeof this, (void *) mult_lvl_cmp);

    if (!no_header)
	puts(hdrs[CL_fmt]);
    for (i = 0; i < ph->count; ++i) {
      this=arr_ver[i];
      (fmt_fnc[CL_fmt])(this);
      if (CL_fmt != PS_V && CL_fmt != PS_M)
	show_time(this);
      print_cmdline(strlen(this->cmdline) ? this->cmdline : this->cmd,
		    maxcmd);
    }

    free (arr_ver);
}



void show_short(struct ps_proc *this)
{
    printf("%5d %3s %s",
	this->pid,
	this->ttyc,
	status(this));
}

void show_long(struct ps_proc *this)
{
  char wchanb[10];

  if(GL_wchan_nout)
    sprintf(wchanb, "%-9x", this->wchan);
  else
    sprintf(wchanb, "%-9.9s", wchan(this->wchan));
  printf("%3x %5d %5d %5d %3d %2d %4d %4d %-10.10s %s %3s ",
	 this->flags, /* the used_math element will /always/ be set,
			 because crt0.s checks the math emulation,
			 so it isn't worth including here, which is
			 why I didn't include it in the output format
			 from the stat file... */
	 this->uid,
	 this->pid,
	 this->ppid,
	 2*PZERO-this->counter,
	 PZERO - this->priority, /* get standard unix nice value... */
	 this->vsize / 1024,
	 this->rss * 4,
	 wchanb,
	 status(this),
	 this->ttyc);
}

void show_jobs(struct ps_proc *this)
{
    printf("%5d %5d %5d %5d %3s %5d  %s %5d ",
	this->ppid,
	this->pid,
	this->pgrp,
	this->session,
	this->ttyc,
	this->tpgid,
	status(this),
	this->uid);
}

void show_user(struct ps_proc *this)
{
  int pmem, total_time, seconds;
  time_t start;
  unsigned int pcpu;

  if (CL_num_outp)
    printf("%5d    ", this->uid);
  else
    printf("%-8s ", this->user);
  seconds = (((GL_current_time * 100) - this->start_time) / HZ);
  start = GL_time_now - seconds;
  total_time = (this->utime + this->stime +
		(CL_Sum ? this->cutime + this->cstime : 0));
  pcpu = seconds ?
         (total_time * 10) / seconds :
         0;
  if (pcpu > 999) pcpu = 999;
  pmem = this->rss * 1000 / (GL_main_mem / 4096);
  printf("%5d %2u.%u %2d.%d %4d %4d %2s %s%.6s ",
	 this->pid,
	 pcpu / 10, pcpu % 10,
	 pmem / 10, pmem % 10,
	 this->vsize / 1024,
	 this->rss * 4,
	 this->ttyc,
	 status(this),
	 ctime(&start) + (GL_time_now - start > 3600*24 ? 4 : 10));
}

void show_sig(struct ps_proc *this)
{

    printf("%5d %5d %08x %08x %08x %08x %s %3s ",
	this->uid,
	this->pid,
	this->signal,
	this->blocked,
	this->sigignore,
	this->sigcatch,
	status(this),
	this->ttyc);
}

void show_vm(struct ps_proc *this)
{
    int pmem;

    printf("%5d %3s %s",
	   this->pid,
	   this->ttyc,
	   status(this));
    show_time(this);
    printf(" %6d %4d %4d %4d ",
	   this->maj_flt + (CL_Sum ? this->cmaj_flt : 0),
	   this->end_code / 1024,
	   (this->vsize - this->end_code) / 1024,
	   this->rss * 4);
    if(this->rss_rlim == RLIM_INFINITY)
      printf("   xx ");
    else
      printf("%5d ", this->rss_rlim / 1024);
    pmem = this->rss * 1000 / (GL_main_mem / 4096);
    printf("%2d.%d ", pmem / 10, pmem % 10);
}


void show_m(struct ps_proc *this)
{

  printf("%5d %3s %6d %6d %4d %4d %4d %4d %4d %4d %4d %3d ", 
	 this->pid,
	 this->ttyc,
	 this->maj_flt + (CL_Sum ? this->cmaj_flt : 0),
	 this->min_flt + (CL_Sum ? this->cmin_flt : 0),
	 this->statm.trs << CL_pg_shift,
	 this->statm.drs << CL_pg_shift,
	 this->statm.size << CL_pg_shift,
	 (this->statm.size - this->statm.resident) << CL_pg_shift,
	 this->statm.resident << CL_pg_shift,
	 this->statm.share << CL_pg_shift,
	 this->statm.lrs << CL_pg_shift,
	 this->statm.dt);
}

void show_regs(struct ps_proc *this)
{
    printf("%2d %5d %8x %8x %8x ",
	this->start_code >> 26,
	this->pid,
	this->start_stack,
	this->kstk_esp,
	this->kstk_eip);

    prtime(this->timeout, GL_current_time * 100);
    prtime(this->it_real_value, 0);

    printf("%s %3s ",
	status(this),
	this->ttyc);
}

void prtime(unsigned long t, unsigned long rel)
{
    if (t == 0) {
	printf("      ");
	return;
    }
    if ((long) t == -1) {
	printf("   xx ");
	return;
    }
    if ((long) (t -= rel) < 0)
	t = 0;
    
    if (t > 9999)
	printf("%5lu ", t / 100);
    else
	printf("%2lu.%02lu ", t / 100, t % 100);
}

void (*fmt_fnc[])() = {
    show_short,
    show_long,
    show_user,
    show_jobs,
    show_sig,
    show_vm,
    show_m,
    show_regs
};


void show_time(struct ps_proc * this)
{
    unsigned t;
    t = (this->utime + this->stime) / HZ;
    if (CL_Sum) t += (this->cutime + this->cstime) / HZ;
    printf("%3d:%02d ", t / 60, t % 60);
}


void read_globals()
{
  char uptime[30], memory[300];
  int fd;

  fd = open("/proc/uptime", O_RDONLY, 0);
  if (fd == -1) {
    fprintf(stderr, "Error: /proc must be mounted\n"
      "  Make sure that a directory /proc exists, then include the following\n"
      "  line in your /etc/fstab file:\n"
      "      /proc   /proc   proc    defaults\n"
      "  Then the next time you boot, ps should work.  In the meantime, do:\n"
      "      mount /proc /proc -t proc\n");
    exit(1);
  }
  read(fd,uptime,29);
  close(fd);
  GL_current_time = atoi(uptime);
  fd = open("/proc/meminfo", O_RDONLY, 0);
  if(fd == -1) {
    perror("ps.c:/proc/meminfo");
    exit(1);
  }
  read(fd,memory,299);
  close(fd);
  sscanf(memory, "%*s %*s %*s %*s %*s %*s %u", &GL_main_mem);
  GL_time_now = time(0L);
}
