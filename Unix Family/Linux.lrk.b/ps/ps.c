/*
 * ps.c                - show process status
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


#define        PS_D        0        /* default format (short) */
#define        PS_L        1        /* long format */
#define        PS_U        2        /* user format */
#define        PS_J        3        /* jobs format */
#define        PS_S        4        /* signal format */
#define        PS_V        5        /* vm format */
#define        PS_M        6        /* mem. stuff */
#define        PS_X        7        /* regs etc., for testing */

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

int maxcols=0;

struct tree_node *node;
int nodes = 0;
int maxnodes = 0;

extern void (*fmt_fnc[])();        /* forward declaration */
char *prtime(char *s, unsigned long t, unsigned long rel);
void read_globals();
void usage(void);
void show_procs(unsigned int maxcmd, int no_header);
void show_time(char *s, struct ps_proc * this);
void add_node(char *s, struct ps_proc *task);
int node_cmp(const void *s1, const void *s2);
void show_tree(int n, int depth, char *continued);
void show_forest( void );
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
pid_t *CL_pids = NULL;        /* a zero-terminated list, dynamically allocated */
int CL_show_env = 0;
int CL_num_outp = 0;        /* numeric fields for user or wchan */
int CL_pg_shift = 2;        /* default: show k instead of pages */
int CL_Sum = 0;
int CL_sort = 1;
int CL_forest = 0;

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
    int next_arg = 0;
    int toppid = 0;

    if (argc > 1) do
    {
        --argc;
        ++argv;  /* shift to line args. At top of loop because of argv[0] */
        for (p = *argv; *p; ++p) {
            switch (*p) {
                case '-':               /* "--" ==> long name options */
                  if (*(p+1) == '-') {
                    if (strncmp(p+2,"sort",4)==0) {
                      if (parse_long_sort(p+7) == -1)
                        usage();
                      user_ord = 1;
                      break;
                    } else if (strncmp(p+2, "help", 4) == 0) {
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
                case 'l': CL_fmt = PS_L; strncpy(fmt_ord,"Pp",MX_OP); break;
                case 'u': CL_fmt = PS_U; strncpy(fmt_ord,"up",MX_OP); break;
                case 'j': CL_fmt = PS_J; strncpy(fmt_ord,"gPp",MX_OP); break;
                case 's': CL_fmt = PS_S; strncpy(fmt_ord,"p",MX_OP); break;
                case 'v': CL_fmt = PS_V; strncpy(fmt_ord,"p",MX_OP); break;
                case 'm': CL_fmt = PS_M; strncpy(fmt_ord,"s",MX_OP); break;
                case 'X': CL_fmt = PS_X; strncpy(fmt_ord,"p",MX_OP); break; /* regs */
                case 'f': CL_forest = 1; break;
                case 'a': CL_all = 1; break;
                case 'c': CL_kern_comm = 1; break;
                case 'x': CL_no_ctty = 1; break;
                case 't': CL_ctty = p + 1; next_arg = 1; break;
                case 'r': CL_run_only = 1; break;
                case 'e': CL_show_env = 1; break;
                case 'w': ++width; break;
                case 'h': no_header = 1; break;
                case 'n': CL_num_outp = 1; GL_wchan_nout = 1; break;
                case 'S': CL_Sum = 1; break;
                case 'p': CL_pg_shift = 0; break;
                case 'g': break;   /* old flag, ignore */ 
                case 'o': CL_sort = !CL_sort; break; /* off or on by default?*/
                case 'O': if (parse_sort_opt(p+1) == -1) usage(); user_ord = 1; next_arg = 1; break;
                default:
                /* Step through, reading comma-delimited pids and allocating space for them. */
                    if (isdigit(*p)) {
                        while (*p) {
                            CL_pids = xrealloc(CL_pids, (toppid + 2) * sizeof(pid_t));
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
                        usage();
            }
            if (next_arg) {
                next_arg = 0;
                break;       /* end loop over chars in this argument */
            }
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
    
    maxcols = 80;
    if (ioctl(1, TIOCGWINSZ, &win) != -1 && win.ws_col > 0)
        maxcols = win.ws_col;

    switch (w_opts) {
        case 0: break;
        case 1: maxcols += 52; break;
        case 2: maxcols *= 2; break;
        default: maxcols = MAXCMD;
    }
    return maxcols - strlen(hdrs[CL_fmt]) + 7;
}


int print_cmdline(char *cmdline, int maxcmd)
{
  int i = 0;
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
    for(i=0; i<maxcmd,cmdline[i] != (char) 0; i++)
      if (!isprint(cmdline[i]))
          cmdline[i] = ' ';
    if (i >= maxcmd)
      cmdline[maxcmd] = (char) 0;
  }
  fputs(cmdline, stdout);
  return maxcmd - i;
}


void print_env(int pid, int maxenv) {
    char c, buf[22];
    FILE* environ;

    fputs(" + ", stdout); maxenv -= 3;
    if (maxenv > 0) {
	sprintf(buf, "/proc/%d/environ", pid);
        environ = fopen(buf, "r");
        while (maxenv-- > 0) {
            c = fgetc(environ);
            putchar(isprint(c)?c:' ');
        }
    }
}


void show_procs(unsigned int maxcmd, int no_header)
{
    struct ps_proc_head *ph;
    struct ps_proc *this, **arr_ver;
    int tty = 0, uid, i, space_left;
    char s[80];

    uid = getuid();

    if (CL_ctty)
      if ((tty = tty_to_dev(CL_ctty))==-1) {
          fprintf(stderr, "the name `%s' is not a tty\n", CL_ctty);
          exit(1);
      }

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

    if (!CL_forest && CL_sort)          /* run qsort on the array with multi-level compare */
        qsort(arr_ver, ph->count, sizeof this, (void *) mult_lvl_cmp);

    if (!no_header)
        puts(hdrs[CL_fmt]);
    for (i = 0; i < ph->count; ++i) {
      this=arr_ver[i];
      (fmt_fnc[CL_fmt])(s, this);
      if (CL_fmt != PS_V && CL_fmt != PS_M)
        show_time(s+strlen(s), this);
      if (CL_forest)
        add_node(s, this);        
      else        
      {
        printf( "%s", s );
        space_left = print_cmdline(*(this->cmdline) ? this->cmdline : this->cmd, maxcmd);
        if (CL_show_env)
            print_env(this->pid, space_left);
        puts(""); /* newline */
      }
    }
    if (CL_forest)
        show_forest();
    free (arr_ver);
}

void
add_node(char *s, struct ps_proc *task)
{
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
    node[nodes].proc = task;
    node[nodes].pid = task->pid;
    node[nodes].ppid =task->ppid;
    node[nodes].line = strdup(s);
    node[nodes].cmd = *(task->cmdline) ? task->cmdline : task->cmd;
    node[nodes].children = 0;
    node[nodes].have_parent = 0;
    nodes++;
}

int
node_cmp(const void *s1, const void *s2)
{
    struct tree_node *n1 = (struct tree_node *) s1;
    struct tree_node *n2 = (struct tree_node *) s2;

    return n1->pid - n2->pid;
}

void
show_tree(int n, int depth, char *continued)
{
    int i;
    int cols;
    int space_left;

    cols = printf("%s", node[n].line);

    for (i = 0; i < depth; i++) 
    {
        if (cols + 4 >= maxcols - 1)
            break;
        if (i == depth - 1)
            printf(" \\_ ");
        else if (continued[i])
            printf(" |  ");
        else
            printf("    ");
        cols += 4;
    }
    /*printf("%-.*s\n", maxcols - cols - 1, node[n].cmd);*/
    space_left = print_cmdline( node[n].cmd, maxcols - cols );
    if (CL_show_env)
	print_env(node[n].pid, space_left);
    puts(""); /* newline */
    for (i = 0; i < node[n].children; i++) 
    {
        continued[depth] = i != node[n].children - 1;
        show_tree(node[n].child[i], depth + 1, continued);
    }
}

void
show_forest(void)
{
    register int i, j;
    int parent;
    char continued[1024];

    if (CL_sort)
            qsort((void *) node, nodes, sizeof(struct tree_node), (void*)node_mult_lvl_cmp);
            
    for (i = 0; i < nodes; i++) {
        if (node[i].ppid > 1 && node[i].pid != node[i].ppid) 
        {
           parent = -1;
           for ( j=0; j<nodes; j++ )
                   if (node[j].pid==node[i].ppid)
                           parent = j;
        }
        else
            parent = -1;
        if (parent >= 0) 
        {
            node[i].have_parent++;
            if (node[parent].children == 0) {
                node[parent].child = (int *) malloc(16 * sizeof(int *));
                node[parent].maxchildren = 16;
            }
            else if (node[parent].children == node[parent].maxchildren) {
                node[parent].maxchildren *= 2;
                node[parent].child = (int *) realloc(node[parent].child,
                                                     node[parent].maxchildren
                                                     * sizeof(int *));
            }
            node[parent].child[node[parent].children++] = i;
        }
    }

    for (i = 0; i < nodes; i++) {
        if (!node[i].have_parent)
            show_tree(i, 0, continued);
    }
}

void show_short(char *s, struct ps_proc *this)
{
    sprintf(s, "%5d %3s %s",
        this->pid,
        this->ttyc,
        status(this));
}

void show_long(char *s, struct ps_proc *this)
{
  char wchanb[10];

  if(GL_wchan_nout)
    sprintf(wchanb, "%-9x", this->wchan);
  else
    sprintf(wchanb, "%-9.9s", wchan(this->wchan));
/*sprintf(s, "%2x %5d %5d %5d %3d %2d %4d %4d %-10.10s %s %3s ",*/
  sprintf(s, "%3x %5d %5d %5d %3d %2d %4d %4d %-10.10s %s %3s ",
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

void show_jobs(char *s, struct ps_proc *this)
{
    sprintf(s, "%5d %5d %5d %5d %3s %5d  %s %5d ",
        this->ppid,
        this->pid,
        this->pgrp,
        this->session,
        this->ttyc,
        this->tpgid,
        status(this),
        this->uid);
}

void show_user(char *s, struct ps_proc *this)
{
  int pmem, total_time, seconds;
  time_t start;
  unsigned int pcpu;

  if (CL_num_outp)
    s += sprintf(s, "%5d    ", this->uid);
  else
    s += sprintf(s, "%-8s ", this->user);
  seconds = (((GL_current_time * 100) - this->start_time) / HZ);
  start = GL_time_now - seconds;
  total_time = (this->utime + this->stime +
                (CL_Sum ? this->cutime + this->cstime : 0));
  pcpu = seconds ?
         (total_time * 10) / seconds :
         0;
  if (pcpu > 999) pcpu = 999;
  pmem = this->rss * 1000 / (GL_main_mem / 4096);
  sprintf(s, "%5d %2u.%u %2d.%d %4d %4d %2s %s%.6s ",
         this->pid,
         pcpu / 10, pcpu % 10,
         pmem / 10, pmem % 10,
         this->vsize / 1024,
         this->rss * 4,
         this->ttyc,
         status(this),
         ctime(&start) + (GL_time_now - start > 3600*24 ? 4 : 10));
}

void show_sig(char *s, struct ps_proc *this)
{

    sprintf(s, "%5d %5d %08x %08x %08x %08x %s %3s ",
        this->uid,
        this->pid,
        this->signal,
        this->blocked,
        this->sigignore,
        this->sigcatch,
        status(this),
        this->ttyc);
}

void show_vm(char *s, struct ps_proc *this)
{
    int pmem;

    s += sprintf(s,"%5d %3s %s",
           this->pid,
           this->ttyc,
           status(this));
    show_time(s, this);
    s += strlen(s);
    s += sprintf(s, " %6d %4d %4d %4d ",
           this->maj_flt + (CL_Sum ? this->cmaj_flt : 0),
           this->end_code / 1024,
           (this->vsize - this->end_code) / 1024,
           this->rss * 4);
    if(this->rss_rlim == RLIM_INFINITY)
      s += sprintf(s, "   xx ");
    else
      s += sprintf(s, "%5d ", this->rss_rlim / 1024);
    pmem = this->rss * 1000 / (GL_main_mem / 4096);
    sprintf(s, "%2d.%d ", pmem / 10, pmem % 10);
}


void show_m(char *s, struct ps_proc *this)
{

  sprintf(s, "%5d %3s %6d %6d %4d %4d %4d %4d %4d %4d %4d %3d ", 
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

void show_regs(char *s, struct ps_proc *this)
{
    char time1[16];
    char time2[16];

    s += sprintf(s, "%2d %5d %8x %8x %8x %s %s %s %3s ",
        this->start_code >> 26,
        this->pid,
        this->start_stack,
        this->kstk_esp,
        this->kstk_eip,
        prtime(time1, this->timeout, GL_current_time * 100),
        prtime(time2, this->it_real_value, 0),
        status(this),
        this->ttyc);
}

char *prtime(char *s, unsigned long t, unsigned long rel)
{
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


void show_time(char *s, struct ps_proc * this)
{
    unsigned t;
    t = (this->utime + this->stime) / HZ;
    if (CL_Sum) t += (this->cutime + this->cstime) / HZ;
    sprintf(s, "%3d:%02d ", t / 60, t % 60);
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
