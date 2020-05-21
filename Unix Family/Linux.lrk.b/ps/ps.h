/*
 * ps.h
 *
 * Copyright (c) 1992 Branko Lankester
 *
 * Modified heavily by Michael K. Johnson
 *
 * $Log: ps.h,v $
 * Revision 1.6  1994/09/14  03:36:40  cb
 * changes for bauke's forest feature.
 *
 * Revision 1.5  1994/07/27  22:56:54  cb
 * shields revisions for multi-pids
 *
 * Revision 1.4  1994/04/03  15:06:41  johnsonm
 * Added dump_keys() so that it can be called from ps.c.
 * May need to change it later to take a FILE* to print to so that
 *   ps and/or other programs can automagically pipe it through more or
 *   screen-oriented programs can display it on the screen.
 *   Remember that the GNU library can use file streams...
 *
 * Revision 1.3  1994/04/03  13:08:13  johnsonm
 * Added support for compare.c
 *
 * Revision 1.2  1994/01/01  11:16:30  johnsonm
 * Removed devline(), added dev3().
 *
 */


#include <sys/types.h>
#include <linux/sched.h>


#define	MAXCMD	1024	/* max # bytes to write from the command line */


struct ps_statm {
  int size, resident, share, trs, lrs, drs, dt;
};

struct ps_proc {
  char cmdline[256], user[10], cmd[40], state, ttyc[4];
  int uid, pid, ppid, pgrp, session, tty, tpgid, utime, stime,
    cutime, cstime, counter, priority, start_time, signal, blocked,
    sigignore, sigcatch;
  unsigned int flags, min_flt, cmin_flt, maj_flt, cmaj_flt, timeout,
    it_real_value, vsize, rss, rss_rlim, start_code, end_code,
    start_stack, kstk_esp, kstk_eip, wchan;
  struct ps_statm statm;
  struct ps_proc *next;
};

struct ps_proc_head {
  struct ps_proc *head;
  int count;
};

struct tree_node 
{
    struct ps_proc *proc;
    pid_t pid;
    pid_t ppid;
    char *line;
    char *cmd;
    int children;
    int maxchildren;
    int *child;
    int have_parent;
};

char *find_func();
void dev_to_tty(char *tty, int dev);
char *dev3(char *ttyname);
char *wchan(unsigned int);
char *status();
void *xcalloc(void *pointer, int size);
int mult_lvl_cmp(void* a, void* b);
int node_mult_lvl_cmp(void* a, void* b);
void dump_keys(void);

/* a, u, x, m, and r correspond to those command line options: if the
   variable is set, then the corresponding command line option was
   chosen. */
struct ps_proc_head *take_snapshot(char a, char u, char x, char m, char r,
				   uid_t uid, int ctty);
struct ps_proc_head *refresh_snapshot(struct ps_proc_head *ph,
				      char a, char u, char x, char m, char r,
				      uid_t uid, int ctty);
struct ps_proc_head *get_process(pid_t pid, int m);
struct ps_proc_head *get_processes(pid_t *pids, int m);
void free_psproc(struct ps_proc *this);
void dev_to_tty(char *tty, int dev);
int tty_to_dev(char *tty);
char *user_from_uid(int uid);
int open_psdb(void);
void close_psdb(void);

#define PZERO 15
char *status(struct ps_proc *task);
