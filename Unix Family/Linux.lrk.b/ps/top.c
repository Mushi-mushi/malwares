/*
 * top.c		- show top CPU processes
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

#include "sysinfo.h"
#include "ps.h"
#include "whattime.h"
#include "signals.h"


/* This structure stores some critical information from one frame to
   the next. */
struct save_hist {
    int ticks;
    int pid;
    int pcpu;
    int utime;
    int stime;
};


/* The original terminal attributes. */
struct termio Savetty;
/* The new terminal attributes. */
struct termio Rawtty;

/* Cached termcap entries. */
char *cm, *cl, *clrtobot, *clrtoeol, *ho;

/* Current window size.  Note that it is legal to set Display_procs
   larger than can fit; if the window is later resized, all will be ok.
   In other words: Display_procs is the specified max number of
   processes to display (zero for infinite), and Maxlines is the actual
   number. */
int Lines, Cols, Maxlines, Display_procs;

/* Maximum length of the command line of a process. */
unsigned Maxcmd;

/* The top of the main loop. */
jmp_buf redraw_jmp;

/* Information about each task. */
struct save_hist New_save_hist[NR_TASKS];

/* Controls how long we sleep between screen updates.  Accurate to
   microseconds. */
float Sleeptime = 5;

/* Mode flags. */
int Secure = 0;
int Cumulative = 0;
int Noidle = 0;


/* The header printed at the top of the process list.  It would make
   sense if TIME became (say) CTIME in cumulative mode, but that's not
   how ps does it. */
#define HEADER \
    "  PID USER     PRI  NI SIZE  RES SHRD STAT %CPU %MEM  TIME COMMAND"

/* The response to the interactive 'h' command. */
#define HELP_SCREEN "\
Interactive commands are:\n\
\n\
^L\tRedraw the screen\n\
h or ?\tPrint this list\n\
i\tToggle displaying of idle proceses\n\
k\tKill a task (with any signal)\n\
n or #\tSet the number of process to show\n\
q\tQuit\n\
r\tRenice a task\n\
S\tToggle cumulative mode\n\
s\tSet the delay in seconds between updates\n"
#define SECURE_HELP_SCREEN "\
Interactive commands available in secure mode are:\n\
\n\
^L\tRedraw the screen\n\
h or ?\tPrint this list\n\
i\tToggle displaying of idle proceses\n\
n or #\tSet the number of process to show\n\
q\tQuit\n\
S\tToggle cumulative mode\n"

/* Number of lines not to use for displaying processes. */
#define HEADER_LINES 7

/* String to use in error messages. */
#define PROGNAME "top"


/* Clear the screen. */
#define clear_screen() \
    printf("%s", cl)

/* Show an error in the context of the spiffy full-screen display. */
#define SHOWMESSAGE(x) do { 			\
    printf("%s%s", tgoto(cm, 0, 5), clrtoeol);	\
    printf x;					\
    fflush(stdout);				\
    sleep(2);					\
} while (0)


void end(void);
void stop(void);
void window_size(void);
void show_procs(struct ps_proc_head *ph);
float get_elapsed_time(void);
unsigned show_meminfo(void);
void do_stats(struct ps_proc_head *ph, float elapsed_time,int pass);
void do_key(char c);
int getnum(void);
char *getstr(void);
int getsig(void);
float getfloat(void);
   

int
main(int argc, char **argv)
{
    /* For the snapshot. */
    struct ps_proc_head *ph;
    float elapsed_time;
    /* For select(2). */
    struct timeval tv;
    fd_set in;
    /* For parsing arguments. */
    char *cp;
    /* The key read in. */
    char c;

    char *termtype;
    struct termio newtty;

    /*
     * Parse arguments.
     */
    argv++;
    while (*argv) {
    	cp = *argv++;
	while (*cp) {
	    switch (*cp) {
	    case 'd':
		if (sscanf(cp+1, "%f", &Sleeptime) != 1) {
		    fprintf(stderr, PROGNAME ": Bad delay time `%s'\n", cp+1);
		    exit(1);
		}
		goto breakargv;
		break;
	    case 'q':
		if (!getuid())
		    /* Why not -20, which the manpage says is the highest?
		       Would that interfere with the kernel? */
		    if (setpriority(PRIO_PROCESS, getpid(), -15)) {
		    	/* We check this just for paranoia.  It's not
		    	   fatal, and shouldn't happen. */
		    	perror(PROGNAME ": setpriority() failed");
		    }
		Sleeptime = 0;
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
		break; /* Just ignore it */
	    default:
		fprintf(stderr, PROGNAME ": Unknown argument `%c'\n", *cp);
		exit(1);
	    }
	    cp++;
	}
    breakargv:
    }

    /*
     * Set up the terminal attributes.
     */
    termtype = getenv("TERM");
    if (!termtype) { 
	/* In theory, $TERM should never not be set, but in practice,
	   some gettys don't.  Fortunately, vt100 is nearly always
	   correct (or pretty close). */
	termtype = "VT100";
	/* fprintf(stderr, PROGNAME ": $TERM not set\n"); */
	/* exit(1); */
    }
    close(0);
    if (open("/dev/tty", O_RDONLY)) {
	perror(PROGNAME ": stdin is not there\n");
	exit(errno);
    }
    if (ioctl(0, TCGETA, &Savetty) == -1) {
	perror(PROGNAME ": ioctl() failed");
	exit(errno);
    }
    newtty = Savetty;
    newtty.c_lflag &= ~ICANON;
    newtty.c_lflag &= ~ECHO;
    newtty.c_cc[VMIN] = 1;
    newtty.c_cc[VTIME] = 0;
    if (ioctl(0, TCSETAF, &newtty) == -1) {
	printf("cannot put tty into raw mode\n");
	exit(1);
    }
    ioctl(0, TCGETA, &Rawtty);

    /*
     * Get termcap entries and window size.
     */
    tgetent(NULL, termtype);
    cm = tgetstr("cm", 0);
    clrtobot = tgetstr("cd", 0);
    cl = tgetstr("cl", 0);
    clrtoeol = tgetstr("ce", 0);
    ho = tgetstr("ho", 0);
    window_size();

    /*
     * Set up signal handlers.
     */
    signal(SIGHUP, (void *)(int) end);
    signal(SIGINT, (void *)(int) end);
    signal(SIGTSTP, (void *)(int) stop);
    signal(SIGWINCH, (void *)(int) window_size);

    /* first time through, just collect process stats */
    ph = take_snapshot(1, 1, 1, 1, 0, 0, 0);
    elapsed_time = get_elapsed_time();
    do_stats(ph, elapsed_time, 0);
    sleep(1);

    /* loop, collecting process info and sleeping */
    while(1) {
	if (setjmp(redraw_jmp))
	    clear_screen();

	/* display the tasks */
	show_procs(ph);
	
	/* sleep & wait for keyboard input */
	tv.tv_sec = Sleeptime;
	tv.tv_usec = (Sleeptime - (int)Sleeptime) * 1000000;
	FD_ZERO(&in);
	FD_SET(0, &in);
	if (select(16, &in, 0, 0, &tv) > 0 && read(0, &c, 1) == 1)
	    do_key(c);
    }
}



/*
 * Normal end of execution.
 */
void
end(void)
{
    ioctl(0, TCSETAF, &Savetty);
    printf("%s\r\n", tgoto(cm, 0, Lines - 1));
    exit(0);
}


/*
 * SIGTSTP catcher.
 */
void
stop(void)
{
    /* Reset terminal. */
    ioctl(0, TCSETAF, &Savetty);
    printf("%s", tgoto(cm, 0, Lines - 3));
    fflush(stdout);
    raise(SIGTSTP);
    /* Later... */
    ioctl(0, TCSETAF, &Rawtty);
    signal(SIGTSTP, (void *)(int) stop);
    longjmp(redraw_jmp, 1);
}


/*
 * Reads the window size and clear the window.  This is called on setup,
 * and also catches SIGWINCHs, and adjusts Maxlines.  Basically, this is
 * the central place for window size stuff.
 */
void
window_size(void)
{
    struct winsize ws;

    if (ioctl(1, TIOCGWINSZ, &ws) != -1) {
	Cols = ws.ws_col;
	Lines = ws.ws_row;
    } else {
	Cols = tgetnum("co");
	Lines = tgetnum("li");
    }
    Maxlines = Display_procs ? Display_procs : Lines - HEADER_LINES;
    if (Maxlines > Lines - HEADER_LINES)
    	Maxlines = Lines - HEADER_LINES;
    Maxcmd = Cols - strlen(HEADER) + 7;
    clear_screen();
}


/*
 * Get a string from the user; the base of getint(), et al.  This really
 * ought to handle long input lines and errors better.  NB: The pointer
 * returned is a statically allocated buffer, so don't expect it to
 * persist between calls.
 */
char *
getstr(void)
{
    static char line[BUFSIZ];		/* BUFSIZ from <stdio.h>; arbitrary */
    int i = 0;

    /* Must make sure that buffered IO doesn't kill us. */
    fflush(stdout);
    fflush(stdin);			/* Not POSIX but ok */

    do {
	read(STDIN_FILENO, &line[i], 1);
    } while (line[i++] != '\n' && i < sizeof(line));
    line[--i] = 0;

    return(line);
}


/*
 * Get an integer from the user.  Display an error message and return -1
 * if it's invalid; else return the number.
 */
int
getint(void)
{
    char *line;
    int i;
    int r;

    line = getstr();

    for (i = 0; line[i]; i++) {
	if (!isdigit(line[i])) {
            SHOWMESSAGE(("That's not a number!"));
            return(-1);
        }
    }

    /* An empty line is a legal error (hah!). */
    if (!line[0])
    	return (-1);

    sscanf(line, "%d", &r);
    return(r);
}


/*
 * Get a float from the user.  Just like getint().
 */
float
getfloat(void)
{
    char *line;
    int i;
    float r;

    line = getstr();

    for (i = 0; line[i]; i++) {
	if (!isdigit(line[i])) {
            SHOWMESSAGE(("That's not a number!"));
            return(-1);
        }
    }

    /* An empty line is a legal error (hah!). */
    if (!line[0])
    	return (-1);

    sscanf(line, "%f", &r);
    return(r);
}


/*
 * Get a signal number or name from the user.  Return the number, or -1
 * on error.
 */
int
getsig(void)
{
    char *line;

    /* This is easy. */
    line = getstr();
    return(get_signal2(line));
}


/*
 * This is the real program!  Read process info and display it.
 */
void
show_procs(struct ps_proc_head *ph)
{
    struct ps_proc *this, *best;
    int count, top;
    int index, best_index;
    float elapsed_time;
    unsigned int main_mem;

    /* Display the load averages. */
    printf("%s%s%s\n", ho, sprint_uptime(), clrtoeol);

    /* Get the process info. */
    ph = refresh_snapshot(ph, 1, 1, 1, 1, 0, 0, 0);
    /* Immediately find out the elapsed time for the frame. */
    elapsed_time = get_elapsed_time();

    /* Display the system stats and calculate percent CPU time. */
    do_stats(ph, elapsed_time, 1);

    /* Display the memory and swap space usage. */
    main_mem = show_meminfo();
    printf("%s%s", HEADER, clrtoeol);
    
    /*
     * Finally!  Loop through to find the top task, and display it.
     * Lather, rinse, repeat.
     */
    count = 0;
    top = 100;
    while ((count < Maxlines) && (top >= 0)) {
	/* Find the top of the remaining processes. */
	top = -1;
	this = ph->head;
	best = this;
	best_index = 0;
	index = 0;
	while (this) {
	    if (New_save_hist[index].pcpu > top) {
		top = New_save_hist[index].pcpu;
		best = this;
		best_index = index;
	    }
	    index++;
	    this = this->next;
	}
	count++;
	if (top >= 0) {
	    int pcpu, pmem;
	    unsigned int t;
	    char *cmdptr;
	    char *stat;

	    stat = status(best);

	    if (!Noidle || (*stat != 'S' && *stat != 'Z')) {

		/*
		 * Show task info.
		 */
		pcpu = New_save_hist[best_index].pcpu;
		pmem = best->rss * 1000 / (main_mem / 4096);
		printf("\n%5d %-8s %3d %3d %4d %4d %4d %s %2d.%d %2d.%d", 
		       best->pid, best->user, 2 * PZERO - best->counter,
		       PZERO - best->priority, best->vsize / 1024,
		       best->rss * 4, best->statm.share << 2, stat,
		       pcpu / 10, pcpu % 10, pmem / 10, pmem % 10);

		/*
		 * Show total CPU time.
		 */
		t = (best->utime + best->stime) / HZ;
		if (Cumulative)
		    t += (best->cutime + best->cstime) / HZ;
		printf("%3d:%02d ", t / 60, t % 60);
		
		/*
		 * Show command line.
		 */
		if (*best->cmdline)
		    cmdptr = best->cmdline;
		else
		    cmdptr = best->cmd;
		if (strlen(cmdptr) > Maxcmd)
		    cmdptr[Maxcmd - 1] = 0;
		printf("%s%s", cmdptr, clrtoeol);
	    }
	}

	New_save_hist[best_index].pcpu = -1;
    }
    printf("%s%s", clrtobot, tgoto(cm, 0, 5));

    fflush(stdout);
}


/*
 * Finds the current time (in microseconds) and calculates the time
 * elapsed since the last update. This is essential for computing
 * percent CPU usage.
 */
float
get_elapsed_time(void)
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
    return(elapsed_time);
}


/*
 * Reads the memory info and displays it.  Returns the total memory
 * available, for use in percent memory usage calculations.
 */
unsigned
show_meminfo(void)
{
  char memory[1024];
  static int fd;
  unsigned int main_mem, used_mem, free_mem, shared_mem, buf_mem;
  unsigned int swap_mem, used_swap, free_swap;

  fd = open("/proc/meminfo", O_RDONLY, 0);
  if (fd == -1) {
      perror(PROGNAME ": Couldn't open /proc/meminfo");
      end();
  }
  read(fd, memory, sizeof(memory) - 1);
  close(fd);
  sscanf(memory, "%*s %*s %*s %*s %*s %*s %u %u %u %u %u %*s %u %u %u",
	 &main_mem, &used_mem, &free_mem, &shared_mem, &buf_mem,
	 &swap_mem, &used_swap, &free_swap);
  printf("Mem:  %5dK av, %5dK used, %5dK free, %5dK shrd, %5dK buff%s\n",
	 main_mem / 1024, used_mem / 1024, free_mem / 1024, 
	 shared_mem / 1024, buf_mem / 1024, clrtoeol);
  printf("Swap: %5dK av, %5dK used, %5dK free%s\n%s\n",
	 swap_mem / 1024, used_swap / 1024, free_swap / 1024,
	 clrtoeol, clrtoeol);
  return(main_mem);
}


/*
 * Calculates the number of tasks in each state (running, sleeping, etc.).
 * Calculates the CPU time in each state (system, user, nice, etc).
 * Calculates percent cpu usage for each task.
 */
void
do_stats(struct ps_proc_head *ph, float elapsed_time, int pass)
{
    struct ps_proc *this;
    int index, total_time, i;
    int sleeping = 0, stopped = 0, zombie = 0, running = 0;
    int system_ticks = 0, user_ticks = 0, nice_ticks = 0, idle_ticks = 1000;
    static int prev_count = 0;
    static struct save_hist save_hist[NR_TASKS];
    int stime, utime;

    if (ph->count >NR_TASKS) {
	printf(PROGNAME ": Help!  Too many tasks!\n");
	end();
    }

    /*
     * Make a pass through the data to get stats.
     */
    index = 0;
    this = ph->head;
    while (this) {
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
	/* find matching entry from previous pass*/
	i = 0;
	while (i < prev_count) {
	    if (save_hist[i].pid == this->pid) {
		total_time -= save_hist[i].ticks;
		stime -= save_hist[i].stime;
		utime -= save_hist[i].utime;

		i = NR_TASKS;
	    }
	    i++;
	}

	/*
	 * Calculate percent cpu time for this task.
	 */
	New_save_hist[index].pcpu = (total_time * 10) / elapsed_time;
	if (New_save_hist[index].pcpu > 999)
	    New_save_hist[index].pcpu = 999;

	/*
	 * Calculate time in idle, system, user and niced tasks.
	 */
	idle_ticks -= New_save_hist[index].pcpu;
	system_ticks += stime;
	user_ticks += utime;
	if (this->priority < PZERO)
	    nice_ticks += New_save_hist[index].pcpu;

	index++;
	this = this->next;
    }

    if (idle_ticks < 0)
	idle_ticks = 0;
    system_ticks = (system_ticks * 10) / elapsed_time;      
    user_ticks = (user_ticks * 10) / elapsed_time;

    /*
     * Display stats.
     */
    if (pass>0) {
	printf("%d processes: %d sleeping, %d running, %d zombie, "
	       "%d stopped%s\n",
	       ph->count, sleeping, running, zombie, stopped, clrtoeol);
	printf("CPU states: %2d.%d%% user, %2d.%d%% system,"
	       " %2d.%d%% nice, %2d.%d%% idle%s\n",
	       user_ticks / 10, user_ticks % 10,
	       system_ticks / 10, system_ticks % 10,
	       nice_ticks / 10, nice_ticks % 10,
	       idle_ticks / 10, idle_ticks % 10, clrtoeol);
    }

    /*
     * Save this frame's information.
     */
    for (i = 0; i < ph->count; i++) {
	/* copy the relevant info for the next pass */
	save_hist[i].pid = New_save_hist[i].pid;
	save_hist[i].ticks = New_save_hist[i].ticks;
	save_hist[i].stime = New_save_hist[i].stime;
	save_hist[i].utime = New_save_hist[i].utime;
    }
    prev_count = ph->count;
}


/*
 * Process keyboard input.
 */
void
do_key(char c)
{
    int numinput;

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
    case 'h':
	printf("%s%s\nProc-Top Revision 0\n", cl, ho);
	printf("Secure mode %s; cumulative mode %s; noidle mode %s\n\n",
	       Secure ? "on" : "off", Cumulative ? "on" : "off",
	       Noidle ? "on" : "off");
	printf("%s\n\nPress any key to continue\n",
	       Secure ? SECURE_HELP_SCREEN : HELP_SCREEN);
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

	    printf("PID to kill: ");
	    pid = getint();
	    if (pid == -1)
	        break;
	    printf("%s%sKill PID %d with signal [15]: ",
	    	   tgoto(cm, 0, 5), clrtoeol, pid);
	    signal = getsig();
	    if (signal == -1)
	        signal = SIGTERM;
	    if (kill(pid, signal))
		SHOWMESSAGE(("\aKill of PID %d with %d failed: %s",
			     pid, signal, strerror(errno)));
	}
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
	    printf("%s%sRenice PID %d to value: ",
	    	   tgoto(cm, 0, 5), clrtoeol, pid);
	    val = getint();
	    if (val == -1)
	        val = 10;
	    if (setpriority(PRIO_PROCESS, pid, val))
		SHOWMESSAGE(("\aRenice of PID %d to %d failed: %s",
			     pid, val, strerror(errno)));
	}
	break;
    case 'S':
    	Cumulative = !Cumulative;
    	SHOWMESSAGE(("Cumulative mode %s", Cumulative ? "on" : "off"));
    	break;
    case 's':
	if (Secure)
	    SHOWMESSAGE(("\aCan't change delay in secure mode"));
	else {
	    printf("Delay between updates: ");
	    numinput = getfloat();
	    if (numinput != -1)
	    	Sleeptime = numinput;
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
