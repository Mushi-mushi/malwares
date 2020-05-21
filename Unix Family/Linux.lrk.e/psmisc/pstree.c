/* pstree.c - display process tree */

/* Copyright 1993-1996 Werner Almesberger. See file COPYING for details. */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <dirent.h>
#include <termios.h>
#include <termcap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "comm.h"


#ifndef MAX_DEPTH
#define MAX_DEPTH    100
#endif
#define PROC_BASE    "/proc"

/* UTF-8 defines by Johan Myreen */
#define UTF_V	"\342\224\202\277"		/* Vertical line drawing char */
#define UTF_VR	"\342\224\234\277"		/* Vertical and right */
#define UTF_H	"\342\224\200\277"		/* Horizontal */
#define UTF_UR	"\342\224\224\277"		/* Up and right */
#define UTF_HD	"\342\224\254\277"		/* Horizontal and down */

#define VT_BEG	"\033(0\017"			/* use graphic chars */
#define VT_END	"\033(B"			/* back to normal char set */
#define VT_V	"x"				/* see UTF definitions above */
#define VT_VR	"t"
#define VT_H	"q"
#define VT_UR	"m"
#define	VT_HD	"w"

typedef struct _proc {
    char comm[COMM_LEN+1];
    char **argv;	/* only used : argv[0] is 1st arg; undef if argc < 1 */
    int argc;		/* with -a   : number of arguments, -1 if swapped    */
    pid_t pid;
    uid_t uid;
    int highlight;
    struct _child *children;
    struct _proc *parent;
    struct _proc *next;
} PROC;

typedef struct _child {
    PROC *child;
    struct _child *next;
}  CHILD;

static struct {
    const char *empty_2;	/*    */
    const char *branch_2;	/* |- */
    const char *vert_2;		/* |  */
    const char *last_2;		/* `- */
    const char *single_3;	/* --- */
    const char *first_3;	/* -+- */
} sym_ascii = { "  ",
	        "|-",
		"| ",
		"`-",
		"---",
		"-+-" },
  sym_utf =   { "  ",
		UTF_VR UTF_H,
		UTF_V " ",
		UTF_UR UTF_H,
		UTF_H UTF_H UTF_H,
		UTF_H UTF_HD UTF_H },
  sym_vt100 = { "  ",
		VT_BEG VT_VR VT_H VT_END,
		VT_BEG VT_V VT_END " ",
		VT_BEG VT_UR VT_H VT_END,
		VT_BEG VT_H VT_H VT_H VT_END,
		VT_BEG VT_H VT_HD VT_H VT_END },
  *sym = &sym_ascii;

static PROC *list = NULL;
static int width[MAX_DEPTH],more[MAX_DEPTH];
static int print_args = 0,compact = 1,user_change = 0,pids = 0,by_pid = 0,
  trunc = 1;
static output_width = 132;
static int cur_x = 1;
static char last_char = 0;
static int dumped = 0; /* used by dump_by_user */


static void out_char(char c)
{
    cur_x += (c & 0xc0) != 0x80; /* only count first UTF-8 char */
    if (cur_x <= output_width || !trunc) putchar(c);
    if (cur_x == output_width+1 && trunc)
	if (last_char || (c & 0x80)) putchar('+');
	else {
	    last_char = c;
	    cur_x--;
	    return;
	}
}


static void out_string(const char *str)
{
    while (*str) out_char(*str++);
}


static int out_int(int x) /* non-negative integers only */
{
    int digits,div;

    digits = 0;
    for (div = 1; x/div; div *= 10) digits++;
    if (!digits) digits = 1;
    for (div /= 10; div; div /= 10) out_char('0'+(x/div) % 10);
    return digits;
}


static void out_newline(void)
{
    if (last_char && cur_x == output_width) putchar(last_char);
    last_char = 0;
    putchar('\n');
    cur_x = 1;
}


static PROC *find_proc(pid_t pid)
{
    PROC *walk;

    for (walk = list; walk; walk = walk->next)
	if (walk->pid == pid) break;
    return walk;
}


static PROC *new_proc(const char *comm,pid_t pid,uid_t uid)
{
    PROC *new;

    if (!(new = malloc(sizeof(PROC)))) {
	perror("malloc");
	exit(1);
    }
    strcpy(new->comm,comm);
    new->pid = pid;
    new->uid = uid;
    new->highlight = 0;
    new->children = NULL;
    new->parent = NULL;
    new->next = list;
    return list = new;
}


static void add_child(PROC *parent,PROC *child)
{
    CHILD *new,**walk;
    int cmp;

    if (!(new = malloc(sizeof(CHILD)))) {
	perror("malloc");
	exit(1);
    }
    new->child = child;
    for (walk = &parent->children; *walk; walk = &(*walk)->next)
	if (by_pid) {
	    if ((*walk)->child->pid > child->pid) break;
	}
	else if ((cmp = strcmp((*walk)->child->comm,child->comm)) > 0) break;
	    else if (!cmp && (*walk)->child->uid > child->uid) break;
    new->next = *walk;
    *walk = new;
}


static void set_args(PROC *this,const char *args,int size)
{
    char *start;
    int i;

    if (!size) {
	this->argc = -1;
	return;
    }
    this->argc = 0;
    for (i = 0; i < size-1; i++)
	if (!args[i]) this->argc++;
    if (!this->argc) return;
    if (!(this->argv = malloc(sizeof(char *)*this->argc))) {
	perror("malloc");
	exit(1);
    }
    start = strchr(args,0)+1;
    size -= start-args;
    if (!(this->argv[0] = malloc((size_t) size))) {
	perror("malloc");
	exit(1);
    }
    start = memcpy(this->argv[0],start,(size_t) size);
    for (i = 1; i < this->argc; i++) this->argv[i] = start = strchr(start,0)+1;
}


static void add_proc(const char *comm,pid_t pid,pid_t ppid,uid_t uid,
  const char *args,int size)
{
    PROC *this,*parent;

    if (!(this = find_proc(pid))) this = new_proc(comm,pid,uid);
    else {
	strcpy(this->comm,comm);
	this->uid = uid;
    }
    if (args) set_args(this,args,size);
    if (pid == ppid) ppid = 0;
    if (!(parent = find_proc(ppid))) parent = new_proc("?",ppid,0);
    add_child(parent,this);
    this->parent = parent;
}


static int tree_equal(const PROC *a,const PROC *b)
{
    const CHILD *walk_a,*walk_b;

    if (strcmp(a->comm,b->comm)) return 0;
    if (user_change && a->uid != b->uid) return 0;
    for (walk_a = a->children, walk_b = b->children; walk_a && walk_b;
      walk_a = walk_a->next, walk_b = walk_b->next)
	if (!tree_equal(walk_a->child,walk_b->child)) return 0;
    return !(walk_a || walk_b);
}


static void dump_tree(PROC *current,int level,int rep,int leaf,int last,
  uid_t prev_uid,int closing)
{
    CHILD *walk,*next,**scan;
    const struct passwd *pw;
    int lvl,i,add,offset,len,swapped,info,count,comm_len,first;
    const char *tmp,*here;
    char comm_tmp[5];

    if (!current) return;
    if (level >= MAX_DEPTH-1) {
	fprintf(stderr,"MAX_DEPTH not big enough.\n");
	exit(1);
    }
    if (!leaf)
	for (lvl = 0; lvl < level; lvl++) {
	    for (i = width[lvl]+1; i; i--) out_char(' ');
	    out_string(lvl == level-1 ? last ? sym->last_2 : sym->branch_2 :
	       more[lvl+1] ? sym->vert_2 : sym->empty_2);
	}
    if (rep < 2) add = 0;
    else {
	add = out_int(rep)+2;
	out_string("*[");
    }
    if (current->highlight && (tmp = tgetstr("md",NULL))) tputs(tmp,1,putchar);
    if (swapped = print_args && current->argc < 0) out_char('(');
    comm_len = 0;
    for (here = current->comm; *here; here++)
	if (*here == '\\') {
	    out_string("\\\\");
	    comm_len += 2;
	}
	else if (*here > ' ' && *here <= '~') {
		out_char(*here);
		comm_len++;
	    }
	    else {
		sprintf(comm_tmp,"\\%03o",(unsigned char) *here);
		out_string(comm_tmp);
		comm_len += 4;
	    }
    offset = cur_x;
    info = pids || (user_change && prev_uid != current->uid);
    if (info) out_char(swapped ? ',' : '(');
    if (pids) (void) out_int(current->pid);
    if (user_change && prev_uid != current->uid) {
	if (pids) out_char(',');
	if ((pw = getpwuid(current->uid))) out_string(pw->pw_name);
	else (void) out_int(current->uid);
    }
    if (info || swapped) out_char(')');
    if (current->highlight && (tmp = tgetstr("me",NULL))) tputs(tmp,1,putchar);
    if (print_args) {
	for (i = 0; i < current->argc; i++) {
	    out_char(' ');
	    len = 0;
	    for (here = current->argv[i]; *here; here++)
		len += *here > ' ' && *here <= '~' ? 1 : 4;
	    if (cur_x+len <= output_width-(i == current->argc-1 ? 0 : 4))
		for (here = current->argv[i]; *here; here++)
		    if (*here > ' ' && *here <= '~') out_char(*here);
		    else {
			sprintf(comm_tmp,"\\%03o",(unsigned char) *here);
			out_string(comm_tmp);
		    }
	    else {
		out_string("...");
		break;
	    }
	}
    }
    if (print_args || !current->children) {
	while (closing--) out_char(']');
	out_newline();
	if (print_args) {
	    more[level] = !last;
	    width[level] = swapped+(comm_len > 1 ? 0 : -1);
	    for (walk = current->children; walk; walk = walk->next)
		dump_tree(walk->child,level+1,1,0,!walk->next,current->uid,0);
	}
    }
    else {
	more[level] = !last;
	width[level] = comm_len+cur_x-offset+add;
	if (cur_x >= output_width && trunc) {
	    out_string(sym->first_3);
	    out_string("+");
	    out_newline();
	}
	else {
	    first = 1;
	    for (walk = current->children; walk; walk = next) {
		count = 0;
		next = walk->next;
		if (compact) {
		    scan = &walk->next;
		    while (*scan)
			if (!tree_equal(walk->child,(*scan)->child)) 
			    scan = &(*scan)->next;
			else {
			    if (next == *scan) next = (*scan)->next;
			    count++;
			    *scan = (*scan)->next;
			}
		}
		if (first) {
		    out_string(next ? sym->first_3 : sym->single_3);
		    first = 0;
		}
		dump_tree(walk->child,level+1,count+1,walk == current->children,
		  !next,current->uid,closing+(count ? 1 : 0));
	    }
	}
    }
}


static void dump_by_user(PROC *current,uid_t uid)
{
    const CHILD *walk;

    if (current->uid == uid) {
	if (dumped) putchar('\n');
	dump_tree(current,0,1,1,1,uid,0);
	dumped = 1;
	return;
    }
    for (walk = current->children; walk; walk = walk->next)
	dump_by_user(walk->child,uid);
}


static void read_proc(void)
{
    DIR *dir;
    struct dirent *de;
    FILE *file;
    struct stat st;
    char path[PATH_MAX+1],comm[COMM_LEN+1];
    char *buffer;
    pid_t pid,ppid;
    int fd,size;
    int empty,dummy;

    if (!print_args) buffer = NULL;
    else if (!(buffer = malloc((size_t) (output_width+1)))) {
	    perror("malloc");
	    exit(1);
	}
    if (!(dir = opendir(PROC_BASE))) {
	perror(PROC_BASE);
	exit(1);
    }
    empty = 1;
    while (de = readdir(dir))
	if (pid = atoi(de->d_name)) {
	    sprintf(path,"%s/%d/stat",PROC_BASE,pid);
	    if (file = fopen(path,"r")) {
		empty = 0;
		if (fstat(fileno(file),&st) < 0) {
		    perror(path);
		    exit(1);
		}
		if (fscanf(file,"%d (%[^)]) %c %d",&dummy,comm,(char *) &dummy,
		  &ppid) == 4) {
		    if (!print_args) add_proc(comm,pid,ppid,st.st_uid,NULL,0);
		    else {
			sprintf(path,"%s/%d/cmdline",PROC_BASE,pid);
			if ((fd = open(path,O_RDONLY)) < 0) {
			    perror(path);
			    exit(1);
			}
			if ((size = read(fd,buffer,(size_t) output_width)) < 0)
			  {
			    perror(path);
			    exit(1);
			}
			(void) close(fd);
			if (size) buffer[size++] = 0;
			add_proc(comm,pid,ppid,st.st_uid,buffer,size);
		    }
		}
		(void) fclose(file);
	    }
	}
    (void) closedir(dir);
    if (print_args) free(buffer);
    if (empty) {
	fprintf(stderr,PROC_BASE " is empty (not mounted ?)\n");
	exit(1);
    }
}


#if 0

/* Could use output of  ps achlx | awk '{ print $3,$4,$2,$13 }'  */

static void read_stdin(void)
{
    char comm[PATH_MAX+1];
    char *cmd;
    int pid,ppid,uid;

    while (scanf("%d %d %d %s\n",&pid,&ppid,&uid,comm) == 4) {
	if (cmd = strrchr(comm,'/')) cmd++;
	else cmd = comm;
	if (*cmd == '-') cmd++;
	add_proc(cmd,pid,ppid,uid,NULL,0);
    }
}

#endif


static void usage(void)
{
    fprintf(stderr,"usage: pstree [ -a ] [ -c ] [ -h ] [ -l ] [ -n ] [ -p ] "
      "[ -u ] [ -G | -U ]\n%14s[ pid | user]\n","");
    fprintf(stderr,"       pstree -V\n\n");
    fprintf(stderr,"    -a     show command line arguments\n");
    fprintf(stderr,"    -c     don't compact identical subtrees\n");
    fprintf(stderr,"    -h     highlight current process and its ancestors\n");
    fprintf(stderr,"    -G     use VT100 line drawing characters\n");
    fprintf(stderr,"    -l     don't truncate long lines\n");
    fprintf(stderr,"    -n     sort output by PID\n");
    fprintf(stderr,"    -p     show PIDs; implies -c\n");
    fprintf(stderr,"    -u     show uid transitions\n");
    fprintf(stderr,"    -U     use UTF-8 (Unicode) line drawing characters\n");
    fprintf(stderr,"    -V     display version information\n");
    fprintf(stderr,"    pid    start at pid, default 1 (init)\n");
    fprintf(stderr,"    user   show only trees rooted at processes of that "
      "user\n\n");
    exit(1);
}


int main(int argc,char **argv)
{
    PROC *current;
    struct winsize winsz;
    const struct passwd *pw;
    pid_t pid,highlight;
    char termcap_area[1024];
    int c;

    if (ioctl(1,TIOCGWINSZ,&winsz) >= 0)
	if (winsz.ws_col) output_width = winsz.ws_col;
    pid = 1;
    highlight = 0;
    pw = NULL;
    while ((c = getopt(argc,argv,"acGhnpluUV")) != EOF)
	switch (c) {
	    case 'a':
		print_args = 1;
		break;
	    case 'c':
		compact = 0;
		break;
	    case 'G':
		if (sym != &sym_ascii) usage();
		sym = &sym_vt100;
		break;
	    case 'h':
		if (getenv("TERM") && tgetent(termcap_area,getenv("TERM")) > 0)
		    highlight = getpid();
		break;
	    case 'l':
		trunc = 0;
		break;
	    case 'n':
		by_pid = 1;
		break;
	    case 'p':
		pids = 1;
		compact = 0;
		break;
	    case 'u':
		user_change = 1;
		break;
	    case 'U':
		if (sym != &sym_ascii) usage();
		sym = &sym_utf;
		break;
	    case 'V':
		fprintf(stderr,"pstree from psmisc version " PSMISC_VERSION
		  "\n");
		return 0;
	    default:
		usage();
	}
    if (optind == argc-1)
	if (isdigit(*argv[optind])) {
	    if (!(pid = atoi(argv[optind++]))) usage();
	}
	else if (!(pw = getpwnam(argv[optind++]))) {
		fprintf(stderr,"No such user name: %s\n",argv[optind-1]);
		return 1;
	    }
    if (optind != argc) usage();
    read_proc();
    for (current = find_proc(highlight); current; current = current->parent)
	current->highlight = 1;
    if (!pw)
	dump_tree(find_proc(pid),0,1,1,1,0,0);
    else {
	dump_by_user(find_proc(1),pw->pw_uid);
	if (!dumped) {
	    fprintf(stderr,"No processes found.\n");
	    return 1;
	}
    }
    return 0;
}
