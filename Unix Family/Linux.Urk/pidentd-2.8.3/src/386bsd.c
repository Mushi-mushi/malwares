/*
** 386bsd.c		Low level kernel access functions for 386BSD
**
** This program is in the public domain and may be used freely by anyone
** who wants to. 
**
** Please send bug fixes/bug reports to: Peter Eriksson <pen@lysator.liu.se>
*/

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <nlist.h>
#include <pwd.h>
#include <signal.h>
#include <syslog.h>

#include "kvm.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <sys/socketvar.h>

#define KERNEL

#include <sys/file.h>

#undef KERNEL
#include <sys/kinfo.h>

#include <fcntl.h>

#include <sys/user.h>

#include <sys/wait.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <netinet/in_pcb.h>

#include <netinet/tcp.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>

#include <arpa/inet.h>

#include "identd.h"
#include "error.h"


extern void *calloc();
extern void *malloc();


struct nlist nl[] =
{
#define N_FILE 0
#define N_NFILE 1
#define N_TCB 2
      
  { "_filehead" },
  { "_nfiles" },
  { "_tcb" },
  { "" }
};


static struct file *xfile;
static int nfile;

static struct inpcb tcb;

#ifdef	__bsdi__
static kvm_t *kd;

int k_open()
{
  
  /*
  ** Open the kernel memory device
  */
  if ((kd = kvm_openfiles(path_unix, path_kmem, NULL, O_RDONLY)) == 0)
    ERROR("main: kvm_open");
  
  /*
  ** Extract offsets to the needed variables in the kernel
  */
  if (kvm_nlist(kd, nl) < 0)
    ERROR("main: kvm_nlist");

  return 0;
}
#else
int k_open()
{
  int kd;
  
  /*
  ** Open the kernel memory device
  */
  if ((kd = kvm_openfiles(path_unix, path_kmem, NULL)))
    ERROR("main: kvm_open");
  
  /*
  ** Extract offsets to the needed variables in the kernel
  */
  if (kvm_nlist(nl) < 0)
    ERROR("main: kvm_nlist");

  return 0;
}
#endif

/*
** Get a piece of kernel memory with error handling.
** Returns 1 if call succeeded, else 0 (zero).
*/
static int getbuf(addr, buf, len, what)
  long addr;
  char *buf;
  int len;
  char *what;
{
#ifdef	__bsdi__
  if (kvm_read(kd, addr, buf, len) < 0)
#else
  if (kvm_read(addr, buf, len) < 0)
#endif
  {
    if (syslog_flag)
      syslog(LOG_ERR, "getbuf: kvm_read(%08x, %d) - %s : %m",
	     addr, len, what);

    return 0;
  }
  
  return 1;
}



/*
** Traverse the inpcb list until a match is found.
** Returns NULL if no match.
*/
static struct socket *
    getlist(pcbp, faddr, fport, laddr, lport)
  struct inpcb *pcbp;
  struct in_addr *faddr;
  int fport;
  struct in_addr *laddr;
  int lport;
{
  struct inpcb *head;

  if (!pcbp)
    return NULL;

  
  head = pcbp->inp_prev;
  do 
  {
    if ( pcbp->inp_faddr.s_addr == faddr->s_addr &&
	 pcbp->inp_laddr.s_addr == laddr->s_addr &&
	 pcbp->inp_fport        == fport &&
	 pcbp->inp_lport        == lport )
      return pcbp->inp_socket;
  } while (pcbp->inp_next != head &&
	   getbuf((long) pcbp->inp_next,
		  pcbp,
		  sizeof(struct inpcb),
		  "tcblist"));

  return NULL;
}



/*
** Return the user number for the connection owner
*/
int k_getuid(faddr, fport, laddr, lport, uid)
  struct in_addr *faddr;
  int fport;
  struct in_addr *laddr;
  int lport;
  int *uid;
{
  long addr;
  struct socket *sockp;
  int i;
  struct ucred ucb;
  
  /* -------------------- FILE DESCRIPTOR TABLE -------------------- */
  if (!getbuf(nl[N_NFILE].n_value, &nfile, sizeof(nfile), "nfile"))
    return -1;
  
  if (!getbuf(nl[N_FILE].n_value, &addr, sizeof(addr), "&file"))
    return -1;

  {
    int siz = (nfile+10)*sizeof(struct file);
    xfile = (struct file *) calloc(nfile+10, sizeof(struct file));
    if (!xfile)
      ERROR2("k_getuid: calloc(%d,%d)", nfile+10, sizeof(struct file));

    if (!getkerninfo(KINFO_FILE, xfile, &siz, 0))
    {
      ERROR("k_getuid: getkerninfo");
      return -1;
    }
    xfile = (struct file *)((char *)xfile + sizeof(filehead));
  }
  
  /* -------------------- TCP PCB LIST -------------------- */
  if (!getbuf(nl[N_TCB].n_value, &tcb, sizeof(tcb), "tcb"))
    return -1;
  
  tcb.inp_prev = (struct inpcb *) nl[N_TCB].n_value;
  sockp = getlist(&tcb, faddr, fport, laddr, lport);
  
  if (!sockp)
    return -1;

  /*
  ** Locate the file descriptor that has the socket in question
  ** open so that we can get the 'ucred' information
  */
  for (i = 0; i < nfile; i++)
  {
    if (xfile[i].f_count == 0)
      continue;
    
    if (xfile[i].f_type == DTYPE_SOCKET &&
	(struct socket *) xfile[i].f_data == sockp)
    {
      if (!getbuf(xfile[i].f_cred, &ucb, sizeof(ucb), "ucb"))
	return -1;

      *uid = ucb.cr_uid;
      return 0;
    }
  }

  return -1;
}

