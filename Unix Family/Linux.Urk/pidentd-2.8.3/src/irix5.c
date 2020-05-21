/*
** irix5.c             Kernel access functions to retrieve user number
**
** This program is in the public domain and may be used freely by anyone
** who wants to. 

** Please send bug fixes/bug reports to: Peter Eriksson <pen@lysator.liu.se>
**
**
** Hacked to work with irix5, 27 May 1994 by
** Robert Banz (banz@umbc.edu) Univ. of Maryland, Baltimore County
**
** does some things the irix4 way, some the svr4 way, and some just the 
** silly irix5 way.
**
** Hacked to work with irix5.3, 26 Jan 1995 by
** Frank Maas (maas@wi.leidenuniv.nl) Leiden University, The Netherlands
** but all the credits go to Robert Banz (again), who found out about the
** hacks and included them in sources for pidentd-2.3.
**
** =========================================================================
** august 24th 1997
** Changed the code to scan down from file to pcb and not try to match a pcb
** socket to a a file socket. Which for me at least would fail almost 50% of
** the time... With this approach we have a 100% match rate. Using itest.
** I only used itest to perform these tests if there are still problems with
** "real" applications then please let me know.
** Luc Chouinard, lucc@sgi.com
** =========================================================================
**
*/
#define _KMEMUSER

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
#include <sys/cred.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#ifdef IRIX53
/** hack 1: IRIX 5.3 uses 64bit int's for file offsets in the kernel **/
/**         but a 32bit int is used in user programs. sadly though,  **/
/**         there is no way of using <sys/file.h> properly, so we    **/
/**         create our own struct.                                   **/
typedef struct file {
   struct file 	  *f_next;
   struct file 	  *f_prev;
   int 		  f_flag;	/* ushort in <sys/file.h> */
   cnt_t 	  f_count;
   unsigned short f_lock;	/* lock_t (uint) in <sys/file.h> */
   struct vnode   *f_vnode;
   __uint64_t 	  f_offset;	/* off_t (long) in <sys/file.h> */
   struct cred 	  *f_cred;
   cnt_t 	  f_msgcount;
} file_t;
#elif defined(IRIX62)
typedef struct file {
    struct file     *f_next;
    struct file     *f_prev;
    __uint64_t      f_offset; /* off_t (long) in <sys/file.h>  */
    lock_t          f_lock;     /* lock_t (uint) in <sys/file.h> */
    ushort          f_flag;     /* ushort in <sys/file.h>        */
    cnt_t           f_count;
    cnt_t           f_msgcount;
    mutex_t         f_offlock;
    struct vnode    *f_vnode;
    struct  cred    *f_cred;
} file_t;
#else
#include <sys/file.h>
#endif	/* IRIX53 */

#if defined(IRIX6) || (defined(IRIX62) && _MIPS_SZPTR == 64)
#define nlist nlist64
#endif

/** Well... here some problems begin: when upgrading IRIX to 5.3 the **/
/** `inst' program shows one of its peculiar bugs: the file vnode.h  **/
/** has changed location in between versions and now the file is up- **/
/** grade first (new package) and then deleted (old package). So if  **/
/** you have problems finding this file: reinstall eoe1.sw.unix.     **/
#include <sys/vnode.h>

#include <fcntl.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>

#ifdef IRIX62
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

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


#define N_FILE 0 
#define N_TCB  1
 
struct nlist nl[] =
{
  { "file" },
  { "tcb" },
  { "" }
};

static kvm_t *kd;

static struct file *xfile;
static int nfile;

static struct inpcb tcb;

int k_open()
{
  /*
  ** Open the kernel memory device
  */
  if (!(kd = kvm_open(path_unix, path_kmem, NULL, O_RDONLY, NULL)))
    ERROR("main: kvm_open");
  
  /*
  ** Extract offsets to the needed variables in the kernel
  */
  if (kvm_nlist(kd, nl) != 0)
    ERROR("main: kvm_nlist");

  return 0;
}


/*
** Get a piece of kernel memory with error handling.
** Returns 1 if call succeeded, else 0 (zero).
*/
static int getbuf(addr, buf, len, what)
  long addr;
  void *buf;
  int len;
  char *what;
{

  if (kvm_read(kd, addr, buf, len) < 0)
  {
    if (syslog_flag)
      syslog(LOG_ERR, "getbuf: kvm_read(%08x, %d) - %s : %m",
	     addr, len, what);

    if (debug_flag > 1)    
      fprintf(stderr, "getbuf: kvm_read(%08x, %d) = %s - failed\n",
	      addr, len, what);
    
    return 0;
  }
  
  return 1;
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
  struct socket *sockp;
  struct file *fp;
  struct file file;
  int count = 0xffff;	/** Yep, it's hack 2 again **/
  
  if (debug_flag > 1)
    fprintf(stderr, "k_getuid(%08x, %08x, %d, %d)\n",
	    faddr->s_addr,
	    laddr->s_addr,
	    fport,
	    lport);

  /* -------------------- OPEN FILE TABLE ----------------- */

  fp = (struct file *) nl[N_FILE].n_value;

  if (!getbuf((long) fp,(void *) &file, (int) sizeof(struct file), "file"))
    {
      if (debug_flag)
	fprintf(stderr, "failed getting file table pointer\n");

      return -1;
    }

  do 
    {
      struct vnode tvnode;
      struct cred creds;
      
      if (file.f_vnode && getbuf((long) file.f_vnode,(void *) &tvnode,
		 (int) sizeof(struct vnode),"vnode"))
	{
           if(tvnode.v_type==VSOCK)
           {
                struct socket s;

                  /* read socket */
                  if(getbuf((long)tvnode.v_data, (char *)&s, sizeof(s), "socket"))
                  {
                  struct protosw *protop, proto;

                    /* read protosw for it */
                    if(getbuf((long)s.so_proto, (char *)&proto, sizeof(proto), "proto"))
                    {
                    struct domain *domp, dom;

                      /* get domain */
                      if(getbuf((long)proto.pr_domain, (char *)&dom, sizeof(dom), "dom"))
                      {
                        if(dom.dom_family==AF_INET)
                        {
                        struct inpcb inp;

                          if(getbuf((long)s.so_pcb, (char *)&inp, sizeof(inp), "inp"))
                          {
                            
                            if (inp.inp_faddr.s_addr    == faddr->s_addr 
                                && inp.inp_laddr.s_addr == laddr->s_addr
                                && inp.inp_fport        == fport
                                && inp.inp_lport        == lport)
                            {
                            struct  cred creds;

                              /* have a match!  return the user information! */
                              if (getbuf((long)file.f_cred,(char*)&creds,sizeof(struct cred),"cred"))
                              {
                                *uid = creds.cr_ruid;
                                return 0;
                              }
                            }
                          }
                        }
                      }
                    }
                  }
	    } 
	}

      /* if it's the end of the list _or_ we can't get the next
	 entry, then get out of here...*/
      if ((!file.f_next) ||
	  (!getbuf((long) file.f_next,(void *)&file,
		   (int) sizeof(struct file), "file")))
	{
	  if (debug_flag > 1)
	    fprintf(stderr, "aborting - entry not found\n");
	  break;
	}
      
    } while (file.f_next != fp && (count--)); 

  /* heck, if we ever get here, something is really messed up.*/
  if (debug_flag)
    fprintf(stderr, "fubar!\n");

  syslog(LOG_ERR,"ident: k_getuid: lookup failure.");
  return -1;
}
