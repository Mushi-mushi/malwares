/*
** kernel/irix64.c             Kernel access functions to retrieve user number
**
** This program is in the public domain and may be used freely by anyone
** who wants to. 
**
   Starting with IRIX64 the file struct contains a ref to a vsocket.
   BUT the inpcb struct still points to a struct socket.
   The vsocket.h file is not available.
   to transate between the vsocket and socket one most
   - get the vsocket struct
     typedef struct vsocket {
        long    vs_magic;
        bhv_head_t      vs_bh;
        ...
    } vsock_t;

   - Get the (struct bhv_desc *) vs_bh->bh_first
     typedef struct bhv_head {
        struct bhv_desc *bh_first;
     } bhv_head_t;

   - Get the (void *) bd_pdata out of the
     typedef struct bhv_desc {
        void            *bd_pdata;
        ...
     } bhv_desc_t;

    bp_data is the pointer to the socket.

   Further more the file table is not available.
   Each process contains it's own dynamic file table.
   So to retrieve the files of each process one must defence the
   
   typedef struct ufchunk {
        struct file     *uf_ofile[NFPCHUNK];
        char            uf_pofile[NFPCHUNK];
        cnt_t           uf_inuse[NFPCHUNK];
        struct ufchunk  *uf_next;
   } ufchunk_t;

   struct fdt {
        int             fd_nofiles;
        struct ufchunk  fd_flist; 
        mrlock_t        fd_lock;        
        sema_t          fd_fwait;      
        lock_t          fd_fwaitlock; 
        short           fd_fwaiting; 
   } fdt_t;
   
   struct proc {
    ...

        struct fdt      *p_fdt;

   ...
   } proc_t;


   Furthermore the process table itself is not available anymore.
   A hash tabel is used instead. The kernel symbol "pacthashtab" contains the
   address of the that table. "pacthashmask" gets you a pointer to the size of
   the table. Each hash slot is chained through p-p_active;

   initial coding  : Luc Chouinard, lucc@sgi.com 03/29/1996
**
*/
#define _KERNEL         1
#define _KMEMUSER       1

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
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/file.h>
#include <sys/sysmp.h>
#include <sys/hwperftypes.h>
#include <sys/proc.h>

#include <ksys/behavior.h>

#define nlist nlist64

#include <sys/vnode.h>
#include <fcntl.h>

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

/*#include <arpa/inet.h> */

#include "identd.h"
#include "error.h"

#define NFPCHUNK        16

/* missing structures */

typedef struct ufchunk {
        struct file     *uf_ofile[NFPCHUNK];
        char            uf_pofile[NFPCHUNK];
        cnt_t           uf_inuse[NFPCHUNK];
        struct ufchunk  *uf_next;
} ufchunk_t;
typedef struct fdt {
        int             fd_nofiles;
        struct ufchunk  fd_flist;
        mrlock_t        fd_lock;
        sema_t          fd_fwait;
        lock_t          fd_fwaitlock;
        short           fd_fwaiting;
} fdt_t;
typedef struct vsocket {
        long    vs_magic;
#define VS_MAGIC        0x03903513
        bhv_head_t      vs_bh;          /* Base behaviour */
        u_int   vs_flags;
        mutex_t vs_lock;
        int     vs_refcnt;
        int     vs_type;                /* cached from create */
        int     vs_protocol;            /* cached from create */
        int     vs_domain;              /* cached from create */
} vsock_t;

extern void *calloc();
extern void *malloc();

struct nlist64 nl[] =
{
#define N_TCB   0
#define N_HTAB  1
#define N_HMSK  2
  { "tcb" },
  { "pacthashtab" },
  { "pacthashmask" },
  { "" }
};

typedef unsigned long kadr;

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
  char *buf;
  size_t len;
  char *what;
{

  if (kvm_read(kd, addr, buf, len) < 0)
  {
    if (syslog_flag)
      syslog(LOG_ERR, "getbuf: kvm_read(%08x, %d) - %s : %m",
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
  struct proc *kp, *p, **pp;
  fdt_t fdt;
  ufchunk_t *cp;
  int tsize, psize, i;
  kadr hmsk=nl[N_HMSK].n_value;
  kadr htab=nl[N_HTAB].n_value;

  /* get the size of the hash table */
  if(!getbuf(hmsk, (char*)&tsize, sizeof(tsize))) return -1;

  /* get the size of the proc table as the kernel knows it */
  psize=sysmp(MP_KERNADDR,MPKA_PROCSIZE);
  if(!(p=(struct proc *)malloc(psize))) return -1;
  if(!(pp=(struct proc **)malloc(sizeof(kadr)*tsize))) return -1;

  /* get the pointer to the hashtable */
  if(!getbuf(htab, (char*)&kp, sizeof(kp), "hashp")) return -1;
  /* read in the complete hash table */
  if(!getbuf((long)kp, (char *)pp, (size_t)sizeof(kadr)*tsize, "hashtac")) return -1;

  /* scan all processes */
  for(i=0;i<tsize;i++)
  {

    kp=pp[i];

    while(kp)
    {

      if(!getbuf((long)kp, (char *)p, (size_t)psize)) return -1;

      kp=p->p_active;

      if(!p->p_fdt) continue;

      /* use the file descriptor table pointer */
      if(!getbuf((long)(p->p_fdt), (char *)&fdt, sizeof(fdt))) continue;

      /* get the first chunk */
      cp=&fdt.fd_flist;

      /* loop on each chunks */
      while(cp)
      {
      int j;
    
        for(j=0;j<NFPCHUNK; j++)
        {
          if(cp->uf_ofile[j]) /* check that file */
          {
          struct file *fp;
          struct file file;

            if (getbuf((long)cp->uf_ofile[j],(char *)&file,sizeof(struct file), "file"))
            {
            vsock_t vs;

              /* get the vsocket */
              if (file.f_flag&FSOCKET && getbuf((long)file.f_data.f_vs, (char*)&vs, sizeof(vs), "vsock"))
              {
              struct socket *sp;

                /* get the struct bhv_desc's first member. Which is a socket pointer really  */
                if(getbuf((long)vs.vs_bh.bh_first,(char*) &sp, sizeof(sp), "socket*"))
                {
                struct socket s;

                  /* read socket */
                  if(getbuf((long)sp, (char *)&s, sizeof(s), "socket"))
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
            }
          }
        }
        /* read extend chunk */
        if(!cp->uf_next || !getbuf((long)cp->uf_next, (char *)&fdt.fd_flist, sizeof(fdt.fd_flist))) break;
      }
    }
  }
  syslog(LOG_ERR,"ident: k_getuid: lookup failure.");
  return -1;
}
