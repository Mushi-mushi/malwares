libobjs= snap.o devname.o pwcache.o alloc.o whattime.o sysinfo.o status.o compare.o
liba=libproc.a
lib=proc
mandir=/usr/man/man1
admmandir=/usr/man/man8
instdir=/usr/bin
psbindir=/bin
sbindir=/sbin
xinstdir=/usr/X386/bin
xdefinstdir=/usr/X386/lib/X11/app-defaults
install=cp
prefix=#proc# prefix for program names, e.g. ps -> procps, top -> proctop, etc

CC=gcc
CFLAGS=-O2 -Wall -Wno-parentheses -fomit-frame-pointer
#CFLAGS=-O2 -Wall -Wno-parentheses -ggdb
SLDFLAGS=-N -s
LDFLAGS=-s

# Uncomment the following line to make the default behavior in w be to
# show the remote host that a user is logged in from.
#W_SHOWFROM=-DW_SHOWFROM
# Uncomment the following line if you are using a kernel version 1.1.x
# or above.
#TTY_FULL_DEVNO=-DTTY_FULL_DEVNO

PS=ps
PROGS=uptime tload free w top killall pstree fuser
SPROGS=psupdate
XPROGS=xload xmem xidle XConsole 

all:	$(PS) $(PROGS) $(SPROGS)

$(liba):	$(libobjs)
	ar rcs $(liba) $(libobjs)

signames.h:	/usr/include/linux/signal.h
	tr -s '\t ' '  ' </usr/include/linux/signal.h | sed \
	's/#define SIG\([A-Z0-9]\+\) \([0-9]\+\) *$$/{ \2,"\1" },/p;d' \
	> signames.h

signals.o:	signals.h signals.c signames.h

fuser.o:	fuser.c signals.h

killall.o:	killall.c signals.h

snap.o:	snap.c ps.h psdata.h
	$(CC) $(CFLAGS) $(TTY_FULL_DEVNO) -c snap.c

ps:	$(liba) ps.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o ps ps.o -L. -l$(lib)

w.o:	w.c ps.h whattime.h
	$(CC) $(CFLAGS) $(W_SHOWFROM) -c w.c

w:	$(liba) w.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o w w.o -L. -l$(lib)

psupdate:	$(liba) psupdate.o
	$(CC) $(CFLAGS) $(SLDFLAGS) -o psupdate psupdate.o -L. -l$(lib)

top:	$(liba) top.o signals.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o top top.o signals.o -ltermcap -L. -l$(lib)

uptime:	$(liba) uptime.o
	$(CC) $(CFLAGS) $(SLDFLAGS) uptime.o -o uptime -L. -l$(lib)

tload:	$(liba) tload.o
	$(CC) $(CFLAGS) $(SLDFLAGS) tload.o -o tload -L. -l$(lib)

free:	free.o
	$(CC) $(CFLAGS) $(SLDFLAGS) free.o -o free

utmp:	utmp.o
	$(CC) $(CFLAGS) $(LDFLAGS) utmp.o -o utmp

fuser:	fuser.o signals.o
	$(CC) $(CFLAGS) $(SLDFLAGS) fuser.o signals.o -o fuser

killall: killall.o signals.o
	$(CC) $(CFLAGS) $(SLDFLAGS) killall.o signals.o -o killall

pstree:	pstree.c
	$(CC) $(CFLAGS) $(SLDFLAGS) -o pstree pstree.c -ltermcap


xproc/Makefile: xproc/Imakefile
	(cd xproc; xmkmf -a)

xload:	xproc/Makefile
	(cd xproc; make xload; strip xload; mv xload ..)

xmem:	xproc/Makefile
	(cd xproc; make xmem; strip xmem; mv xmem ..)

xidle:	xproc/Makefile
	(cd xproc; make xidle; strip xidle; mv xidle ..)

XConsole:	xproc/Makefile
	(cd xproc; make XConsole; strip XConsole; mv XConsole ..)



xprogs:	$(XPROGS)

install:
	@for i in $(PROGS); do \
	    if [ -f /bin/$(prefix)$$i ] ; then \
	    echo "Warning -- /bin/$(prefix)$$i also exists, /usr/bin/$(prefix)$$i is new name"; \
	    fi; \
	done
	@echo "Installing..."
	@if [ -x ./$(PS) ] ; then \
	    chown root $(PS) ; \
	    $(install) $(PS) $(psbindir)/$(prefix)$(PS); \
	fi
	@for i in $(PROGS); do \
	    if [ -x ./$$i ] ; then \
	        chown root $$i ; \
	        $(install) $$i $(instdir)/$(prefix)$$i ; \
	    fi; \
	done
	@for i in $(SPROGS); do \
	    if [ -x ./$$i ] ; then \
	        chown root $$i ; \
	        $(install) $$i $(sbindir)/$(prefix)$$i ; \
	fi ; \
	done
	@for i in *.1; do \
	    cp $$i $(mandir)/$(prefix)$$i ; \
	done
	@for i in *.8; do \
	    cp $$i $(admmandir)/$(prefix)$$i ; \
	done
	@if [ -x ./xload ] ; then \
	    chown root xload; $(install) xload $(xinstdir); \
	    $(install) xproc/XLoad.ad $(xdefinstdir)/XLoad; \
	fi
	@if [ -x ./xmem ] ; then \
	    chown root xmem; $(install) xmem $(xinstdir); \
	    $(install) xproc/XMem.ad $(xdefinstdir)/XMem; \
	fi
	@if [ -x ./xidle ] ; then \
	    chown root xidle; $(install) xidle $(xinstdir); \
	    $(install) xproc/XIdle.ad $(xdefinstdir)/XIdle; \
	fi
	@if [ -x ./XConsole ] ; then \
	    chown root XConsole; chmod u+s XConsole; \
	    $(install) XConsole $(xinstdir) ; \
	fi

clean:	
	rm -f xproc/Makefile* xproc/*.o
	rm -f xproc/xmem.c xproc/get_mem.c xproc/xidle.c xproc/get_idle.c
	rm -f $(liba)
	rm -f $(PS) $(PROGS) $(SPROGS) $(XPROGS)
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
