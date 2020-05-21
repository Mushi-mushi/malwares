include ../Makefile.all
CFLAGS	= -O -DNOPLUS $(XFLAGS)
COMMOBJ	= open_limit.o rcmd.o fixenv.o utmp_host.o
S5R3OBJ	= utmp_init.o utmp_login.o utmp_logout.o updwtmp.o $(COMMOBJ)
S5R4OBJ	= stream_pty.o utmpx_init.o utmpx_login.o utmpx_logout.o $(COMMOBJ)
BSD4OBJ	= login.o logout.o logwtmp.o $(COMMOBJ)
LINXOBJ	= linux_login.o $(COMMOBJ)
RANLIB	= ranlib
EXTRA	=
SHELL	= /bin/sh
#MAKE	= make

what:
	@echo This Makefile is not to be invoked directly 1>&2; exit 1

bsd44 freebsd bsdi:
	@$(MAKE) XFLAGS="-DBSD44" OBJS="$(BSD4OBJ)" \
	    all

linux:
	@$(MAKE) XFLAGS="-DLINUX -D__const=" OBJS="$(LINXOBJ)" \
	    all

sunos4:
	@$(MAKE) XFLAGS="-DSUNOS4" OBJS="$(BSD4OBJ) setenv.o" \
	    all

ultrix4:
	@$(MAKE) XFLAGS="-DULTRIX4" OBJS="$(BSD4OBJ) setenv.o \
	    getusershell.o strdup.o" \
	    all

sysv4:
	@$(MAKE) XFLAGS=-DSYSV4 OBJS="$(S5R4OBJ) setenv.o getusershell.o" \
	    RANLIB=echo all

sunos5:
	@$(MAKE) XFLAGS="-DSYSV4 -DSUNOS5" \
	    OBJS="$(S5R4OBJ) setenv.o getusershell.o" \
	    RANLIB=echo all

irix5:
	@$(MAKE) XFLAGS="-DSYSV4 -DIRIX5" \
	    OBJS="$(S5R4OBJ) setenv.o getusershell.o" \
	    RANLIB=echo all

irix4:
	@$(MAKE) XFLAGS="-cckr -DSYSV3 -DIRIX4" \
	    OBJS="$(S5R3OBJ) setenv.o" RANLIB=echo all

hpux9:
	@$(MAKE) XFLAGS="-DHPUX9" OBJS="$(S5R3OBJ) setenv.o" RANLIB=echo all

newsos4:
	@$(MAKE) XFLAGS="-DNEWSOS4" OBJS="$(BSD4OBJ)" all

osf1:
	@$(MAKE) XFLAGS="-DDECOSF1" OBJS="$(COMMOBJ)" all

all:	libutil.a

libutil.a: ${OBJS}
	ar rv $@ $?
	$(RANLIB) $@

clean:
	rm -f *.o libutil.a utmp_host

stream_pty: tiocpkt.h
rcmd.o utmp_login.o: sys_defs.h
