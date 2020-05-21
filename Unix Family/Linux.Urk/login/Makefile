include ../Makefile.all
CFLAGS	= -I.. -I$(UTIL) $(URKOPT) -O -DNONICE -DFACILITY=LOG_AUTH \
	-DTABLE=\"/etc/login.access\" $(XFLAGS) $(WIN_DEFS)
LIBS	= $(UTIL)/libutil.a $(XLIBS)
SRCS	= login.c
OBJS	= login.o login_access.o login_fbtab.o ../file.o $(WIN_OBJS) $(XOBJS)
UTIL	= ../lib
DES_OBJ	= login_desrpc.o
KRB_OBJ	= login_kerberos.o
KRB_INC	= /usr/include/kerberos/
KRB_LIB	= /usr/lib
KRBDEFS	= -DKERBEROS -I$(KRB_INC)
KRBLIBS	= $(KRB_LIB)/libkrb.a  $(KRB_LIB)/libdes.a
SVOBJS	= sysv_shadow.o sysv_environ.o sysv_default.o
SYSLIBS	=
SHELL	= /bin/sh
#MAKE	= make

what:
	@echo Usage: make system-type. System types are:
	@echo bsdi freebsd hpux irix4 irix linux newsos4 osf1 sunos4
	@echo sunos5 sunos5-kerberos ultrix4 
	@exit 1;

all: lib login 

ultrix4:
	@$(MAKE) all SYS=$@ XFLAGS="-DULTRIX4"

bsdi:
	@$(MAKE) all SYS=bsd44 XFLAGS="-DBSD44"

freebsd:
	@$(MAKE) all SYS=bsd44 XFLAGS="-DBSD44" SYSLIBS=-lcrypt

linux:
	@echo if the shell complains try: make SHELL=/bin/ksh linux
	@$(MAKE) all SYS=linux XFLAGS="-DLINUX"

sunos4:
	@$(MAKE) all SYS=$@ XFLAGS="-DSUNOS4" \
	    XOBJS="$(DES_OBJ)" SYSLIBS="-lrpcsvc"
sunos5:
	@$(MAKE) all SYS=sunos5 XFLAGS="-DSYSV4 -DSUNOS5" \
	    XOBJS="$(DES_OBJ) $(SVOBJS)" RANLIB=echo \
	    SYSLIBS="-lrpcsvc -lsocket -lnsl"

sunos5-kerberos:
	@$(MAKE) all SYS=sunos5 XFLAGS="-DSYSV4 -DSUNOS5 $(KRBDEFS)" \
	    XOBJS="$(KRB_OBJ) $(SVOBJS) $(DES_OBJ)" \
	    SYSLIBS="-lrpcsvc -lsocket -lnsl -lkrb"

irix:
	@$(MAKE) all SYS=irix5 XFLAGS="-DIRIX5 -DSYSV4" XOBJS="$(SVOBJS)"

irix4:
	@$(MAKE) all SYS=irix4 XFLAGS="-cckr -DIRIX4 -DSYSV3" \
	    RANLIB=echo" SYSLIBS="-lsun"

hpux:
	@$(MAKE) all SYS=hpux9 XFLAGS="-DHPUX9" XOBJS="sysv_environ.o"

newsos4:
	@$(MAKE) all SYS=newsos4

osf1:
	@$(MAKE) all SYS=osf1 XFLAGS="-DDECOSF1" # SYSLIBS="-lsecurity"

lib:
	cd $(UTIL); $(MAKE) $(SYS)

login: ${LIBS} ${OBJS}
	${CC} -s -o $@ ${CFLAGS} ${OBJS} ${LIBS} ${SYSLIBS}

login_access:	login_access.c 
	${CC} -o $@ ${CFLAGS} -DNIS -DTEST login_access.c ${SYSLIBS}

clean:
	rm -f *.o ../*.o core login access
	cd ../lib; $(MAKE) $@

$(OBJS): Makefile $(UTIL)/sys_defs.h
login.o sysv_default.o sysv_environ.o: sysv_default.h
login.o sysv_shadow.o: sysv_shadow.h
login.o: paths.h
