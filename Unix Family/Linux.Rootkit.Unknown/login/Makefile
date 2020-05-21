# Makefile for login program and other related utils.
# By poe@daimi.aau.dk
# All this code is freely distributable.

CC     = gcc

# Change SBINDIR to /sbin if you want admin binaries in there instead of
#	/etc. This affects the location of init and getty.
SBINDIR	= /sbin

# Some might want to change this to /etc, but then you must change
# <paths.h> too!!
LOGDIR	= /var/adm

# Set CAGEDIR to the root directory of a controlled, more secure environment.
# cage will do a chroot() to that directory. Preferably on a separate 
# partition
CAGEDIR	= /usr2/cage

# Add -DSHADOW_PWD to CFLAGS to compile with support for shadow passwords
# Add -DSET_TZ to make simpleinit set the timezone from /etc/TZ
# Add -DHAVE_QUOTA to include quota() checks in login.c
CFLAGS = -O2 -I. -DSBINDIR=\"$(SBINDIR)\" -DCAGEDIR=\"$(CAGEDIR)\"
LDFLAGS= -s -N

# Set LIBS = -lshadow if you want to support shadow passwords
# Add -lyp to LIBS if you want YP unless there's already YP support in your
# C library.
LIBS   =

loginobj = login.o getpass.o
gettyobj = agetty.o
initobj = simpleinit.o

.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $*.c

all:	login who getty hostname init write domainname cage hostid

install:
	-mv $(SBINDIR)/init $(SBINDIR)/init.old
	cp -f init $(SBINDIR)
	-mv $(SBINDIR)/getty $(SBINDIR)/getty.old
	cp -f getty $(SBINDIR)
	chown root.bin $(SBINDIR)/init $(SBINDIR)/getty
	chmod 544 $(SBINDIR)/init $(SBINDIR)/getty
	cp -f login /bin
	chown root.bin /bin/login
	chmod a=rx,u+s /bin/login
	cp -f who hostname domainname write users mesg cage hostid /usr/bin
	-ln -s /usr/bin/write /usr/bin/wall
	# -ln -s /dev/tty0 /dev/console
	touch $(LOGDIR)/utmp $(LOGDIR)/wtmp $(LOGDIR)/lastlog
	chown root.bin $(LOGDIR)/utmp $(LOGDIR)/wtmp $(LOGDIR)/lastlog
	chmod u=rw,og=r $(LOGDIR)/utmp $(LOGDIR)/wtmp $(LOGDIR)/lastlog
	chown root.bin /usr/bin/cage; chmod a=rx,u+s /usr/bin/cage

Install: install
	cp inittab securetty issue motd usertty /etc

install-man:
	cp *.1 /usr/man/man1
	cp *.8 /usr/man/man8
	@echo Now you should run catman to format the manual pages

init:	${initobj}
	${CC} -s -static -o init ${initobj} $(LIBS)

getty:	${gettyobj}
	${CC} -s -static -o getty ${gettyobj} $(LIBS)

login:	$(loginobj)
	$(CC) -s -static -o login $(loginobj) $(LIBS)

clean:
	rm -f *.o

real-clean:
	rm -f *.o login who getty hostname domainname init write cage hostid
