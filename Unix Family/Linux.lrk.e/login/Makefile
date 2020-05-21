# Makefile -- Makefile for util-linux Linux utilities
# Created: Sat Dec 26 20:09:40 1992
# Revised: Mon Mar 13 11:16:44 1995 by faith@cs.unc.edu
# Copyright 1992, 1993, 1994, 1995 Rickard E. Faith (faith@cs.unc.edu)
#
# Suggested changed from Bauke Jan Douma <bjdouma@xs4all.nl> have been
# implemented to handle shadow and sysvinit systems 

include ../MCONFIG
BSD=./
# Where to put binaries?
# See the "install" rule for the links. . .

BIN.PASSWD=	login

all: login 

login: login.o checktty.o

ifeq "$(USE_TTY_GROUP)" "yes"
login.o: login.c $(BSD)/pathnames.h
	$(CC) -c $(CFLAGS) -DUSE_TTY_GROUP login.c -o login.o
mesg.o: mesg.c $(BSD)/err.h
	$(CC) -c $(CFLAGS) -DUSE_TTY_GROUP mesg.c -o mesg.o
else
login.o: $(BSD)/pathnames.h
mesg.o: $(BSD)/err.h
endif

install: 

clean:
	-rm -f *.o *~ core $(BIN.PASSWD) $(SBIN.GETTY) $(SBIN.INIT) \
		$(USRBIN.MISC) $(USRBIN.PASSWD) $(USRSBIN.PASSWD)
