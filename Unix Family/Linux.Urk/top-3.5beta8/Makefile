# Makefile for "top", a top 10 process display for Unix
#
# This makefile is for top, version 3
#
# Written by William LeFebvre, Group sys Consulting
#		(formerly of Northwestern University and Rice University)

# DO NOT EDIT "Makefile"!!!!  Make changes to "Makefile.X" and rerun
# Configure.

# Executables (these should be obvious):
include ../Makefile.all
SHELL   = /bin/sh
CC      = gcc
AWK     = mawk
INSTALL = ./install

# installation information:
#	OWNER	- name (or uid) for the installed executable's owner
#	GROUP	- group name (or gid) for the installed executable's group
#	MODE	- mode for the installed executable (should start with a 0)
#	BINDIR	- directory where the executable should live
#	MANDIR	- directory where the manual page should live
#	MANEXT	- installed man pages end in .$(MANEXT)
#	MANSTY	- "man" or "catman" depending on what's to be installed
#	SIGNAL	- <signal.h> or <sys/signal.h>; the one with signal definitions
#	TROFF	- most appropriate troff command

OWNER  = root
GROUP  = sys
MODE   = 2711
BINDIR = /usr/local/bin
MANDIR = /usr/man/manl
MANEXT = l
MANSTY = man
SIGNAL = /usr/include/sys/signal.h

# Values for the two defaults in "top":
#	TOPN	- default number of processes to display
#	DELAY	- default delay between updates
#
# set TOPN to -1 to indicate infinity (so that top will display as many
# as the screen will hold).

TOPN = 15
DELAY = 5

CFILES = top.c commands.c display.c screen.c username.c \
	 utils.c version.c getopt.c machine.c
OBJS = top.o commands.o display.o screen.o username.o \
       utils.o version.o getopt.o machine.o ../file.o

CDEFS = -O2
LIBS = -lelf -lkvm -lkstat
TERMCAP = -ltermcap

CFLAGS = -I.. -DHAVE_GETOPT -DORDER -DHAVE_STRERROR $(URKOPT) $(CDEFS)
LINTFLAGS = -x $(CDEFS)

all: Makefile top.local.h top

Makefile: Makefile.X
	@echo 'You need to run the script "Configure" before running "make".'
	exit 10

top.local.h: top.local.H
	@echo 'You need to run the script "Configure" before running "make".'
	exit 10

top: $(OBJS)
	rm -f top
	$(CC) -o top $(OBJS) $(TERMCAP) $(CFLAGS) $(URKOPT) -lm $(LIBS)

lint: sigdesc.h
	$(LINT) $(LINTFLAGS) $(CFILES)

# include file dependencies
top.o: boolean.h display.h screen.h top.h top.local.h utils.h machine.h 
commands.o: boolean.h sigdesc.h utils.h
display.o: boolean.h display.h layout.h screen.h top.h top.local.h utils.h
screen.o: boolean.h screen.h
utils.o: top.h
version.o: top.h patchlevel.h
username.o: top.local.h utils.h

# when compiling machine.c, include os revision definition
machine.o: top.h machine.h utils.h
	$(CC) "-DOSREV=56" $(CFLAGS) -c machine.c

# automatically built include file
sigdesc.h: sigconv.awk $(SIGNAL)
	$(AWK) -f sigconv.awk $(SIGNAL) >sigdesc.h

clean:
	rm -f *.o top core core.* sigdesc.h

veryclean: clean
	rm -f Make.desc machine/*.desc .defaults top.tar SYNOPSIS Makefile top.local.h top.1 machine.c prime

install: top top.1 install-top install-$(MANSTY)

install-top:
	$(INSTALL) -o $(OWNER) -m $(MODE) -g $(GROUP) top $(BINDIR)

install-man:
	$(INSTALL) top.1 $(MANDIR)/top.$(MANEXT)

install-catman:
	tbl top.1 | nroff -man > $(MANDIR)/top.$(MANEXT)

installmeta: top top.1
	$(INSTALL) -o $(OWNER) -m 755 -g $(GROUP) metatop $(BINDIR)/top
	@echo $(INSTALL) -o $(OWNER) -m $(MODE) -g $(GROUP) top $(BINDIR)/top-`uname -m`-`uname -r`
	@$(INSTALL) -o $(OWNER) -m $(MODE) -g $(GROUP) \
		top $(BINDIR)/top-`uname -m`-`uname -r`
	$(INSTALL) top.1 $(MANDIR)/top.$(MANEXT)
