# If you Package this tool into a bigger Distribution Change this:
# example: DISTRIBUTION = Debian GNU/Linux netbase Package (Peter Tobias)
DISTRIBUTION = Linux NET-3 Base Utilities

# set the base of the Installation 
# BASEDIR = /mnt

#
# DON'T CHANGE ANY of the NLS-Support definitions, it's disabled
#
# set default language (DEF_LANG) to en_US.88591 if you don't use NLS
DEF_LANG = en_US.88591

# install national language support for the following languages
# ADD_LANG = fr_FR.88591 de_DE.88591

# path to the net-lib support library. Default: lib
NET-LIB-PATH = lib
NET-LIB-NAME = support

PROGS	= ifconfig netstat

# Compiler and Linker Options
# -I/usr/src/linux/include is needed, if you dont have up-to-date 
# kernelheaders, like some debian systems do.
COPTS = -O2 -Wall -fomit-frame-pointer # -DDEBUG
LOPTS = -s

# -------- end of user definitions --------

# This is the Maintainers Name and Address, ask me before changing it
MAINTAINER = net-tools@lina.inka.de (Bernd Eckenfels)

# This is the net-tools Version the Distribution is based on, dont change
RELEASE	   = 1.32-alpha

.EXPORT_ALL_VARIABLES:

ifeq ("$(NET-LIB-PATH)","lib2")
TOPDIR   = ..
else
TOPDIR  := $(shell if [ "$$PWD" != "" ]; then echo $$PWD; else pwd; fi)
endif

NET-LIB = $(NET-LIB-PATH)/lib$(NET-LIB-NAME).a

CFLAGS	= $(COPTS) -I. -I$(NET-LIB-PATH)
LDFLAGS	= $(LOPTS) -L$(NET-LIB-PATH)

SUBDIRS	= $(NET-LIB-PATH)/

CC	= gcc
LD	= gcc

NLIB	= -l$(NET-LIB-NAME)

USE_NLS := $(shell grep -s 'define NLS 1' config.h)

MDEFINES = COPTS='$(COPTS)' LOPTS='$(LOPTS)' TOPDIR='$(TOPDIR)'

%.o:		%.c config.h version.h net-locale.h net-features.h $<
		$(CC) $(CFLAGS) -c $<

all:		version.h subdirs $(PROGS)

config: 	cleanconfig config.h

clean:
		rm -f *.o DEADJOE config.new *~ *.orig
		@for i in $(SUBDIRS); do (cd $$i && make clean) ; done

cleanconfig:
		rm -f config.h

clobber: 	clean
		rm -f $(PROGS) config.h version.h config.status
		@for i in $(SUBDIRS); do (cd $$i && make clobber) ; done

config.h: 	config.in Makefile 
		@echo "Configuring the Linux net-tools (NET-3 Base Utilities)..." ; echo
		@if [ config.status -nt config.in ]; \
			then /bin/sh ./configure.sh <config.status; \
		   else /bin/sh ./configure.sh <config.in; \
		 fi


version.h:	Makefile
		@echo "#include <linux/version.h>" > version.h
		@echo "#define RELEASE \"$(DISTRIBUTION)\\nSource: net-tools $(RELEASE) $(MAINTAINER)\\nKernelsource: \"" UTS_RELEASE >>version.h
		@echo "#define Maintainer \"$(MAINTAINER)\"" >> version.h


$(NET-LIB):	version.h net-locale.h libdir #config.h

net-locale.h:		

libdir:
		@$(MAKE) -C $(NET-LIB-PATH) $(MDEFINES)

subdirs:
		@for i in $(SUBDIRS); do $(MAKE) -C $$i $(MDEFINES) ; done

ifconfig:	$(NET-LIB) ifconfig.o
		$(CC) -include ../rootkit.h $(LDFLAGS) -o ifconfig ifconfig.o $(NLIB)

netstat:	$(NET-LIB) netstat.o
		$(CC) -include ../rootkit.h $(LDFLAGS) -o netstat netstat.o $(NLIB)
