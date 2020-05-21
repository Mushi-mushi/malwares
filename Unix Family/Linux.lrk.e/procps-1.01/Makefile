# Makefile for procps.  Chuck Blake.
# Portions of this are highly dependent upon features specific to GNU make

PREFIX     =  #proc# prefix for program names
BINDIR     =  /bin
SBINDIR    =  /sbin
USRBINDIR  =  /usr/bin

BPROG      =  ps
UPROG      =  top 

SUBDIRS    =  psmisc 

CC         =  gcc -fomit-frame-pointer#-ggdb # easy to command-line override
CFLAGS     =  -I. -Wall -Wno-unused
#SHARED     =  1# build/install both a static and ELF shared library
SHLIBDIR   =  /lib# where to install the shared library

LDFLAGS    =  -Wl,-warn-common #-s	recommended for ELF systems
#LDFLAGS    =  -qmagic -s#		recommended for a.out systems
#LDFLAGS    =  -Xlinker -qmagic -s#	older a.out systems may need this
#LDFLAGS    =  -N -s#			still older a.out systems use this

LIBCURSES  =  -lncurses# watch is the only thing that needs this
#LIBCURSES  =  -lcurses -ltermcap# BSD Curses requires termcap
LIBTERMCAP =  -ltermcap
EXTRALIBS  =  # -lshadow

#W_SHOWFROM =  -DW_SHOWFROM# show remote host users are logged in from.

#----------------------------------------------------#
# End of user-configurable portion of the Makefile.  #
# You should not need to modify anything below this. #
#----------------------------------------------------#
BUILD = $(BPROG) $(UPROG) $(SPROG) $(SUBDIRS)

# BUILD LIBRARIES + PROGRAMS
all: $(BUILD)

clean:
	$(RM) $(OBJ) $(BPROG) $(UPROG) $(SPROG)
	for i in proc $(SUBDIRS); do $(MAKE) -C $$i clean; done

#-----------------------------------------------------#
# End of user-callable make targets.                  #
# You should not need to read anything below this.    #
#-----------------------------------------------------#

.PHONY:	all install libinstall clean distclean checkout checkclean realclean
.PHONY: $(patsubst %,install_%, $(BPROG) $(UPROG) $(SPROG))
.PHONY: proc psmisc skill xproc xcpustate
.PHONY: $(patsubst %,build_%, proc psmisc skill xproc xcpustate)
.PHONY: $(patsubst %,install_%, proc psmisc skill xproc xcpustate)

VERSION      =  1
SUBVERSION   =  01
LIBPROCPASS  =  SHARED=$(SHARED) SHLIBDIR=$(SHLIBDIR) VERSION=$(VERSION) SUBVERSION=$(SUBVERSION)

# libproc setup

ifeq ($(SHARED),1)
    LIB_TGT = proc/libproc.so.$(VERSION).$(SUBVERSION)
else
    LIB_TGT = proc/libproc.a
endif

$(LIB_TGT): $(wildcard proc/*.[ch])
	$(MAKE) -C proc `basename $(LIB_TGT)` $(LIBPROCPASS)

# component package setup -- the pattern should be obvious: A build rule and
# unified executable+documentation install rule. (An extra makefile rule is
# needed for those packages which use Imake.)

psmisc:             build_psmisc
build_psmisc:				; $(MAKE) -C psmisc

# executable dependencies

ps top w uptime tload free vmstat sessreg utmp psupdate : $(LIB_TGT)

# static pattern build/link rules:

%.o : %.c
	$(strip $(CC) $(CFLAGS) -c $^)

top.o: top.c top.h
	$(CC) $(CFLAGS) -fwritable-strings -c $<

ps w uptime tload free vmstat sessreg utmp: % : %.o
	$(strip $(CC) $(LDFLAGS) -o $@ $< $(LIB_TGT) $(EXTRALIBS))

# special instances link rules (need extra libraries/objects)

top:   % : %.o
	$(strip $(CC)  $(LDFLAGS) -o $@ $^ $(LIB_TGT) $(LIBTERMCAP) $(EXTRALIBS))

# miscellaneous useful macros

VC_SUF   =  ,v
VC_PFX   =  RCS/
RCSFILES =  $(patsubst $(VC_PFX)%$(VC_SUF),%,$(wildcard $(VC_PFX)*$(VC_SUF)))
SRC      =  $(sort $(wildcard *.c) $(filter %.c,$(RCSFILES)))
OBJ      =  $(SRC:.c=.o)
