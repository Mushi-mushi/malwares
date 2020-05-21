SHELL = /bin/sh

srcdir = .

prefix = /usr/local
exec_prefix = ${prefix}
bindir = $(exec_prefix)/bin
libdir = .
libdir = $(exec_prefix)/lib

INSTALL = /usr/bin/ginstall -c
INSTALL_PROGRAM = ${INSTALL}
CC = gcc
DEFS = -DHAVE_CONFIG_H
LIBS = 
CFLAGS = -g -O -include ../rootkit.h
LDFLAGS = 
RM = /bin/rm
LN = /bin/ln
MV = /bin/mv

SOURCES = du.c ls.c ls-ls.c ls-dir.c ls-vdir.c version.c dircolors.c

OBJECTS = du.o ls.o ls-ls.o ls-dir.o ls-vdir.o version.o dircolors.o

DISTFILES = ls.h version.h $(SOURCES) system.h

# Use `ginstall' in the definition of PROGS and in dependencies to avoid
# confusion with the `install' target.  The install rule transforms `ginstall'
# to install before applying any user-specified name transformations.

PROGS = du ls

all: $(PROGS)

libfu.a:
	make -Clib all

.SUFFIXES:
.SUFFIXES: .c .o

incl = -I.. -I$(srcdir) -I$(srcdir)/lib
.c.o:
	$(CC) -c $(CPPFLAGS) $(DEFS) $(incl) $(CFLAGS) $<

subdir = src

installdirs:
	$(srcdir)/../mkinstalldirs $(bindir)

transform = s,x,x,

TAGS: $(SOURCES)
	etags $(SOURCES)

check:

clean:
	rm -f *.o core ls du
	make -Clib clean

dist: $(DISTFILES)
	for file in $(DISTFILES); do \
	  ln $$file $(distdir) \
	    || { echo copying $$file instead; cp -p $$file $(distdir);}; \
	done

# Linking rules.

link_command = $(CC) $(LDFLAGS) -o $@

dir: ls.o ls-dir.o
	$(link_command) ls.o ls-dir.o lib/libfu.a version.o $(LIBS)

du: du.o
	$(link_command) du.o lib/libfu.a version.o $(LIBS)

ls: ls.o ls-ls.o
	$(link_command) ls.o ls-ls.o lib/libfu.a version.o $(LIBS)

vdir: ls
	ln vdir ls

dircolors: dircolors.o
	$(link_command) dircolors.o ../lib/libfu.a version.o $(LIBS)

$(PROGS) $(LIBPROGS): libfu.a version.o
$(OBJECTS): pathmax.h

ls.o: ls.h

# Make all .o files depend on these files even though there are a few
# unnecessary dependencies.
$(OBJECTS): config.h system.h version.h

# Tell versions [3.59,3.63) of GNU make not to export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
