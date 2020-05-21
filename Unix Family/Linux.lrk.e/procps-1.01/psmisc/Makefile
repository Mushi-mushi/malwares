CC=cc
CFLAGS=-g -DPSMISC_VERSION=\"`cat VERSION`\" \
  -Wall -Wno-parentheses -Wwrite-strings -Wpointer-arith -Wcast-align \
  # -Wconversion -g
LDFLAGS=#-s -N #-Xlinker -qmagic
REAL_CPP=/lib/cpp
PROGS=pstree 
EBINDIR=/bin		# essential binaries
BINDIR=/usr/bin		# not so essential ones

all:		$(PROGS)

signames.h:	/usr/include/signal.h
		$(REAL_CPP) -dM </usr/include/signal.h | \
		tr -s '\t ' '  ' | sort -n +2 | sed \
	's:#define SIG\([A-Z]\+[0-9]*\) \([0-9]\+\) *\(\|/\*.*\)$$:{\
\2,"\1" },:p;d' \
		  > signames.h

signals.o:	signals.h signals.c signames.h Makefile

pstree:		pstree.c comm.h Makefile VERSION
		$(CC) $(CFLAGS) $(LDFLAGS) -o pstree pstree.c -ltermcap

clean:
		rm -f *.o signames.h pstree
