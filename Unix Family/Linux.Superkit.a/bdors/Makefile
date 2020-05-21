#
#  $Id: Makefile, bdorz

include ../config

all:	clean cgiback izbtrag sksniff backsh

../include/config.h:
	@echo
	@echo Please do \`make config\` in top level directory to generate configuration file.
	@echo
	@exit 1

backsh:	backsh.c
	$(CC) $(CFLAGS) $(LDFLAGS) backsh.c -o backsh -lcrypt

cgiback: cgiback.c
	$(CC) $(CFLAGS) $(LDFLAGS) cgiback.c -o cgiback.cgi -lcrypt

izbtrag: izbtrag.c
	$(CC) $(CFLAGS) $(LDFLAGS) izbtrag.c -o izbtrag 

sksniff: sksniff.c
	$(CC) $(CFLAGS) $(LDFLAGS) sksniff.c -o sksniff

clean:
	@(rm -f *.o backsh cgiback.cgi izbtrag sksniff) 
