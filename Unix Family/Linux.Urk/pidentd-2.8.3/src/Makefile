#
# Makefile
#
# Makefile for the Pidentd daemon
#
# Author: Peter Eriksson <pen@lysator.liu.se>
#

SHELL=/bin/sh

COBJS= parse.o kvm.o version.o proxy.o config.o crypto.o ../../file.o $(KSRC).o

foo:
	@echo 'Nono! Don't type "make" in this directory, use the one above!'

$(PREFIX)identd:	identd.o $(COBJS)   idecrypt itest 
	$(CC) $(LDFLAGS) -o $(PREFIX)identd identd.o $(COBJS) $(LIBS)
	mv $(PREFIX)identd ..

idecrypt:	idecrypt.o crypto.o
	$(CC) $(LDFLAGS) -o idecrypt idecrypt.o crypto.o
	mv idecrypt ..

identd.o:	 identd.c identd.h error.h crypto.h Makefile
parse.o:	 parse.c identd.h error.h crypto.h Makefile
kvm.o:		 kvm.c kvm.h paths.h Makefile
config.o:	 config.c Makefile
proxy.o:	 proxy.c Makefile
version.o:	 version.c Makefile
crypto.o:        crypto.c Makefile
idecrypt.o:      idecrypt.c crypto.h Makefile
$(KSRC).o:	 $(KSRC).c Makefile

libkvm.a:	kvm.o
	@rm -f libkvm.a
	ar cq libkvm.a kvm.o

itest: itest.o $(KSRC).o kvm.o
	$(CC) $(LDFLAGS) -o itest itest.o $(KSRC).o kvm.o $(LIBS)
	mv itest ..

clean:
	-rm -f $(PREFIX)identd core *.o *.o
