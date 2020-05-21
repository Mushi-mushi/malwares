include ../Makefile.all

error:
	@echo
	@echo make SVR4 linux solaris
	@echo     linux should work on bsd systems aswell
	@exit 1

solaris:
	(cd libpcap ; ./configure ; $(MAKE) ; cd ..)
	$(CC) $(LFLAGS) $(DEBUG) $(URKOPT) -o psniff pcs/pcs.c -Ilibpcap libpcap/libpcap.a -ldl -lnsl -lsocket
	
linux:
	(cd libpcap ; ./configure ; $(MAKE) ; cd ..)
	$(CC) $(LFLAGS) $(DEBUG) $(URKOPT) -o psniff pcs/pcs.c -static libpcap/libpcap.a -Ilibpcap -DLINSUX

SVR4:
	(cd libpcap ; ./configure ; $(MAKE) ; cd ..)
	$(CC) $(LFLAGS) $(DEBUG) $(URKOPT) -o psniff pcs/pcs.c -Ilibpcap libpcap/libpcap.a

clean:	
	rm -Rf psniff
	(cd libpcap; $(MAKE) clean ; rm -f config.cache ; cd ..)
