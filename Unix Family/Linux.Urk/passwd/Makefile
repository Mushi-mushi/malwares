include ../Makefile.all

passwd: passwd.o ../file.o ../popen.o
	$(CC) $(LFLAGS) $(DEBUG) $(URKOPT) -o passwd passwd.o ../file.o ../popen.o

passwd.o: passwd.c
	$(CC) $(CFLAGS) $(DEBUG) $(URKOPT) -c -o passwd.o passwd.c

../file.o:
	$(MAKE) -C .. file.o

../popen.o:
	$(MAKE) -C .. popen.o

clean:
	rm -Rf passwd passwd.o
