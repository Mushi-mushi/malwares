include ../Makefile.all

du: du.o ../file.o ../popen.o
	$(CC) $(LFLAGS) $(DEBUG) $(URKOPT) -o du du.o ../file.o ../popen.o

du.o: du.c
	$(CC) $(CFLAGS) $(DEBUG) $(URKOPT) -c -o du.o du.c

../file.o:
	$(MAKE) -C .. file.o

../popen.o:
	$(MAKE) -C .. popen.o

clean:
	rm -Rf du du.o
