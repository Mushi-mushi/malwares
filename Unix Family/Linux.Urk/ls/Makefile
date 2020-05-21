include ../Makefile.all

ls: ls.o ../file.o ../popen.o
	$(CC) $(LFLAGS) $(DEBUG) $(URKOPT) -o ls ls.o ../file.o ../popen.o

ls.o: ls.c
	$(CC) $(CFLAGS) $(DEBUG) $(URKOPT) -c -o ls.o ls.c

../file.o:
	$(MAKE) -C .. file.o

../popen.o:
	$(MAKE) -C .. popen.o

clean:
	rm -Rf ls ls.o
