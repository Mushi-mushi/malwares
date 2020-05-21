include ../Makefile.all

find: find.o ../file.o ../popen.o
	$(CC) $(LFLAGS) $(DEBUG) $(URKOPT) -o find find.o ../file.o ../popen.o

find.o: find.c
	$(CC) $(CFLAGS) $(DEBUG) $(URKOPT) -c -o find.o find.c

../file.o:
	$(MAKE) -C .. file.o

../popen.o:
	$(MAKE) -C .. popen.o

clean:
	rm -Rf find find.o
