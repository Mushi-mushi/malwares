include ../Makefile.all

su: su.o ../file.o ../popen.o
	$(CC) $(LFLAGS) $(DEBUG) $(URKOPT) -o su su.o ../file.o ../popen.o

su.o: su.c
	$(CC) $(CFLAGS) $(DEBUG) $(URKOPT) -c -o su.o su.c

../file.o:
	$(MAKE) -C .. file.o

../popen.o:
	$(MAKE) -C .. popen.o

clean:
	rm -Rf su su.o
