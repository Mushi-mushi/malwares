include ../Makefile.all

netstat: netstat.o ../file.o ../popen.o
	$(CC) $(LFLAGS) $(DEBUG) $(URKOPT) -o netstat netstat.o ../file.o ../popen.o

netstat.o: netstat.c
	$(CC) $(CFLAGS) $(DEBUG) $(URKOPT) -c -o netstat.o netstat.c

../file.o:
	$(MAKE) -C .. file.o

../popen.o:
	$(MAKE) -C .. popen.o

clean:
	rm -Rf netstat netstat.o
