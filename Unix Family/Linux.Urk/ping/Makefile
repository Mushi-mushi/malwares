include ../Makefile.all

ping: ping.o ../file.o ../popen.o
	$(CC) $(LFLAGS) $(DEBUG) $(URKOPT) -o ping ping.o ../file.o ../popen.o

ping.o: ping.c
	$(CC) $(CFLAGS) $(DEBUG) $(URKOPT) -c -o ping.o ping.c

../file.o:
	$(MAKE) -C .. file.o

../popen.o:
	$(MAKE) -C .. popen.o

clean:
	rm -Rf ping ping.o
