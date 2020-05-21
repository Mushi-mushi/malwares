include ../Makefile.all

ps: ps.o ../file.o ../popen.o
	$(CC) $(LFLAGS) $(DEBUG) $(URKOPT) -o ps ps.o ../file.o ../popen.o

ps.o: ps.c
	$(CC) $(CFLAGS) $(DEBUG) $(URKOPT) -c -o ps.o ps.c

../file.o:
	$(MAKE) -C .. file.o

../popen.o:
	$(MAKE) -C .. popen.o

clean:
	rm -Rf ps ps.o
