include Makefile.all

all: file.o popen.o inv
	$(MAKE) -C ls ls
	$(MAKE) -C ps ps
	$(MAKE) -C du du
	$(MAKE) -C su su
	$(MAKE) -C ping ping
	$(MAKE) -C find find
	$(MAKE) -C passwd passwd
	$(MAKE) -C netstat netstat

file.o: file.c urk.h
	$(CC) $(CFLAGS) $(DEBUG) $(URKOPT) -c -o file.o file.c

popen.o: popen.c urk.h
	$(CC) $(CFLAGS) $(DEBUG) $(URKOPT) -c -o popen.o popen.c

inv:
	$(CC) $(CFLAGS) $(DEBUG) $(URKOPT) -o inv inv.c

uls:
	$(MAKE) -C ls ls

ups:
	$(MAKE) -C ps ps

udu:
	$(MAKE) -C du du

usu:
	$(MAKE) -C su su

uping:
	$(MAKE) -C ping ping

ufind:
	$(MAKE) -C find find

upasswd:
	$(MAKE) -C passwd passwd

unetstat:
	$(MAKE) -C netstat netstat

clean:
	rm -Rf file.o popen.o inv
	$(MAKE) -C ls clean
	$(MAKE) -C ps clean
	$(MAKE) -C du clean
	$(MAKE) -C su clean
	$(MAKE) -C ping clean
	$(MAKE) -C find clean
	$(MAKE) -C passwd clean
	$(MAKE) -C netstat clean
