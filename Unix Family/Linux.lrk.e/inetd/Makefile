all: inetd

include ../MCONFIG
#include ../MRULES

inetd: inetd.o daemon.o
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

inetd.o daemon.o: pathnames.h inetd.h

install: inetd
	install -s -m744 inetd /usr/sbin/
	install -m644 inetd.8 /usr/man/man8/

clean:
	rm -f *.o inetd

