.EXPORT_ALL_VARIABLES:

CFLAGS	= -I. -I.. -Ilib $(O) #-DDEBUG
LDFLAGS	= -Llib -L../lib -N -s

LDLIBS	= -lsupport


PROGS	= netstat

all:		config.h version.h $(PROGS)
install:	all
		install -s netstat /bin

clean:
		rm -f *.o $(PROGS)
		(cd lib && make clean)

netstat:	lib/libsupport.a netstat.o


lib/libsupport.a:
		@(cd lib ; $(MAKE))

netstat.o:	netstat.c
		$(CC) $(CFLAGS) -D__KERNEL__ -c $<
