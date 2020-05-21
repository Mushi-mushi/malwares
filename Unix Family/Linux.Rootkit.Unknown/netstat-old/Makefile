.EXPORT_ALL_VARIABLES:

CFLAGS  = -O2
LDFLAGS = -s

PROGS   = netstat

all:	$(PROGS)

install:	all
		install -s netstat /bin

clean:		
		rm -f *.o $(PROGS)

netstat:	netstat.o

netstat.o:	netstat.c
		$(CC) $(CFLAGS) -c $<
