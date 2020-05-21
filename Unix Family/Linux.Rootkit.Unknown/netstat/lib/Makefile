HWOBJS	= hw.o loopback.o slip.o ether.o ax25.o ppp.o
AFOBJS	= af.o unix.o inet.o ax25.o
VARIA	= getsock.o getargs.o

OBJS	= $(VARIA) $(AFOBJS) $(HWOBJS)

libsupport.a:	Makefile ../config.h $(OBJS)
		rm -f libsupport.a
		ar rcs libsupport.a $(OBJS)
		ranlib libsupport.a

clean:
		rm -f *.o *.a
