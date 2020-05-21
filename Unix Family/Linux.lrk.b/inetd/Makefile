include ../MCONFIG

USE_GNU_READLINE=true
YACC=bison -y
O=-O2 -fomit-frame-pointer -pipe
LDFLAGS=
IBSD=-I/usr/include/bsd -include /usr/include/bsd/bsd.h
CFLAGS = ${O} ${IBSD} 
LDLIBS = -lbsd

inetd: inetd.o

clean:
	rm -f *.o inetd
