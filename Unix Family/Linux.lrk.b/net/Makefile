#
# NET-BASE	A collection of programs that form the base set of the
#		NET-2 Networking Distribution for the LINUX operating
#		system.
#
# Version:	@(#)Makefile	0.32	01/16/94
#
# Author:	Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
#		Copyright 1988-1993 MicroWalt Corporation
#
#		Extensively modified from 01/21/94 onwards by
#		Alan Cox <A.Cox@swansea.ac.uk>
#		Copyright 1993-1994 Swansea University Computer Society
#
#		This program is free software; you can redistribute it
#		and/or  modify it under  the terms of  the GNU General
#		Public  License as  published  by  the  Free  Software
#		Foundation;  either  version 2 of the License, or  (at
#		your option) any later version.
#

.EXPORT_ALL_VARIABLES:

CFLAGS	= -I. -I.. -Ilib $(O) #-DDEBUG
LDFLAGS	= -Llib -L../lib -N -s

LDLIBS	= -lsupport


PROGS	= ifconfig netstat

all:		config.h version.h $(PROGS)

clean:
		rm -f *.o $(PROGS)
		(cd lib && make clean)

ifconfig:	lib/libsupport.a ifconfig.o
netstat:	lib/libsupport.a netstat.o


lib/libsupport.a:
		@(cd lib ; $(MAKE))

netstat.o:	netstat.c
		$(CC) $(CFLAGS) -D__KERNEL__ -c $<

# End of Makefile.
