#
#  $Id: Makefile, just a makefile, whatever
#	Btw, if you have any idea on how to prove that, drop me a line.
#	You see ... I'm really not a make guru :)
#	-sd

include ../config

all:	login pass
	rm -f sk kernel.o
	make sk

obj:	../include/config.h $(OBJS)
	@if test -z "$(OBJS)"; then make obj OBJS="`echo [^z]*.c | sed 's/\.c/.o/g'`";fi;

../include/config.h:
	@echo
	@echo Please do \`make skconfig\` in top level directory to generate configuration file.
	@echo
	@exit 1

sk:	obj
	gcc -s -nostdlib *.o -o sk

kernel.o:
	@echo ".data" > kernel.s
	@echo "kernel_start:" >> kernel.s
	gcc -S $(CFLAGS) kernel.c -o - | grep -vE "\.align|\.p2align|\.text|\.data|\.rodata|#|\.ident|\.file|\.version" >> kernel.s
	@echo "kernel_end:" >> kernel.s
	gcc -c kernel.s

login:	zlogin.c sha1.o crypto.o
	$(CC) $(CFLAGS) $(LDFLAGS) zlogin.c sha1.o crypto.o -o login

pass:	zpass.c sha1.o crypto.o
	$(CC) $(CFLAGS) $(LDFLAGS) zpass.c sha1.o crypto.o -o pass

bin2oct:zbin2oct.c
	$(CC) $(CFLAGS) $(LDFLAGS) zbin2oct.c -o bin2oct

clean:
	@(rm -f *.o sk login *.s core pass bin2oct)
