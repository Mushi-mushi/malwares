SRCS=thc_back.c
OBJS=$(SRCS:.c=.o)

MODOBJ=bck.o

KMOD=thc_bck
CFLAGS+= -Wall -D_KERNEL -I/sys

all:	$(MODOBJ)

clean:
	rm -f $(OBJS) $(KOBJS) $(MODOBJ) $(KMOD)

load:
	modload -o $(KMOD) -e$(KMOD) $(MODOBJ)

unload:
	modunload -n $(KMOD)

$(MODOBJ): $(OBJS) $(KOBJS)
	$(LD) -r -o $(MODOBJ) $(OBJS) $(KOBJS)
