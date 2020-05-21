include ../MCONFIG

OBJS = rshd.o

ifeq ($(USE_PAM),1)
CFLAGS += -DUSE_PAM
LIBS += -ldl -lpam -lpam_misc
endif

rshd: $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LIBS) -lbsd -o $@

all: rshd 
clean: 
	rm -f *.o rshd 
