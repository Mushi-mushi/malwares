# version 0.1
SHELL  = /bin/sh

# Logs compression, ala gzip. (zlib)
# Uncomment the following lines to enable it
#COMPFLAGS = -DCOMPRESS
#COMPLIB = -lz

#LIBS for sunos
#LIBS   = -lsocket -lnsl -lpcap $(COMPLIB)
#

CC = gcc
LIBS = -lpcap -lz $(COMPLIB)



BIN = .
CFLAGS = -I. -L. $(COMPFLAGS) 

VERSION = "private 1.0 beta 0"
all: ADMsniff

ADMsniff:thesniff.c
	@echo "..ooOO ADMsniff $(VERSION) OOoo.."	
	@tar xvf libpcap-0.4.tar
	@echo "compiling libpcap..."
	@/bin/sh -c "cd libpcap-0.4;./configure; make ; cp libpcap.a  ../"
	@echo "compiling ADMsniff..."
	$(CC) $(CFLAGS) thesniff.c  $(LIBS) -o $(BIN)/sniffer
	@echo "Done!"
clean:
	rm -f $(BIN)/ADMsniff $(BIN)/libpcap.a *~ core a.out *:*
	@cd libpcap-0.4;make clean
