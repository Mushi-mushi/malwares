# Sniffit for LinuxRootKit. Requires ncurses...

all: sniffit

sniffit:
	cc -w -O2 -I/usr/include/ncurses -o sniffit sniffit.0.1.2.c -lncurses

clean:
	rm -f *.o core sniffit
