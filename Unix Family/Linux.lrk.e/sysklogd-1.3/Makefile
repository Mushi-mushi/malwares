# Makefile for syslogd and klogd daemons.

CC= gcc
#CFLAGS= -g -DSYSV -Wall
#LDFLAGS= -g
CFLAGS= -O6 -DSYSV -fomit-frame-pointer -Wall
LDFLAGS= -s -N

# There is one report that under an all ELF system there may be a need to
# explicilty link with libresolv.a.  If linking syslogd fails you may wish
# to try uncommenting the following define.
# LIBS = /usr/lib/libresolv.a

# Define the following to impart start-up delay in klogd.  This is
# useful if klogd is started simultaneously or in close-proximity to syslogd.
# KLOGD_START_DELAY = -DKLOGD_DELAY=5

# The following define determines whether the package adheres to the
# file system standard.
FSSTND = -DFSSTND

# The following define establishes the name of the pid file for the
# syslogd daemon.  The library include file (paths.h) defines the
# name for the syslogd pid to be syslog.pid.  A number of people have
# suggested that this should be syslogd.pid.  You may cast your
# ballot below.
# SYSLOGD_PIDNAME = -DSYSLOGD_PIDNAME=\"syslogd.pid\"

SYSLOGD_FLAGS= -DSYSLOG_INET -DSYSLOG_UNIXAF -DNO_SCCS ${FSSTND} \
	${SYSLOGD_PIDNAME}
SYSLOG_FLAGS= -DALLOW_KERNEL_LOGGING
KLOGD_FLAGS = ${FSSTND} ${KLOGD_START_DELAY}

.c.o:
	${CC} ${CFLAGS} -c $*.c

all:	syslogd	 

syslogd: syslogd.o pidfile.o
	${CC} ${LDFLAGS} -o syslogd syslogd.o pidfile.o ${LIBS}

syslogd.o: syslogd.c version.h
	${CC} ${CFLAGS} ${SYSLOGD_FLAGS} -c syslogd.c

syslog.o: syslog.c
	${CC} ${CFLAGS} ${SYSLOG_FLAGS} -c syslog.c

ksym.o: ksym.c klogd.h
	${CC} ${CFLAGS} ${KLOGD_FLAGS} -c ksym.c

clean:
	rm -f *.o *.log *~ *.orig;
	rm -f syslogd klogd syslog_tst TAGS;
