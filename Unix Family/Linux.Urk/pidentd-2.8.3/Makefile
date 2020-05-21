#
# Makefile				Makefile for the Pidentd daemon
#
# This program is in the public domain and may be used freely by anyone
# who wants to. 
#
# Please send bug fixes/bug reports to: Peter Eriksson <pen@lysator.liu.se>
#
include ../Makefile.all

#
# Modify it below to suit your particular system, or specify it
# on the command line (like "make DESTROOT=/usr/wheel sunos4")
#
SHELL=/bin/sh
TAR=tar
#MAKE=make
PGPSIGN=pgps

# set this to 'in.' if you like Sun's prefix on internet daemons
PREFIX=in.
 
DESTROOT=/usr/local

# set this to '/share' if your man pages are in /usr/share
#SHARE=/share

# set this to your favourite secure bin under DESTROOT (eg, etc)
SBIN=sbin

DESTDIR=$(DESTROOT)/$(SBIN)
CONFDIR=$(DESTROOT)/etc

MANROOT=$(DESTROOT)$(SHARE)/man
MANSECT=8
MANDIR=$(MANROOT)/man$(MANSECT)

INSTALL=aux/install-sh -c


# NEXTSTEP 3.x Multi-Architecture-Binary (FAT) compiles
# If you want compile only for one specific platform, specifiy
# 	"-arch m68k" for Motorola 600[34]0
# or
# 	"-arch i386" for Intel i486
# (The Multi-Architecture-Binary is about double as big as the
#  Single-Architecture-Binary)
NEXTARCHS=-arch m68k -arch i386

#
# Global compile-time and link-time options
#
# Please note the the INCLUDE_CRYPT option needs a DES library. You can
# find a free one on ftp.lysator.liu.se in pub/libraries or on
# ftp.funet.fi in pub/crypt/libdes.
#
# GDEFS=-DINCLUDE_EXTENSIONS -DINCLUDE_PROXY -DINCLUDE_CRYPT \
#
# GDEFS=-DINCLUDE_EXTENSIONS -DINCLUDE_PROXY -DINCLUDE_CRYPT \
#	-DSTRONG_LOG -DALLOW_FORMAT \
#
GDEFS=-DINCLUDE_EXTENSIONS -DSTRONG_LOG -DALLOW_FORMAT \
	-DDPATH_CONFIG='\"$(CONFDIR)/identd.conf\"' \
	-DPATH_DESKEY='\"$(CONFDIR)/identd.key\"'

# GLIBS=-lident -ldes
GLIBS=

CFLAGS=-O -I../.. $(URKOPT)
#LDFLAGS=-L$(DESTROOT)/lib

all:
	@echo "Please specify the type of system you wish to build for."
	@echo "Valid systems are:"
	@echo ""
	@echo "	sunos3		SunOS 3.x (tested with 3.5)"
	@echo "	sunos4		Sun SunOS 4"
	@echo "	sunos5		Sun SunOS 5 (Solaris 2)"
	@echo "	bsdi		BSD/386 (The commercial one)"
	@echo "	386bsd		386BSD (The free one)"
	@echo "	netbsd		NetBSD"
	@echo "	freebsd		FreeBSD 2.x"
	@echo "	2.11bsd		2.11BSD"
	@echo "	4.3bsd		4.3BSD Reno"
	@echo "	4.3bsd-tahoe	4.3BSD Tahoe"
	@echo "	dynix3		Sequent Dynix 3"
	@echo "	riscos4		MIPS RISC/OS 4"
	@echo "	aix3		IBM AIX 3.2"
	@echo "	aix40		IBM AIX 4.0 or 4.1"
	@echo "	aix42		IBM AIX 4.2 or 4.3"
	@echo "	irix4		Silicon Graphics IRIX 4"
	@echo "	irix5		Silicon Graphics IRIX 5 (< 5.3)"
	@echo "	irix53		Silicon Graphics IRIX 5.3"
	@echo "	irix6		Silicon Graphics IRIX 6.0"
	@echo "	irix62		Silicon Graphics IRIX 6.2"
	@echo "	irix64		Silicon Graphics IRIX 6.4"
	@echo " hiuxwe2		Hitachi HI-UX/WE2"
	@echo "	hpux7		Hewlett-Packard HP-UX 7"
	@echo "	hpux8		Hewlett-Packard HP-UX 8"
	@echo "	hpux9		Hewlett-Packard HP-UX 9"
	@echo "	hpux10		Hewlett-Packard HP-UX 10"
	@echo "	sco32_40	SCO unix System V release 3.2 (v4.0 & 4.1)"
	@echo "	sco32_42	SCO Unix System V Release 3.2v4.2"
	@echo "	sco32_5		SCO Unix System V Release 3.2v5"
	@echo "	svr4		Generic System V Release 4 UNIX"
	@echo "	attsvr4		AT&T's own System V Release 4"
	@echo "	uw1		Novell UnixWare v1.x"
	@echo "	uw2		Novell UnixWare v2.x"
	@echo "	aux2		Apple A/UX 2"
	@echo "	aux3		Apple A/UX 3.0 only"
	@echo "	aux301		Apple A/UX 3.0.1 or newer"
	@echo "	ultrix3		Digital Ultrix 3"
	@echo "	ultrix4		Digital Ultrix 4"
	@echo "	apollo		Apollo Domain/OS SR10.x"
	@echo "	alpha		Digital Alpha AXP OSF"
	@echo "	alpha3		Digital Alpha AXP OSF; 3.0 or later"
	@echo "	digitalunix	Digital Alpha AXP Digital Unix"
	@echo "	linux		Linux 0.99.13q or later"
	@echo "	unicos6		Cray UNICOS 6"
	@echo "	convex		Convex ConvexOS"
	@echo "	next		NeXT/Mach (NeXTSTEP 2 or 3.0)"
	@echo "	nextmab		NeXT/Mach (NeXTSTEP 3.1 MAB)"
	@echo "	sony_mips_bsd   Sony NEWS (BSD version)"
	@echo "	pyramid4	Pyramid's dualPort OSx 4"
	@echo "	ptx4		Sequent's Dynix/ptx version 4"
	@echo "	ptx2		Sequent's Dynix/ptx version 2"
	@echo "	machten		Tenon MachTen 4.0.x"
	@echo "	other		Other BSD-based Unixes"
	@echo ""
	@echo "For example: make sunos4"
	@echo ""


auto:
	@make `aux/config.guess`

#
# Use this if Linux 0.99.13q or later
#
linux:
	@echo "Building for Linux 0.99.13q or later ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) -DLINUX -DNO_KVM $(GDEFS)" KSRC=linux PREFIX="$(PREFIX)" $(PREFIX)identd)


#
# Use this if Sun SunOS 4.*
#
sunos sunos4 m68k-sun-sunos4.1.1_U1 sparc-sun-sunos4.1.3 sparc-sun-sunos4.1.4:
	@echo "Building for Sun SunOS 4 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lkvm $(GLIBS)" CFLAGS="$(CFLAGS) -DSUN $(GDEFS)" KSRC=sunos4 PREFIX="$(PREFIX)" $(PREFIX)identd)


#
# Use this if Sun SunOS 5.* (Solaris 2.*)
#
solaris solaris2 sunos5 sparc-sun-solaris2.4 sparc-sun-solaris2.5 sparc-sun-solaris2.5.1 sparc-sun-solaris-2.6:
	@echo "Building for Sun SunOS 5 (Solaris 2) ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lkvm -lelf -lsocket -lnsl $(GLIBS)" CFLAGS="$(CFLAGS) -DHAVE_KVM -DSOLARIS=`uname -r|sed -e 's/\./0/g' -e 's/^...$$/&00/'` -DSVR4 $(GDEFS)" KSRC=sunos5 PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if 386BSD
#
386bsd:
	@echo "Building for 386BSD (The free one) ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lutil $(GLIBS)" CFLAGS="$(CFLAGS) -DBSD386 $(GDEFS)" KSRC=386bsd PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if NetBSD
#
netbsd:
	@echo "Building for NetBSD ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" \
		LIBS="-lutil -lkvm $(GLIBS)" CFLAGS="$(CFLAGS) -DBSD386 \
		$(GDEFS) -DHAVE_KVM" KSRC=netbsd PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if FreeBSD 2.x
#
freebsd:
	@echo "Building for FreeBSD 2.x ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" \
		LIBS="-lkvm $(GLIBS)" CFLAGS="$(CFLAGS) -DFREEBSD \
		$(GDEFS) -DHAVE_KVM" KSRC=freebsd PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if BSDI's BSD/386 (the commercial BSD)
#
bsdi bsd386:
	@echo "Building for BSDI's BSD/386 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lutil -lkvm $(GLIBS)" CFLAGS="$(CFLAGS) -DBSDI -DHAVE_KVM $(GDEFS)" KSRC=bsdi PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if 2.11BSD
#
2.11bsd:
	@echo "Building for 2.11BSD"
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS) -i" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) -DNO_KVM $(GDEFS)" MAKE=$(MAKE) KSRC=2.11bsd PREFIX="" identd)


#
# Use this if 4.3BSD
#
bsd 4.3bsd 4.3bsd-reno:
	@echo "Building for 4.3BSD-Reno ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) -DBSD43 $(GDEFS)" MAKE=$(MAKE) KSRC=4.3bsd PREFIX="$(PREFIX)" $(PREFIX)identd)

4.3bsd-tahoe:
	@echo "Building for 4.3BSD-Tahoe ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) -DBSD43 -DTAHOE $(GDEFS)" MAKE=$(MAKE) KSRC=4.3bsd PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this for AIX 3.2
#
aix3:
	@echo "Building for AIX 3.2 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="-DSVR4 -D_AIX32 $(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=aix PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this for AIX 4.x
#
aix40 aix41:
	@echo "Building for AIX 4.0 or 4.1 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="-DSVR4 -D_AIX4 $(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=aix PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this for AIX 4.x
#
aix42 aix43:
	@echo "Building for AIX 4.2 or 4.3 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="-DSVR4 -D_AIX4 -D_AIX42 $(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=aix PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if Sequent Dynix 3.*
#
dynix dynix3 i386-sequent-dynix:
	@echo "Building for Sequent Dynix 3 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=other PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if Mips RISC/OS 4.*
#
mips riscos riscos4:
	@echo "Building for MIPS RISC/OS 4 ..."
	@(cd src ; $(MAKE) CC="$(CC) -systype bsd43" LDFLAGS="$(LDFLAGS)" LIBS="-lmld $(GLIBS)" CFLAGS="$(CFLAGS) -I/usr/include/bsd43 -I/usr/include/bsd43/sys -I/usr/include -DMIPS $(GDEFS)" MAKE=$(MAKE) KSRC=other PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if SGI IRIX 4.*
#
irix4:
	@echo "Building for Silicon Graphics IRIX 4 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lmld -lsun -lc_s $(GLIBS)" CFLAGS="$(CFLAGS) -DIRIX $(GDEFS)" MAKE=$(MAKE) KSRC=irix4 PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if SGI IRIX 5.* (< 5.3)
#
sgi irix irix5:
	@echo "Building for Silicon Graphics IRIX 5 (< 5.3)..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lmld -lsun -lc_s $(GLIBS)" CFLAGS="$(CFLAGS) -DIRIX $(GDEFS)" MAKE=$(MAKE) KSRC=irix5 PREFIX="$(PREFIX)" $(PREFIX)identd)


#
# Use this if SGI IRIX 5.3
#
sgi53 irix53:
	@echo "Building for Silicon Graphics IRIX 5.3 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lmld -lsun -lc_s $(GLIBS)" CFLAGS="$(CFLAGS) -DIRIX -DIRIX53 $(GDEFS)" MAKE=$(MAKE) KSRC=irix5 PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if SGI IRIX 6
#
irix6:
	@echo "Building for Silicon Graphics IRIX 6.0 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lelf $(GLIBS)" CFLAGS="$(CFLAGS) -DIRIX -DIRIX6 $(GDEFS)" MAKE=$(MAKE) KSRC=irix5 PREFIX="$(PREFIX)" $(PREFIX)identd)

 
#
# Use this if SGI IRIX 6.2
#
irix62:
	@echo "Use 'make irix62_32' or 'make irix62_64' instead"
	@exit 1

irix62_32:
	@echo "Building for Silicon Graphics IRIX 6.2, 32bit CPUs ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS) -mips3" LIBS="-lelf $(GLIBS)" CFLAGS="$(CFLAGS) -mips3 -DIRIX -DIRIX62 $(GDEFS)" MAKE=$(MAKE) KSRC=irix5 PREFIX="$(PREFIX)" $(PREFIX)identd)
  
irix62_64:
	@echo "Building for Silicon Graphics IRIX 6.2, 64bit CPUs ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS) -mips3 -64" LIBS="-lelf $(GLIBS)" CFLAGS="$(CFLAGS) -mips3 -64 -DIRIX -DIRIX62 $(GDEFS)" MAKE=$(MAKE) KSRC=irix5 PREFIX="$(PREFIX)" $(PREFIX)identd)
  

#
# Use this if SGI IRIX 6.4
#
irix64:
	@echo "Building for Silicon Graphics IRIX 6.4 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS) -64" LIBS="$(GLIBS) -lelf" CFLAGS="$(CFLAGS) -DIRIX -DIRIX64 -mips3 -DULI -D_PAGESZ=16384 -DCKPT -DINTR_KTHREADS -DNUMA_BASE -DNUMA_PM -DR10000 -64 $(GDEFS)" MAKE=$(MAKE) KSRC=irix64 PREFIX="$(PREFIX)" $(PREFIX)identd)


#
# Use this if SCO SVR3.2v4.0 and v4.1
#
sco32_40 sco32_41 sco3.2v40 sco3.2v41:
	@echo "Building for SCO 3.2v4.0 and 3.2v4.1..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS) -lsocket -lc_s" CFLAGS="$(CFLAGS) -Dsco $(GDEFS)" MAKE=$(MAKE) KSRC=sco324 PREFIX="$(PREFIX)" $(PREFIX)identd)


machten:
	@echo "Building for MachTen 4.0.x ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lkvm $(GLIBS)" CFLAGS="$(CFLAGS) -DHAVE_KVM $(GDEFS)" MAKE=$(MAKE) KSRC=machten PREFIX="$(PREFIX)" $(PREFIX)identd)
 

#
# Use this if Hewlett-Packard HP-UX 7.*
#
hpux7:
	@echo "Building for Hewlett-Packard HP-UX 7 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) -DHPUX7 $(GDEFS)" MAKE=$(MAKE) KSRC=hpux PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if Hewlett-Packard HP-UX 8.* or 9.*
#
hpux8 hpux9:
	@echo "Building for Hewlett-Packard HP-UX 8 or 9..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="-D_HPUX_SOURCE $(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=hpux PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if Hewlett-Packard HP-UX 10.*
#
hpux10 hpux10_20:
	@echo "Building for Hewlett-Packard HP-UX 10..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="-D_HPUX_SOURCE -DHPUX_10 $(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=hpux PREFIX="$(PREFIX)" $(PREFIX)identd)


#
# Use this if Hitachi HI-UX/WE2
#
hiuxwe2:
	@echo "Building for Hitachi HI-UX/WE2"
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) $(GDEFS) -Dhp9000s800 -Dhpux" MAKE=$(MAKE) KSRC=hpux PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if UnixWare v2.x
#
uw2:
	@echo "Building for UnixWare v2.x ... "
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lelf -lgen -lresolv -lsocket -lnsl $(GLIBS)" CFLAGS="$(CFLAGS) -DSVR4 -DUW2 $(GDEFS)" MAKE=$(MAKE) KSRC=uw2 PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if SysV R4
#
svr4 uw1:
	@echo "Building for UNIX System V Release 4 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lelf -lresolv -lsocket -lnsl $(GLIBS)" CFLAGS="$(CFLAGS) -DSVR4 $(GDEFS)" MAKE=$(MAKE) KSRC=svr4 PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if AT&T's own SysV R4
#
attsvr4:
	@echo "Building for AT&T's own System V Release 4 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lelf -lresolv -lsocket -lnsl $(GLIBS)" CFLAGS="$(CFLAGS) -DATTSVR4 -DSVR4 $(GDEFS)" MAKE=$(MAKE) KSRC=svr4 PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if A/UX 2
#
# MANROOT=/usr/catman/u_man
# MANDIR=$(MANROOT)/man8
aux2:
	@echo "Building for A/UX 2..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) -D_AUX_SOURCE -ZB $(GDEFS)" MAKE=$(MAKE) KSRC=aux PREFIX="$(PREFIX)" $(PREFIX)identd)
	@echo "Build done. When/if you do 'make install', don't forget to"
	@echo "specify MANDIR=/usr/catman/u_man/man8."

#
# Use this if A/UX 3
#
aux3:
	@echo "Building for A/UX 3..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) -D_AUX_SOURCE -D'ushort=unsigned short' -D'uint=unsigned int' -ZB $(GDEFS)" MAKE=$(MAKE) KSRC=aux PREFIX="$(PREFIX)" $(PREFIX)identd)
	@echo "Build done. When/if you do 'make install', don't forget to"
	@echo "specify MANDIR=/usr/catman/u_man/man8."

#
# Use this is A/UX 3.0.1 or Newer
#
aux aux301:
	@echo "Building for A/UX 3.0.1 or newer..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS) -lbsd" CFLAGS="$(CFLAGS) -D_AUX_SOURCE -D'ushort=unsigned short' -D'uint=unsigned int' -ZB $(GDEFS)" MAKE=$(MAKE) KSRC=aux301 PREFIX="$(PREFIX)" $(PREFIX)identd)
	@echo "Build done. When/if you do 'make install', don't forget to"
	@echo "specify MANDIR=/usr/catman/u_man/man8."


#
# Use this if DEC Ultrix 3 or 4
#
ultrix ultrix3 ultrix4 vax-dec-ultrix4.5 mips-dec-ultrix4.5:
	@echo "Building for Digital Ultrix 3 or 4 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=other PREFIX="$(PREFIX)" $(PREFIX)identd)


#
# Alpha AXP OSF/1, before version 3.0
#
alpha AlphaOSF:
	@echo "Building for Digital Alpha AXP OSF/1..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="-I/usr/sys/include -I/usr/sys/BINARY $(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=other PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Alpha AXP OSF/1, version 3.0 and later.
#
alpha3 alpha_3.0:
	@echo "Building for Digital Alpha AXP OSF/1 version 3.0 or later..."
	@echo " "
	@echo "Make sure you have in file /etc/sysconfigtab the two lines:"
	@echo "vm:"
	@echo "	kernel-stack-guard-pages = 0"
	@echo "otherwise multiple identd requests may cause a kernel panic."
	@echo " "
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=alpha3 PREFIX="$(PREFIX)" $(PREFIX)identd)

digitalunix alpha-dec-osf4.0:
	@echo "Building for Digital Alpha AXP Digital Unix..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=alpha3 PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Apollo Domain/OS SR10.x
#
PIDOFF=0xc9
apollo:
	@echo "Building for Apollo Domain/OS SR10.x"
	@echo "Must set correct PIDOFF in Makefile !!"
	@echo "Checks below are advisory only."
	@BLDT=`/usr/apollo/bin/bldt -n 0 | /bin/sed -n -e 's/^.*revision \([^,]*\),.*$$/\1/p' `; \
	case "$$BLDT,$$ISP" in \
	  10.2*,m68k )   PIDO=0x46;; \
	  10.3*,m68k )   PIDO=0xc9;; \
	  10.4*,m68k )   PIDO=0xc9;; \
	  10.4.1*,a88k ) PIDO=0x52;; \
	  * )            PIDO=; \
	esac; \
	if [ -z "$$PIDO" ]; then \
	  echo "Cannot determine correct value of PIDOFF for OS version $$BLDT ($$ISP)."; \
	  echo 'Make sure current PIDOFF of $(PIDOFF) is correct:'; \
	elif [ "$$PIDO" = '$(PIDOFF)' ]; then \
	  echo "Current PIDOFF of $(PIDOFF) seems correct for OS version $$BLDT ($$ISP):"; \
	else \
	  echo "Current PIDOFF of $(PIDOFF) seems INCORRECT for OS version $$BLDT ($$ISP):"; \
	  echo '[Compile apollo.c with -DDEBUG and use itest to find correct value]'; \
	fi; \
	echo ' OS Version    PIDOFF'; \
	echo ' 10.2   m68k   0x46   (probably should be higher!)'; \
	echo ' 10.3   m68k   0xc9'; \
	echo ' 10.4   m68k   0xc9'; \
	echo ' 10.4.1 m68k   0xc9'; \
	echo ' 10.4.1 a88k   0x52   (probably should be higher!)'
	(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) $(GDEFS) -DPIDOFF=$(PIDOFF) -DNO_KVM" MAKE=$(MAKE) KSRC=apollo PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if Cray UNICOS 6.*
#
cray unicos unicos6:
	@echo "Building for Cray UNICOS 6 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=unicos6 PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if Convex ConvexOS
#
convex:
	@echo "Building for Convex ConvexOS ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=other PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if NeXTSTEP 3.1 or up - Multi-Architecture Binary or 
#				   Single-Architecture Binary depending on
#				   $(NEXTARCHS)
#
nextmab next3.1 nextstep3.1 nextintel:
	@echo "Building for NeXT/Mach 3.1 Multi-Architecture  (m68k+i386)"
	@(cd src ; $(MAKE) CC="$(CC)" \
		LDFLAGS="-s -object $(LDFLAGS) $(NEXTARCHS)" \
		LIBS="$(GLIBS)" \
		CFLAGS="-DNeXT31 -O2 -Wall -pipe $(GDEFS) $(NEXTARCHS)" \
		KSRC=next_mach PREFIX="$(PREFIX)" $(PREFIX)identd)
	@size $(PREFIX)identd ; file $(PREFIX)identd ; lipo -info $(PREFIX)identd

#
# Use this if NeXTSTEP 2 or 3.0
#
next next3.0 nextstep3.0 next2 nextstep2:
	@echo "Building for NeXT/Mach 2 or 3.0 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=next_mach PREFIX="$(PREFIX)" $(PREFIX)identd)


#
# Use this if SunOS 3.x (tested on SunOS 3.5 using GCC)
#
sunos3:
	@echo "Building for SunOS 3..."
	@if [ ! -h h ]; then echo "You need a symbolic link put in here - ln -s /usr/include/sys h"; fi
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) -DSUNOS35 $(GDEFS)" MAKE=$(MAKE) KSRC=other PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this for Pyramid's dualPort OSx 4.*
#
pyramid4:
	@echo "Building for Pyramid's dualPort OSx 4..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=other PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if SCO 3.2v4.2
#
sco32_42:
	@echo "Building for SCO 3.2v4.2..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS) -lsocket -lc_s" CFLAGS="$(CFLAGS) -Dsco=42 $(GDEFS)" MAKE=$(MAKE) KSRC=sco32_42+5 PREFIX="$(PREFIX)" $(PREFIX)identd)
 
 
#
# Use this if SCO 3.2v5.0
#
sco32_5:
	@echo "Building for SCO 3.2v5.0.0..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS) -belf" LIBS="$(GLIBS) -lsocket " CFLAGS="$(CFLAGS) -O3 -Kspace -Dsco=500 $(GDEFS)" MAKE=$(MAKE) KSRC=sco32_42+5 PREFIX="$(PREFIX)" $(PREFIX)identd)




#
# For Sony MIPS BSD...
#
sony_mips_bsd:
	@echo "Building for sony mips bsd ...""
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lmld$(GLIBS)" CFLAGS="$(CFLAGS) -Dsony_mips_bsd $(GDEFS)" MAKE=$(MAKE) KSRC=other PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# Use this if Sequent Dynix/ptx v4
#
ptx4:
	@echo "Building for Sequent Dynix/ptx Version 4 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lelf -lsocket -lnsl $(GLIBS)" CFLAGS="$(CFLAGS) -DSVR4 $(GDEFS)" MAKE=$(MAKE) KSRC=ptx4 PREFIX="$(PREFIX)" $(PREFIX)identd)

#
#
# Use this if Sequent Dynix/ptx v2
#
ptx2:
	@echo "Building for Sequent Dynix/ptx Version 2 ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="-lsocket -linet -lnsl $(GLIBS)" CFLAGS="$(CFLAGS) -DSVR4 $(GDEFS)" MAKE=$(MAKE) KSRC=ptx2 PREFIX="$(PREFIX)" $(PREFIX)identd)

#
# And all others can try this - but don't put to much hope into it...
#
other:
	@echo "Building for other unspecified Unix (BSD-like) ..."
	@(cd src ; $(MAKE) CC="$(CC)" LDFLAGS="$(LDFLAGS)" LIBS="$(GLIBS)" CFLAGS="$(CFLAGS) $(GDEFS)" MAKE=$(MAKE) KSRC=other PREFIX="$(PREFIX)" $(PREFIX)identd)


#
# End of system-type definitions --------------------------------------
#
$(PREFIX)identd: 
	@echo "Sorry, you have to manually specify what system you wish to"
	@echo "build for. Type 'make' without any arguments to see what"
	@echo "systems are supported."
	@sh -c "exit 1"

identd.$(MANSECT): identd.man
	sed -e 's,xDESTDIRx,$(DESTDIR),g' -e 's,xCONFDIRx,$(CONFDIR),g' $? > $@-t
	rm -f $@
	mv $@-t $@
	chmod 644 $@

identconn: identconn.sh
	sed -e 's,xDESTROOTx,$(DESTROOT),g' $? > $@-t
	rm -f $@
	mv $@-t $@
	chmod 755 $@

install: $(PREFIX)identd identd.$(MANSECT) identconn itest idecrypt
	$(INSTALL) -m 644 identd.$(MANSECT) $(MANDIR)
	if [ -n "$(PREFIX)" ] ; then \
		rm -f $(MANDIR)/$(PREFIX)identd.$(MANSECT) ; \
		echo ".so `basename $(MANDIR)`/identd.$(MANSECT)" > $(MANDIR)/$(PREFIX)identd.$(MANSECT) ; \
	fi
	$(INSTALL) -m 755 $(PREFIX)identd $(DESTDIR)
	$(INSTALL) -m 755 identconn $(DESTROOT)/bin
	$(INSTALL) -m 644 idecrypt.man  $(MANDIR)/idecrypt.$(MANSECT)
	$(INSTALL) -m 755 idecrypt $(DESTDIR)/idecrypt
	@echo "The following command will fail it you are not Root."
	-$(INSTALL) -o root -g kmem -m 2555 itest $(DESTROOT)/bin


tests:
	(cd testdir ; make)

clean:
	-rm -f $(PREFIX)identd idecrypt itest identconn
	@find . '(' -name '*~' -o -name 'core' -o -name '.nfs*' -o -name '%*' -o -name '#*' ')' -print -exec rm -f {} \;
	(cd src ; make clean)
	(cd testdir ; make clean)


version:
	(PACKNAME=`basename \`pwd\`` ; echo 'char version[] = "'`echo $$PACKNAME | sed -e 's/^.*-//'`'";' >src/version.c)
#	(PACKNAME=`basename \`pwd\`` ; echo 'char version[] = "'`echo $$PACKNAME | cut -d- -f2`'";' >src/version.c)

# Many tar implementations do not have Z option. Use compress, like gzip below.
# (But who wants compress anyway?)
distZ:		clean version
	(PACKNAME=`basename \`pwd\`` ; cd .. ; $(TAR) cf - $$PACKNAME | compress >$$PACKNAME.tar.Z)

dist distz:	clean version
	(PACKNAME=`basename \`pwd\`` ; cd .. ; $(TAR) cf - $$PACKNAME | gzip -9 >$$PACKNAME.tar.gz)

upload:		sign
	(PACKNAME=`basename \`pwd\`` ; cd .. ; scp $$PACKNAME.tar.gz $$PACKNAME.sig pen@ftp.lysator.liu.se:/usr/ftp/pub/ident/servers)

sign:		distz
	(PACKNAME=`basename \`pwd\`` ; cd .. ; $(PGPSIGN) -ab $$PACKNAME.tar.gz -o $$PACKNAME.sig && chmod go+r $$PACKNAME.sig)

