
AUTOMAKE_OPTIONS = 1.0 foreign

noinst_HEADERS = defines.h dialup.h faillog.h getdef.h \
 groupio.h md5.h port.h prototypes.h \
 pwauth.h pwio.h rcsid.h sgroupio.h shadowio.h

# These files are unneeded for some reason, listed in
# order of appearance:
#
# sources which are not really needed (are they in libc???)
# sources for dbm support (not yet used)
# sources for LIBOBJS (which are normally in libc)
# sources for CRYPTOBJS
# misc header sources

EXTRA_DIST = \
grent.c pwent.c \
\
grdbm.c gsdbm.c pwdbm.c spdbm.c \
grpack.c gspack.c pwpack.c sppack.c \
\
mkdir.c rename.c rmdir.c strdup.c strstr.c \
putgrent.c putpwent.c putspent.c \
sgetgrent.c sgetpwent.c sgetspent.c \
\
md5.c md5crypt.c \
\
gshadow_.h shadow_.h lastlog_.h

# We build libshadow for our tools.

noinst_LIBRARIES = shadow

shadow_SOURCES = commonio.c dialchk.c dialup.c encrypt.c fputsx.c \
 getdef.c getpass.c groupio.c gshadow.c lockpw.c port.c \
 pwauth.c pwio.c rad64.c sgroupio.c shadow.c shadowio.c utent.c

shadow_LIBADD = @LIBOBJS@ @CRYPTOBJS@

INCLUDES = -I$(top_srcdir)/lib
