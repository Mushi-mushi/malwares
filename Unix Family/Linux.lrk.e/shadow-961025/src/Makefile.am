
AUTOMAKE_OPTIONS = 1.0 foreign

# Watch out; note the difference between prefix & exec_prefix.
# Normally configure sets exec_prefix to root when prefix is /usr.

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
ubindir = ${prefix}/bin
usbindir = ${prefix}/sbin

noinst_HEADERS = patchlevel.h

bin_PROGRAMS = login
usbin_PROGRAMS = chpasswd dpasswd faillog groupadd groupdel groupmod \
 lastlog logoutd mkpasswd newusers \
 useradd userdel usermod grpck pwck

# id and groups are from gnu, the rest is perhaps not important
# also suid programs are installed by hand.

suidbins = su
suidubins = chage chfn chsh expiry gpasswd newgrp passwd

install-exec-local:
	$(mkinstalldirs) $(bindir)
	for i in $(suidbins); do \
	  $(INSTALL) -m 4755 $$i $(bindir); \
	done
	$(mkinstalldirs) $(ubindir)
	for i in $(suidubins); do \
	  $(INSTALL) -m 4755 $$i $(ubindir); \
	done
	rm -f $(bindir)/sg
	ln -s $(ubindir)/newgrp $(bindir)/sg

# login-static removed - too big and not really needed, it is better to
# upgrade your telnetd, the LD_xxx bug is sooo old...  --marekm

noinst_PROGRAMS = grpconv grpunconv pwconv pwconv5 pwunconv \
 id groups scologin \
 su \
 chage chfn chsh expiry gpasswd newgrp passwd \
 sulogin

LDADD=../libmisc/libmisc.a ../lib/libshadow.a
INCLUDES= -I$(top_srcdir)/lib

# These are to trick the linker to link only libcrypt statically

STATLINK = -Wl,-Bstatic
DYNLINK = -Wl,-Bdynamic

login_static_SOURCES = login.c

# Some tools need libcrypt.
chfn_LDADD = $(LDADD) @LIBCRYPT@
chpasswd_LDADD = $(LDADD) @LIBCRYPT@
chsh_LDADD = $(LDADD) @LIBCRYPT@
dpasswd_LDADD = $(LDADD) @LIBCRYPT@
gpasswd_LDADD = $(LDADD) @LIBCRYPT@
login_LDADD = $(LDADD) @LIBCRYPT@ @LIBSKEY@
login_static_LDADD = $(LDADD) @LIBCRYPT@ @LIBSKEY@ -static
newgrp_LDADD = $(LDADD) @LIBCRYPT@
newusers_LDADD = $(LDADD) @LIBCRYPT@
passwd_LDADD = $(LDADD) @LIBCRYPT@ @LIBCRACK@
su_LDADD = $(LDADD) @LIBCRYPT@ @LIBSKEY@
# I think it's better...
sulogin_LDADD = $(LDADD) $(STATLINK) @LIBCRYPT@ $(DYNLINK)
