[script]
n0=on *:start:identd on $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) | username $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) | /nick $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) | /set %reklam $read reklam.txt | /set %emailemail $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) $+ $r(a,z) | server
n1=on *^:text:*:?:closemsg $nick | haltdef
n2=on *^:action:*:?:closemsg $nick | haltdef
n3=on *^:notice:*:?:closemsg $nick | haltdef
n4=on *:connect:.timerP 0 30 ctcp $me ping | listed
n5=raw 433:*:nick $read nick.txt
n6=raw 471:*:%kanallar = $remtok(%kanallar,$2,44) | timerr off | join $gettok(%kanallar,$rand(1,$numtok(%kanallar,44)),44)
n7=raw 473:*:%kanallar = $remtok(%kanallar,$2,44) | timerr off | join $gettok(%kanallar,$rand(1,$numtok(%kanallar,44)),44)
n8=raw 474:*:%kanallar = $remtok(%kanallar,$2,44) | timerr off | join $gettok(%kanallar,$rand(1,$numtok(%kanallar,44)),44)
n9=raw 475:*:%kanallar = $remtok(%kanallar,$2,44) | timerr off | join $gettok(%kanallar,$rand(1,$numtok(%kanallar,44)),44)
n10=raw 477:*:%kanallar = $remtok(%kanallar,$2,44) | timerr off | join $gettok(%kanallar,$rand(1,$numtok(%kanallar,44)),44)
n11=raw 366:*:{
n12=  %kanal = $2 | %kanallar = $remtok(%kanallar,$2,44)
n13=  if ($numtok(%kanallar,44) = 2) { list >170 }
n14=  unset %y | unset %z | %x = 0 | :loop | inc %x
n15=  if ($nick(%kanal,%x)) && ($nick(%kanal,%x) isreg %kanal) { %y = $addtok(%y,$nick(%kanal,%x),44) }
n16=  if (%x <= 39) { goto loop }
n17=  mmsg %y %reklam | timerR 0 25 Reklam
n18=}
n19=alias listed {
n20=  unset %kanallar | unset %kanal
n21=  %x = 1 | :loop | inc %x
n22=  addkanal $read -l $+ %x dalnet.txt
n23=  if (%x < $lines(dalnet.txt)) { goto loop }
n24=  join $gettok(%kanallar,$rand(1,$numtok(%kanallar,44)),44)
n25=}
n26=alias addkanal {
n27=  if ($1-) { %kanallar = $addtok(%kanallar,$1,44) }
n28=}
n29=
n30=alias Reklam {
n31=  unset %y | %z = %x | :loop | inc %x
n32=  if ($nick(%kanal,%x) = $null) { mmsg %y %reklam | echo -s 0,1  $+ %kanal $+  Kanal�na At�lan Reklam Tamamland�. | timerr off | .raw part %kanal | unset %x %y %z %kanal | join $gettok(%kanallar,$rand(1,$numtok(%kanallar,44)),44) | if ($numtok(%kanallar,44) = $false) { listed } | halt }
n33=  if ($nick(%kanal,%x) isreg %kanal) { %y = $addtok(%y,$nick(%kanal,%x),44) }
n34=  if ($calc(%z + 40) >= %x) { goto loop }
n35=  mmsg %y %reklam
n36=}
n37=alias mmsg {
n38=  unset %tmp.mmsg
n39=  set %i.mmsg 0
n40=  :start
n41=  inc %i.m
n42=  inc %i.mmsg
n43=  if ($gettok($1,%i.mmsg,44) != $null) {
n44=    if ($gettok($1,%i.mmsg,44) != $me) set %tmp.mmsg $addtok(%tmp.mmsg,$gettok($1,%i.mmsg,44),44)
n45=    if ($gettok(%tmp.mmsg,0,44) == 10) {
n46=      qmsg %tmp.mmsg $2-
n47=      unset %tmp.mmsg
n48=    }
n49=    goto start
n50=  }
n51=  if (%tmp.mmsg) { quote privmsg %tmp.mmsg : $+ $2- }
n52=}
n53=alias qmsg { quote privmsg $1 : $+ $2- }
n43232=on 1:NOTIFY:/msg $nick YO YO
